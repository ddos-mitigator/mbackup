#!/usr/bin/env python3
# pylint: disable=E1101

import copy
import json
import logging
import sys

import _mbase


class Restore:
    def restore(self, params=None):
        if self._supported_version not in self._source_version:
            sys.exit(
                f'FATAL ERROR: do not support restoring from {self._source_version} to {self._supported_version}'
            )

        if self.policies:
            logging.info('recreating policies')
            self._recreate_policies()
        if self.groups:
            logging.info('recreating groups')
            self._recreate_groups()
        if self.rules:
            logging.info('recreating rules')
            self._recreate_rules()
        if self.autodetect_params:
            logging.info('resetting autodetect parameters')
            self._resetup_autodetect_parameters()
        if self.protection_params:
            logging.info('recreating protection parameters start')
            self._recreate_protection_params()
        if self.autodetect_params:
            logging.info('resetting autodetect switches')
            self._resetup_autodetect_switches()
        if self.policies:
            logging.info('resetting policies autodetect parameters')
            self._resetup_policies_autodetect()
        if self.bgp:
            logging.info('resetting bgp parameters')
            self._resetup_bgp()

    def load_params_from_json(self, raw_json):
        try:
            _json_data = json.loads(raw_json)['data']
        except json.JSONDecodeError as e:
            sys.exit(e)

        self._source_version = json.loads(raw_json).get('version')

        self.protection_params = _json_data.get('protection_params', dict())
        self.policies = _json_data.get('policies', dict())
        self.rules = _json_data.get('rules', {'patches': list()})
        self.groups = _json_data.get('groups', dict())
        self.autodetect_params = _json_data.get('autodetect', dict())
        self.bgp = _json_data.get('bgp', dict())

    def _recreate_policies(self):
        is_geo_base_uploaded = self.req(path='/geo/db/continents') is not None
        if not is_geo_base_uploaded:
            logging.warning('no GeoIP db uploaded, GEO countermeasure params restore will be skipped...')

        for _old_policy_id, _old_policy_data in self.policies.items():
            if not is_geo_base_uploaded:
                self.protection_params[str(_old_policy_id)]['geo'] = dict()

            if _old_policy_data.get('is_default', False):
                self._old_new_policies_map['1'] = 1
                self.req(
                    path='/policies/policy/1',
                    method='PUT',
                    data={
                        'name': _old_policy_data.get('name'),
                        'auto_mitigation': False,
                        'description': _old_policy_data.get('description'),
                    },
                )

                _mbase._set_simple(
                    req_func=self.req,
                    settings={'path': '/toggle/switch', 'data': {'switch': _old_policy_data.get('switch')}},
                    policy=self._old_new_policies_map[_old_policy_id],
                )

                _mbase._set_simple(
                    req_func=self.req,
                    settings={'path': '/bgp/announce', 'data': {'switch': _old_policy_data.get('announce_switch')}},
                    policy=self._old_new_policies_map[_old_policy_id],
                )
                continue

            self._old_new_policies_map[_old_policy_id] = self.req(
                path='/policies/policy',
                data={
                    'name': _old_policy_data.get('name'),
                    'auto_mitigation': False,
                    'description': _old_policy_data.get('description'),
                },
            )['id']

            _mbase._set_simple(
                req_func=self.req,
                settings={'path': '/toggle/switch', 'data': {'switch': _old_policy_data.get('switch')}},
                policy=self._old_new_policies_map[_old_policy_id],
            )

            _mbase._set_simple(
                req_func=self.req,
                settings={'path': '/bgp/announce', 'data': {'switch': _old_policy_data.get('announce_switch')}},
                policy=self._old_new_policies_map[_old_policy_id],
            )

    def _recreate_groups(self):
        for _old_group_id, _old_group_data in self.groups.items():
            for index, policy_id in enumerate(_old_group_data.get('policies', list())):
                _old_group_data['policies'][index] = self._old_new_policies_map[str(policy_id)]

            self._old_new_groups_map[_old_group_id] = self.req(path='/groups/groups', data=_old_group_data)[
                'id'
            ]

    def _recreate_rules(self):
        for index, patch in enumerate(self.rules.get('patches', [])):
            for _record_index, _record in enumerate(patch.get('patch', list())):
                self.rules['patches'][index]['patch'][_record_index]['value'][
                    'policy_id'
                ] = self._old_new_policies_map[str(_record['value']['policy_id'])]
            if self._old_new_groups_map:
                __old_patch_group_id = patch.get('group_id')
                if __old_patch_group_id:
                    __new_group_id = self._old_new_groups_map.get(str(__old_patch_group_id))
                    if __new_group_id:
                        self.rules['patches'][index]['group_id'] = __new_group_id

        _mbase._set_simple(
            req_func=self.req, settings={'path': '/policySwitch/rules', 'data': self.rules}, method='PATCH'
        )

    def _recreate_protection_params(self):
        for _target in ['general', *self._old_new_policies_map]:
            policy = self._old_new_policies_map[_target] if _target != 'general' else None

            if _target == 'general':
                if _target in self.protection_params:
                    logging.info('recreate protection parameters for general protection')
                else:
                    logging.error('protection parameters for general protection not found')
                    continue
            else:
                if _target in self.protection_params:
                    logging.info(f'recreate protection parameters for policy with id {policy}')
                else:
                    logging.info(f'protection parameters for policy with id {policy} not found')
                    continue

            for _cm_key, _cm_data in self.protection_params[_target].items():
                _cm_switch = _cm_data.get('switch')
                _cm_settings = _cm_data.get('settings', dict())
                for _s_key, _s_data in _cm_settings.items():
                    _mbase._set_simple(
                        req_func=self.req, settings=_s_data, policy=policy, method=_s_data.get('add_method')
                    )

                if (_cm_switch and _cm_settings) or (_cm_key == 'facl'):
                    _mbase._set_simple(req_func=self.req, settings=_cm_switch, policy=policy)

    def _resetup_autodetect_parameters(self):
        _global_switch = self.autodetect_params.get('switch')
        if _global_switch:
            _mbase._set_simple(
                req_func=self.req, settings={'path': '/system/autodetect/switch', 'data': _global_switch},
            )

        for _old_policy_id in self._old_new_policies_map:

            _custom_metrics = self.autodetect_params[_old_policy_id].get('custom_metrics')
            _timings = self.autodetect_params[_old_policy_id].get('timings')
            _cm_timings = self.autodetect_params[_old_policy_id].get('cm_timings', list())

            if _custom_metrics:
                self.req(
                    path='/autodetect/custom_metrics',
                    method='PUT',
                    policy=self._old_new_policies_map[_old_policy_id],
                    data=_custom_metrics,
                )

            if _timings:
                self.req(
                    path='/autodetect/timings',
                    method='PUT',
                    policy=self._old_new_policies_map[_old_policy_id],
                    data=_timings,
                )

            for _cm_timing in _cm_timings:
                _cm_timing_key, _cm_timing_data = _cm_timing.popitem()
                self.req(
                    path=f'/autodetect/timings/{_cm_timing_key}',
                    method='PUT',
                    policy=self._old_new_policies_map[_old_policy_id],
                    data=_cm_timing_data,
                )

    def _resetup_autodetect_switches(self):
        for _old_policy_id in self._old_new_policies_map:
            _cm_switchs = self.autodetect_params[_old_policy_id].get('cm_switchs', list())
            for _cm_switch in _cm_switchs:
                _cm_switch_key, _cm_switch_data = _cm_switch.popitem()
                if _cm_switch_key == 'wafr':
                    continue

                self.req(
                    path=f'/autodetect/switch/{_cm_switch_key}',
                    method='PUT',
                    policy=self._old_new_policies_map[_old_policy_id],
                    data=_cm_switch_data,
                )

    def _resetup_policies_autodetect(self):
        for _old_policy_id, _old_policy_data in self.policies.items():
            if _old_policy_data.get('is_default', False):
                self.req(
                    path='/policies/policy/1',
                    method='PUT',
                    data={
                        'name': _old_policy_data.get('name'),
                        'auto_mitigation': _old_policy_data.get('auto_mitigation'),
                    },
                )
                continue

            self.req(
                path=f'/policies/policy/{self._old_new_policies_map[_old_policy_id]}',
                method='PUT',
                data={
                    'name': _old_policy_data.get('name'),
                    'auto_mitigation': _old_policy_data.get('auto_mitigation'),
                },
            )

    def _resetup_bgp(self):
        _bgp_community_lists = self.bgp.get('community_lists', list())
        _bgp_flowspec_lists = self.bgp.get('flowspec_lists', list())
        _bgp_global = self.bgp.get('global')
        _bgp_neighbors = self.bgp.get('neighbors', list())
        _bgp_neighbors_policies = self.bgp.get('neighbors_policies', dict())
        _bgp_prefix_lists = self.bgp.get('prefix_lists', list())

        __community_lists_map = dict()
        __flowspec_lists_map = dict()
        __neighbors_map = dict()
        __prefix_lists_map = dict()

        if _bgp_community_lists:
            for _record in _bgp_community_lists:
                __old_record_id = _record['id']
                del _record['id']
                __community_lists_map[__old_record_id] = self.req(path='/bgp/community_lists', data=_record)[
                    'id'
                ]

        if _bgp_flowspec_lists:
            for _record in _bgp_flowspec_lists:
                __old_record_id = _record['id']
                del _record['id']
                __flowspec_lists_map[__old_record_id] = self.req(path='/bgp/flowspec_lists', data=_record)[
                    'id'
                ]

        if _bgp_neighbors:
            for _record in _bgp_neighbors:
                __record_group_id = _record.get('group_id')
                if __record_group_id:
                    _record['group_id'] = self._old_new_groups_map.get(str(__record_group_id))

                __old_record_id = _record['id']
                del _record['id']
                del _record['established']
                __neighbors_map[__old_record_id] = self.req(path='/bgp/neighbors', data=_record)['id']

        if _bgp_prefix_lists:
            for _record in _bgp_prefix_lists:
                __old_record_id = _record['id']
                del _record['id']
                __prefix_lists_map[__old_record_id] = self.req(path='/bgp/prefix_lists', data=_record)['id']

        # remap and set neighbors policies
        for __old_neighbor_id, __neighbor_policies in _bgp_neighbors_policies.items():
            for __policy in __neighbor_policies['policy']:
                __tmp_prefix_lists = list()
                for __prefix in __policy.get('prefix_lists', list()):
                    if __prefix['id'] == 1:
                        __tmp_prefix_lists.append(1)
                    else:
                        __tmp_prefix_lists.append(__prefix_lists_map[__prefix['id']])
                if __tmp_prefix_lists:
                    __policy['prefix_lists'] = __tmp_prefix_lists
                elif 'prefix_lists' in __policy:
                    del __policy['prefix_lists']

                __tmp_community_lists = list()
                for __community in __policy.get('community_lists', list()):
                    __tmp_community_lists.append(__community_lists_map[__community['id']])
                if __tmp_community_lists:
                    __policy['community_lists'] = __tmp_community_lists
                elif 'community_lists' in __policy:
                    del __policy['community_lists']

                __tmp_flowspec_lists = list()
                for __flowspec in __policy.get('flowspec_lists', list()):
                    __tmp_flowspec_lists.append(__flowspec_lists_map[__flowspec['id']])
                if __tmp_flowspec_lists:
                    __policy['flowspec_lists'] = __tmp_flowspec_lists
                elif 'flowspec_lists' in __policy:
                    del __policy['flowspec_lists']

            self.req(
                path=f'/bgp/neighbors/{__neighbors_map[int(__old_neighbor_id)]}/policy',
                method='PUT',
                data=__neighbor_policies,
            )

        if _bgp_global:
            self.req(path='/bgp/global', method='PUT', data=_bgp_global)
