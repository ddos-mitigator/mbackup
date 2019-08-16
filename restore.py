#!/usr/bin/env python3

import copy
import json
import logging
import sys

import mbase
import mitigator


class Restore:
    def __init__(self, _mitigator):
        self.mitigator = _mitigator
        self.config = mbase.Base(_mitigator)

        self.policies = dict()
        self.protection_params = dict()
        self.rules = {'patches': list()}
        self.groups = dict()
        self.autodetect_params = dict()
        self.bgp = dict()

        self._old_new_policies_map = dict()
        self._old_new_groups_map = dict()

    def restore(self, params=None):
        logging.info('recreating policies')
        self._recreate_policies()
        logging.info('recreating groups')
        self._recreate_groups()
        logging.info('recreating rules')
        self._recreate_rules()
        logging.info('recteating protection parameters start')
        self._recreate_protection_params()
        logging.info('resetting autodetect')
        self._resetup_autodetect()
        logging.info('resetting bgp parameters')
        self._resetup_bgp()

    def load_params_from_json(self, raw_json):
        try:
            _json_data = json.loads(raw_json)['data']
        except json.JSONDecodeError as e:
            sys.exit(e)

        self.protection_params = _json_data.get('protection_params', dict())
        self.policies = _json_data.get('policies', dict())
        self.rules = _json_data.get('rules', {'patches': list()})
        self.groups = _json_data.get('groups', dict())
        self.autodetect_params = _json_data.get('autodetect', dict())
        self.bgp = _json_data.get('bgp', dict())

    def _recreate_policies(self):
        for _old_policy_id, _old_policy_data in self.policies.items():
            if _old_policy_data.get('is_default', False):
                self._old_new_policies_map['1'] = '1'
                self.mitigator.make_request(
                    uri='/policies/policy/1',
                    method='PUT',
                    data={
                        'name': _old_policy_data.get('name'),
                        'auto_mitigation': _old_policy_data.get('auto_mitigation'),
                        'description': _old_policy_data.get('description'),
                    },
                )

                self.config._set_simple(
                    settings={'path': '/toggle/switch', 'data': {'switch': _old_policy_data.get('switch')}},
                    policy=self._old_new_policies_map[_old_policy_id],
                )
                continue

            self._old_new_policies_map[_old_policy_id] = self.mitigator.make_request(
                uri='/policies/policy',
                data={
                    'name': _old_policy_data.get('name'),
                    'auto_mitigation': _old_policy_data.get('auto_mitigation'),
                    'description': _old_policy_data.get('description'),
                },
            )['id']

            self.config._set_simple(
                settings={'path': '/toggle/switch', 'data': {'switch': _old_policy_data.get('switch')}},
                policy=self._old_new_policies_map[_old_policy_id],
            )

    def _recreate_groups(self):
        for _old_group_id, _old_group_data in self.groups.items():
            for index, policy_id in enumerate(_old_group_data.get('policies', list())):
                _old_group_data['policies'][index] = self._old_new_policies_map[str(policy_id)]

            self._old_new_groups_map[_old_group_id] = self.mitigator.make_request(
                uri='/groups/groups', data=_old_group_data
            )['id']

    def _recreate_rules(self):
        for index, patch in enumerate(self.rules['patches']):
            for _record_index, _record in enumerate(patch.get('patch', list())):
                self.rules['patches'][index]['patch'][_record_index]['value'][
                    'policy_id'
                ] = self._old_new_policies_map[str(_record['value']['policy_id'])]
            if self._old_new_groups_map:
                self.rules['patches'][index]['group_id'] = self._old_new_groups_map.get(
                    str(patch['group_id'])
                )

        self.config._set_simple(settings={'path': '/policySwitch/rules', 'data': self.rules}, method='PATCH')

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
                    self.config._set_simple(settings=_s_data, policy=policy, method=_s_data.get('add_method'))

                if _cm_switch and _cm_settings:
                    self.config._set_simple(settings=_cm_switch, policy=policy)

    def _resetup_autodetect(self):
        self.config._set_simple(
            settings={'path': '/autodetect/switch', 'data': self.autodetect_params['switch']}
        )
        for policy in self._old_new_policies_map:
            self.config._set_simple(settings=self.autodetect_params[policy], policy=policy)

    def _resetup_bgp(self):
        _bgp_community_lists = self.bgp.get('community_lists')
        _bgp_flowspec_lists = self.bgp.get('flowspec_lists')
        _bgp_global = self.bgp.get('global')
        _bgp_neighbors = self.bgp.get('neighbors')
        _bgp_prefix_lists = self.bgp.get('prefix_lists')
        _bgp_neighbors_policies = self.bgp.get('neighbors_policies')

        __community_lists_map = dict()
        __flowspec_lists_map = dict()
        __neighbors_map = dict()
        __prefix_lists_map = dict()

        if _bgp_community_lists:
            for _record in _bgp_community_lists:
                __old_record_id = _record['id']
                del _record['id']
                __community_lists_map[__old_record_id] = self.mitigator.make_request(
                    uri='/bgp/community_lists', data=_record
                )['id']

        if _bgp_flowspec_lists:
            for _record in _bgp_flowspec_lists:
                __old_record_id = _record['id']
                del _record['id']
                __flowspec_lists_map[__old_record_id] = self.mitigator.make_request(
                    uri='/bgp/flowspec_lists', data=_record
                )['id']

        if _bgp_neighbors:
            for _record in _bgp_neighbors:
                __old_record_id = _record['id']
                del _record['id']
                __neighbors_map[__old_record_id] = self.mitigator.make_request(
                    uri='/bgp/neighbors', data=_record
                )['id']

        if _bgp_prefix_lists:
            for _record in _bgp_prefix_lists:
                __old_record_id = _record['id']
                del _record['id']
                __prefix_lists_map[__old_record_id] = self.mitigator.make_request(
                    uri='/bgp/prefix_lists', data=_record
                )['id']

        # remap and set neighbors policies
        for __old_neighbor_id, __neighbor_policies in _bgp_neighbors_policies.items():
            for __policy in __neighbor_policies['policy']:
                __tmp_prefix_lists = list()
                for __prefix in __policy.get('prefix_lists', list()):
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

            self.mitigator.make_request(
                uri=f'/bgp/neighbors/{__neighbors_map[int(__old_neighbor_id)]}/policy', method='PUT', data=__neighbor_policies
            )

        if _bgp_global:
            self.mitigator.make_request(uri='/bgp/global', method='PUT', data=_bgp_global)
