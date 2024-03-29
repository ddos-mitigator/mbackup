#!/usr/bin/env python3
# pylint: disable=E1101

import copy
import json
import logging

import _mbase
from __mrequest import M404Exception


class Backup:
    def create_backup(self, params=None):
        if self._supported_version not in self.version:
            sys.exit(f'FATAL ERROR: do not support backuping from {self.version}')

        logging.info('getting policies')
        self._get_policies()
        logging.info('getting protection parameters start')
        self._get_protection_params()
        logging.info('getting groups')
        self._get_groups()
        logging.info('getting rules')
        self._get_rules()
        logging.info('getting autodetect parameters start')
        self._get_autodetect_params()
        logging.info('getting bgp parameters')
        self._get_bgp_params()

    def get_backup_as_json(self, pretty=False):
        return json.dumps(
            {
                'version': self.version,
                'data': {
                    'policies': self.policies,
                    'protection_params': self.protection_params,
                    'groups': self.groups,
                    'rules': self.rules,
                    'autodetect': self.autodetect_params,
                    'bgp': self.bgp,
                },
            },
            ensure_ascii=False,
            indent=4 if pretty else None,
        )

    # TODO: /policies/settings/ ??
    def _get_policies(self):
        _policies = self.req(path='/policies/policies')['policies']
        _policies.sort(key=lambda x: x['id'])

        for policy in _policies:
            policy_id = str(policy['id'])

            del policy['id']
            del policy['click_policy']

            self.policies[policy_id] = policy

            # policy switch
            self.policies[policy_id].update(self.req(path='/toggle/switch', policy=policy_id))
            self.policies[policy_id].update(
                {'announce_switch': self.req(path='/bgp/announce', policy=policy_id).get("switch")}
            )
            self.policies[policy_id].update(
                {'monitor_mode': self.req(path=f'/policies/monitor_mode/{policy_id}').get("monitor_mode")}
            )

    def _get_protection_params(self):
        for _target in ['general', *self.policies]:
            self.protection_params[_target] = dict()
            policy = _target if _target != 'general' else None
            key = 'inpolicy' if policy else 'general'

            if _target == 'general':
                logging.info('getting protection parameters for general protection')
            else:
                logging.info(f'getting protection parameters for policy with id {policy}')

            for _cm_key, _cm_data in _mbase.countermeasures.items():
                if _cm_data[key]:
                    self.protection_params[_target][_cm_key] = dict()

                    if 'switch' in _cm_data:
                        self.protection_params[_target][_cm_key]['switch'] = copy.deepcopy(_cm_data['switch'])
                        _mbase._get_countermeasure_switch(
                            req_func=self.req,
                            settings=self.protection_params[_target][_cm_key]['switch'],
                            policy=policy,
                        )

                    self.protection_params[_target][_cm_key]['settings'] = copy.deepcopy(_cm_data['settings'])
                    for _s_key, _s_data in _cm_data['settings'].items():
                        _backup_func = _s_data.get('backup_func', _mbase._get_simple)
                        try:
                            _backup_func(
                                req_func=self.req,
                                settings=self.protection_params[_target][_cm_key]['settings'][_s_key],
                                policy=policy,
                            )
                        except M404Exception as e:
                            logging.warning(e)

                        if 'backup_func' in _s_data:
                            del self.protection_params[_target][_cm_key]['settings'][_s_key]['backup_func']

        _mbase._recursive_cleanup(self.protection_params)

    def _get_groups(self):
        _groups = self.req(path='/groups/groups')['groups']

        for _group in _groups:
            _policies_list = list()
            for _policy in _group['policies']:
                _policies_list.append(_policy['id'])
            _group['policies'] = _policies_list

            _group_id = _group['id']

            del _group['id']
            del _group['rules']
            self.groups[_group_id] = copy.deepcopy(_group)

        _mbase._recursive_cleanup(self.groups)

    def _get_rules(self):
        _rules = self.req(path='/policySwitch/rules')['rules']
        for rule in _rules:
            if 'is_default' in rule:
                continue

            for index, patch in enumerate(self.rules['patches']):
                _type_id = rule.get('type_id')
                _its_same_type_id = _type_id == patch.get('type_id')
                _its_same_group_id = rule.get('group_id') == patch.get('group_id')
                if _its_same_type_id and _its_same_group_id:
                    _patch = {
                        'op': 'add',
                        'value': {
                            'dst_prefix': rule.get('dst_prefix'),
                            'dst_port': rule.get('dst_port'),
                            'src_prefix': rule.get('src_prefix'),
                            'src_port': rule.get('src_port'),
                            'protocol': rule.get('protocol'),
                            'policy_id': rule.get('policy_id'),
                        },
                    }
                    if _type_id == 3:
                        _patch['before'] = 1
                    _mbase._recursive_cleanup(_patch)
                    self.rules['patches'][index]['patch'].append(_patch)
                    break
            else:
                _type_id = rule.get('type_id')
                _patch = {
                    'op': 'add',
                    'value': {
                        'dst_prefix': rule.get('dst_prefix'),
                        'dst_port': rule.get('dst_port'),
                        'src_prefix': rule.get('src_prefix'),
                        'src_port': rule.get('src_port'),
                        'protocol': rule.get('protocol'),
                        'policy_id': rule.get('policy_id'),
                    },
                }
                if _type_id == 3:
                    _patch['before'] = 1
                obj = {
                    'type_id': _type_id,
                    'group_id': rule.get('group_id'),
                    'version': 1 if _type_id == 3 else 0,
                    'patch': [_patch],
                }
                _mbase._recursive_cleanup(obj)
                self.rules['patches'].append(obj)

    def _get_autodetect_params(self):
        self.autodetect_params['switch'] = self.req(path='/system/autodetect/switch')
        for policy in self.policies:
            self.autodetect_params[policy] = {'cm_timings': [], 'cm_switchs': []}
            _mbase._get_autodetect_setting(
                req_func=self.req, settings=self.autodetect_params[policy], policy=policy
            )

        _mbase._recursive_cleanup(self.autodetect_params)

    def _get_bgp_params(self):
        self.bgp = dict()
        self.bgp.update(self.req(path='/bgp/community_lists'))
        self.bgp.update(self.req(path='/bgp/neighbors'))
        self.bgp.update(self.req(path='/bgp/prefix_lists'))

        self.bgp.update({'global': self.req(path='/bgp/global')})

        flowspec_templates = ('system.policy.prefixes', 'system.policy.rules')

        for connection in self.bgp.get('global'):
            del connection['id']

        self.bgp['flowspec_lists'] = list()
        for flowspec_list in self.req(path='/bgp/flowspec_lists').get('flowspec_lists', list()):
            if flowspec_list.get('name') not in flowspec_templates:
                self.bgp['flowspec_lists'].append(flowspec_list)

        self.bgp['flowspec_templates'] = dict()
        for template in flowspec_templates:
            template_body = self.req(path=f'/bgp/flowspec_templates/{template}').get('template', str())
            if template_body:
                self.bgp['flowspec_templates'][template] = template_body

        self.bgp['neighbors_policies'] = dict()
        for neighbor in self.bgp.get('neighbors', list()):
            neighbor_id = neighbor['id']
            self.bgp['neighbors_policies'][neighbor_id] = self.req(path=f'/bgp/neighbors/{neighbor_id}/policy')

        for index, prefix in enumerate(self.bgp.get('prefix_lists', list())):
            if prefix.get('name') == 'system.flow.detect':
                break
        try:
            del self.bgp['prefix_lists'][index]
        except (KeyError, NameError):
            pass

        _mbase._recursive_cleanup(self.bgp)
