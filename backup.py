#!/usr/bin/env python3

import copy
import json
import logging

import mbase
import mitigator


class Backup:
    def __init__(self, _mitigator):
        self.mitigator = _mitigator
        self.config = mbase.Base(_mitigator)

        self.policies = dict()
        self.protection_params = dict()
        self.rules = {'patches': list()}
        self.groups = dict()
        self.autodetect_params = dict()
        self.bgp = dict()

    def create_backup(self, params=None):
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

    def get_backup_as_json(self):
        return json.dumps(
            {
                'version': self.mitigator.version,
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
        )

    # TODO: policies switches
    def _get_policies(self):
        _policies = self.mitigator.make_request(uri='/policies/policies')['policies']
        _policies.sort(key=lambda x: x['id'])

        for policy in _policies:
            policy_id = str(policy['id'])

            del policy['id']
            del policy['click_policy']

            self.policies[policy_id] = policy

            # policy switch
            self.policies[policy_id].update(
                self.mitigator.make_request(uri='/toggle/switch', policy=policy_id)
            )

    # TODO: autodetect
    def _get_protection_params(self):
        for _target in ['general', *self.policies]:
            self.protection_params[_target] = dict()
            policy = _target if _target != 'general' else None
            key = 'inpolicy' if policy else 'general'

            if _target == 'general':
                logging.info('getting protection parameters for general protection')
            else:
                logging.info(f'getting protection parameters for policy with id {policy}')

            for _cm_key, _cm_data in self.config.countermeasures.items():
                if _cm_data[key]:
                    self.protection_params[_target][_cm_key] = dict()

                    # old _get_policy_prot_switches
                    self.protection_params[_target][_cm_key]['switch'] = copy.deepcopy(_cm_data['switch'])
                    self.config._get_countermeasure_switch(
                        self.protection_params[_target][_cm_key]['switch'], policy
                    )

                    # old _get_policy_prot_params
                    self.protection_params[_target][_cm_key]['settings'] = copy.deepcopy(_cm_data['settings'])
                    for _s_key, _s_data in _cm_data['settings'].items():
                        _backup_func = _s_data.get('backup_func', self.config._get_simple)
                        try:
                            _backup_func(
                                settings=self.protection_params[_target][_cm_key]['settings'][_s_key],
                                policy=policy,
                            )
                        except mitigator.M404Exception as e:
                            logging.warning(e)

                        if 'backup_func' in _s_data:
                            del self.protection_params[_target][_cm_key]['settings'][_s_key]['backup_func']

        mbase._recursive_cleanup(self.protection_params)

    def _get_groups(self):
        _groups = self.mitigator.make_request(uri='/groups/groups')['groups']

        for _group in _groups:
            _policies_list = list()
            for _policy in _group['policies']:
                _policies_list.append(_policy['id'])
            _group['policies'] = _policies_list

            _group_id = _group['id']

            del _group['id']
            del _group['rules']
            self.groups[_group_id] = copy.deepcopy(_group)

        mbase._recursive_cleanup(self.groups)

    def _get_rules(self):
        rules = self.mitigator.make_request(uri='/policySwitch/rules')['rules']
        for rule in rules:
            if 'is_default' in rule:
                continue

            for index, patch in enumerate(self.rules['patches']):
                _its_same_type_id = rule.get('type_id') == patch.get('type_id')
                _its_same_group_id = rule.get('group_id') == patch.get('group_id')
                if _its_same_type_id and _its_same_group_id:
                    _patch = {
                        'op': 'add',
                        'value': {
                            'version': 0,
                            'dst_prefix': rule.get('dst_prefix'),
                            'dst_port': rule.get('dst_port'),
                            'src_prefix': rule.get('src_prefix'),
                            'src_port': rule.get('src_port'),
                            'protocol': rule.get('protocol'),
                            'policy_id': rule.get('policy_id'),
                        },
                    }
                    mbase._recursive_cleanup(_patch)
                    self.rules['patches'][index]['patch'].append(_patch)
                    break
            else:
                _patch = {
                    'op': 'add',
                    'value': {
                        'version': 0,
                        'dst_prefix': rule.get('dst_prefix'),
                        'dst_port': rule.get('dst_port'),
                        'src_prefix': rule.get('src_prefix'),
                        'src_port': rule.get('src_port'),
                        'protocol': rule.get('protocol'),
                        'policy_id': rule.get('policy_id'),
                    },
                }
                mbase._recursive_cleanup(_patch)
                obj = {'type_id': rule.get('type_id'), 'group_id': rule.get('group_id'), 'patch': [_patch]}
                self.rules['patches'].append(obj)

    def _get_autodetect_params(self):
        self.autodetect_params['switch'] = self.mitigator.make_request(uri='/autodetect/switch')
        for policy in self.policies:
            self.autodetect_params[policy] = {'path': '/autodetect'}
            self.config._get_autodetect_setting(settings=self.autodetect_params[policy], policy=policy)

        mbase._recursive_cleanup(self.autodetect_params)

    def _get_bgp_params(self):
        self.bgp['path'] = '/bgp'
        self.bgp = self.mitigator.make_request(uri='/bgp')

        self.bgp['neighbors_policies'] = dict()
        for neighbor in self.bgp.get('neighbors', list()):
            neighbor_id = neighbor['id']
            self.bgp['neighbors_policies'][neighbor_id] = self.mitigator.make_request(uri=f'/bgp/neighbors/{neighbor_id}/policy')

        mbase._recursive_cleanup(self.bgp)
