#!/usr/bin/env python3

import copy
import json
import logging
import sys

import _mbase


class Update:
    _target_version = 'v20.06'
    _supported_version = 'v20.02'

    def __init__(self):
        self.autodetect_params = dict()
        self.bgp = dict()
        self.groups = dict()
        self.policies = dict()
        self.protection_params = dict()
        self.rules = {'patches': list()}
        self.version = None

    def load_params_from_json(self, raw_json):
        try:
            _json_data = json.loads(raw_json)['data']
        except json.JSONDecodeError as e:
            sys.exit(e)

        self.version = json.loads(raw_json).get('version')

        self.autodetect_params = _json_data.get('autodetect', dict())
        self.bgp = _json_data.get('bgp', dict())
        self.groups = _json_data.get('groups', dict())
        self.policies = _json_data.get('policies', dict())
        self.protection_params = _json_data.get('protection_params', dict())
        self.rules = _json_data.get('rules', {'patches': list()})

    def get_params_as_json(self, pretty=False):
        return json.dumps(
            {
                'version': self._target_version,
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

    def update_params(self):
        if not (self.version and self.policies and self.protection_params):
            sys.exit('FATAL ERROR: params not loaded (or empty)')

        if self._target_version in self.version:
            sys.exit(
                f'FATAL ERROR: do not support updating from ~same version (from {self.version} to {self._target_version})'
            )
        elif self._supported_version not in self.version:
            sys.exit(f'FATAL ERROR: do not support updating from {self.version} to {self._target_version}')

        ### UPDATING PROTECTION PARAMS
        logging.info('updating protection params')

        for _policy_name, _policy in self.protection_params.items():

            _val_settings_settings_data = (
                _policy.get('val', dict()).get('settings', dict()).get('val_settings', dict()).get('data')
            )
            if _val_settings_settings_data:
                _val_settings_settings_data['tcp_drop_odd_mss'] = False

            _tcpFloodProt_settings_settings_data = (
                _policy.get('tcpFloodProt', dict())
                .get('settings', dict())
                .get('tcpFloodProt_settings', dict())
                .get('data')
            )
            if _tcpFloodProt_settings_settings_data:
                _tcpFloodProt_settings_settings_data[
                    'idle_timeout'
                ] = _tcpFloodProt_settings_settings_data.get('strict_cleanup_period', 30)

                for key in ['strict_cleanup_period', 'strict_idle_timeout', 'ack_mode_indicator']:
                    try:
                        del _tcpFloodProt_settings_settings_data[key]
                    except KeyError:
                        pass

            _mcr_settings_settings_data = (
                _policy.get('mcr', dict()).get('settings', dict()).get('mcr_settings', dict()).get('data')
            )
            if _mcr_settings_settings_data:
                _mcr_settings_settings_data['key'] = _mcr_settings_settings_data['key'].encode().hex()

                if 'ack_mode_indicator' in _mcr_settings_settings_data:
                    del _mcr_settings_settings_data['ack_mode_indicator']

            _crb_settings_settings_data = (
                _policy.get('crb', dict())
                .get('settings', dict())
                .get('crb_settings', dict())
                .get('data', dict())
            )
            print(_crb_settings_settings_data, _policy_name, 'limit' not in _crb_settings_settings_data)
            if 'limit' not in _crb_settings_settings_data:
                if 'crb' in _policy:
                    del _policy['crb']
                if self.autodetect_params and _policy_name in self.autodetect_params:
                    if 'switch_crb' in self.autodetect_params[_policy_name]['data']:
                        del self.autodetect_params[_policy_name]['data']['switch_crb']
                    if 'timings_crb' in self.autodetect_params[_policy_name]['data']:
                        del self.autodetect_params[_policy_name]['data']['timings_crb']

            self.protection_params[_policy_name] = {k: _policy[k] for k in sorted(_policy)}

        _mbase._recursive_cleanup(self.protection_params)

        ### UPDATING AUTODETECT
        logging.info('updating autodetect params')

        _autodetect_global_switch = self.autodetect_params.pop('switch', dict())

        for _policy_id, _policy in self.autodetect_params.items():
            if _policy:
                _new_policy_data = {'cm_timings': [], 'cm_switchs': []}

                _new_policy_data['custom_metrics'] = _policy.pop('custom_metrics', dict())
                _new_policy_data['timings'] = _policy.pop('timings', dict())

                _keys = _policy.keys()

                for key in _keys:
                    if key.startswith('timings_'):
                        _new_policy_data['cm_timings'].append({key[len('timings_') :]: _policy[key]})

                    if key.startswith('switch_'):
                        _new_policy_data['cm_switchs'].append({key[len('switch_') :]: _policy[key]})

                _policy = _new_policy_data

        _mbase._recursive_cleanup(self.autodetect_params)
