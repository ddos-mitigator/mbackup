#!/usr/bin/env python3

import copy
import json
import logging
import sys

import _mbase


class Update:
    _target_version = 'v20.02'
    _supported_version = 'v19.12'

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

            _atls_settings_settings_data = (
                _policy.get('atls', dict()).get('settings', dict()).get('atls_settings', dict()).get('data')
            )
            if _atls_settings_settings_data:
                _atls_settings_settings_data['min_truncated_size'] = _atls_settings_settings_data.get(
                    'min_frag_size', 1400
                )
                _atls_settings_settings_data['max_invalid_size'] = 0

                try:
                    del _atls_settings_settings_data['min_frag_size']
                except KeyError:
                    pass

            _crb_settings_settings_data = (
                _policy.get('crb', dict()).get('settings', dict()).get('crb_settings', dict()).get('data')
            )
            if _crb_settings_settings_data:
                _crb_settings_settings_data['averaging_period'] = 1

            _lcon_settings = _policy.get('lcon', dict()).get('settings')
            if _lcon_settings:
                _lcon_settings_advanced_data = _lcon_settings.get('lcon_advanced', dict()).get('data')
                _lcon_settings_config_data = _lcon_settings.get('lcon_config', dict()).get('data')
                if _lcon_settings_config_data:
                    _lcon_settings['lcon_settings'] = {
                        'path': '/lcon/settings',
                        'data': {
                            'limit': _lcon_settings_config_data.get('limit'),
                            'conn_timeout': _lcon_settings_advanced_data.get('idle_max')
                            if _lcon_settings_advanced_data
                            else 120,
                            'block': _lcon_settings_config_data.get('block'),
                            'block_time': _lcon_settings_config_data.get('block_time'),
                        },
                    }

                for key in ['lcon_advanced', 'lcon_config']:
                    try:
                        del _lcon_settings[key]
                    except KeyError:
                        pass

            _slow_settings_settings_data = (
                _policy.get('slow', dict()).get('settings', dict()).get('slow_settings', dict()).get('data')
            )
            if _slow_settings_settings_data:
                _slow_settings_settings_data['fragments'] = _slow_settings_settings_data.get('parts_max', 10)
                _slow_settings_settings_data['conn_timeout'] = _slow_settings_settings_data.get('idle_max', 5)
                _slow_settings_settings_data['violations'] = _slow_settings_settings_data.get(
                    'violations_max', 20
                )

                for key in ['parts_max', 'idle_max', 'violations_max']:
                    try:
                        del _slow_settings_settings_data[key]
                    except KeyError:
                        pass

            _spli_settings_settings_data = (
                _policy.get('spli', dict()).get('settings', dict()).get('spli_settings', dict()).get('data')
            )
            if _spli_settings_settings_data:
                _spli_settings_settings_data['idle_timeout'] = 30

            self.protection_params[_policy_name] = {k: _policy[k] for k in sorted(_policy)}

        _mbase._recursive_cleanup(self.protection_params)
