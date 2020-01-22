#!/usr/bin/env python3

import copy
import json
import logging
import sys

import _mbase


class Update:
    _target_version = 'v19.12'
    _supported_version = 'v19.08'

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

            _policy['tempBlacklist'] = {
                'settings': {
                    'tempBlacklist_settings': {
                        'path': '/tempBlacklist/settings',
                        'data': {'progressive_blocking': False, 'tracking_period': 60, 'common_ratio': 2},
                    }
                }
            }

            _slow_settings = _policy.get('slow', dict()).get('settings')
            if _slow_settings:
                _policy['slow'].get('switch', dict()).get('data', dict())['switch'] = (
                    _policy['slow'].get('switch', dict()).get('data', dict()).get('slowlorisprot_switch')
                )

                try:
                    del _policy['slow']['switch']['data']['slowlorisprot_switch']
                except KeyError:
                    pass

            del _slow_settings

            _dlim6_settings = _policy.get('dlim6', dict()).get('settings')
            if _dlim6_settings:
                _dlim6_settings['dlim6_items'] = _dlim6_settings.get('dlim_items')
                _dlim6_settings['dlim6_settings'] = _dlim6_settings.get('dlim_settings')

                _mbase._recursive_cleanup(_dlim6_settings)

                for key in ['dlim_items', 'dlim_settings']:
                    try:
                        del _dlim6_settings[key]
                    except KeyError:
                        pass

                if _dlim6_settings.get('dlim6_items', dict()).get('data'):
                    _dlim6_settings['dlim6_items']['add_method'] = 'PATCH'
                    for index, _ in enumerate(_dlim6_settings['dlim6_items']['data'].get('items', list())):
                        _dlim6_settings['dlim6_items']['data']['items'][index]['op'] = 'add'

            del _dlim6_settings

            _spli_settings = _policy.get('tcpSplicer', dict()).get('settings')
            if _spli_settings:
                _spli_settings_rtt_data = _spli_settings.get('tcpSplicer_rtt', dict()).get('data')
                if _spli_settings_rtt_data:
                    _policy['spli'] = {
                        'switch': {
                            'path': '/spli/switch',
                            'data': _policy['tcpSplicer'].get('switch', dict()).get('data'),
                        },
                        'settings': {
                            'spli_settings': {
                                'path': '/spli/settings',
                                'data': {'handshake_timeout': _spli_settings_rtt_data.get('rtt')},
                            }
                        },
                    }
            try:
                del _policy['tcpSplicer']
            except KeyError:
                pass

            del _spli_settings

            _sour_settings = _policy.get('valveQueryCacher', dict()).get('settings')
            if _sour_settings:
                _policy['sour'] = {
                    'switch': {
                        'path': '/sour/switch',
                        'data': _policy['valveQueryCacher'].get('switch', dict()).get('data'),
                    },
                    'settings': {
                        'sour_settings': {
                            'path': '/sour/settings',
                            'data': _sour_settings.get('valveQueryCacher_settings', dict()).get('data'),
                        },
                        'sour_servers': {
                            'path': '/sour/servers',
                            'data': _sour_settings.get('valveQueryCacher_servers', dict()).get('data'),
                        },
                    },
                }
            try:
                del _policy['valveQueryCacher']
            except KeyError:
                pass

            del _sour_settings

            _atls_settings = _policy.get('tlsProt', dict()).get('settings')
            if _atls_settings:
                _tlsProt_filter_settings_data = _atls_settings.get('tlsProt_filter_settings', dict()).get(
                    'data', dict()
                )

                _updated_atls_settings_new_data = {
                    'active_mode': bool(
                        _atls_settings.get('tlsProt_fingerprint_switch', dict())
                        .get('data', dict())
                        .get('switch', 0)
                    ),
                    'ports': _tlsProt_filter_settings_data.get('ports', [443]),
                    'block_time': _tlsProt_filter_settings_data.get('block_time', 3600),
                    'auth_request_num': _atls_settings.get('tlsProt_filter_checks', dict())
                    .get('data', dict())
                    .get('checks', 100),
                    'min_frag_size': 1400,
                    'max_cipher_suites': _tlsProt_filter_settings_data.get('max_cipher_suites', 16384),
                    'cipher_suites_mode': _atls_settings.get('tlsProt_filter_mode', dict())
                    .get('data', dict())
                    .get('mode', 0),
                    'max_extensions': _tlsProt_filter_settings_data.get('max_extensions', 16384),
                    'extensions_mode': _atls_settings.get('tlsProt_filter_mode', dict())
                    .get('data', dict())
                    .get('mode', 0),
                    'grease_mode': 0,
                }

                _policy['atls'] = {
                    'switch': {
                        'path': '/atls/switch',
                        'data': _policy['tlsProt'].get('switch', dict()).get('data'),
                    },
                    'settings': {
                        'atls_settings': {'path': '/atls/settings', 'data': _updated_atls_settings_new_data}
                    },
                }
            try:
                del _policy['tlsProt']
            except KeyError:
                pass

            _lcon_settings = _policy.get('tcpConnLimiter', dict()).get('settings')
            if _lcon_settings:
                _policy['lcon'] = {
                    'switch': {
                        'path': '/lcon/switch',
                        'data': _policy['tcpConnLimiter'].get('switch', dict()).get('data'),
                    },
                    'settings': {
                        'lcon_advanced': {
                            'path': '/lcon/advanced',
                            'data': _lcon_settings.get('tcpConnLimiter_advanced', dict()).get('data'),
                        },
                        'lcon_config': {
                            'path': '/lcon/config',
                            'data': _lcon_settings.get('tcpConnLimiter_config', dict()).get('data'),
                        },
                    },
                }
            try:
                del _policy['tcpConnLimiter']
            except KeyError:
                pass

            del _lcon_settings

            self.protection_params[_policy_name] = {k: _policy[k] for k in sorted(_policy)}

        _mbase._recursive_cleanup(self.protection_params)

        ### UPDATING AUTODETECT

        logging.info('updating autodetect params')

        for _policy_name, _policy in self.autodetect_params.items():
            _pa_data = _policy.get('data', dict())
            if _pa_data:
                _pa_data['switch_atls'] = _pa_data.get('switch_tlsProt')
                _pa_data['timings_atls'] = _pa_data.get('timings_tlsProt')

                _pa_data['switch_lcon'] = _pa_data.get('switch_tcpConnLimiter')
                _pa_data['timings_lcon'] = _pa_data.get('timings_tcpConnLimiter')

                if 'switch_packetCapture' not in _pa_data:
                    _pa_data['switch_packetCapture'] = {'switch': 0}
                if 'timings_packetCapture' not in _pa_data:
                    _pa_data['timings_packetCapture'] = {'history_size': 5, 'severity_limit': 3}

                for __key in [
                    'switch_tlsProt',
                    'timings_tlsProt',
                    'switch_tcpConnLimiter',
                    'timings_tcpConnLimiter',
                ]:
                    try:
                        del _pa_data[__key]
                    except KeyError:
                        pass

                self.autodetect_params[_policy_name]['data'] = {k: _pa_data[k] for k in sorted(_pa_data)}
