#!/usr/bin/env python3

import copy
import json
import logging
import sys

import _mbase


class Update:
    _target_version = 'v19.08'
    _supported_version = 'v19.05'

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
            _dlim_settings_data = (
                _policy.get('dlim', dict())
                .get('settings', dict())
                .get('dlim_settings', dict())
                .get('data', dict())
            )
            if _dlim_settings_data and 'refill_interval' not in _dlim_settings_data:
                _dlim_settings_data['refill_interval'] = 10

            _frag_settings = _policy.get('ipfrag', dict()).get('settings', dict())
            if _frag_settings:
                _policy['frag'] = {
                    'settings': {
                        'ipfrag_settings': {
                            'path': '/frag/settings',
                            'data': {
                                'mode': _policy['ipfrag']
                                .get('switch', dict())
                                .get('data', dict())
                                .get('switch'),
                                'limit_pps': _frag_settings.get('ipfrag_rate', dict())
                                .get('data', dict())
                                .get('rate'),
                                'reassembly_timeout': _frag_settings.get('ipfrag_ttl', dict())
                                .get('data', dict())
                                .get('ttl'),
                                'refill_interval': _frag_settings.get('ipfrag_refill_interval', dict())
                                .get('data', dict())
                                .get('refill_interval'),
                            },
                        }
                    }
                }
            try:
                del _policy['ipfrag']
            except KeyError:
                pass

            _sip_settings = _policy.get('sipProt', dict()).get('settings', dict())
            if _sip_settings:
                _sip_settings_params_data = _sip_settings.get('sipProt_params', dict()).get('data', dict())
                if _sip_settings_params_data:
                    _policy['sip'] = {
                        'switch': {
                            'path': '/sip/switch',
                            'data': _policy['sipProt'].get('switch', dict()).get('data'),
                        },
                        'settings': {
                            'sip_settings': {
                                'path': '/sip/settings',
                                'data': {
                                    'protection_enabled': _sip_settings_params_data.get('protection_enabled'),
                                    'max_field_length': _sip_settings_params_data.get('max_field_length'),
                                    'server_port': _sip_settings_params_data.get('server_port'),
                                    'session_ttl': _sip_settings_params_data.get('session_ttl'),
                                    'refill_interval': _sip_settings.get('sipProt_refill_interval', dict())
                                    .get('data', dict())
                                    .get('refill_interval'),
                                    'limit_pps': _sip_settings.get('sipProt_rate', dict())
                                    .get('data', dict())
                                    .get('rate'),
                                },
                            }
                        },
                    }
            try:
                del _policy['sipProt']
            except KeyError:
                pass

            _slow_settings = _policy.get('slowloris', dict()).get('settings', dict())
            if _slow_settings:
                _slow_settings_config_data = _slow_settings.get('slowloris_config', dict()).get(
                    'data', dict()
                )
                if _slow_settings_config_data:
                    _policy['slow'] = {
                        'switch': {
                            'path': '/slow/switch',
                            'data': _policy['slowloris'].get('switch', dict()).get('data'),
                        },
                        'settings': {
                            'slow_settings': {
                                'path': '/slow/settings',
                                'data': {
                                    'block_time': _slow_settings_config_data.get('block_time'),
                                    'parts_max': _slow_settings_config_data.get('parts_max'),
                                    'idle_max': _slow_settings_config_data.get('idle_max'),
                                    'violations_max': _slow_settings_config_data.get('violations_max'),
                                    'ports': [
                                        int(_port)
                                        for _port in _slow_settings.get('slowloris_ports', dict())
                                        .get('data', dict())
                                        .get('ports')
                                    ],
                                },
                            }
                        },
                    }
            try:
                del _policy['slowloris']
            except KeyError:
                pass

            _game_settings = _policy.get('gameProt', dict()).get('settings', dict())
            if _game_settings:
                _game_settings_params_data = _game_settings.get('gameProt_params', dict()).get('data', dict())
                if _game_settings_params_data:
                    _policy['game'] = {
                        'switch': {
                            'path': '/game/switch',
                            'data': _policy['gameProt'].get('switch', dict()).get('data'),
                        },
                        'settings': {
                            'game_settings': {
                                'path': '/game/settings',
                                'data': {
                                    'mode': (_game_settings_params_data.get('mode') + 1) % 4,
                                    'version': _game_settings_params_data.get('version'),
                                    'session_ttl': _game_settings_params_data.get('expiration_time'),
                                    'port_range': _game_settings_params_data.get('port_range'),
                                    'limit_pps': _game_settings.get('gameProt_rate', dict())
                                    .get('data', dict())
                                    .get('rate'),
                                    'refill_interval': _game_settings.get('gameProt_refill_interval', dict())
                                    .get('data', dict())
                                    .get('refill_interval'),
                                    'poll_period': _game_settings_params_data.get('poll_period'),
                                },
                            },
                            'game_servers': {
                                'path': '/game/servers',
                                'data': {
                                    'servers': _game_settings.get('gameProt_servers', dict())
                                    .get('data', dict())
                                    .get('servers')
                                },
                            },
                        },
                    }
            try:
                del _policy['gameProt']
            except KeyError:
                pass

            _tlsProt_settings = _policy.get('tlsProt', dict()).get('settings', dict())
            if _tlsProt_settings:
                _tlsProt_settings['tlsProt_filter_checks'] = _tlsProt_settings.get('tlsProt_filter/checks')
                _tlsProt_settings['tlsProt_filter_mode'] = _tlsProt_settings.get('tlsProt_filter/mode')
                _tlsProt_settings['tlsProt_filter_settings'] = _tlsProt_settings.get(
                    'tlsProt_filter/settings'
                )
                _tlsProt_settings['tlsProt_fingerprint_switch'] = _tlsProt_settings.get(
                    'tlsProt_fingerprint/switch'
                )

                __tlsProt_sd = _tlsProt_settings['tlsProt_filter_settings'].get('data', dict())
                if __tlsProt_sd and 'ports' not in __tlsProt_sd:
                    __tlsProt_sd['ports'] = [443]

            for __key in [
                'tlsProt_filter/checks',
                'tlsProt_filter/mode',
                'tlsProt_filter/settings',
                'tlsProt_fingerprint/switch',
            ]:
                try:
                    del _tlsProt_settings[__key]
                except KeyError:
                    pass

        _mbase._recursive_cleanup(self.protection_params)

        ### UPDATING AUTODETECT

        logging.info('updating autodetect params')

        _default_metrics = [
            {'metric': 'ATLS.Algo.Enabled', 'value': '1'},
            {'metric': 'ATLS.Algo.Training.Enabled', 'value': '1'},
            {'metric': 'ATLS.Algo.Detection.Enabled', 'value': '1'},
            {'metric': 'HTTP.Algo.Enabled', 'value': '1'},
            {'metric': 'HTTP.Algo.Detection.Enabled', 'value': '1'},
            {'metric': 'HTTP.Algo.Mode', 'value': '1'},
            {'metric': 'HTTP.Algo.Training.Enabled', 'value': '1'},
            {'metric': 'HTTP.Algo.Training.MaxWindow', 'value': '12'},
            {'metric': 'HTTP.Algo.Empirical.InsignificantLevel', 'value': '0.05'},
            {'metric': 'HTTP.Algo.Empirical.SignificantFraction', 'value': '0.10'},
            {'metric': 'HTTP.Algo.Statistical.ErrorProbability', 'value': '0.01'},
            {'metric': 'HTTP.Algo.Training.ConsistentTests', 'value': '10'},
        ]

        _renamed_metrics = {
            "geoIPFilter.IcmpBps.Off": "GEO.IcmpBps.Off",
            "geoIPFilter.IcmpBps.On": "GEO.IcmpBps.On",
            "geoIPFilter.IcmpPps.Off": "GEO.IcmpPps.Off",
            "geoIPFilter.IcmpPps.On": "GEO.IcmpPps.On",
            "geoIPFilter.InputBps.Off": "GEO.InputBps.Off",
            "geoIPFilter.InputBps.On": "GEO.InputBps.On",
            "geoIPFilter.InputPps.Off": "GEO.InputPps.Off",
            "geoIPFilter.InputPps.On": "GEO.InputPps.On",
            "geoIPFilter.Low.Bps": "GEO.Low.Bps",
            "geoIPFilter.Low.Pps": "GEO.Low.Pps",
            "geoIPFilter.OtherBps.Off": "GEO.OtherBps.Off",
            "geoIPFilter.OtherBps.On": "GEO.OtherBps.On",
            "geoIPFilter.OtherPps.Off": "GEO.OtherPps.Off",
            "geoIPFilter.OtherPps.On": "GEO.OtherPps.On",
            "geoIPFilter.TcpBps.Off": "GEO.TcpBps.Off",
            "geoIPFilter.TcpBps.On": "GEO.TcpBps.On",
            "geoIPFilter.TcpPps.Off": "GEO.TcpPps.Off",
            "geoIPFilter.TcpPps.On": "GEO.TcpPps.On",
            "geoIPFilter.UdpBps.Off": "GEO.UdpBps.Off",
            "geoIPFilter.UdpBps.On": "GEO.UdpBps.On",
            "geoIPFilter.UdpPps.Off": "GEO.UdpPps.Off",
            "geoIPFilter.UdpPps.On": "GEO.UdpPps.On",
        }

        for _policy_name, _policy in self.autodetect_params.items():
            _pa_data = _policy.get('data', dict())
            if _pa_data:
                _custom_metrics = _pa_data.get('custom_metrics', dict())
                if _custom_metrics:
                    __to_append = list()
                    if 'custom_metrics' not in _custom_metrics:
                        _custom_metrics['custom_metrics'] = list()
                    for __dm in _default_metrics:
                        for __mm_index, __mm in enumerate(_custom_metrics['custom_metrics']):
                            __mm_m = __mm.get('metric')
                            if __dm['metric'] == __mm_m:
                                break
                            if __mm_m in _renamed_metrics:
                                _custom_metrics['custom_metrics'][__mm_index] = {
                                    'metric': _renamed_metrics[__mm_m],
                                    'value': __mm.get('value'),
                                }
                        else:
                            __to_append.append(__dm)
                    _custom_metrics['custom_metrics'] += __to_append

                _pa_data['switch_crb'] = {"switch": 0}
                _pa_data['timings_crb'] = _pa_data.get('timings')

                _pa_data['switch_geo'] = _pa_data.get('switch_geoIPFilter')
                _pa_data['timings_geo'] = _pa_data.get('timings_geoIPFilter')

                for __key in ['switch_geoIPFilter', 'timings_geoIPFilter']:
                    try:
                        del _pa_data[__key]
                    except KeyError:
                        pass

        ### UPDATING RULES

        logging.info('updating rules')

        for _patch in self.rules.get('patches', list()):
            _type_id = _patch.get('type_id')
            if _type_id == 3:
                _patch['version'] = 1
                for _rec in _patch.get('patch', dict()):
                    if 'version' in _rec.get('value'):
                        del _rec['value']['version']

                    if _rec.get('value', dict()).get('policy_id') == 1:
                        _rec['before'] = 1

            else:
                _patch['version'] = 0
                for _rec in _patch.get('patch', dict()):
                    if 'version' in _rec.get('value'):
                        del _rec['value']['version']
