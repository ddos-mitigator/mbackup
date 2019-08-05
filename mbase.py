#!/usr/bin/env python3

import copy
import sys


class Base:
    def __init__(self, _mitigator):
        self.mitigator = _mitigator
        self.base_version = 'v19.05'
        self.countermeasures = {
            'acl': {
                'switch': {'path': '/acl/switch'},
                'settings': {'acl_entries': {'path': '/acl/entries'}},
                'general': True,
                'inpolicy': True,
            },
            'acl6': {
                'switch': {'path': '/acl6/switch'},
                'settings': {'acl6_entries': {'path': '/acl6/entries'}},
                'general': True,
                'inpolicy': False,
            },
            'bgpAcl': {
                'switch': {'path': '/bgpAcl/switch'},
                'settings': dict(),
                'general': True,
                'inpolicy': False,
            },
            'blacklist': {
                'switch': {'path': '/blacklist/switch'},
                'settings': {'blacklist_prefixes': {'path': '/blacklist/prefixes'}},
                'general': True,
                'inpolicy': True,
            },
            'blacklist6': {
                'switch': {'path': '/blacklist6/switch'},
                'settings': {'blacklist6_prefixes': {'path': '/blacklist6/prefixes'}},
                'general': True,
                'inpolicy': False,
            },
            'dlim': {
                'switch': {'path': '/dlim/switch'},
                'settings': {
                    'dlim_items': {'path': '/dlim/items', 'add_method': 'POST'},
                    'dlim_settings': {'path': '/dlim/settings'},
                },
                'general': True,
                'inpolicy': False,
            },
            'dns': {
                'switch': {'path': '/dns/switch'},
                'settings': {
                    'dns_settings': {'path': '/dns/settings'},
                    'dns_validator_switch': {'path': '/dns/validator_switch'},
                },
                'general': False,
                'inpolicy': True,
            },
            'gameProt': {
                'switch': {'path': '/gameProt/switch'},
                'settings': {
                    'gameProt_params': {
                        'path': '/gameProt/params',
                        'backup_func': self._get_gameprot_setting,
                    },
                    'gameProt_rate': {'path': '/gameProt/rate'},
                    'gameProt_refill_interval': {'path': '/gameProt/refill_interval'},
                    'gameProt_servers': {'path': '/gameProt/servers'},
                },
                'general': False,
                'inpolicy': True,
            },
            'gre': {
                'switch': {'path': '/gre/switch'},
                'settings': {
                    'gre_settings': {'path': '/gre/settings', 'backup_func': self._get_gre_setting}
                },
                'general': False,
                'inpolicy': True,
            },
            'httpFloodProt': {
                'switch': {'path': '/httpFloodProt/switch'},
                'settings': {
                    'httpFloodProt_settings': {
                        'path': '/httpFloodProt/settings',
                        'backup_func': self._get_httpfloodprot_setting,
                    }
                },
                'general': False,
                'inpolicy': True,
            },
            'ipfrag': {
                'switch': {'path': '/ipfrag/switch'},
                'settings': {
                    'ipfrag_rate': {'path': '/ipfrag/rate'},
                    'ipfrag_ttl': {'path': '/ipfrag/ttl'},
                    'ipfrag_refill_interval': {'path': '/ipfrag/refill_interval'},
                },
                'general': True,
                'inpolicy': False,
            },
            'mcr': {
                'switch': {'path': '/mcr/switch'},
                'settings': {
                    'mcr_settings': {'path': '/mcr/settings', 'backup_func': self._get_mcr_setting}
                },
                'general': False,
                'inpolicy': True,
            },
            'rateLimiter': {
                'switch': {'path': '/rateLimiter/switch'},
                'settings': {
                    'rateLimiter_settings': {
                        'path': '/rateLimiter/settings',
                        'backup_func': self._get_limiter_setting,
                    }
                },
                'general': False,
                'inpolicy': True,
            },
            'rateLimiter6': {
                'switch': {'path': '/rateLimiter6/switch'},
                'settings': {
                    'rateLimiter6_settings': {
                        'path': '/rateLimiter6/settings',
                        'backup_func': self._get_limiter_setting,
                    }
                },
                'general': True,
                'inpolicy': False,
            },
            'rex': {
                'switch': {'path': '/rex/switch'},
                'settings': {'rex_settings': {'path': '/rex/settings'}},
                'general': True,
                'inpolicy': True,
            },
            'rex6': {
                'switch': {'path': '/rex6/switch'},
                'settings': {'rex6_settings': {'path': '/rex6/settings'}},
                'general': True,
                'inpolicy': False,
            },
            'sipProt': {
                'switch': {'path': '/sipProt/switch'},
                'settings': {
                    'sipProt_params': {'path': '/sipProt/params'},
                    'sipProt_rate': {'path': '/sipProt/rate'},
                    'sipProt_refill_interval': {'path': '/sipProt/refill_interval'},
                },
                'general': False,
                'inpolicy': True,
            },
            'slowloris': {
                'switch': {'path': '/slowloris/switch'},
                'settings': {
                    'slowloris_config': {'path': '/slowloris/config'},
                    'slowloris_ports': {'path': '/slowloris/ports'},
                },
                'general': False,
                'inpolicy': True,
            },
            'sourceLimiter': {
                'switch': {'path': '/sourceLimiter/switch'},
                'settings': {
                    'sourceLimiter_settings': {
                        'path': '/sourceLimiter/settings',
                        'backup_func': self._get_limiter_setting,
                    }
                },
                'general': False,
                'inpolicy': True,
            },
            'tcpConnLimiter': {
                'switch': {'path': '/tcpConnLimiter/switch'},
                'settings': {
                    'tcpConnLimiter_advanced': {'path': '/tcpConnLimiter/advanced'},
                    'tcpConnLimiter_config': {'path': '/tcpConnLimiter/config'},
                },
                'general': False,
                'inpolicy': True,
            },
            'tcpFloodProt': {
                'switch': {'path': '/tcpFloodProt/switch'},
                'settings': {'tcpFloodProt_settings': {'path': '/tcpFloodProt/settings'}},
                'general': False,
                'inpolicy': True,
            },
            'tcpSplicer': {
                'switch': {'path': '/tcpSplicer/switch'},
                'settings': {'tcpSplicer_rtt': {'path': '/tcpSplicer/rtt'}},
                'general': False,
                'inpolicy': True,
            },
            'tlsFloodProt': {
                'switch': {'path': '/tlsFloodProt/switch'},
                'settings': {'tlsFloodProt_settings': {'path': '/tlsFloodProt/settings'}},
                'general': False,
                'inpolicy': True,
            },
            'tlsProt': {
                'switch': {'path': '/tlsProt/switch'},
                'settings': {
                    'tlsProt_filter/checks': {'path': '/tlsProt/filter/checks'},
                    'tlsProt_filter/mode': {'path': '/tlsProt/filter/mode'},
                    'tlsProt_filter/settings': {'path': '/tlsProt/filter/settings'},
                    'tlsProt_fingerprint/switch': {'path': '/tlsProt/fingerprint/switch'},
                },
                'general': False,
                'inpolicy': True,
            },
            'valveQueryCacher': {
                'switch': {'path': '/valveQueryCacher/switch'},
                'settings': {
                    'valveQueryCacher_settings': {'path': '/valveQueryCacher/settings'},
                    'valveQueryCacher_servers': {'path': '/valveQueryCacher/servers'},
                },
                'general': False,
                'inpolicy': True,
            },
            'whitelist': {
                'switch': {'path': '/whitelist/switch'},
                'settings': {'whitelist_prefixes': {'path': '/whitelist/prefixes'}},
                'general': True,
                'inpolicy': True,
            },
            'whitelist6': {
                'switch': {'path': '/whitelist6/switch'},
                'settings': {'whitelist6_prefixes': {'path': '/whitelist6/prefixes'}},
                'general': True,
                'inpolicy': False,
            },
        }

        if self.base_version < _mitigator.version:
            self._change_countermeasures(_mitigator.version)

    def _change_countermeasures(self, version):
        # if version == 'v19.08':
        #     import mver_v1908
        #     _new_version = mver_v1908.Version()
        #     for _cm_key in _new_version.countermeasures:
        #         self.countermeasures[_cm_key] = copy.deepcopy(_new_version.countermeasures[_cm_key])
        #     del _new_version
        pass

    def _get_simple(self, settings, policy=None):
        settings['data'] = self.mitigator.make_request(uri=settings['path'], policy=policy)

    _get_countermeasure_setting = _get_simple

    _get_countermeasure_switch = _get_simple

    def _get_gameprot_setting(self, settings, policy):
        _data = self.mitigator.make_request(uri=settings['path'], policy=policy)
        if _data['mode'] != 3:
            settings['data'] = copy.deepcopy(_data)

    def _get_gre_setting(self, settings, policy):
        _data = self.mitigator.make_request(uri=settings['path'], policy=policy)
        if 'switch' in _data:
            del _data['switch']
        settings['data'] = copy.deepcopy(_data)

    def _get_httpfloodprot_setting(self, settings, policy):
        _data = self.mitigator.make_request(uri=settings['path'], policy=policy)
        if _data['type'] == 'custom':
            _data['templates'] = {
                'get_response': _data['available']['templates']['custom_get_response'],
                'unavailable_response': _data['available']['templates']['custom_unavailable_response'],
                'not_get_response': _data['available']['templates']['custom_not_get_response'],
                'success_response': _data['available']['templates']['custom_success_response'],
            }
        del _data['available']
        settings['data'] = copy.deepcopy(_data)

    def _get_mcr_setting(self, settings, policy):
        _data = self.mitigator.make_request(uri=settings['path'], policy=policy)
        if _data['key']:
            settings['data'] = copy.deepcopy(_data)

    def _get_limiter_setting(self, settings, policy):
        _data = self.mitigator.make_request(uri=settings['path'], policy=policy)
        if _data['pps'] or _data['bps']:
            settings['data'] = copy.deepcopy(_data)

    def _get_autodetect_setting(self, settings, policy):
        _data = self.mitigator.make_request(uri=settings['path'], policy=policy)
        if 'custom_metrics' in _data:
            # remap (bug in backend v19.05)
            _data['custom_metrics'] = {'custom_metrics': _data['custom_metrics']}
        if 'thresholds' in _data:
            del _data['thresholds']
        settings['data'] = _data

    ###

    def _set_simple(self, settings, method=None, policy=None):
        self.mitigator.make_request(settings['path'], policy=policy, method=method if method else 'PUT', data=settings['data'])


def _recursive_cleanup(obj):
    _list_keys_to_remove = list()
    for _obj_key, _obj_data in obj.items():
        if isinstance(_obj_data, dict):
            _recursive_cleanup(_obj_data)
            if 'path' in _obj_data and 'data' not in _obj_data:
                _list_keys_to_remove.append(_obj_key)

        # BOOL is subINT
        if not _obj_data and not isinstance(_obj_data, int):
            _list_keys_to_remove.append(_obj_key)

    for _key in _list_keys_to_remove:
        del obj[_key]
