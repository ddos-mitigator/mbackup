#!/usr/bin/env python3

import copy
import sys


def _get_simple(req_func, settings, policy=None):
    settings['data'] = req_func(uri=settings['path'], policy=policy)


_get_countermeasure_setting = _get_simple

_get_countermeasure_switch = _get_simple


def _get_dlim6_items(req_func, settings, policy):
    _data = req_func(uri=settings['path'], policy=policy)
    if _data:
        for index, _ in enumerate(_data.get('items', list())):
            _data['items'][index]['op'] = 'add'

        settings['data'] = copy.deepcopy(_data)


def _get_game_setting(req_func, settings, policy):
    _data = req_func(uri=settings['path'], policy=policy)
    if _data['mode'] != 0:
        settings['data'] = copy.deepcopy(_data)


def _get_gre_setting(req_func, settings, policy):
    _data = req_func(uri=settings['path'], policy=policy)
    if 'switch' in _data:
        del _data['switch']
    settings['data'] = copy.deepcopy(_data)


def _get_httpfloodprot_setting(req_func, settings, policy):
    _data = req_func(uri=settings['path'], policy=policy)
    if _data['type'] == 'custom':
        _data['templates'] = {
            'get_response': _data['available']['templates']['custom_get_response'],
            'unavailable_response': _data['available']['templates']['custom_unavailable_response'],
            'not_get_response': _data['available']['templates']['custom_not_get_response'],
            'success_response': _data['available']['templates']['custom_success_response'],
        }
    del _data['available']
    settings['data'] = copy.deepcopy(_data)


def _get_mcr_setting(req_func, settings, policy):
    _data = req_func(uri=settings['path'], policy=policy)
    if _data['key']:
        settings['data'] = copy.deepcopy(_data)


def _get_limiter_setting(req_func, settings, policy):
    _data = req_func(uri=settings['path'], policy=policy)
    if _data['pps'] or _data['bps']:
        settings['data'] = copy.deepcopy(_data)


def _get_autodetect_setting(req_func, settings, policy):
    _data = req_func(uri=settings['path'], policy=policy)
    if 'custom_metrics' in _data:
        # remap (bug in backend v19.05)
        _data['custom_metrics'] = {'custom_metrics': _data['custom_metrics']}
    if 'thresholds' in _data:
        del _data['thresholds']
    settings['data'] = _data


###


def _set_simple(req_func, settings, method=None, policy=None):
    req_func(settings['path'], policy=policy, method=method or 'PUT', data=settings['data'])


countermeasures = {
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
    'atls': {
        'switch': {'path': '/atls/switch'},
        'settings': {'atls_settings': {'path': '/atls/settings'}},
        'general': False,
        'inpolicy': True,
    },
    'bgpAcl': {'switch': {'path': '/bgpAcl/switch'}, 'settings': dict(), 'general': True, 'inpolicy': False},
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
    'crb': {
        'switch': {'path': '/crb/switch'},
        'settings': {'crb_settings': {'path': '/crb/settings'}},
        'general': False,
        'inpolicy': True,
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
    'dlim6': {
        'switch': {'path': '/dlim6/switch'},
        'settings': {
            'dlim6_items': {'path': '/dlim6/items', 'add_method': 'PATCH', 'backup_func': _get_dlim6_items},
            'dlim6_settings': {'path': '/dlim6/settings'},
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
    'game': {
        'switch': {'path': '/game/switch'},
        'settings': {
            'game_settings': {'path': '/game/settings', 'backup_func': _get_game_setting},
            'game_servers': {'path': '/game/servers'},
        },
        'general': False,
        'inpolicy': True,
    },
    'gre': {
        'switch': {'path': '/gre/switch'},
        'settings': {'gre_settings': {'path': '/gre/settings', 'backup_func': _get_gre_setting}},
        'general': False,
        'inpolicy': True,
    },
    'httpFloodProt': {
        'switch': {'path': '/httpFloodProt/switch'},
        'settings': {
            'httpFloodProt_settings': {
                'path': '/httpFloodProt/settings',
                'backup_func': _get_httpfloodprot_setting,
            }
        },
        'general': False,
        'inpolicy': True,
    },
    'frag': {'settings': {'ipfrag_settings': {'path': '/frag/settings'}}, 'general': True, 'inpolicy': False},
    'lcon': {
        'switch': {'path': '/lcon/switch'},
        'settings': {'lcon_advanced': {'path': '/lcon/advanced'}, 'lcon_config': {'path': '/lcon/config'}},
        'general': False,
        'inpolicy': True,
    },
    'mcr': {
        'switch': {'path': '/mcr/switch'},
        'settings': {'mcr_settings': {'path': '/mcr/settings', 'backup_func': _get_mcr_setting}},
        'general': False,
        'inpolicy': True,
    },
    'rateLimiter': {
        'switch': {'path': '/rateLimiter/switch'},
        'settings': {
            'rateLimiter_settings': {'path': '/rateLimiter/settings', 'backup_func': _get_limiter_setting}
        },
        'general': False,
        'inpolicy': True,
    },
    'rateLimiter6': {
        'switch': {'path': '/rateLimiter6/switch'},
        'settings': {
            'rateLimiter6_settings': {'path': '/rateLimiter6/settings', 'backup_func': _get_limiter_setting}
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
    'sip': {
        'switch': {'path': '/sip/switch'},
        'settings': {'sip_settings': {'path': '/sip/settings'}},
        'general': False,
        'inpolicy': True,
    },
    'slow': {
        'switch': {'path': '/slow/switch'},
        'settings': {'slow_settings': {'path': '/slow/settings'}},
        'general': False,
        'inpolicy': True,
    },
    'sour': {
        'switch': {'path': '/sour/switch'},
        'settings': {'sour_settings': {'path': '/sour/settings'}, 'sour_servers': {'path': '/sour/servers'}},
        'general': False,
        'inpolicy': True,
    },
    'sourceLimiter': {
        'switch': {'path': '/sourceLimiter/switch'},
        'settings': {
            'sourceLimiter_settings': {'path': '/sourceLimiter/settings', 'backup_func': _get_limiter_setting}
        },
        'general': False,
        'inpolicy': True,
    },
    'spli': {
        'switch': {'path': '/spli/switch'},
        'settings': {'spli_settings': {'path': '/spli/settings'}},
        'general': False,
        'inpolicy': True,
    },
    'tcpFloodProt': {
        'switch': {'path': '/tcpFloodProt/switch'},
        'settings': {'tcpFloodProt_settings': {'path': '/tcpFloodProt/settings'}},
        'general': False,
        'inpolicy': True,
    },
    'tempBlacklist': {
        'settings': {'tempBlacklist_settings': {'path': '/tempBlacklist/settings'}},
        'general': True,
        'inpolicy': True,
    },
    'tlsFloodProt': {
        'switch': {'path': '/tlsFloodProt/switch'},
        'settings': {'tlsFloodProt_settings': {'path': '/tlsFloodProt/settings'}},
        'general': False,
        'inpolicy': True,
    },
    'val': {'settings': {'val_settings': {'path': '/val/settings'}}, 'general': False, 'inpolicy': True},
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
