#!/usr/bin/env python3

import copy
import sys


def _get_simple(req_func, settings, policy=None):
    settings['data'] = req_func(path=settings['path'], policy=policy)


_get_countermeasure_setting = _get_simple

_get_countermeasure_switch = _get_simple


def _get_dlim6_items(req_func, settings, policy):
    _data = req_func(path=settings['path'], policy=policy)
    if _data:
        for index, _ in enumerate(_data.get('items', list())):
            _data['items'][index]['op'] = 'add'

        settings['data'] = copy.deepcopy(_data)


def _get_game_setting(req_func, settings, policy):
    _data = req_func(path=settings['path'], policy=policy)
    if _data['mode'] != 0:
        settings['data'] = copy.deepcopy(_data)


def _get_http_setting(req_func, settings, policy):
    _data = req_func(path=settings['path'], policy=policy)
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
    _data = req_func(path=settings['path'], policy=policy)
    if 'ack_mode_indicator' in _data:
        del _data['ack_mode_indicator']

    if _data['key']:
        settings['data'] = copy.deepcopy(_data)


def _get_limiter_setting(req_func, settings, policy):
    _data = req_func(path=settings['path'], policy=policy)
    if _data['pps'] or _data['bps']:
        settings['data'] = copy.deepcopy(_data)


def _get_autodetect_setting(req_func, settings, policy):
    settings['custom_metrics'] = req_func(path='/autodetect/custom_metrics', policy=policy)

    settings['timings'] = req_func(path='/autodetect/timings', policy=policy)

    keys = req_func(path='/autodetect/countermeasures').get('countermeasures')

    for key in keys:
        settings['cm_timings'].append({key: req_func(path=f'/autodetect/timings/{key}', policy=policy)})
        settings['cm_switchs'].append({key: req_func(path=f'/autodetect/switch/{key}', policy=policy)})


def _get_tcp_setting(req_func, settings, policy):
    _data = req_func(path=settings['path'], policy=policy)
    if 'ack_mode_indicator' in _data:
        del _data['ack_mode_indicator']

    settings['data'] = copy.deepcopy(_data)


def _get_crb_setting(req_func, settings, policy):
    _data = req_func(path=settings['path'], policy=policy)
    if 'limit' in _data:
        settings['data'] = copy.deepcopy(_data)


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
    'bl': {
        'switch': {'path': '/bl/switch'},
        'settings': {'bl_prefixes': {'path': '/bl/prefixes'}},
        'general': True,
        'inpolicy': True,
    },
    'bl6': {
        'switch': {'path': '/bl6/switch'},
        'settings': {'bl6_prefixes': {'path': '/bl6/prefixes'}},
        'general': True,
        'inpolicy': False,
    },
    'crb': {
        'switch': {'path': '/crb/switch'},
        'settings': {'crb_settings': {'path': '/crb/settings', 'backup_func': _get_crb_setting}},
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
    'facl': {'switch': {'path': '/facl/switch'}, 'settings': dict(), 'general': True, 'inpolicy': False},
    'frb': {
        'switch': {'path': '/frb/switch'},
        'settings': {'frb_settings': {'path': '/frb/settings'},},
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
    'http': {
        'switch': {'path': '/http/switch'},
        'settings': {'http_settings': {'path': '/http/settings', 'backup_func': _get_http_setting,}},
        'general': False,
        'inpolicy': True,
    },
    'frag': {'settings': {'ipfrag_settings': {'path': '/frag/settings'}}, 'general': True, 'inpolicy': False},
    'itls': {
        'switch': {'path': '/itls/switch'},
        'settings': {'itls_settings': {'path': '/itls/settings'}},
        'general': False,
        'inpolicy': True,
    },
    'lcon': {
        'switch': {'path': '/lcon/switch'},
        'settings': {'lcon_settings': {'path': '/lcon/settings'}},
        'general': False,
        'inpolicy': True,
    },
    'lim': {
        'switch': {'path': '/lim/switch'},
        'settings': {'lim_settings': {'path': '/lim/settings', 'backup_func': _get_limiter_setting}},
        'general': False,
        'inpolicy': True,
    },
    'lim6': {
        'switch': {'path': '/lim6/switch'},
        'settings': {'lim6_settings': {'path': '/lim6/settings', 'backup_func': _get_limiter_setting}},
        'general': True,
        'inpolicy': False,
    },
    'mcr': {
        'switch': {'path': '/mcr/switch'},
        'settings': {'mcr_settings': {'path': '/mcr/settings', 'backup_func': _get_mcr_setting}},
        'general': False,
        'inpolicy': True,
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
    'sorb': {
        'switch': {'path': '/sorb/switch'},
        'settings': {'sorb_settings': {'path': '/sorb/settings', 'backup_func': _get_limiter_setting}},
        'general': False,
        'inpolicy': True,
    },
    'spli': {
        'switch': {'path': '/spli/switch'},
        'settings': {'spli_settings': {'path': '/spli/settings'}},
        'general': False,
        'inpolicy': True,
    },
    'tbl': {'settings': {'tbl_settings': {'path': '/tbl/settings'}}, 'general': True, 'inpolicy': True,},
    'tcp': {
        'switch': {'path': '/tcp/switch'},
        'settings': {'tcp_settings': {'path': '/tcp/settings', 'backup_func': _get_tcp_setting,}},
        'general': False,
        'inpolicy': True,
    },
    'tun': {
        'switch': {'path': '/tun/switch'},
        'settings': {'tun_settings': {'path': '/tun/settings'}},
        'general': False,
        'inpolicy': True,
    },
    'val': {'settings': {'val_settings': {'path': '/val/settings'}}, 'general': False, 'inpolicy': True},
    'wg': {
        'switch': {'path': '/wg/switch'},
        'settings': {'wg_settings': {'path': '/wg/settings', 'backup_func': _get_mcr_setting}},
        'general': False,
        'inpolicy': True,
    },
    'wl': {
        'switch': {'path': '/wl/switch'},
        'settings': {'wl_prefixes': {'path': '/wl/prefixes'}},
        'general': True,
        'inpolicy': True,
    },
    'wl6': {
        'switch': {'path': '/wl6/switch'},
        'settings': {'wl6_prefixes': {'path': '/wl6/prefixes'}},
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
