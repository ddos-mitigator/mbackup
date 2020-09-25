#!/usr/bin/env python3

import copy
import json
import logging
import sys

import _mbase


class Update:
    _target_version = 'v20.08'
    _supported_version = 'v20.06'

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

            blacklist_switch = _policy.get('blacklist', dict()).get('switch', dict()).get('data')
            blacklist_data = (
                _policy.get('blacklist', dict())
                .get('settings', dict())
                .get('blacklist_prefixes', dict())
                .get('data')
            )
            if blacklist_data:
                _policy['bl'] = {
                    'switch': {'path': '/bl/switch', 'data': copy.deepcopy(blacklist_switch)},
                    'settings': {
                        'bl_prefixes': {'path': '/bl/prefixes', 'data': copy.deepcopy(blacklist_data)}
                    },
                    'general': True,
                    'inpolicy': True,
                }
                del _policy['blacklist']

            blacklist6_switch = _policy.get('blacklist6', dict()).get('switch', dict()).get('data')
            blacklist6_data = (
                _policy.get('blacklist6', dict())
                .get('settings', dict())
                .get('blacklist6_prefixes', dict())
                .get('data')
            )
            if blacklist6_data:
                _policy['bl6'] = {
                    'switch': {'path': '/bl6/switch', 'data': copy.deepcopy(blacklist6_switch)},
                    'settings': {
                        'bl6_prefixes': {'path': '/bl6/prefixes', 'data': copy.deepcopy(blacklist6_data)}
                    },
                    'general': True,
                    'inpolicy': False,
                }
                del _policy['blacklist6']


            bgpAcl_switch = _policy.get('bgpAcl', dict()).get('switch', dict()).get('data')
            if bgpAcl_switch:
                _policy['facl'] = {'switch': {'path': '/facl/switch', 'data': copy.deepcopy(bgpAcl_switch)}, 'general': True, 'inpolicy': False}
                del _policy['bgpAcl']

            httpFloodProt_switch = _policy.get('httpFloodProt', dict()).get('switch', dict()).get('data')
            httpFloodProt_data = (
                _policy.get('httpFloodProt', dict())
                .get('settings', dict())
                .get('httpFloodProt_settings', dict())
                .get('data')
            )
            if httpFloodProt_data:
                _policy['http'] = {
                    'switch': {'path': '/http/switch', 'data': copy.deepcopy(httpFloodProt_switch)},
                    'settings': {
                        'http_settings': {'path': '/http/settings', 'data': copy.deepcopy(httpFloodProt_data)}
                    },
                    'general': False,
                    'inpolicy': True,
                }
                del _policy['httpFloodProt']

            rateLimiter_switch = _policy.get('rateLimiter', dict()).get('switch', dict()).get('data')
            rateLimiter_data = (
                _policy.get('rateLimiter', dict())
                .get('settings', dict())
                .get('rateLimiter_settings', dict())
                .get('data')
            )
            if rateLimiter_data:
                _policy['lim'] = {
                    'switch': {'path': '/lim/switch', 'data': copy.deepcopy(rateLimiter_switch)},
                    'settings': {
                        'lim_settings': {'path': '/lim/settings', 'data': copy.deepcopy(rateLimiter_data)}
                    },
                    'general': False,
                    'inpolicy': True,
                }
                del _policy['rateLimiter']

            rateLimiter6_switch = _policy.get('rateLimiter6', dict()).get('switch', dict()).get('data')
            rateLimiter6_data = (
                _policy.get('rateLimiter6', dict())
                .get('settings', dict())
                .get('rateLimiter6_settings', dict())
                .get('data')
            )
            if rateLimiter6_data:
                _policy['lim6'] = {
                    'switch': {'path': '/lim6/switch', 'data': copy.deepcopy(rateLimiter6_switch)},
                    'settings': {
                        'lim6_settings': {'path': '/lim6/settings', 'data': copy.deepcopy(rateLimiter6_data)}
                    },
                    'general': True,
                    'inpolicy': False,
                }
                del _policy['rateLimiter6']

            sourceLimiter_switch = _policy.get('sourceLimiter', dict()).get('switch', dict()).get('data')
            sourceLimiter_data = (
                _policy.get('sourceLimiter', dict())
                .get('settings', dict())
                .get('sourceLimiter_settings', dict())
                .get('data')
            )
            if sourceLimiter_data:
                _policy['sorb'] = {
                    'switch': {'path': '/sorb/switch', 'data': copy.deepcopy(sourceLimiter_switch)},
                    'settings': {
                        'sorb_settings': {'path': '/sorb/settings', 'data': copy.deepcopy(sourceLimiter_data)}
                    },
                    'general': False,
                    'inpolicy': True,
                }
                del _policy['sourceLimiter']

            tcpFloodProt_switch = _policy.get('tcpFloodProt', dict()).get('switch', dict()).get('data')
            tcpFloodProt_data = (
                _policy.get('tcpFloodProt', dict())
                .get('settings', dict())
                .get('tcpFloodProt_settings', dict())
                .get('data')
            )
            if tcpFloodProt_data:
                _policy['tcp'] = {
                    'switch': {'path': '/tcp/switch', 'data': copy.deepcopy(tcpFloodProt_switch)},
                    'settings': {
                        'tcp_settings': {'path': '/tcp/settings', 'data': copy.deepcopy(tcpFloodProt_data)}
                    },
                    'general': False,
                    'inpolicy': True,
                }
                del _policy['tcpFloodProt']

            tlsFloodProt_switch = _policy.get('tlsFloodProt', dict()).get('switch', dict()).get('data')
            tlsFloodProt_data = (
                _policy.get('tlsFloodProt', dict())
                .get('settings', dict())
                .get('tlsFloodProt_settings', dict())
                .get('data')
            )
            if tlsFloodProt_data:
                _policy['itls'] = {
                    'switch': {'path': '/itls/switch', 'data': copy.deepcopy(tlsFloodProt_switch)},
                    'settings': {
                        'itls_settings': {'path': '/itls/settings', 'data': copy.deepcopy(tlsFloodProt_data)}
                    },
                    'general': False,
                    'inpolicy': True,
                }
                del _policy['tlsFloodProt']

            tempBlacklist_data = (
                _policy.get('tempBlacklist', dict())
                .get('settings', dict())
                .get('tempBlacklist_settings', dict())
                .get('data')
            )
            if tempBlacklist_data:
                _policy['tbl'] = {
                    'settings': {
                        'tbl_settings': {'path': '/tbl/settings', 'data': copy.deepcopy(tempBlacklist_data)}
                    },
                    'general': True,
                    'inpolicy': True,
                }
                del _policy['tempBlacklist']

            whitelist_switch = _policy.get('whitelist', dict()).get('switch', dict()).get('data')
            whitelist_data = (
                _policy.get('whitelist', dict())
                .get('settings', dict())
                .get('whitelist_prefixes', dict())
                .get('data')
            )
            if whitelist_data:
                _policy['wl'] = {
                    'switch': {'path': '/wl/switch', 'data': copy.deepcopy(whitelist_switch)},
                    'settings': {
                        'wl_prefixes': {'path': '/wl/prefixes', 'data': copy.deepcopy(whitelist_data)}
                    },
                    'general': True,
                    'inpolicy': True,
                }
                del _policy['whitelist']

            whitelist6_switch = _policy.get('whitelist6', dict()).get('switch', dict()).get('data')
            whitelist6_data = (
                _policy.get('whitelist6', dict())
                .get('settings', dict())
                .get('whitelist6_prefixes', dict())
                .get('data')
            )
            if whitelist6_data:
                _policy['wl6'] = {
                    'switch': {'path': '/wl6/switch', 'data': copy.deepcopy(whitelist6_switch)},
                    'settings': {
                        'wl6_prefixes': {'path': '/wl6/prefixes', 'data': copy.deepcopy(whitelist6_data)}
                    },
                    'general': True,
                    'inpolicy': False,
                }
                del _policy['whitelist6']

            gre_switch = _policy.get('gre', dict()).get('switch', dict()).get('data')
            gre_data = (
                _policy.get('gre', dict())
                .get('settings', dict())
                .get('gre_settings', dict())
                .get('data')
            )
            if gre_data:
                _policy['tun'] = {
                    'switch': {'path': '/tun/switch', 'data': copy.deepcopy(gre_switch)},
                    'settings': {
                        'tun_settings': {'path': '/tun/settings', 'data': copy.deepcopy(gre_data)}
                    },
                    'general': False,
                    'inpolicy': True,
                }
                del _policy['gre']

            wg_data = (
                _policy.get('wg', dict())
                .get('settings', dict())
                .get('wg_settings', dict())
                .get('data')
            )
            if wg_data:
                if 'key' in wg_data:
                    wg_data['mask'] = 32
                else:
                    del _policy['wg']

            game_data = (
                _policy.get('game', dict())
                .get('settings', dict())
                .get('game_settings', dict())
                .get('data')
            )
            if game_data:
                game_data['learning'] = False
                game_data['learning_period'] = 10

            val_data = (
                _policy.get('val', dict())
                .get('settings', dict())
                .get('val_settings', dict())
                .get('data')
            )
            if val_data:
                val_data['tcp_drop_zero_seqnum'] = False
                val_data['tcpudp_drop_zero_port'] = False

            frb_data = (
                _policy.get('frb', dict())
                .get('settings', dict())
                .get('frb_settings', dict())
                .get('data', dict())
            )
            if not frb_data.get('use_default') and frb_data.get('rules'):
                pass
            elif frb_data.get('use_default') and (frb_data.get('limit_packets') or frb_data.get('limit_bits')):
                pass
            else:
                _policy['frb'] = dict()

        _mbase._recursive_cleanup(self.autodetect_params)


        ### UPDATING AUTODETECT
        logging.info('updating autodetect params')

        for _policy_id, _policy in self.autodetect_params.items():
            if _policy:
                if 'cm_timings' in _policy:
                    elems = _policy['cm_timings']
                    for elem in elems:
                        key, value = elem.popitem()
                        if key == 'blacklist':
                            elem['bl'] = value

                        elif key == 'bgpAcl':
                            elem['facl'] = value

                        elif key == 'httpFloodProt':
                            elem['http'] = value

                        elif key == 'rateLimiter':
                            elem['lim'] = value

                        elif key == 'rateLimiter6':
                            elem['lim6'] = value

                        elif key == 'sourceLimiter':
                            elem['sorb'] = value

                        elif key == 'tcpFloodProt':
                            elem['tcp'] = value

                        elif key == 'tlsFloodProt':
                            elem['itls'] = value

                        elif key == 'whitelist':
                            elem['wl'] = value

                        elif key == 'packetCapture':
                            elem['pcap'] = value

                        else:
                            elem[key] = value



                if 'cm_switchs' in _policy:
                    elems = _policy['cm_switchs']
                    for elem in elems:
                        key, value = elem.popitem()
                        if key == 'blacklist':
                            elem['bl'] = value

                        elif key == 'bgpAcl':
                            elem['facl'] = value

                        elif key == 'httpFloodProt':
                            elem['http'] = value

                        elif key == 'rateLimiter':
                            elem['lim'] = value

                        elif key == 'rateLimiter6':
                            elem['lim6'] = value

                        elif key == 'sourceLimiter':
                            elem['sorb'] = value

                        elif key == 'tcpFloodProt':
                            elem['tcp'] = value

                        elif key == 'tlsFloodProt':
                            elem['itls'] = value

                        elif key == 'whitelist':
                            elem['wl'] = value

                        elif key == 'packetCapture':
                            elem['pcap'] = value

                        else:
                            elem[key] = value

        _mbase._recursive_cleanup(self.autodetect_params)
