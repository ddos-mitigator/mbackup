#!/usr/bin/env python3

import logging
import sys

import _mbase
from __backup import Backup
from __mrequest import M404Exception, MOthException
from __mrequest import MRequest as MReq
from __restore import Restore


class Mitigator(Backup, Restore):
    _supported_version = 'v19.12'

    def __init__(self, server, username, password, insecure=False):
        self.server = server
        self.insecure = insecure

        MReq.preconfig(insecure)

        self.token = MReq.make_request(
            server=server, path='/users/session', token=None, data={'username': username, 'password': password}
        )['token']

        self.version = self.req(path='/backend/version')['version']

        if self._supported_version not in self.version:
            sys.exit(
                f'FATAL ERROR: version {self.version} unsupport (supported version is {self._supported_version})'
            )

        self.policies = dict()
        self.protection_params = dict()
        self.rules = {'patches': list()}
        self.groups = dict()
        self.autodetect_params = dict()
        self.bgp = dict()

        self._old_new_policies_map = dict()
        self._old_new_groups_map = dict()

    def req(self, path, method=None, policy=None, data=None):
        try:
            return MReq.make_request(
                server=self.server, path=path, token=self.token, method=method, policy=policy, data=data
            )
        except M404Exception as e:
            logging.error(e)
