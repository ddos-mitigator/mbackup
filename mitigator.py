#!/usr/bin/env python3

import json
import urllib.request
import sys

try:
    import requests
    import urllib3

    REQUESTS = True

except ImportError:
    import ssl
    import urllib.error
    CTX = ssl.create_default_context()
    CTX.check_hostname = False
    CTX.verify_mode = ssl.CERT_NONE

    REQUESTS = False


class M404Exception(Exception):
    def __init__(self, error):
        super(M404Exception).__init__()
        self.error = error


class MOthException(Exception):
    def __init__(self, error):
        super(MOthException).__init__()
        self.error = error


class Mitigator:
    def __init__(self, server, username, password, insecure=False):
        self.server = server
        self.insecure = insecure
        # TODO: fix it
        self.token = None

        if REQUESTS:
            self.S = requests.Session()
            self.make_request = self.__requests_make_request
            if insecure:
                self.S.verify = False
                urllib3.disable_warnings()

            self.proxies = {}
        else:
            self.make_request = self.__urllib_make_request

        try:
            self.token = self.make_request(
                uri='/users/session',  data={ 'username': username, 'password': password }
            )['token']
        except MOthException as e:
            sys.exit(e)
        self.version = self.make_request(uri='/backend/version')['version']

        if self.version not in ['v19.05']:
            raise MOthException(f'unsupported mitigator version ({self.version})')

    def __requests_make_request(self, uri, method=None, policy=None, data=None):
        url = f'''https://{self.server}/api/v4/{uri[1:] if uri.startswith('/') else uri}'''
        url += f'?policy={policy}' if policy else ""

        if not (method or data):
            _method = 'GET'
        elif not method and data:
            _method = 'POST'
        else:
            _method = method

        prepped_request = requests.Request(
            _method, url, json=data, headers={'X-Auth-Token': self.token} if self.token else None
        ).prepare()

        try:
            try:
                r = self.S.send(prepped_request, proxies=self.proxies, timeout=3)
            except requests.ConnectTimeout:
                self.proxies = urllib.request.getproxies()
                r = self.S.send(prepped_request, proxies=self.proxies, timeout=3)
        except requests.ConnectionError as e:
            raise MOthException(e)

        if not r.ok:
            if r.status_code == 404:
                raise M404Exception(f'{url} => 404 {r.reason}')
            else:
                raise MOthException(
                    f'url: {url} => {r.status_code} {r.reason} '
                    f'[data: {prepped_request.body.decode() if prepped_request.body else "None"}] '
                    f'[raw: {r.text[:-1]}]'
                )
        else:
            return r.json()['data']

    def __urllib_make_request(self, uri, method=None, policy=None, data=None):
        url = f'''https://{self.server}/api/v4/{uri[1:] if uri.startswith('/') else uri}'''
        url += f'?policy={policy}' if policy else ""

        request = urllib.request.Request(url, method=method)
        if self.token:
            request.add_header('X-Auth-Token', self.token)
        if data:
            request.data = json.dumps(data).encode()

        try:
            response = urllib.request.urlopen(request, context=CTX if self.insecure else None)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise M404Exception(f'{url} => 404 {e.msg}')
            else:
                raise MOthException(
                    f'url: {url} => {e.code} {e.msg} '
                    f'[data: {request.data.decode() if request.data else "None"}] '
                    f'[raw: {e.fp.read().decode()[:-1]}]'
                )
        except urllib.error.URLError as e:
            MOthException(e)

        return json.load(response)['data']
