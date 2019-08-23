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


class MRequest:
    # Initial timeout is small to probe connection quickly,
    # it is adjusted to a larger default after connection succeeds.
    TIMEOUT_INIT = 3
    TIMEOUT_DEF = 30
    timeout = TIMEOUT_INIT

    @classmethod
    def preconfig(cls, insecure):
        cls.insecure = insecure

        if REQUESTS:
            cls.S = requests.Session()
            if insecure:
                cls.S.verify = False
                urllib3.disable_warnings()

            cls.proxies = {}

            cls.make_request = MRequest.__requests_make_request
        else:
            cls.make_request = MRequest.__urllib_make_request

    @staticmethod
    def __requests_make_request(server, uri, token, method=None, policy=None, data=None):
        url = f'''https://{server}/api/v4/{uri[1:] if uri.startswith('/') else uri}'''
        url += f'?policy={policy}' if policy else ""

        if not (method or data):
            _method = 'GET'
        elif not method and data:
            _method = 'POST'
        else:
            _method = method

        prepped_request = requests.Request(
            _method, url, json=data, headers={'X-Auth-Token': token} if token else None
        ).prepare()

        try:
            try:
                r = MRequest.S.send(prepped_request, proxies=MRequest.proxies, timeout=MRequest.timeout)
            except requests.ConnectTimeout:
                MRequest.proxies = urllib.request.getproxies()
                r = MRequest.S.send(prepped_request, proxies=MRequest.proxies, timeout=MRequest.timeout)
        except requests.ConnectionError as e:
            raise MOthException(e)

        MRequest.timeout = MRequest.TIMEOUT_DEF

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

    @staticmethod
    def __urllib_make_request(server, uri, token, method=None, policy=None, data=None):
        url = f'''https://{server}/api/v4/{uri[1:] if uri.startswith('/') else uri}'''
        url += f'?policy={policy}' if policy else ""

        request = urllib.request.Request(url, method=method)
        if token:
            request.add_header('X-Auth-Token', token)
        if data:
            request.data = json.dumps(data).encode()

        try:
            response = urllib.request.urlopen(
                request, context=CTX if MRequest.insecure else None, timeout=MRequest.timeout
            )
            MRequest.timeout = MRequest.TIMEOUT_DEF
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
