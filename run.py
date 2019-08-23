#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from aiohttp import web, BasicAuth, ClientSession, client_exceptions
from argparse import ArgumentParser
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime as dt, timedelta
from logging import error, getLogger
from os import path
from yajl import dumps, loads


auth = None
cipher_suite = None
cookie_lifetime = None
cookie_name = 'OAuth2Provider'
http_ok = [200, 201, 204]
keyrock = None
location = None
redirect_uri = None
routes = web.RouteTableDef()
upstream = None
version = dict()


@routes.get('/oauth2/auth')
async def get_handler(request):
    cookie = request.cookies.get(cookie_name)
    if cookie is None:
        return web.HTTPUnauthorized()

    cookie = loads(cipher_suite.decrypt(urlsafe_b64decode(cookie)).decode('UTF-8'))

    url = keyrock + '/user'
    params = {'access_token': cookie['access_token']}

    try:
        async with ClientSession() as session:
            async with session.get(url, params=params) as response:
                await response.read()
    except client_exceptions.ClientConnectorError:
        return web.HTTPUnauthorized()

    if response.status not in http_ok:
        return web.HTTPUnauthorized()

    if dt.utcnow().isoformat() > cookie['expires']:
        return web.HTTPUnauthorized()

    return web.HTTPOk()


@routes.get('/oauth2/callback')
async def get_handler(request):

    url = keyrock + '/oauth2/token'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    data = {'grant_type': 'authorization_code',
            'code': request.rel_url.query['code'],
            'redirect_uri': redirect_uri}

    try:
        async with ClientSession() as session:
            async with session.post(url, auth=auth, data=data, headers=headers) as response:
                content = loads(await response.text())
    except client_exceptions.ClientConnectorError:
        return web.HTTPUnauthorized()

    if response.status not in http_ok:
        return web.HTTPUnauthorized()

    if 'access_token' not in content:
        return web.HTTPUnauthorized()

    expires = dt.utcnow() + timedelta(seconds=cookie_lifetime)
    expires_cookie = dt.strftime(expires, '%a, %d-%b-%Y %H:%M:%S')

    value = {
        'access_token': content['access_token'],
        'refresh_token': content['refresh_token'],
        'expires': expires.isoformat()
    }

    value = urlsafe_b64encode(cipher_suite.encrypt(dumps(value).encode())).decode('UTF-8')

    response = web.HTTPSeeOther(upstream)
    response.set_cookie(name=cookie_name,
                        value=value,
                        expires=expires_cookie)

    return response


@routes.get('/oauth2/sign_in')
async def get_handler(request):
    return web.HTTPSeeOther(location)


@routes.get('/oauth2/ping')
async def get_handler(request):
    return web.Response(text = 'Pong')


@routes.get('/oauth2/version')
async def get_handler(request):
    return web.Response(text=version)


if __name__ == '__main__':

    parser = ArgumentParser()
    parser.add_argument('--ip', default='0.0.0.0', help='ip to use, default is 0.0.0.0')
    parser.add_argument('--port', default=8080, help="port to use, default is 8080")
    parser.add_argument('--client_id', required=True)
    parser.add_argument('--client_secret', required=True)
    parser.add_argument('--redirect_uri', required=True)
    parser.add_argument('--keyrock', required=True)
    parser.add_argument('--upstream', required=True)
    parser.add_argument('--cookie_key', required=True)
    parser.add_argument('--cookie_lifetime', required=True)
    parser.add_argument('--salt', required=True)

    args = parser.parse_args()

    redirect_uri = args.redirect_uri
    keyrock = args.keyrock
    upstream = args.upstream
    cookie_lifetime = int(args.cookie_lifetime)

    getLogger().setLevel(40)

    version_path = './version'
    if not path.isfile(version_path):
        error('Version file not found')
        exit(1)
    try:
        with open(version_path) as f:
            version_file = f.read().split('\n')
            version['build'] = version_file[0]
            version['commit'] = version_file[1]
            version = dumps(version)
    except IndexError:
        error('Unsupported version file type')
        exit(1)

    auth = BasicAuth(args.client_id, args.client_secret)
    location = keyrock + '/oauth2/authorize?' + \
                         'client_id=' + args.client_id + '&' \
                         'redirect_uri=' + redirect_uri + '&' + \
                         'response_type=code&' + \
                         'state=xyz'

    app = web.Application()
    app.add_routes(routes)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=args.salt.encode(),
        iterations=100000,
        backend=default_backend()
    )

    cipher_suite = Fernet(urlsafe_b64encode(kdf.derive(args.cookie_key.encode())))

    web.run_app(app, host=args.ip, port=args.port)
