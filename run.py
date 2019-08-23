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
from os import path
from yajl import dumps, loads


auth = None
cipher_suite = None
cookie_name = 'OAuth2Provider'
http_ok = [200, 201, 204]
location = None
routes = web.RouteTableDef()


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
    return web.json_response({'message': 'Pong'}, dumps=dumps)


@routes.get('/oauth2/version')
async def get_handler(request):
    return web.json_response(version, dumps=dumps)


if __name__ == '__main__':

    parser = ArgumentParser()
    parser.add_argument('--ip', dest="ip", default='0.0.0.0', help='ip address (default: 0.0.0.0)', action="store")
    parser.add_argument('--port', dest="port", default=8080, help='port (default: 8080)', action="store")
    parser.add_argument('--client_id', dest='client_id', required=True, help='client_id', action="store")
    parser.add_argument('--client_secret', dest='client_secret', required=True, help='client_secret', action="store")
    parser.add_argument('--redirect_uri', dest='redirect_uri', required=True, help='redirect_uri', action="store")
    parser.add_argument('--keyrock', dest='keyrock', required=True, help='OAuth2 provider', action="store")
    parser.add_argument('--upstream', dest='upstream', required=True, help='upstream', action="store")
    parser.add_argument('--cookie_key', dest='cookie_key', required=True, help='password to encrypt cookie',
                        action="store")
    parser.add_argument('--cookie_lifetime', dest='cookie_lifetime', required=True, help='lifetime in hours',
                        action="store")

    args = parser.parse_args()

    redirect_uri = args.redirect_uri
    keyrock = args.keyrock
    upstream = args.upstream
    cookie_lifetime = int(args.cookie_lifetime)

    version_path = path.split(path.abspath(__file__))[0] + '/version'
    version = dict()
    if not path.isfile(version_path):
        print(dumps({'message': 'Version file not found', 'code': 500, 'cmd': 'start'}, indent=2))
        version_file = None
        exit(1)
    try:
        with open(version_path) as f:
            version_file = f.read().split('\n')
            version['build'] = version_file[0]
            version['commit'] = version_file[1]
    except IndexError:
        print(dumps({'message': 'Unsupported version file type', 'code': 500, 'cmd': 'start'}, indent=2))
        exit(1)

    auth = BasicAuth(args.client_id, args.client_secret)
    location = keyrock + '/oauth2/authorize?' + \
                         'client_id=' + args.client_id + '&' \
                         'redirect_uri=' + redirect_uri + '&' + \
                         'response_type=code&' + \
                         'state=xyz'

    app = web.Application()
    app.add_routes(routes)

    salt = b'dfvuy3947r397gfbcvdfvaofp398434'

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    cipher_suite = Fernet(urlsafe_b64encode(kdf.derive(args.cookie_key.encode())))

    web.run_app(app, host=args.ip, port=args.port)