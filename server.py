#!/usr/bin/python3
# -*- coding: utf-8 -*-

import json as jsn
import socket
import threading
import http.server
from http.cookies import SimpleCookie
from Crypto import Random
from Crypto.Cipher import AES
import hashlib
import requests
import base64
import os
import argparse
import datetime
import time


def parse_request_line(request_line):
    request_line = request_line.split('HTTP')[0].strip()
    if len(request_line.split('/')) == 3:
        if request_line.split('/')[1].strip().split('?')[0] == 'oauth2':
            cmd = request_line.split('/')[2].strip().split('?')[0]
            param = dict()
            if cmd in ['callback']:
                if len(request_line.split('?')) > 1:
                    for element in request_line.split('?')[1].split('&'):
                        if element.split('=')[0] in ['code']:
                            param[element.split('=')[0]] = element.split('=')[1]
            if cmd in cmd_tec:
                return cmd, None
            if cmd in cmd_get:
                return cmd, param

    return False, None


class AESCipher(object):

    def __init__(self, key):
        self.bs = 16
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


class Handler(http.server.BaseHTTPRequestHandler):

    def reply(self, message=dict(), cookie=SimpleCookie(), code=200, cmd='', location=''):
        self.send_response(code)
        if code == 301:
            self.send_header('Location', location)
        if cookie:
            self.send_header('Set-Cookie', cookie.output(header=''))
        self.send_header('content-type', 'application/json')
        self.end_headers()
        self.wfile.write(bytes(jsn.dumps(message, indent=2) + '\n', 'utf8'))

        if cmd != 'ping':
            message['code'] = code
            if self.headers.get('X-Real-IP'):
                message['ip'] = self.headers.get('X-Real-IP')
            else:
                message['ip'] = self.client_address[0]
            message['request'] = self.requestline
            message['date'] = datetime.datetime.now().isoformat()
            if cmd:
                message['cmd'] = cmd
            print(jsn.dumps(message, indent=2))
        return

    def log_message(self, format, *args):
        return

    def do_GET(self):
        cmd, param = parse_request_line(self.requestline)
        if not cmd:
            message = {'message': 'Request not found'}
            self.reply(message, code=404)
            return

        if cmd == 'ping':
            message = {'message': 'Pong'}
            self.reply(message)
            return

        if cmd == 'version':
            message = {'message': version}
            self.reply(message, cmd=cmd)
            return

        if cmd == 'auth':
            cookie = self.headers.get('Cookie')
            status = False
            if cookie:
                val = jsn.loads(crypt.decrypt(cookie.split('=', 1)[1]))
                if 'session' in val:
                    if 'expires' in val['session']:
                        expires = datetime.datetime.strptime(val['session']['expires'][:-4], '%a, %d-%b-%Y %H:%M:%S')
                        expires = expires.isoformat()
                        now = time.strftime("%Y-%m-%dT%T", time.gmtime(time.time()))
                        if expires > now:
                            status = True

            if status:
                self.reply({'message': 'Authorized'}, cmd=cmd)
                return
            else:
                self.reply({'message': 'Unauthorized'}, code=401, cmd=cmd)
                return

        if cmd == 'sign_in':
            url = idm + '/oauth2/authorize?' + \
                  'client_id=' + client_id + '&' \
                  'redirect_uri=' + redirect_uri + '&' + \
                  'response_type=code&' + \
                  'state=xyz'

            self.reply({'message': url}, code=301, location=url, cmd=cmd)
            return

        if cmd == 'callback':
            if 'code' in param:
                url = idm + '/oauth2/token'
                payload = {'grant_type': 'authorization_code',
                           'code': param['code'],
                           'redirect_uri': redirect_uri}
                try:
                    resp = requests.post(url, auth=auth, data=payload, headers=headers, timeout=5)
                except requests.exceptions.ConnectionError:
                    self.reply({'message': 'IDM request timeout'}, code=408, cmd=cmd)
                    return
                if resp.status_code == 200:
                    reply = jsn.loads(resp.text)
                    if 'access_token' in reply:
                        url = idm + '/user'
                        payload = {'access_token': reply['access_token']}
                        try:
                            resp = requests.get(url, params=payload, timeout=5)
                        except requests.exceptions.ConnectionError:
                            self.reply({'message': 'IDM request timeout'}, code=408, cmd=cmd)
                            return
                        if resp.status_code != 201:
                            self.reply({'message': 'Unauthorized'}, code=401, cmd=cmd)
                            return
                        else:
                            lease = 60 * 60 * cookie_lifetime
                            expires = time.strftime("%a, %d-%b-%Y %T GMT", time.gmtime(time.time() + lease))
                            path = '/'
                            cookie = SimpleCookie()
                            cookie['session'] = ''
                            cookie['session']['path'] = path
                            cookie['session']['expires'] = expires

                            uuid = crypt.encrypt(jsn.dumps(cookie)).decode('utf8')
                            cookie['session'] = uuid

                            self.reply({'message': "Authorized"}, location=upstream, cookie=cookie, code=301, cmd=cmd)
                            return

        message = {'message': 'Hook not found'}
        self.reply(message, code=404, cmd=cmd)
        return


class Thread(threading.Thread):
    def __init__(self, i):
        threading.Thread.__init__(self)
        self.i = i
        self.daemon = True
        self.start()

    def run(self):
        httpd = http.server.HTTPServer(address, Handler, False)

        httpd.socket = sock
        httpd.server_bind = self.server_close = lambda self: None

        httpd.serve_forever()


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--ip', dest="ip", default='0.0.0.0', help='ip address (default: 0.0.0.0)', action="store")
    parser.add_argument('--port', dest="port", default=8000, help='port (default: 8000)', action="store")
    parser.add_argument('--threads', dest='threads', default=3, help='threads to start (default: 3)', action="store")
    parser.add_argument('--socks', dest='socks', default=3, help='threads to start (default: 3)', action="store")
    parser.add_argument('--client_id', dest='client_id', required=True, help='client_id', action="store")
    parser.add_argument('--client_secret', dest='client_secret', required=True, help='client_secret', action="store")
    parser.add_argument('--redirect_uri', dest='redirect_uri', required=True, help='redirect_uri', action="store")
    parser.add_argument('--idm', dest='idm', required=True, help='oauth2 provider (idm only)', action="store")
    parser.add_argument('--upstream', dest='upstream', required=True, help='upstream', action="store")
    parser.add_argument('--cookie_key', dest='cookie_key', required=True, help='key to encrypt cookies', action="store")
    parser.add_argument('--cookie_lifetime', dest='cookie_lifetime', required=True, help='lifetime in hours',
                        action="store")

    args = parser.parse_args()

    ip = args.ip
    port = args.port
    threads = args.threads
    socks = args.socks
    client_id = args.client_id
    client_secret = args.client_secret
    redirect_uri = args.redirect_uri
    idm = args.idm
    upstream = args.upstream
    cookie_key = args.cookie_key
    cookie_lifetime = int(args.cookie_lifetime)

    address = (ip, port)

    cmd_tec = ['ping', 'version']
    cmd_get = ['sign_in', 'callback', 'auth']
    cmd_all = cmd_tec + cmd_get
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    crypt = AESCipher(cookie_key)
    auth = requests.auth.HTTPBasicAuth(client_id, client_secret)

    version_file = open(os.path.split(os.path.abspath(__file__))[0] + '/version').read().split('\n')
    version = dict()
    version['build'] = version_file[0]
    version['commit'] = version_file[1]

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(address)
    sock.listen(socks)

    [Thread(i) for i in range(threads)]

    print(jsn.dumps({'message': 'Service started', 'code': 200, 'threads': threads, 'socks': socks}, indent=2))

    while True:
        time.sleep(9999)
