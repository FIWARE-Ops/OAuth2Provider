![FIWARE Banner](https://nexus.lab.fiware.org/content/images/fiware-logo1.png)

# OAuth2 Provider for Keyrock and NGINX
[![Docker badge](https://img.shields.io/docker/pulls/fiware/service.oauth2provider.svg)](https://hub.docker.com/r/fiware/service.oauth2provider/)
[![Build Status](https://travis-ci.org/FIWARE-Ops/OAuth2Provider.svg?branch=master)](https://travis-ci.org/FIWARE-Ops/OAuth2Provider)

## Overview
This project is part of [FIWARE](https://fiware.org) OPS infrastructure.
It provides possibility to NGINX to authenticate users via [Keyrock](https://github.com/ging/fiware-idm) IDM with [OAuth2](https://oauth.net/2/) protocol. 
It works as a service in pair with NGINX [http_auth_request_module](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html) and allow to check if user has
an access to defined service or not. Service use cookies.

## WARNING
This is an alfa revision

## How to run
```console
$ docker run -d fiware/service.oauth2provider \
             --ip ${IP} \
             --port ${PORT} \
             --threads ${THREADS} \
             --socks ${SOCKS} \
             --idm https://account.fiware.org
             --client_id ${CLIENT_ID}
             --client_secret ${CLIENT_SECRET}
             --redirect_uri ${REDIRECT_URI}
             --upstream ${UPSTREAM}
             --cookie_key=${BIG_RANDOM_NUMBER}
             --cookie_lifetime=${TIME_IN_HOURS}
```
```console
$ curl http://localhost:8000/oauth2/ping
```

## How to configure
+ You should provide a valid values of CLIENT_ID, CLIENT_SECRET, IDM, REDIRECT_URI and UPSTREAM.
+ Cookie_key uses to encrypt cookie

## List of endpoints
+ /oauth2/auth - check validity of cookie prepared by other endpoint, reply 200, 401 (because of http_auth_request_module)
+ /oauth2/sign_in - redirect to IDM, reply 301
+ /oauth2/callback - entrypoint to IDM, preparing cookies, reply 301, 401, 408
+ /oauth2/ping - reply pong
+ /oauth2/version - reply with version

## Example with docker-compose
+custom-nginx - simple nginx docker image with site config on board
+echo-server  - simple tool that reply with "pong" (200)

#### docker-compose file
```console
version: '3'
services:

  echo:
    image: echo-server
    networks:
      test:
        aliases:
        - echo

  oauth2provider:
    image: fiware/service.oauth2provider
    networks:
      test:
        aliases:
        - oauth2provider
    command:
      - '--idm=https://account.fiware.org'
      - '--client_id=${CLIENT_ID}'
      - '--client_secret=${CLIENT_SECRET}'
      - '--redirect_uri=${REDIRECT_URI}'
      - '--upstream=${UPSTREAM}'
      - '--cookie_key=hg83u4thb83iubgyoudfjbnosivun3084uybg3uohr vr'
      - '--cookie_lifetime=24'

  nginx:
    image: custom-nginx
    ports:
    - 0.0.0.0:80:80
    networks:
      test:
        aliases:
        - nginx

networks:
    test:
        external: true
```
        
#### NGXIN site config
```console
server {
  listen 80;
  server_name localhost;

  location /oauth2/ {
    proxy_pass      http://oauth2provider:8000;
  }

  location = /oauth2/auth {
    proxy_pass                http://oauth2provider:8000;
    proxy_set_header          Content-Length   "";
    proxy_pass_request_body   off;
  }

 location / {
    auth_request /oauth2/auth;
    error_page 401 = /oauth2/sign_in;

    proxy_pass http://echo:8000/;
  }
}
```