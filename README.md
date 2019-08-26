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
$ docker run -it --rm \
             -p 0.0.0.0:8080:8080 \
             fiware/service.oauth2provider \
             --keyrock ${KEYROCK}
             --client_id ${CLIENT_ID}
             --client_secret ${CLIENT_SECRET}
             --redirect_uri ${REDIRECT_URI}
             --upstream ${UPSTREAM}
             --cookie_key ${BIG_RANDOM_NUMBER}
             --cookie_lifetime ${TIME_IN_HOURS}
             --salt ${SALT}
```
```console
$ curl http://localhost:8080/oauth2/ping
```

## How to configure
+ You must provide a valid values for all parameters except 'ip' and 'port'.
+ Cookie_key uses to encrypt cookie

## List of endpoints
+ /oauth2/auth - check validity of cookie prepared by other endpoints, reply 200, 401
+ /oauth2/sign_in - redirect to Keyrock, reply 303
+ /oauth2/callback - entrypoint for Keyrock, validate a token, preparing cookies, reply 303, 403
+ /oauth2/ping - reply pong
+ /oauth2/version - reply with version

## Sampe NGINX config
Test configuration prepared, see `default.conf`. You can use docker-compose file to test it.
