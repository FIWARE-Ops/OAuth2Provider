FROM alpine
MAINTAINER Dmitrii Demin <mail@demin.co>

ADD server.py /opt/
ADD version /opt/

RUN apk add --no-cache --update python3 python3-dev build-base \
&&  pip3 install requests cookies pycrypto \
&&  apk del python3-dev build-base

WORKDIR /opt

ENTRYPOINT ["/usr/bin/python3", "-u", "/opt/server.py"]

EXPOSE 8000
