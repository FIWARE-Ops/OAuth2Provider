FROM python:3.7.3-alpine3.10
LABEL maintainer="Dmitrii Demin <mail@demin.co>"

WORKDIR /opt/

COPY . /opt/

RUN apk update && \
    apk add --no-cache git build-base libffi-dev openssl-dev && \
    pip install -r requirements.txt && \
    apk del git build-base libffi-dev openssl-dev && \
    rm -Rf /var/cache/apk/*

USER nobody

EXPOSE 8080

ENTRYPOINT ["/usr/bin/env", "python3", "-u", "/opt/run.py"]
