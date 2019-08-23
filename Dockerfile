FROM python:3.7.3-alpine3.9
LABEL maintainer="Dmitrii Demin <mail@demin.co>"

WORKDIR /opt/

COPY . /opt/

RUN apk add --no-cache git build-base libffi-dev openssl-dev && \
    pip install -r requirements.txt && \
    apk del build-base git libffi-dev openssl-dev

ENTRYPOINT ["/usr/bin/env", "python3", "-u", "/opt/run.py"]
