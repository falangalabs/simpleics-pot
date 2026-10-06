FROM python:3.14-alpine@sha256:3f818d6811ff5f3f2b5e5d836df3d25c2dd2e588d3b4981338a8ba17e422f74f

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# The base stays pinned by digest; this applies the security updates its
# Alpine branch has published since that digest was cut. The price is that two
# builds of the same commit are no longer byte-identical.
RUN apk upgrade --no-cache

RUN addgroup -S -g 10001 simpleics \
    && adduser -S -D -H -u 10001 -G simpleics -s /sbin/nologin simpleics

COPY requirements.lock /app/requirements.lock
# pip and setuptools are build-time tools. Leaving them in the running image
# costs two HIGH advisories that have nothing to do with this project -- the
# base image's bundled setuptools, and the msgpack pip vendors for its cache --
# and hands anyone who reaches code execution inside the decoy a package
# installer. The decoy imports pymodbus and the standard library and nothing
# else, so both go once the lockfile is installed.
RUN python -m pip install --require-hashes --only-binary=:all: \
        --requirement /app/requirements.lock \
    && python -m pip uninstall --yes setuptools pip

COPY src /app/src
COPY config/register_map.v1.json /app/config/register_map.v1.json
RUN chmod -R a-w /app

USER 10001:10001

EXPOSE 1502/tcp

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import socket; s=socket.create_connection(('127.0.0.1',1502),2); s.close()"]

ENTRYPOINT ["python", "-m", "simpleics_pot.runtime"]
CMD ["--host", "0.0.0.0", "--port", "1502", "--allow-non-loopback"]
