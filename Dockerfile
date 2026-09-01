FROM python:3.13-alpine@sha256:62e80a1ff2a4af41c6fe72a629e5729463a4fd05ae89ecc9c812a6c1457f2cc7

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

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
