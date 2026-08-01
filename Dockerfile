FROM python:3.13-alpine@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN addgroup -S -g 10001 simpleics \
    && adduser -S -D -H -u 10001 -G simpleics -s /sbin/nologin simpleics

COPY requirements.lock /app/requirements.lock
RUN python -m pip install --require-hashes --only-binary=:all: \
        --requirement /app/requirements.lock

COPY src /app/src
COPY config/register_map.v1.json /app/config/register_map.v1.json
RUN chmod -R a-w /app

USER 10001:10001

EXPOSE 1502/tcp

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import socket; s=socket.create_connection(('127.0.0.1',1502),2); s.close()"]

ENTRYPOINT ["python", "-m", "simpleics_pot.runtime"]
CMD ["--host", "0.0.0.0", "--port", "1502", "--allow-non-loopback"]
