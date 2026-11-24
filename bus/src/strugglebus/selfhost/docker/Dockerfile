# Strugglebus in one container: the bus and its HTTPS gateway (Caddy).
#
# Build context: a folder holding the release files (the wheel,
# requirements.lock and SHA256SUMS) next to the files from this directory.
FROM caddy:2 AS gateway

FROM python:3.13-slim
COPY --from=gateway /usr/bin/caddy /usr/local/bin/caddy
COPY SHA256SUMS requirements.lock strugglebus-*.whl /release/
RUN cd /release \
 && sha256sum --check --ignore-missing SHA256SUMS \
 && python -m venv /opt/strugglebus \
 && /opt/strugglebus/bin/pip install --no-cache-dir --quiet --require-hashes --only-binary=:all: -r requirements.lock \
 && /opt/strugglebus/bin/pip install --no-cache-dir --quiet --no-deps strugglebus-*.whl \
 && ln -s /opt/strugglebus/bin/strugglebus /usr/local/bin/strugglebus \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin strugglebus \
 && mkdir -p /data /etc/strugglebus \
 && chown strugglebus:strugglebus /data \
 && chmod 700 /data \
 && rm -rf /release
COPY Caddyfile /etc/strugglebus/Caddyfile
COPY entrypoint.sh /usr/local/bin/strugglebus-entrypoint
COPY info.sh /usr/local/bin/strugglebus-info
RUN chmod 755 /usr/local/bin/strugglebus-entrypoint /usr/local/bin/strugglebus-info
USER strugglebus
# Fixed paths, set here so `docker compose exec bus strugglebus ...` sees them too.
ENV STRUGGLEBUS_DATA_DIR=/data/bus \
    STRUGGLEBUS_DATABASE_PATH=/data/bus/strugglebus.db \
    STRUGGLEBUS_BACKUP_DIR=/data/backups \
    STRUGGLEBUS_RUNTIME_DIR=/tmp/strugglebus-run \
    CREDENTIALS_DIRECTORY=/data/credentials \
    STRUGGLEBUS_ADMIN_CREDENTIAL_PATH=/data/credentials/admin-token \
    XDG_DATA_HOME=/data/gateway \
    XDG_CONFIG_HOME=/data/gateway/config
VOLUME /data
EXPOSE 8443
HEALTHCHECK --interval=15s --timeout=4s --start-period=30s --retries=4 \
  CMD ["/opt/strugglebus/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3)"]
ENTRYPOINT ["/bin/bash", "/usr/local/bin/strugglebus-entrypoint"]
