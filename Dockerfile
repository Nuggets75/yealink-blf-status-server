FROM ubuntu:24.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    asterisk asterisk-modules python3-minimal ca-certificates gosu \
    && rm -rf /var/lib/apt/lists/*
COPY app/app.py /opt/blf/app.py
COPY templates/source-yealinkT4x.ph.xml /opt/blf/templates/source-yealinkT4x.ph.xml
COPY config/modules.conf /etc/asterisk/modules.conf
COPY scripts/entrypoint.sh /usr/local/bin/blf-entrypoint
RUN chmod 0755 /usr/local/bin/blf-entrypoint && chmod 0644 /opt/blf/app.py /opt/blf/templates/source-yealinkT4x.ph.xml
ENTRYPOINT ["/usr/local/bin/blf-entrypoint"]
