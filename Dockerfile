FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

# Ubuntu 24.04 (universe): Asterisk 20 und SIP-/Presence-Module.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       asterisk asterisk-modules ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY config/extensions.conf /etc/asterisk/extensions.conf
COPY config/modules.conf /etc/asterisk/modules.conf
COPY scripts/entrypoint.sh /usr/local/bin/blf-entrypoint

RUN chmod 0755 /usr/local/bin/blf-entrypoint

ENTRYPOINT ["/usr/local/bin/blf-entrypoint"]
