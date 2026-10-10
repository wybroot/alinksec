FROM ubuntu:24.04
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod 755 /usr/sbin/policy-rc.d \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends rsyslog=8.2312.0-3ubuntu9.4 acl \
    && rm -rf /var/lib/apt/lists/* \
    && printf 'isolated-rsyslog-cron-routing-v1\n' > /usr/local/lib/alinksec-rsyslog-cron-fixture
