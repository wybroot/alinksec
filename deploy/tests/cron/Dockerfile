FROM ubuntu:24.04
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod 755 /usr/sbin/policy-rc.d \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends cron=3.0pl1-184ubuntu2 acl \
    && rm -rf /var/lib/apt/lists/* \
    && printf 'isolated-cron-metadata-fixture-v1\n' > /usr/local/lib/alinksec-cron-fixture
