FROM ubuntu:24.04
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod 755 /usr/sbin/policy-rc.d \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends auditd \
    && rm -rf /var/lib/apt/lists/* \
    && printf 'isolated-auditd-config-fixture-v1\n' > /usr/local/lib/alinksec-auditd-fixture
