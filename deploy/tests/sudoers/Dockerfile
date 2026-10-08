FROM ubuntu:24.04
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod 755 /usr/sbin/policy-rc.d \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends sudo=1.9.15p5-3ubuntu5.24.04.3 acl \
    && rm -rf /var/lib/apt/lists/* \
    && printf 'isolated-sudoers-declarations-v1\n' > /usr/local/lib/alinksec-sudoers-fixture
