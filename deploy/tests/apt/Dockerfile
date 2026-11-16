FROM ubuntu:24.04
# This isolated oracle validates exactly APT 2.8.3. Keep all three binary
# packages available after the live archive supersedes its development package.
# https://snapshot.ubuntu.com/
ARG APT_FIXTURE_SNAPSHOT=20261001T000000Z
RUN apt-get -o APT::Update::Error-Mode=any update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates \
    && apt-get -o APT::Update::Error-Mode=any --snapshot "$APT_FIXTURE_SNAPSHOT" update \
    && DEBIAN_FRONTEND=noninteractive apt-get --snapshot "$APT_FIXTURE_SNAPSHOT" install -y --allow-downgrades --no-install-recommends apt=2.8.3 libapt-pkg6.0t64=2.8.3 libapt-pkg-dev=2.8.3 g++ acl \
    && rm -rf /var/lib/apt/lists/* \
    && printf 'isolated-apt-install-policy-v1\n' > /usr/local/lib/alinksec-apt-fixture \
    && printf '# foreign owner fixture\n' > /usr/local/lib/alinksec-apt-foreign \
    && chown 1000:0 /usr/local/lib/alinksec-apt-foreign

COPY deploy/tests/apt/sources-oracle.cc /tmp/sources-oracle.cc
RUN g++ -std=c++17 -O0 -o /usr/local/bin/alinksec-apt-sources-oracle /tmp/sources-oracle.cc -lapt-pkg \
    && rm /tmp/sources-oracle.cc
