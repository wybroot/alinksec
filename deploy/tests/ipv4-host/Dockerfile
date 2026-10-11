FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends iproute2 procps \
    && rm -rf /var/lib/apt/lists/* \
    && printf 'isolated-ipv4-host-fixture-v1\n' > /usr/local/lib/alinksec-ipv4-host-fixture
