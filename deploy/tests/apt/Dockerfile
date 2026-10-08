FROM ubuntu:24.04
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends apt=2.8.3 libapt-pkg6.0t64=2.8.3 acl \
    && rm -rf /var/lib/apt/lists/* \
    && printf 'isolated-apt-install-policy-v1\n' > /usr/local/lib/alinksec-apt-fixture \
    && printf '# foreign owner fixture\n' > /usr/local/lib/alinksec-apt-foreign \
    && chown 1000:0 /usr/local/lib/alinksec-apt-foreign
