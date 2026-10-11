FROM rockylinux:9
RUN test -x /usr/bin/rpm && test -x /usr/bin/python3 && \
    /usr/bin/python3 -c 'import dnf' && \
    mkdir -p /usr/local/lib && \
    printf 'isolated-dnf-fixture-v1\n' > /usr/local/lib/alinksec-dnf-fixture
