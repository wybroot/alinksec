FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    gcc libc6-dev libpam0g-dev libpam-modules libpam-modules-bin libpam-pwquality libcrypt-dev passwd \
    && rm -rf /var/lib/apt/lists/*
COPY deploy/tests/pam/probe.c /src/probe.c
COPY deploy/tests/pam/auth-probe.c /src/auth-probe.c
RUN gcc -Wall -Wextra -Werror -O2 /src/probe.c -lpam -lcrypt -o /usr/local/bin/alinksec-pam-probe \
    && gcc -Wall -Wextra -Werror -O2 /src/auth-probe.c -lpam -o /usr/local/bin/alinksec-pam-auth-probe \
    && useradd -M -s /bin/sh alinksec-pam-test \
    && printf 'isolated-pam-fixture-v1\n' > /usr/local/lib/alinksec-pam-fixture
ENV ALINKSEC_PAM_ISOLATED_REQUIRED=true
