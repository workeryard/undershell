# OpenSSH as a distribution ships it, with PAM so keyboard-interactive works.
#   BASE=alpine:latest   the newest OpenSSH Alpine has
#   BASE=ubuntu:20.04    OpenSSH 8.2, an old LTS: no strict KEX, no ext-info quirks fixed since
ARG BASE=alpine:latest
FROM ${BASE}
RUN if command -v apk >/dev/null; then \
      apk add --no-cache openssh-server-pam openssh-sftp-server linux-pam bash; \
    else \
      apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server && \
      rm -rf /var/lib/apt/lists/*; \
    fi
COPY openssh-entrypoint.sh /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
