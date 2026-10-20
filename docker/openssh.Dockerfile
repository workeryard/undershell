# OpenSSH as a distribution ships it, with PAM so keyboard-interactive works.
#   BASE=alpine:latest      the newest OpenSSH Alpine has
#   BASE=ubuntu:20.04       OpenSSH 8.2, an old LTS
#   BASE=debian:12 / :10    OpenSSH 9.2 / 7.9
#   BASE=centos:7           OpenSSH 7.4, as RHEL 7 still runs it
#   BASE=rockylinux:9       OpenSSH 8.7 under RHEL's crypto-policies
ARG BASE=alpine:latest
FROM ${BASE}
RUN if command -v apk >/dev/null; then \
      apk add --no-cache openssh-server-pam openssh-sftp-server linux-pam bash; \
    elif command -v apt-get >/dev/null; then \
      # Releases past their end of life live on archive.debian.org.
      if grep -q 'buster' /etc/os-release 2>/dev/null; then \
        printf '%s\n' 'deb http://archive.debian.org/debian buster main' \
          'deb http://archive.debian.org/debian buster-updates main' \
          'deb http://archive.debian.org/debian-security buster/updates main' > /etc/apt/sources.list; \
      fi; \
      apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server && \
      rm -rf /var/lib/apt/lists/*; \
    else \
      # CentOS 7's mirrors are gone; its packages are on the vault.
      if grep -q 'CentOS Linux 7' /etc/os-release; then \
        sed -i -e 's|^mirrorlist=|#mirrorlist=|' -e 's|^#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|' /etc/yum.repos.d/CentOS-*.repo; \
      fi; \
      (command -v dnf >/dev/null && dnf install -y openssh-server passwd || yum install -y openssh-server passwd) && \
      (dnf clean all 2>/dev/null || yum clean all); \
    fi
COPY openssh-entrypoint.sh /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
