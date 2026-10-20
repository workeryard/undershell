# Dropbear, as Alpine ships it: the other server embedded systems run.
FROM alpine:latest
RUN apk add --no-cache dropbear dropbear-dbclient openssh-sftp-server
COPY dropbear-entrypoint.sh /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
