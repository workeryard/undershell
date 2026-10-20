#!/bin/sh
set -e
mkdir -p /etc/dropbear
[ -f /etc/dropbear/ed25519 ] || dropbearkey -t ed25519 -f /etc/dropbear/ed25519 >/dev/null
[ -f /etc/dropbear/ecdsa ] || dropbearkey -t ecdsa -s 256 -f /etc/dropbear/ecdsa >/dev/null
[ -f /etc/dropbear/rsa ] || dropbearkey -t rsa -s 3072 -f /etc/dropbear/rsa >/dev/null
for key in ed25519 ecdsa rsa; do dropbearkey -y -f /etc/dropbear/$key | grep '^ssh\|^ecdsa' > /etc/dropbear/$key.pub; done
id tester >/dev/null 2>&1 || adduser -D -s /bin/sh tester
echo "tester:tester-password" | chpasswd
mkdir -p /home/tester/.ssh
cat /keys/*.pub > /home/tester/.ssh/authorized_keys
chown -R tester /home/tester/.ssh
chmod 700 /home/tester/.ssh
chmod 600 /home/tester/.ssh/authorized_keys
exec dropbear -F -E -p 22 -r /etc/dropbear/ed25519 -r /etc/dropbear/ecdsa -r /etc/dropbear/rsa
