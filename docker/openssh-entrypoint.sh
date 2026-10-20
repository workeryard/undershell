#!/bin/sh
# Every host key type, two users, and the methods the matrix logs in with.
# /keys holds the client public keys, mounted read-only.
set -e
mkdir -p /run/sshd /etc/ssh/keys
for type in ed25519 rsa; do
  [ -f /etc/ssh/keys/$type ] || ssh-keygen -q -t $type -N '' -f /etc/ssh/keys/$type
done
for bits in 256 384 521; do
  [ -f /etc/ssh/keys/ecdsa$bits ] || ssh-keygen -q -t ecdsa -b $bits -N '' -f /etc/ssh/keys/ecdsa$bits
done

for user in tester twofactor; do
  id $user >/dev/null 2>&1 || { adduser -D -s /bin/sh $user 2>/dev/null || useradd -m -s /bin/sh $user; }
  echo "$user:$user-password" | chpasswd
  mkdir -p /home/$user/.ssh
  cat /keys/*.pub > /home/$user/.ssh/authorized_keys
  chown -R $user /home/$user/.ssh
  chmod 700 /home/$user/.ssh
  chmod 600 /home/$user/.ssh/authorized_keys
done

{
  for key in ed25519 ecdsa256 ecdsa384 ecdsa521 rsa; do echo "HostKey /etc/ssh/keys/$key"; done
  echo "UsePAM yes"
  echo "PasswordAuthentication yes"
  echo "KbdInteractiveAuthentication yes"
  echo "ChallengeResponseAuthentication yes"
  echo "PubkeyAuthentication yes"
  echo "AllowTcpForwarding yes"
  echo "MaxAuthTries 20"
  echo "Subsystem sftp internal-sftp"
  echo "LogLevel VERBOSE"
  # Re-key every megabyte, so any transfer in the matrix crosses a key exchange.
  echo "RekeyLimit 1M"
  # Every algorithm the matrix pins, whether or not this version's default offers it.
  echo "KexAlgorithms +ecdh-sha2-nistp256"
  echo "HostKeyAlgorithms +ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521"
  echo "Match User twofactor"
  echo "  AuthenticationMethods publickey,keyboard-interactive"
} > /etc/ssh/sshd_config
# Ubuntu's PAM asks for nothing more; Alpine's needs a stack for sshd.
[ -f /etc/pam.d/sshd ] || printf 'auth required pam_unix.so\naccount required pam_unix.so\nsession optional pam_unix.so\n' > /etc/pam.d/sshd
# Alpine names the PAM build sshd.pam.
exec "$(command -v sshd.pam || echo /usr/sbin/sshd)" -D -e
