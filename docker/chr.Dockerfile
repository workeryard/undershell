# MikroTik's Cloud Hosted Router, RouterOS for x86, booted under QEMU with
# KVM. The image is not redistributed: scripts/matrix-docker.ts downloads it
# from download.mikrotik.com into .cache/chr/ and mounts it.
FROM alpine:latest
RUN apk add --no-cache qemu-system-x86_64
EXPOSE 22
ENTRYPOINT ["qemu-system-x86_64", "-enable-kvm", "-m", "256", "-nographic", "-snapshot", \
  "-drive", "file=/chr.img,format=raw,if=virtio", \
  "-netdev", "user,id=net0,hostfwd=tcp::22-:22", "-device", "virtio-net-pci,netdev=net0"]
