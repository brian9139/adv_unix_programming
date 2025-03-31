#!/bin/sh
DEBUG=
APPEND="console=ttyS0"

if [ "$1" = "debug" ]; then
	DEBUG="-s -S"
	APPEND="$APPEND nokaslr"
fi

exec qemu-system-x86_64 \
  -smp 2 \
  -kernel ./dist/vmlinuz-* \
  -initrd ./dist/rootfs.cpio.bz2 \
  -append "$APPEND" \
  -serial mon:stdio \
  -monitor none \
  -nographic \
  -no-reboot \
  -cpu qemu64 \
  -netdev user,id=mynet0,net=192.168.76.0/24,dhcpstart=192.168.76.101,hostfwd=tcp::8000-:80 -device e1000,netdev=mynet0 \
  -m 96M $DEBUG

