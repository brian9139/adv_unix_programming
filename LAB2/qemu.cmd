set KERNELVERSION=6.6.17
set KERNELAPPEND="console=ttyS0"

"c:\program files\qemu\qemu-system-x86_64.exe" -smp 2 -kernel ./dist/vmlinuz-%KERNELVERSION% -initrd ./dist/rootfs.cpio.bz2 -append %KERNELAPPEND% -serial mon:stdio -monitor none -nographic -no-reboot -cpu qemu64 -netdev user,id=mynet0,net=192.168.76.0/24,dhcpstart=192.168.76.101 -device e1000,netdev=mynet0 -m 96M
