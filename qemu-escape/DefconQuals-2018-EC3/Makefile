ALL:
	gcc -O0 -static -o exp exp.c
	-rm ../initramfs-busybox-x86_64.cpio.gz
	#-rm ../initramfs-busybox-x86_64.cpio
	find . | cpio -o --format=newc > ../initramfs-busybox-x86_64.cpio
	cd .. && gzip initramfs-busybox-x86_64.cpio
