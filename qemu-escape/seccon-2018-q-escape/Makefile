ALL:
	gcc -O0 -static -o exp exp.c
	-rm ../initramfs.igz 
	#-rm ../initramfs-busybox-x86_64.cpio
	find . | cpio -o --format=newc > ../initramfs
	cd .. && gzip initramfs && mv initramfs.gz initramfs.igz
