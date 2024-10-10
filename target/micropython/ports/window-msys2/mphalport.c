#include "mphalport.h"
#include "py/runtime.h"
#include <stdio.h>
#include <time.h>
#include <windows.h>
#include <bcrypt.h>

extern void usleep(unsigned long usec);
extern ssize_t read(int fd,void*buf,size_t count);
extern int open(const char *pathname, int flags);
extern int close(int fd);

int mp_hal_stdin_rx_chr(){
    unsigned char c = 0;
    c = fgetc(stdin);
    return c;
}

mp_uint_t mp_hal_stdout_tx_strn(const char *str, mp_uint_t len) {

    for (mp_uint_t i = 0; i < len; i++){
        fputc(str[i], stdout);
    }

    return len;
}


void mp_hal_delay_us(mp_uint_t us){
    usleep(us);
}

mp_uint_t mp_hal_ticks_cpu(void) {
    return (mp_uint_t)clock();
}

// --------------

void mp_hal_get_random(void *buf, size_t n) {

    size_t len = n;
    uint8_t* p = (uint8_t*)buf;

    while (len != 0) {
        uint32_t size =
            (len > 0xffffffff) ? 0xffffffff : (uint32_t)len;

        BCryptGenRandom(NULL, p, size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

        p += size;
        len -= size;
    }

}



// --------------

void mp_hal_set_interrupt_char(char c) {
}

void mp_hal_delay_ms(mp_uint_t ms) {
    mp_hal_delay_us(ms * 1000);
}

mp_uint_t mp_hal_ticks_ms(void) {
    return mp_hal_ticks_cpu() * 1000 / CLOCKS_PER_SEC;
}

mp_uint_t mp_hal_ticks_us(void) {
    return mp_hal_ticks_cpu() * 1000000 / CLOCKS_PER_SEC;
}

// uint32_t get_rand32() {
//     uint32_t n;
//     mp_hal_get_random(&n, sizeof(n));
//     return n;
// }

uint32_t ticks_ms_32(){
    return (uint32_t)mp_hal_ticks_ms();
}


