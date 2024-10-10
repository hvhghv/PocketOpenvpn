
#include "mphalport.h"

// 先执行pocketvpn_arch_init1，其中若需要初始化熵源，这必须在此初始化

int pocketvpn_arch_init1() {

    return 0;
}

// 后执行pocketvpn_arch_init2，其中若需要进行lwip_init(),则必须在此进行

int pocketvpn_arch_init2(){

    return 0;
}

int mbedtls_hardware_poll(void *data,
                          unsigned char *output,
                          size_t len,
                          size_t *olen) {

    mp_hal_get_random(output, len);
    *olen += len;

    return 0;
};