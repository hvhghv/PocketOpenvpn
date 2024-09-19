#include <winsock2.h>
#include <windows.h>
#include <bcrypt.h>
#include <intsafe.h>
#include <stdint.h>
#include <time.h>

#include "lwip/init.h"
#include "arch/cc.h"


HANDLE  g_Mutex;

uint32_t ticks_ms_32() {
    return (uint32_t)clock() * 1000 / CLOCKS_PER_SEC;
}

int mbedtls_hardware_poll(void *data,
                          unsigned char *output,
                          size_t len,
                          size_t *olen) {

    while (len != 0) {
        uint32_t size =
            (len > 0xffffffff) ? 0xffffffff : (uint32_t)len;

        BCryptGenRandom(NULL, output, size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

        *olen += size;
        len -= size;
    }

    return 0;
};

sys_prot_t
sys_arch_protect(void) {
    WaitForSingleObject(g_Mutex, INFINITE);
    return 0;
}

void
sys_arch_unprotect(sys_prot_t pval) {
    ReleaseMutex(g_Mutex);
}

// 先执行pocketvpn_arch_init1，其中若需要初始化熵源，这必须在此初始化

int pocketvpn_arch_init1() {


    return 0;
}

// 后执行pocketvpn_arch_init2，其中若需要进行lwip_init(),则必须在此进行

int pocketvpn_arch_init2(){

    g_Mutex = CreateMutex(NULL, FALSE, NULL);
	lwip_init();
    return 0;
}
