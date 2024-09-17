#include <winsock2.h>
#include <windows.h>
#include <bcrypt.h>
#include <intsafe.h>
#include <stdint.h>
#include <time.h>

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

int pocketvpn_arch_init(){

    g_Mutex = CreateMutex(NULL, FALSE, NULL);
    return 0;
}
