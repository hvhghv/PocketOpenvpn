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

void pocketvpn_urandom(void *buffer, uint32_t size){
    BCryptGenRandom(NULL, buffer, size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

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

unsigned __int64 htonll(unsigned __int64 val) {
    return ((unsigned __int64)(htonl(val)) << 32) + (unsigned __int64)htonl(val >> 32);
}

unsigned __int64 ntohll(unsigned __int64 val) {
    return ((unsigned __int64)(ntohl(val)) << 32) + (unsigned __int64)ntohl(val >> 32);
}