#ifndef _POCKETVPN_OPT_H_
#define _POCKETVPN_OPT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "pocketvpn_opt.h"

#ifndef POCKETVPN_DEBUG
#define POCKETVPN_DEBUG (0)
#endif

#ifndef NO_LWIP
#include <lwip/def.h>
#define pocketvpn_htonl lwip_htonl
#define pocketvpn_htons lwip_htons
#define pocketvpn_ntohl lwip_ntohl
#define pocketvpn_ntohs lwip_ntohs
#define pocketvpn_htonll(val) ((uint64_t)(pocketvpn_htonl(val)) << 32) + (uint64_t)pocketvpn_htonl(val >> 32)
#define pocketvpn_ntohll(val) ((uint64_t)(pocketvpn_ntohl(val)) << 32) + (uint64_t)pocketvpn_ntohl(val >> 32)
#endif

#ifndef NO_STD_LIB
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#endif

#ifndef NO_TIME_H
#include <time.h>
#endif

#ifndef POCKETVPN_DEBUG_LEVEL
#define POCKETVPN_DEBUG_LEVEL 10
#endif

#ifndef pocketvpn_printf
#define pocketvpn_printf printf
#endif

#if defined POCKETVPN_DEBUG && POCKETVPN_DEBUG > 0

#define pocket_vpn_debug_string(level, ...)  \
    if (level <= POCKETVPN_DEBUG_LEVEL) { \
        pocketvpn_printf("[POCKETVPN] "); \
        pocketvpn_printf(__VA_ARGS__);    \
        pocketvpn_printf("\n"); \
    } \

#else
#define pocket_vpn_debug_string(level, ...)
#endif

#ifndef pocketvpn_memcpy
#define pocketvpn_memcpy memcpy
#endif

#ifndef pocketvpn_memcmp
#define pocketvpn_memcmp memcmp
#endif

#ifndef pocketvpn_memset
#define pocketvpn_memset memset
#endif

#ifndef pocketvpn_malloc
#define pocketvpn_malloc malloc
#endif

#ifndef pocketvpn_free
#define pocketvpn_free free
#endif

#ifndef pocketvpn_time
#define pocketvpn_time() time(NULL)
#endif

#ifndef pocketvpn_atoi
#define pocketvpn_atoi atoi
#endif

#ifndef CUSTOM_TUN_TABLE
#endif

#ifndef MTU_MAX
#define MTU_MAX 1600
#endif

#ifndef pocketvpn_sprintf
#define pocketvpn_sprintf sprintf
#endif

#ifndef KEY_EXCHANGE_STACK_SIZE
#define KEY_EXCHANGE_STACK_SIZE 256
#endif

#ifndef PRF_STACK_SIZE
#define PRF_STACK_SIZE 384
#endif

#ifndef KEY_GENGRATE_SEED_STACK_SIZE
#define KEY_GENGRATE_SEED_STACK_SIZE 256
#endif

#ifndef PACK_RECODE_RESERVER
#define PACK_RECODE_RESERVER 64
#endif

#ifndef PACKET_HEAD_SIZE_RESERVER
#define PACKET_HEAD_SIZE_RESERVER 192
#endif

#ifndef APPLICATION_PACKET_TAIL_SIZE_RESERVER
#define APPLICATION_PACKET_TAIL_SIZE_RESERVER 64
#endif

#ifndef APPLICATION_RECODE_PACKET_SIZE
#define APPLICATION_RECODE_PACKET_SIZE 64
#endif

#ifndef VPNSOCK_CHECK_TIME
#define VPNSOCK_CHECK_TIME 1
#endif

#define KEY_RANDOM_SIZE 32
#define PRE_MASTER_SIZE 48
#define MAX_CIPHER_KEY_LENGTH 64
#define MAX_HMAC_KEY_LENGTH 64
#define MAX_OCC_STRING 192

#define VPN_LOOP_BUFFER_SIZE 4096

#ifndef pocket_vpn_failed
#define pocket_vpn_failed() \
    {                       \
        while (1)           \
            ;               \
    };
#endif

#ifdef __cplusplus
}
#endif

#endif