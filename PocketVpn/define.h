#ifndef _POCKETVPN_OPT_H_
#define _POCKETVPN_OPT_H_

#ifndef POCKETVPN_DEBUG
#define POCKETVPN_DEBUG (0)
#endif

#ifndef NO_INET_H
#define pocketvpn_htonll htonll
#define pocketvpn_htonl htonl
#define pocketvpn_htons htons
#define pocketvpn_ntohll ntohll
#define pocketvpn_ntohl ntohl
#define pocketvpn_ntohs ntohs
#endif

#ifndef pocketvpn_printf
#define pocketvpn_printf printf
#endif

#if defined POCKETVPN_DEBUG && POCKETVPN_DEBUG > 0

#define pocket_vpn_debug_string(...)  \
    pocketvpn_printf("[POCKETVPN] "); \
    pocketvpn_printf(__VA_ARGS__);    \
    pocketvpn_printf("\n");

#else
#define pocket_vpn_debug_string(...)
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

#ifndef pocketvpn_time
#define pocketvpn_time() time(NULL)
#endif

#ifndef pocketvpn_atoi
#define pocketvpn_atoi atoi
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

#define pbuf_walk(pbuf, data_ptr, count) for (data_ptr = pbuf, count = 0; data_ptr != NULL; count += data_ptr->len, data_ptr = data_ptr->next)

#endif