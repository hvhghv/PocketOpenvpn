#ifndef _POCKETVPN_LWIPOPTS_H
#define _POCKETVPN_LWIPOPTS_H

#include <stdint.h>

#define NO_SYS 1
#define SYS_LIGHTWEIGHT_PROT 1
#define LWIP_DHCP_DOES_ACD_CHECK 0

#define LWIP_ETHERNET 0
#define LWIP_ARP 0
#define LWIP_IGMP 1
#define LWIP_DNS 1
#define LWIP_DHCP 0
#define LWIP_IPV4 1
#define LWIP_UDP  1
#define LWIP_TCP  1
#define LWIP_RAW  1
#define LWIP_ALTCP 0
#define LWIP_ALTCP_TLS 0

#define LWIP_NETCONN 0
#define LWIP_SOCKET 0

#define sys_now ticks_ms_32
#define LWIP_RAND() get_rand32()

extern uint32_t ticks_ms_32();
extern uint32_t get_rand32();

#endif
