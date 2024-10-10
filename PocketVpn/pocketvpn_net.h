#ifndef _POCKETVPN_NET_H
#define _POCKETVPN_NET_H

#ifdef __cplusplus
extern "C" {
#endif

#include "pocketvpn_define.h"
#include "pocketvpn_tun.h"
#include "lwip/netif.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/raw.h"

#define VPNSOCK_FLAG_STOP (1 << 0)

enum _SOCKET_EVENT {
    VPNSOCKET_EVENT_CONNECT,
    VPNSOCKET_EVENT_ACCESS,
    VPNSOCKET_EVENT_RECV,
    VPNSOCKET_EVENT_RECVD,
    VPNSOCKET_EVENT_SENT,
    VPNSOCKET_EVENT_CLEAN,
    VPNSOCKET_EVENT_LOOP

};

enum _SOCKET_TYPE {
    VPNSOCK_TYPE_TCP,
    VPNSOCK_TYPE_UDP,
    VPNSOCK_TYPE_RAW

};

struct _vpnsock_t {

    void *user_mem;
    void *pcb;
    void *sock_dispatch;
    struct pbuf *restore_pbuf;
    uint8_t needClean;
    uint8_t type;
    uint8_t flag;
    struct _vpnsock_t *next;
};

typedef int (*vpnsock_tcp_fn)(struct _vpnsock_t *vpnsock_obj, uint8_t event, uint8_t *buffer, void **outBuffer, uint32_t size, uint32_t *outSize);

typedef int (*vpnsock_udp_fn)(
    struct _vpnsock_t *vpnsock_obj, 
    uint8_t event, 
    uint8_t *buffer, 
    void **outBuffer, 
    uint32_t size, 
    uint32_t *outSize, 
    ip_addr_t **addr,
    uint16_t *port
    );

typedef struct _vpnsock_t vpnsock_t;

err_t tcp_dispatch_service(vpnsock_t *vpnsock, struct tcp_pcb *pcb, uint8_t socket_event, struct pbuf *p);

err_t udp_dispatch_service(vpnsock_t *vpnsock, struct udp_pcb *pcb, uint8_t socket_event, struct pbuf *p, const ip_addr_t *addr, uint16_t port);

err_t tcp_bind_service(
    uint8_t ip1,
    uint8_t ip2,
    uint8_t ip3,
    uint8_t ip4,
    uint16_t port,
    vpnsock_tcp_fn vpnsock_dispatch_func);

struct tcp_pcb *tcp_connect_service(
    uint8_t ip1,
    uint8_t ip2,
    uint8_t ip3,
    uint8_t ip4,
    uint16_t port,
    vpnsock_tcp_fn vpnsock_dispatch_func);

err_t udp_bind_service(
    uint8_t ip1,
    uint8_t ip2,
    uint8_t ip3,
    uint8_t ip4,
    uint16_t port,
    vpnsock_udp_fn vpnsock_dispatch_func
    );

void net_worklist_add(vpnsock_t *vpnsock);

void net_loop();

#ifdef __cplusplus
}
#endif
#endif