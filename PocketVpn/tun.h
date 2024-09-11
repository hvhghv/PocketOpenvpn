#ifndef _TUN_H
#define _TUN_H

#include "lwip/netif.h"
#include "PocketVpn/define.h"

typedef struct _Tun_table {


    void (*outcoming)(void* socket_obj, uint8_t* buffer, uint32_t size);
    uint32_t (*incoming)(void* socket_obj, uint8_t* buffer, uint32_t size);
    void *socket_obj;
    uint8_t ifconfig[12];
// --------------------------------------

    struct netif netif;

} Tun_table;

struct netif *tun_active(Tun_table *tun_table_obj, int num);
void tun_incoming(Tun_table *tun_table_obj, uint8_t *buffer, uint32_t size);
#endif