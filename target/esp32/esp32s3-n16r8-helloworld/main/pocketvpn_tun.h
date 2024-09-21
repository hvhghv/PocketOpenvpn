#ifndef _TUN_H
#define _TUN_H

#ifdef __cplusplus
extern "C" {
#endif

#include "lwip/netif.h"
#include "pocketvpn_define.h"

typedef struct _Tun_table {

#ifdef CUSTOM_TUN_TABLE
    CUSTOM_TUN_TABLE
#endif
    void (*outcoming)(void* socket_obj, uint8_t* buffer, uint32_t size);
    uint32_t (*incoming)(void* socket_obj, uint8_t* buffer, uint32_t size);
    void *socket_obj;
    uint8_t ifconfig[12];
// --------------------------------------

    struct netif netif;

} Tun_table;


struct netif *tun_active(Tun_table *tun_table_obj, int num);
void tun_incoming(Tun_table *tun_table_obj, uint8_t *buffer, uint32_t size);

#define pbuf_walk(pbuf, data_ptr, count) for (data_ptr = pbuf, count = 0; data_ptr != NULL; count += data_ptr->len, data_ptr = data_ptr->next)

#ifdef __cplusplus
}
#endif

#endif