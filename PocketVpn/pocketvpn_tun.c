
#include "lwip/ip.h"
#include "lwip/ip4_addr.h"
#include "lwip/ip4.h"
#include "pocketvpn_tun.h"



void tun_incoming(Tun_table *tun_table_obj, uint8_t* buffer, uint32_t size){

    size = tun_table_obj->incoming(tun_table_obj->socket_obj, buffer, size);
    struct pbuf *p = pbuf_alloc(PBUF_RAW, size, PBUF_ROM);
    p->payload = buffer;
    tun_table_obj->netif.input(p, &tun_table_obj->netif);

}

err_t tun_out(struct netif *netif, struct pbuf *q, const ip4_addr_t *ipaddr) {

    return netif->linkoutput(netif, q);
}

err_t tun_linkout(struct netif *netif, struct pbuf *p) {

    uint8_t buffer[MTU_MAX];
    Tun_table *tun_table_obj = netif->state;

    struct pbuf *q;
    uint32_t count;

    pbuf_walk(p, q, count){

        pocketvpn_memcpy(&buffer[count], q->payload, q->len);

    }

    tun_table_obj->outcoming(tun_table_obj->socket_obj, buffer, count);

    return ERR_OK;
}

err_t tun_init(struct netif *netif) {

    netif->name[0]    = 'v';
    netif->name[1]    = 'n';
    netif->output     = tun_out;
    netif->linkoutput = tun_linkout;
    netif->mtu        = 1300;

    return ERR_OK;
}


struct netif *tun_active(Tun_table *tun_table_obj, int num) {

    if (num == 0){
        goto close;
    }

    ip4_addr_t ip;
    ip4_addr_t mask;
    ip4_addr_t gw;

    IP4_ADDR(&ip, tun_table_obj->ifconfig[0], tun_table_obj->ifconfig[1], tun_table_obj->ifconfig[2], tun_table_obj->ifconfig[3]);
    IP4_ADDR(&mask, tun_table_obj->ifconfig[4], tun_table_obj->ifconfig[5], tun_table_obj->ifconfig[6],tun_table_obj->ifconfig[7]);
    IP4_ADDR(&gw, tun_table_obj->ifconfig[8], tun_table_obj->ifconfig[9], tun_table_obj->ifconfig[10],tun_table_obj->ifconfig[11]);


    netif_add(&tun_table_obj->netif, &ip, &mask, &gw, tun_table_obj, tun_init, ip_input);
    netif_set_link_up(&tun_table_obj->netif);
    netif_set_up(&tun_table_obj->netif);

    return &tun_table_obj->netif;

close:

    netif_set_down(&tun_table_obj->netif);
    netif_set_link_down(&tun_table_obj->netif);
    netif_remove(&tun_table_obj->netif);

    if (num == 0){
        return &tun_table_obj->netif;
    }
    else{
        return NULL;
    }
}

