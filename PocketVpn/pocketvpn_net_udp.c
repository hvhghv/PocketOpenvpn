#include "pocketvpn_net.h"
#define VPNSOCK_UDP_SENDMEM 0xfff

err_t udp_dispatch_service(vpnsock_t *vpnsock, struct udp_pcb *pcb, uint8_t socket_event, struct pbuf *p, const ip_addr_t *addr, uint16_t port) {

    int res   = 0;
    err_t err = ERR_OK;
    vpnsock_udp_fn sock_dispatch = (vpnsock_udp_fn)vpnsock->sock_dispatch;
    struct pbuf *q;
    void *outBuffer = NULL;
    uint32_t count;
    uint32_t tmp = VPNSOCK_UDP_SENDMEM;
    ip_addr_t* out_addr;
    uint16_t out_port;
    struct pbuf * send_pbuf;

    if (socket_event == VPNSOCKET_EVENT_ACCESS) {

        if (sock_dispatch(vpnsock, socket_event, NULL, NULL, 0, NULL, NULL, NULL) != 0) {
            goto event_clean;
        }

        vpnsock->restore_pbuf = NULL;
        vpnsock->pcb          = pcb;
        vpnsock->flag         = 0;
        vpnsock->type         = VPNSOCK_TYPE_UDP;
        goto end;
    }

    if (socket_event == VPNSOCKET_EVENT_RECV) {

        out_addr = (ip_addr_t *)addr;
        out_port = port;

        pbuf_walk(p, q, count) {

            res = sock_dispatch(vpnsock, VPNSOCKET_EVENT_RECV, q->payload, &outBuffer, q->len, &tmp, &out_addr, &out_port);

            if (res < 0) {
                goto except_recv;
            }

            if (outBuffer) {

                send_pbuf = pbuf_alloc(PBUF_TRANSPORT, tmp, PBUF_RAM);
                pbuf_take(send_pbuf, outBuffer, tmp);

                err = udp_sendto(pcb, send_pbuf, (const ip_addr_t *)out_addr, (uint16_t)out_port);

                res = sock_dispatch(vpnsock, VPNSOCKET_EVENT_SENT, outBuffer, &outBuffer, tmp, &tmp, &out_addr, &out_port);

                if (res < 0) {
                    goto except_recv;
                }
            }

        }

    }

    if (socket_event == VPNSOCKET_EVENT_LOOP) {

        res  = sock_dispatch(vpnsock, VPNSOCKET_EVENT_LOOP, outBuffer, &outBuffer, tmp, &tmp, &out_addr, &out_port);
        pcb  = vpnsock->pcb;

        if (res < 0) {
            goto event_clean;
        }

        if (res == 0) {
            goto end;
        }

        send_pbuf = pbuf_alloc(PBUF_TRANSPORT, res, PBUF_RAM);
        pbuf_take(send_pbuf, outBuffer, res);
        err = udp_sendto(pcb, send_pbuf, (const ip_addr_t *)out_addr, (uint16_t)out_port);

        res = sock_dispatch(vpnsock, VPNSOCKET_EVENT_SENT, outBuffer, &outBuffer, (uint32_t)res, (uint32_t *)&res, &out_addr, &out_port);

        if (res < 0) {
            goto event_clean;
        }

    }

    if (socket_event == VPNSOCKET_EVENT_CLEAN) {
        goto event_clean;
    }

end:
    return err;


except_recv:

    pbuf_free(p);
    goto event_clean;


event_clean:

    udp_remove(pcb);
    sock_dispatch(vpnsock, VPNSOCKET_EVENT_CLEAN, NULL, NULL, 0, NULL, NULL, NULL);
    vpnsock->flag |= VPNSOCK_FLAG_STOP;
    return ERR_OK;
}

void udp_recv_service_fn(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port) {
    vpnsock_t *vpnsock = (vpnsock_t *)arg;

    udp_dispatch_service(vpnsock, pcb, VPNSOCKET_EVENT_RECV, p, addr, (uint16_t)port);
}


err_t udp_bind_service(
    uint8_t ip1,
    uint8_t ip2,
    uint8_t ip3,
    uint8_t ip4,
    uint16_t port,
    vpnsock_udp_fn vpnsock_dispatch_func

) {

    struct udp_pcb *pcb = udp_new();

    ip_addr_t addr;

    IP_ADDR4(&addr, ip1, ip2, ip3, ip4);

    if (pcb == NULL) {
        pocket_vpn_debug_string(10, "udp_new failed!");
        return ERR_MEM;
    }

    err_t err = udp_bind(pcb, &addr, port);

    if (err == ERR_USE) {
        pocket_vpn_debug_string(10, "port used!");
        return err;
    }

    if (err != ERR_OK) {
        pocket_vpn_debug_string(10, "udp_bind failed!");
        return err;
    }

    vpnsock_t *vpnsock = (vpnsock_t *)pocketvpn_malloc(sizeof(vpnsock_t));
    if (vpnsock == NULL) {
        return ERR_ABRT;
    }

    vpnsock->sock_dispatch = vpnsock_dispatch_func;
    vpnsock->type          = VPNSOCK_TYPE_UDP;

    err = udp_dispatch_service(vpnsock, pcb, VPNSOCKET_EVENT_ACCESS, NULL, NULL, 0);
    if (err != ERR_OK) {
        return err;
    }

    udp_recv(pcb, udp_recv_service_fn, (void *)vpnsock);
    net_worklist_add(vpnsock);


    return ERR_OK;
}