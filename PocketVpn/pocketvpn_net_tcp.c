
#include "pocketvpn_net.h"

int tcp_event_recv(vpnsock_t *vpnsock, struct tcp_pcb *pcb, struct pbuf *p, int *res, err_t *err) {

    struct pbuf *q;
    void *outBuffer = NULL;
    uint32_t count;
    uint32_t tmp;
    int tmp2;
    vpnsock_tcp_fn sock_dispatch = (vpnsock_tcp_fn)vpnsock->sock_dispatch;

    if (vpnsock->restore_pbuf == NULL) {
        vpnsock->restore_pbuf = p;
    }

    pbuf_walk(vpnsock->restore_pbuf, q, count) {

        tmp  = pcb != NULL ? tcp_sndbuf(pcb) : 0;
        *res = sock_dispatch(vpnsock, VPNSOCKET_EVENT_RECV, q->payload, &outBuffer, q->len, &tmp);
        tmp2 = *res;

        if (*res < 0) {
            return 1;
        }

        if (pcb != NULL && outBuffer) {
            *err = tcp_write(pcb, outBuffer, tmp, TCP_WRITE_FLAG_COPY);

            if (*err == ERR_MEM) {
                pocket_vpn_debug_string(10, "VPNSOCKET_EVENT_RECV tcp_write too larget !");
                *res = -2;
                return 1;
            }

            *res = sock_dispatch(vpnsock, VPNSOCKET_EVENT_SENT, outBuffer, &outBuffer, tmp, &tmp);

            if (*res < 0) {
                return 1;
            }
        }

        if (tmp2 != q->len) {
            count = count - q->len + *res;
            q->payload += *res;
            q->len -= *res;
            *err = ERR_WOULDBLOCK;
            break;
        }
    }

    if (*err == ERR_OK) {
        pbuf_free(p);
        vpnsock->restore_pbuf = NULL;
    }

    if (pcb) {
        tcp_recved(pcb, count);
        sock_dispatch(vpnsock, VPNSOCKET_EVENT_RECVD, NULL, NULL, 0, NULL);
    }

    else {
        return 1;
    }

    return 0;
}

int tcp_event_loop(vpnsock_t *vpnsock, struct tcp_pcb *pcb, int *res, err_t *err) {

    void *outBuffer = NULL;
    uint32_t tmp;
    vpnsock_tcp_fn sock_dispatch = (vpnsock_tcp_fn)vpnsock->sock_dispatch;

    tmp = pcb != NULL ? tcp_sndbuf(pcb) : 0;

    *res = sock_dispatch(vpnsock, VPNSOCKET_EVENT_LOOP, outBuffer, &outBuffer, tmp, &tmp);
    pcb  = vpnsock->pcb;

    if (*res < 0) {
        return 1;
    }

    if (*res == 0) {
        return 0;
    }

    *err = tcp_write(pcb, outBuffer, *(uint32_t *)res, TCP_WRITE_FLAG_COPY);

    if (*err == ERR_OK && tmp == *(uint32_t *)res) {
        tcp_output(pcb);
    }

    if (*err == ERR_MEM) {
        pocket_vpn_debug_string(10, "VPNSOCKET_EVENT_LOOP tcp_write too larget!");
        *res = -2;
        return 1;
    }

    *res = sock_dispatch(vpnsock, VPNSOCKET_EVENT_SENT, NULL, NULL, 0, NULL);

    if (*res < 0) {
        return 1;
    }

    return 0;
}

err_t tcp_dispatch_service(vpnsock_t *vpnsock, struct tcp_pcb* pcb, uint8_t socket_event, struct pbuf *p) {

    int res   = 0;
    err_t err = ERR_OK;
    vpnsock_tcp_fn sock_dispatch = (vpnsock_tcp_fn)vpnsock->sock_dispatch;

    if (socket_event == VPNSOCKET_EVENT_ACCESS || socket_event == VPNSOCKET_EVENT_CONNECT) {

        if (sock_dispatch(vpnsock, socket_event, NULL, NULL, 0, NULL) != 0) {
            res = -2;
            goto except_exit;
        }

        vpnsock->restore_pbuf = NULL;
        vpnsock->pcb          = pcb;
        vpnsock->flag         = 0;
        vpnsock->type         = VPNSOCK_TYPE_TCP;
        goto end;
    }

    if (socket_event == VPNSOCKET_EVENT_RECV) {

        if (tcp_event_recv(vpnsock, pcb, p, &res, &err) == 1) {
            goto except_recv;
        }
    }

    if (socket_event == VPNSOCKET_EVENT_LOOP) {

        if (tcp_event_loop(vpnsock, pcb, &res, &err) == 1) {
            goto except_exit;
        }
    }

    if (socket_event == VPNSOCKET_EVENT_CLEAN) {
        goto event_clean;
    }

end:
    return err;

except_recv:

    pbuf_free(p);

    if (pcb == NULL) {
        goto event_clean;
    }

except_exit:
    if (res == -1) {

        if (tcp_close(vpnsock->pcb) == ERR_OK) {
            goto event_clean;
        }
    }

    tcp_abort(vpnsock->pcb);

    return ERR_ABRT;

event_clean:
    sock_dispatch(vpnsock, VPNSOCKET_EVENT_CLEAN, NULL, NULL, 0, NULL);
    vpnsock->flag |= VPNSOCK_FLAG_STOP;
    return ERR_OK;
}

err_t tcp_recv_service_fn(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t e) {
    err_t err = tcp_dispatch_service((vpnsock_t *)arg, pcb, VPNSOCKET_EVENT_RECV, p);
    return err;
}

void tcp_err_service_fn(void *arg, err_t e) {
    tcp_dispatch_service((vpnsock_t *)arg, NULL, VPNSOCKET_EVENT_CLEAN, NULL);
}

err_t tcp_accept_service_fn(void *arg, struct tcp_pcb *newpcb, err_t e) {

    vpnsock_t *vpnsock = (vpnsock_t *)pocketvpn_malloc(sizeof(vpnsock_t));
    if (vpnsock == NULL) {
        tcp_abort(newpcb);
        return ERR_ABRT;
    }

    vpnsock->sock_dispatch = arg;

    tcp_arg(newpcb, vpnsock);
    tcp_recv(newpcb, tcp_recv_service_fn);
    tcp_err(newpcb, tcp_err_service_fn);

    net_worklist_add(vpnsock);

    err_t err = tcp_dispatch_service(vpnsock, newpcb, VPNSOCKET_EVENT_ACCESS, NULL);

    return err;
}

err_t tcp_connected_service_fn(void *arg, struct tcp_pcb *tpcb, err_t err) {

    vpnsock_t *vpnsock = (vpnsock_t *)pocketvpn_malloc(sizeof(vpnsock_t));
    if (vpnsock == NULL) {
        tcp_abort(tpcb);
        return ERR_ABRT;
    }

    vpnsock->sock_dispatch = arg;

    tcp_arg(tpcb, vpnsock);
    tcp_recv(tpcb, tcp_recv_service_fn);
    tcp_err(tpcb, tcp_err_service_fn);

    net_worklist_add(vpnsock);

    err = tcp_dispatch_service(vpnsock, tpcb, VPNSOCKET_EVENT_CONNECT, NULL);

    return err;
}

struct tcp_pcb *tcp_connect_service(
    uint8_t ip1,
    uint8_t ip2,
    uint8_t ip3,
    uint8_t ip4,
    uint16_t port,
    vpnsock_tcp_fn vpnsock_dispatch_func) {
    struct tcp_pcb *tpcb = tcp_new();

    ip_addr_t addr;

    IP_ADDR4(&addr, ip1, ip2, ip3, ip4);

    if (tpcb == NULL) {
        pocket_vpn_debug_string(10, "tcp_new failed!");
        return NULL;
    }

    tcp_arg(tpcb, (void *)vpnsock_dispatch_func);

    err_t err = tcp_connect(tpcb, &addr, port, tcp_connected_service_fn);

    if (err != ERR_OK) {
        pocket_vpn_debug_string(10, "tcp_connect failed!");
        return NULL;
    }

    return tpcb;
}

err_t tcp_bind_service(
    uint8_t ip1,
    uint8_t ip2,
    uint8_t ip3,
    uint8_t ip4,
    uint16_t port,
    vpnsock_tcp_fn vpnsock_dispatch_func

) {

    struct tcp_pcb *pcb = tcp_new();

    ip_addr_t addr;

    IP_ADDR4(&addr, ip1, ip2, ip3, ip4);

    if (pcb == NULL) {
        pocket_vpn_debug_string(10, "tcp_new failed!");
        return ERR_MEM;
    }

    err_t err = tcp_bind(pcb, &addr, port);

    if (err == ERR_USE) {
        pocket_vpn_debug_string(10, "port used!");
        return err;
    }

    if (err != ERR_OK) {
        pocket_vpn_debug_string(10, "tcp_bind failed!");
        return err;
    }

    pcb = tcp_listen(pcb);

    tcp_arg(pcb, (void *)vpnsock_dispatch_func);
    tcp_accept(pcb, tcp_accept_service_fn);

    return ERR_OK;
}
