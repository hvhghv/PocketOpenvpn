#include "pocketvpn_net.h"
#include "uthash/src/utlist.h"

static vpnsock_t *vpnsock_working_list = NULL;

err_t net_loop_service(void *vpnsock_obj, void* pcb) {

    vpnsock_t *vpnsock = (vpnsock_t *)vpnsock_obj;

    if (vpnsock->flag & VPNSOCK_FLAG_STOP) {

        LL_DELETE(vpnsock_working_list, vpnsock);
        pocketvpn_free(vpnsock);
        return ERR_OK;
    }

    if (vpnsock->type == VPNSOCK_TYPE_TCP){
        return tcp_dispatch_service(vpnsock, (struct tcp_pcb *)pcb, VPNSOCKET_EVENT_LOOP, NULL);
    }

    if (vpnsock->type == VPNSOCK_TYPE_UDP){
        return udp_dispatch_service(vpnsock, (struct udp_pcb *)pcb, VPNSOCKET_EVENT_LOOP, NULL, NULL, 0);
    }

    return ERR_OK;
}

void net_worklist_add(vpnsock_t *vpnsock){
    LL_PREPEND(vpnsock_working_list, vpnsock);
}

void net_loop() {
    vpnsock_t *vpnsock;
    vpnsock_t *vpnsock_tmp;

    LL_FOREACH_SAFE(vpnsock_working_list, vpnsock, vpnsock_tmp) {

        net_loop_service(vpnsock, vpnsock->pcb);
    }
}