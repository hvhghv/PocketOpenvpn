
#include "pocketvpn.h"
#include "app_esp.h"



char vpnsock_send_buf1[200];
int m_vpnsock_dispatch_fn_1(vpnsock_t *vpnsock_obj, uint8_t event, uint8_t *buffer, void **outBuffer, uint32_t size, uint32_t *outSize) {

    int res;

    if (event == VPNSOCKET_EVENT_RECV) {
        res = sprintf(vpnsock_send_buf1, "[server recv]: ");
        memcpy(vpnsock_send_buf1 + res, buffer, size);
        vpnsock_send_buf1[res + size] = '\n';
        *outBuffer                    = vpnsock_send_buf1;
        *outSize                      = res + size + 1;

        if (size >= 5 && memcmp(buffer, "close", 5) == 0) {
            return -1;
        }

        if (size >= 5 && memcmp(buffer, "abort", 5) == 0) {
            return -2;
        }

        return size;
    }

    return 0;
}

void tcp_server_init(){
    tcp_bind_service(0, 0, 0, 0, CONFIG_ESP_APPLICATION_BIND_PORT, m_vpnsock_dispatch_fn_1);
}