
#include "app_esp.h"
#include "esp_log.h"
#include "cert_file.h"
#include "lwip/timeouts.h"
#include "lwip/tcp.h"
#include "freertos/FreeRTOS.h"

pocketvpn_t pocketvpn_1;

uint8_t *socket2vpnserver_recv_p = NULL;
int last_recv_data_size          = 0;
int isConnect = 0;

uint8_t socket2vpnserver_send_buf[4096];
uint8_t *socket2vpnserver_send_buf_p = socket2vpnserver_send_buf;
uint32_t socket2vpnserver_send_buf_size = 0;
int socket2vpnserver_dispatch(vpnsock_t *vpnsock_obj, uint8_t event, uint8_t *buffer, void **outBuffer, uint32_t size, uint32_t *outSize) {

    int t;

    if (event == VPNSOCKET_EVENT_CONNECT){
        isConnect = 1;
    }

    if (event == VPNSOCKET_EVENT_RECV) {

        if (socket2vpnserver_recv_p == NULL && last_recv_data_size == 0) {
            socket2vpnserver_recv_p = buffer;
            last_recv_data_size     = size;
            return 0;
        }

        if (socket2vpnserver_recv_p == NULL && last_recv_data_size > 0) {
            t                   = last_recv_data_size;
            last_recv_data_size = 0;
            return t;
        }
    }

    if (event == VPNSOCKET_EVENT_LOOP){

        if (socket2vpnserver_send_buf_size > 0){
            uint32_t send_size = size < socket2vpnserver_send_buf_size ? size : socket2vpnserver_send_buf_size;
            *outBuffer = socket2vpnserver_send_buf_p;

            if (send_size == socket2vpnserver_send_buf_size){
                socket2vpnserver_send_buf_p = socket2vpnserver_send_buf;
                socket2vpnserver_send_buf_size = 0;
            }

            else{
                socket2vpnserver_send_buf_p += send_size;
                socket2vpnserver_send_buf_size -= send_size;
            }

            return send_size;
        }
    }

    return 0;

}

uint32_t vpn_socket_read(void *socket_obj, uint8_t *buffer, uint32_t size) {

    if (socket2vpnserver_recv_p != NULL) {
        memcpy(buffer, socket2vpnserver_recv_p, last_recv_data_size);
        socket2vpnserver_recv_p = NULL;
        return last_recv_data_size;
    }

    return 0;
}


void vpn_socket_write(void *socket_obj, uint8_t *buffer, uint32_t size) {
    struct tcp_pcb *pcb = (struct tcp_pcb *)socket_obj;

    err_t err = tcp_write(pcb, buffer, size, TCP_WRITE_FLAG_COPY);

    if (err != ERR_OK){
        if (size > sizeof(socket2vpnserver_send_buf)){
            pocketvpn_printf("vpn_socket_write too larget!\n: %d", (int)size);
        }

        memcpy(socket2vpnserver_send_buf, buffer, size);
        socket2vpnserver_send_buf_size += size;

    }

}

uint32_t vpn_socket_write_ready(void *socket_obj){
    if (socket2vpnserver_send_buf_size > 0) {
        return 1;
    }

    return 0;
}

void sys_timeout_pocketvpn(void *arg) {
    pocketvpn_loop((pocketvpn_t *)arg);
    vTaskDelay(1);
    sys_timeout(1, sys_timeout_pocketvpn, arg);
    
}

int vpn_socket_init() {

    pocketvpn_init();
    struct tcp_pcb *pcb = tcp_connect_service(CONFIG_ESP_VPN_SERVER_IP, CONFIG_ESP_VPN_SERVER_PORT, socket2vpnserver_dispatch);

    pocketvpn_new(&pocketvpn_1, pcb, vpn_socket_read, vpn_socket_write, vpn_socket_write_ready, cafile, sizeof(cafile), certfile, sizeof(certfile), keyfile, sizeof(keyfile), CIPHER_AES_256_CBC, HMAC_MODE_SHA512, 0, 1300, 3600);
    sys_timeout(3000, sys_timeout_pocketvpn, &pocketvpn_1);
    return 0;
}
