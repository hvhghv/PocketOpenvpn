#ifndef APP_ESP_H
#define APP_ESP_H

#include "pocketvpn.h"

#define CONFIG_ESP_WIFI_SSID "lm"
#define CONFIG_ESP_WIFI_PASSWORD "34164217"
#define CONFIG_ESP_VPN_SERVER_IP 192,168,1,51
#define CONFIG_ESP_VPN_SERVER_PORT 1194
#define CONFIG_ESP_APPLICATION_BIND_PORT 5678



void wifi_init(void);
int vpn_socket_init(void);
void tcp_server_init(void);
#endif