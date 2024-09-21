#include "app_esp.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"



void app_main(void) {
    wifi_init();

    if (vpn_socket_init() != 0){
        ESP_LOGI("VPN", "VPN Socket Init Failed");
        pocket_vpn_failed();
    }

    tcp_server_init();

    while (1){
        vTaskDelay(1);
    }

}
