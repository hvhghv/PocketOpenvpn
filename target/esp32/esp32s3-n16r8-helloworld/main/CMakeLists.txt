idf_component_register(SRCS "main.c" "pocketvpn_tun.c" "pocketvpn_vpn.c" "pocketvpn.c" "port_layer.c" "app_wifi_init.c" "app_pocketvpn_init.c" "app_server.c"
                       INCLUDE_DIRS ".")

add_definitions("-DMEMP_NUM_SYS_TIMEOUT=30")
