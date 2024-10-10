#ifndef _POCKETVPN_PROCESS_H
#define _POCKETVPN_PROCESS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "pocketvpn_vpn.h"
#include "pocketvpn_tun.h"
#include "pocketvpn_net.h"

#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"

typedef struct _ssl_context {
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt cert;
    mbedtls_pk_context pkey;
    mbedtls_ssl_context ssl;
    uint8_t *bio_incoming_p;
    uint32_t bio_incoming_size;
    PocketVpnContext *pocketvpn_context;
} SSL_CONTEXT;

typedef struct _pocketvpn_t {

    PocketVpnContext pocketvpn;
    Tun_table tun;
    SSL_CONTEXT ssl;
    vBuffer vbuffer;
    uint8_t loop_buf[VPN_LOOP_BUFFER_SIZE];

} pocketvpn_t;


int pocketvpn_init();

void pocketvpn_loop(pocketvpn_t *pocketvpn);

typedef uint32_t (*socket_read_fn)(void *socket_obj, uint8_t *buffer, uint32_t size);
typedef void (*socket_write_fn)(void *socket_obj, uint8_t *buffer, uint32_t size);
typedef uint32_t (*socket_write_ready_fn)(void *socket_obj);

int pocketvpn_new(
    pocketvpn_t *pocketvpn,
    void *socket_obj,
    socket_read_fn socket_read,
    socket_write_fn socket_write,
    socket_write_ready_fn socket_write_ready,
    const void *ca,
    uint32_t ca_size,
    const void *cert,
    uint32_t cert_size,
    const void *key,
    uint32_t key_size,
    uint8_t cipher_mode,
    uint8_t auth_mode,
    uint8_t key_direction,
    uint16_t mtu,
    uint32_t max_run_time

);

#ifdef __cplusplus
}
#endif

#endif