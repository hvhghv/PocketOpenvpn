#include "pocketvpn.h"
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/timeouts.h"
#include "lwip/ip_addr.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#define POCKETVPN_SEED "POCKETVPN"

mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;

extern int pocketvpn_arch_init1();
extern int pocketvpn_arch_init2();

uint32_t get_rand32();

#if defined POCKETVPN_DEBUG && POCKETVPN_DEBUG > 0
void pocketvpn_mbedtls_debug(void *ctx, int level, const char *file, int line, const char *str) {
    pocketvpn_printf("[MBEDTLS:%s:%04d: %s\n]", file, line, str);
};

#endif

static vpnsock_t *vpnsock_working_list = NULL;

err_t tcp_loop_service(void *vpnsock_obj, struct tcp_pcb *pcb);

int pocket_vpn_mbedtls_ssl_send(void *ctx, const unsigned char *buf, size_t len) {

    uint8_t buffer[PACK_RECODE_RESERVER + MTU_MAX];
    uint8_t *buffer_ptr   = buffer + PACK_RECODE_RESERVER;
    uint32_t payload_size = (uint32_t)len < MTU_MAX ? (uint32_t)len : MTU_MAX;
    SSL_CONTEXT *ssl_ctx  = (SSL_CONTEXT *)ctx;

    memcpy(buffer_ptr, buf, payload_size);

    vBuffer vbuffer;
    vbuffer.buf      = buffer;
    vbuffer.s        = buffer_ptr;
    vbuffer.c        = buffer_ptr;
    vbuffer.e        = buffer_ptr + payload_size;
    vbuffer.boundary = buffer + sizeof(buffer);
    vbuffer.flag     = 0;

    pocket_vpn_tls_output(ssl_ctx->pocketvpn_context, &vbuffer);
    return (int)payload_size;
}

int pocket_vpn_mbedtls_ssl_recv(void *ctx, unsigned char *buf, size_t len) {
    SSL_CONTEXT *ssl_ctx = (SSL_CONTEXT *)ctx;
    uint32_t size        = (uint32_t)len < ssl_ctx->bio_incoming_size ? (uint32_t)len : ssl_ctx->bio_incoming_size;

    if (size == 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    memcpy(buf, ssl_ctx->bio_incoming_p, size);
    ssl_ctx->bio_incoming_p += size;
    ssl_ctx->bio_incoming_size -= size;

    return size;
}

uint32_t pocketvpn_tls_read(void *tls_obj, uint8_t *buffer, uint32_t size) {
    SSL_CONTEXT *tls_context = (SSL_CONTEXT *)tls_obj;

    uint32_t count = 0;
    int ret        = 0;

    do {
        ret = mbedtls_ssl_read(&tls_context->ssl, buffer, size);

        if (ret > 0) {
            count += (uint32_t)ret;
        }

        if (tls_context->bio_incoming_size == 0) {
            break;
        }

    } while (1);

    return (uint32_t)count;
}

void pocketvpn_tls_write(PocketVpnContext *pocketvpn_context_obj, void *tls_obj, uint8_t *buffer, uint32_t size) {
    SSL_CONTEXT *tls_context = (SSL_CONTEXT *)tls_obj;

    int ret = mbedtls_ssl_write(&tls_context->ssl, buffer, size);

    if (ret <= 0) {
        pocket_vpn_debug_string(10, "pocketvpn_tls_write error! code: %d", ret);
        pocket_vpn_failed();
    }
}

uint32_t pocketvpn_tls_do_handshark(void *tls_obj) {
    SSL_CONTEXT *tls_context = (SSL_CONTEXT *)tls_obj;
    int ret;

    do {

        ret = mbedtls_ssl_handshake(&tls_context->ssl);

        if (ret != 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret != MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS && ret != MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS) {

            pocket_vpn_debug_string(10, "pocketvpn_tls_do_handshark error! code: %d", ret);
            pocket_vpn_failed();
        }

    } while (tls_context->bio_incoming_size != 0);

    if (ret == 0) {
        return 1;
    }

    if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
        return 0;
    }

    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return 0;
    }

    if (ret == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS) {
        return 0;
    }

    if (ret == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS) {
        return 0;
    }

    pocket_vpn_debug_string(10, "pocketvpn_tls_do_handshark error! code: %d", ret);
    pocket_vpn_failed();
    return 0;
}

void pocketvpn_tls_incoming(PocketVpnContext *pocketvpn_context_obj, void *tls_bio_obj, uint8_t *buffer, uint32_t size) {
    SSL_CONTEXT *tls_context       = (SSL_CONTEXT *)tls_bio_obj;
    tls_context->bio_incoming_p    = buffer;
    tls_context->bio_incoming_size = size;
    pocket_vpn_tls_read(pocketvpn_context_obj, buffer, size);
}

uint32_t pocketvpn_tls_outcoming(void *tls_bio_obj, uint8_t *buffer, uint32_t size) {
    return 0;
}

uint32_t pocketvpn_hmac_digest(uint8_t *key, uint32_t key_size, uint8_t *msg, uint32_t msg_size, uint8_t *buffer, uint32_t buffer_size, uint8_t mode) {
    mbedtls_md_context_t ctx;
    mbedtls_md_info_t *info;
    mbedtls_md_init(&ctx);

    switch (mode) {
    case HMAC_MODE_MD5:
        info = (mbedtls_md_info_t *)mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
        break;

    case HMAC_MODE_SHA1:
        info = (mbedtls_md_info_t *)mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
        break;

    case HMAC_MODE_SHA256:
        info = (mbedtls_md_info_t *)mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        break;

    case HMAC_MODE_SHA512:
        info = (mbedtls_md_info_t *)mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
        break;

    default:
        pocket_vpn_debug_string(10, "pocketvpn_hmac_digest error! code: %d", mode);
        pocket_vpn_failed();
    }

    uint32_t ret_size = mbedtls_md_get_size(info);
    if (ret_size > buffer_size) {
        pocket_vpn_debug_string(10, "pocketvpn_hmac_digest failed! code: %d", (int)ret_size);
        pocket_vpn_failed();
    }

    int ret;

    ret = mbedtls_md_setup(&ctx, info, 1);
    if (ret != 0) {
        pocket_vpn_debug_string(10, "mbedtls_md_setup failed! code: %d", ret);
        pocket_vpn_failed();
    }

    ret = mbedtls_md_hmac_starts(&ctx, key, key_size);
    if (ret != 0) {
        pocket_vpn_debug_string(10, "mbedtls_md_hmac_starts failed! code: %d", ret);
        pocket_vpn_failed();
    }

    ret = mbedtls_md_hmac_update(&ctx, msg, msg_size);
    if (ret != 0) {
        pocket_vpn_debug_string(10, "mbedtls_md_hmac_update failed! code: %d", ret);
        pocket_vpn_failed();
    }

    ret = mbedtls_md_hmac_finish(&ctx, buffer);
    if (ret != 0) {
        pocket_vpn_debug_string(10, "mbedtls_md_hmac_finish failed! code: %d", ret);
        pocket_vpn_failed();
    }

    mbedtls_md_free(&ctx);

    return ret_size;
}

uint32_t pocketvpn_cipher(
    uint8_t *key,
    uint32_t key_size,
    uint8_t *iv,
    uint32_t iv_length,
    uint8_t *text,
    uint32_t text_size,
    uint8_t *buffer,
    uint32_t buffer_size,
    uint8_t mode,
    uint8_t en) {

    mbedtls_cipher_context_t ctx;
    mbedtls_cipher_info_t *info;
    uint32_t output_len = 0;
    size_t t_len;

    mbedtls_cipher_init(&ctx);

    switch (mode) {
    case CIPHER_AES_128_CBC:
        info = (mbedtls_cipher_info_t *)mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC);
        break;

    case CIPHER_AES_256_CBC:
        info = (mbedtls_cipher_info_t *)mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC);
        break;

    default:
        pocket_vpn_debug_string(10, "mbedtls_md_info_from_type error! code: %d", mode);
        pocket_vpn_failed();
    }

    int ret;

    ret = mbedtls_cipher_setup(&ctx, info);
    if (ret != 0) {
        pocket_vpn_debug_string(10, "mbedtls_cipher_setup error! code: %d", ret);
        pocket_vpn_failed();
    }

    ret = mbedtls_cipher_setkey(&ctx, key, key_size * 8, (mbedtls_operation_t)en);
    if (ret != 0) {
        pocket_vpn_debug_string(10, "mbedtls_cipher_setkey error! code: %d", ret);
        pocket_vpn_failed();
    }

    ret = mbedtls_cipher_set_iv(&ctx, iv, iv_length);
    if (ret != 0) {
        pocket_vpn_debug_string(10, "mbedtls_cipher_set_iv error! code: %d", ret);
        pocket_vpn_failed();
    }

    mbedtls_cipher_set_padding_mode(&ctx, MBEDTLS_PADDING_NONE);
    if (ret != 0) {
        pocket_vpn_debug_string(10, "mbedtls_cipher_set_padding_mode! code: %d", ret);
        pocket_vpn_failed();
    }

    ret = mbedtls_cipher_update(&ctx, text, text_size, buffer, &t_len);
    if (ret != 0) {
        pocket_vpn_debug_string(10, "mbedtls_cipher_update error! code: %d", ret);
        pocket_vpn_failed();
    }

    output_len += t_len;

    ret = mbedtls_cipher_finish(&ctx, buffer, &t_len);
    if (ret != 0) {
        pocket_vpn_debug_string(10, "mbedtls_cipher_finish error! code: %d, text_size: %d, key_size: %d, iv_size: %d\n", ret, (int)text_size, (int)key_size, (int)iv_length);
        pocket_vpn_failed();
    }
    output_len += t_len;

    if (output_len > buffer_size) {
        pocket_vpn_debug_string(10, "mbedtls_cipher overflow error! code: %d", (int)output_len);
        pocket_vpn_failed();
    }

    mbedtls_cipher_free(&ctx);
    return output_len;
}

uint32_t pocketvpn_encrypto(uint8_t *key, uint32_t key_size, uint8_t *iv, uint32_t iv_length, uint8_t *text, uint32_t text_size, uint8_t *buffer, uint32_t buffer_size, uint8_t mode) {
    return pocketvpn_cipher(key, key_size, iv, iv_length, text, text_size, buffer, buffer_size, mode, 1);
}

uint32_t pocketvpn_decrypto(uint8_t *key, uint32_t key_size, uint8_t *iv, uint32_t iv_length, uint8_t *en_text, uint32_t en_text_size, uint8_t *buffer, uint32_t buffer_size, uint8_t mode) {
    return pocketvpn_cipher(key, key_size, iv, iv_length, en_text, en_text_size, buffer, buffer_size, mode, 0);
}

void pocketvpn_driver_incoming(void *driver_obj, uint8_t *buffer, uint32_t size) {
    Tun_table *tun_obj = (Tun_table *)driver_obj;
    tun_incoming(tun_obj, buffer, size);
}

uint32_t pocketvpn_driver_outcoming(void *driver_obj, uint8_t *buffer, uint32_t size) {
    return size;
}

uint32_t lwip_tun_in(void *socket_obj, uint8_t *buffer, uint32_t size) {
    return size;
}

void lwip_tun_out(void *socket_obj, uint8_t *buffer, uint32_t size) {

    uint8_t data[PACKET_HEAD_SIZE_RESERVER + MTU_MAX + APPLICATION_PACKET_TAIL_SIZE_RESERVER];
    uint8_t *data_ptr                   = data + PACKET_HEAD_SIZE_RESERVER;
    PocketVpnContext *pocketvpn_context = (PocketVpnContext *)socket_obj;
    vBuffer vbuffer;
    uint32_t payload_size;

    pocket_vpn_debug_string(10, "lwip_tun_out");
    pocket_vpn_debug_bytes(10, buffer, size);

    while (size > 0) {

        payload_size = size < MAX_APPLICATION_PACKET(pocketvpn_context->mtu) ? size : MAX_APPLICATION_PACKET(pocketvpn_context->mtu);
        pocketvpn_memcpy(data_ptr, buffer, payload_size);
        buffer += payload_size;
        size -= payload_size;

        vbuffer.buf      = data;
        vbuffer.s        = data_ptr;
        vbuffer.c        = data_ptr;
        vbuffer.e        = data_ptr + payload_size;
        vbuffer.boundary = data + sizeof(data);
        vbuffer.flag     = 0;
        pocket_vpn_application_output(pocketvpn_context, &vbuffer);
    }
}

void pocketvpn_driver_init(void *driver_obj, uint8_t *ifconfig) {
    struct netif *infer;
    Tun_table *tun = (Tun_table *)driver_obj;

    pocketvpn_memcpy(tun->ifconfig, ifconfig, 12);

    infer = tun_active(tun, 1);

    if (infer == NULL) {

        pocket_vpn_debug_string(10, "m_lwip_init failed!\n");
        pocket_vpn_failed();
    }
}

void pocket_vpn_lwip_init(Tun_table *tun, PocketVpnContext *pocketvpn_context) {

    tun->socket_obj = pocketvpn_context;
    tun->incoming   = lwip_tun_in;
    tun->outcoming  = lwip_tun_out;
}

int pocket_vpn_mbedtls_init(SSL_CONTEXT *ssl_context, PocketVpnContext *pocketvpn_context, const void *ca, uint32_t ca_size, const void *cert, uint32_t cert_size, const void *key, uint32_t key_size) {

    int ret;
    uint32_t seed = get_rand32();

    ssl_context->pocketvpn_context = pocketvpn_context;
    ssl_context->bio_incoming_p    = NULL;
    ssl_context->bio_incoming_size = 0;

    mbedtls_ssl_config_init(&ssl_context->conf);
    mbedtls_x509_crt_init(&ssl_context->cacert);
    mbedtls_x509_crt_init(&ssl_context->cert);
    mbedtls_pk_init(&ssl_context->pkey);
    mbedtls_ssl_init(&ssl_context->ssl);

#if defined POCKETVPN_DEBUG && POCKETVPN_DEBUG > 0 && defined MBEDTLS_DEBUG_C
    mbedtls_debug_set_threshold(3);
#endif

    psa_crypto_init();

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)&seed, sizeof(seed));
    if (ret != 0) {
        pocket_vpn_debug_string(10, "mbedtls_ctr_drbg_seed error!\n");
        return 1;
    }

    ret = mbedtls_ssl_config_defaults(&ssl_context->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        pocket_vpn_debug_string(10, "mbedtls_ssl_config_defaults error!\n");
        return 2;
    }

    mbedtls_ssl_conf_authmode(&ssl_context->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_rng(&ssl_context->conf, mbedtls_ctr_drbg_random, &ctr_drbg);

#if defined POCKETVPN_DEBUG && POCKETVPN_DEBUG > 0
    mbedtls_ssl_conf_dbg(&ssl_context->conf, pocketvpn_mbedtls_debug, NULL);
#endif
    ret = mbedtls_ssl_setup(&ssl_context->ssl, &ssl_context->conf);

    if (ret != 0) {
        pocket_vpn_debug_string(10, "mbedtls_ssl_setup error!");
        return 3;
    }

    ret = mbedtls_x509_crt_parse(&ssl_context->cert, (const unsigned char *)cert, cert_size);
    if (ret != 0) {
        pocket_vpn_debug_string(10, "mbedtls_x509_crt_parse error!");
        return 4;
    }

#if defined MBEDTLS_PK_FN_IS_OLD && MBEDTLS_PK_FN_IS_OLD == 1
    ret = mbedtls_pk_parse_key(&ssl_context->pkey, (const unsigned char *)key, key_size, NULL, 0);
#else
    ret = mbedtls_pk_parse_key(&ssl_context->pkey, (const unsigned char *)key, key_size, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
#endif

    if (ret != 0) {
        pocket_vpn_debug_string(10, "mbedtls_pk_parse_key error!");
        return 5;
    }

    ret = mbedtls_ssl_conf_own_cert(&ssl_context->conf, &ssl_context->cert, &ssl_context->pkey);
    if (ret != 0) {
        pocket_vpn_debug_string(10, "mbedtls_ssl_conf_own_cert error!");
        return 6;
    }

    ret = mbedtls_x509_crt_parse(&ssl_context->cacert, (const unsigned char *)ca, ca_size);
    if (ret != 0) {
        pocket_vpn_debug_string(10, "mbedtls_x509_crt_parse error!");
        return 7;
    }

    mbedtls_ssl_conf_ca_chain(&ssl_context->conf, &ssl_context->cacert, NULL);

    mbedtls_ssl_set_bio(&ssl_context->ssl, ssl_context, pocket_vpn_mbedtls_ssl_send, pocket_vpn_mbedtls_ssl_recv, NULL);

    return 0;
}

int pocketvpn_init() {

    int ret;
    if (pocketvpn_arch_init1() != 0) {
        pocket_vpn_debug_string(10, "pocketvpn_arch_init1 failed!");
        return 1;
    }

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)POCKETVPN_SEED, sizeof(POCKETVPN_SEED));

    if (ret != 0) {
        pocket_vpn_failed();
    }

    if (pocketvpn_arch_init2() != 0) {
        pocket_vpn_debug_string(10, "pocketvpn_arch_init2 failed!");
        return 1;
    }

    return 0;
}

int pocketvpn_new(
    pocketvpn_t *pocketvpn,
    void *socket_obj,
    uint32_t (*socket_read)(void *socket_obj, uint8_t *buffer, uint32_t size),
    void (*socket_write)(void *socket_obj, uint8_t *buffer, uint32_t size),
    uint32_t (*socket_write_ready)(void *socket_obj),
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

) {

    if (mtu == 0) {
        mtu = 1400;
    }

    if (mtu > MTU_MAX) {
        pocket_vpn_debug_string(10, "MTU too large, setting to max");
        mtu = MTU_MAX;
    }

    if (pocket_vpn_mbedtls_init(&pocketvpn->ssl, &pocketvpn->pocketvpn, ca, ca_size, cert, cert_size, key, key_size) != 0) {
        pocket_vpn_failed();
    }

    pocket_vpn_lwip_init(&pocketvpn->tun, &pocketvpn->pocketvpn);

    pocketvpn->pocketvpn.socket_read       = socket_read;
    pocketvpn->pocketvpn.socket_write      = socket_write;
    pocketvpn->pocketvpn.socket_write_ready = socket_write_ready;
    pocketvpn->pocketvpn.tls_read          = pocketvpn_tls_read;
    pocketvpn->pocketvpn.tls_write         = pocketvpn_tls_write;
    pocketvpn->pocketvpn.tls_do_handshark  = pocketvpn_tls_do_handshark;
    pocketvpn->pocketvpn.tls_bio_incoming  = pocketvpn_tls_incoming;
    pocketvpn->pocketvpn.tls_bio_outcoming = pocketvpn_tls_outcoming;
    pocketvpn->pocketvpn.hmac_digest       = pocketvpn_hmac_digest;
    pocketvpn->pocketvpn.encrypto          = pocketvpn_encrypto;
    pocketvpn->pocketvpn.decrypto          = pocketvpn_decrypto;
    pocketvpn->pocketvpn.driver_init       = pocketvpn_driver_init;
    pocketvpn->pocketvpn.driver_incoming   = pocketvpn_driver_incoming;
    pocketvpn->pocketvpn.driver_outcoming  = pocketvpn_driver_outcoming;

    pocketvpn->pocketvpn.socket_obj    = (void *)socket_obj;
    pocketvpn->pocketvpn.tls_obj       = (void *)&pocketvpn->ssl;
    pocketvpn->pocketvpn.tls_bio_obj   = (void *)&pocketvpn->ssl;
    pocketvpn->pocketvpn.driver_obj    = (void *)&pocketvpn->tun;
    pocketvpn->pocketvpn.cipher_mode   = cipher_mode;
    pocketvpn->pocketvpn.auth_mode     = auth_mode;
    pocketvpn->pocketvpn.key_direction = key_direction;
    pocketvpn->pocketvpn.mtu           = mtu;
    pocketvpn->pocketvpn.max_run_time  = max_run_time;

    pocket_vpn_init(&pocketvpn->pocketvpn);

    pocketvpn->vbuffer.buf      = pocketvpn->loop_buf;
    pocketvpn->vbuffer.s        = pocketvpn->loop_buf + 256;
    pocketvpn->vbuffer.c        = pocketvpn->vbuffer.s;
    pocketvpn->vbuffer.e        = pocketvpn->loop_buf + sizeof(pocketvpn->loop_buf);
    pocketvpn->vbuffer.boundary = pocketvpn->vbuffer.e;
    pocketvpn->vbuffer.flag     = 0;

    return 0;
}

void pocketvpn_loop(pocketvpn_t *pocketvpn) {

    pocket_vpn_socket_input(&pocketvpn->pocketvpn, &pocketvpn->vbuffer);
    pocket_vpn_check(&pocketvpn->pocketvpn);
    sys_check_timeouts();

    vpnsock_t *vpnsock_work = vpnsock_working_list;
    
    if (vpnsock_work == NULL){
        return;
    }

    do {
        tcp_loop_service(vpnsock_work, vpnsock_work->pcb);
        vpnsock_work = vpnsock_work->next;
    } while (vpnsock_work != vpnsock_working_list);

}

err_t tcp_dispatch_service(vpnsock_t *vpnsock, struct tcp_pcb *pcb, uint8_t socket_event, struct pbuf *p) {

    struct pbuf *q;
    uint32_t count;
    int res = 0;
    err_t err       = ERR_OK;
    void *outBuffer = NULL;
    uint32_t tmp;
    int tmp2;



    if (socket_event == VPNSOCKET_EVENT_ACCESS || socket_event == VPNSOCKET_EVENT_CONNECT) {

        if (vpnsock->sock_dispatch(vpnsock, socket_event, NULL, NULL, 0, NULL) != 0) {
            res = -2;
            goto except_exit;
        }

        vpnsock->restore_pbuf = NULL;
        vpnsock->pcb          = pcb;
        vpnsock->flag         = 0;
        goto end;
    }

    if (socket_event == VPNSOCKET_EVENT_RECV) {

        if (vpnsock->restore_pbuf == NULL) {
            vpnsock->restore_pbuf = p;
        }

        pbuf_walk(vpnsock->restore_pbuf, q, count) {

            tmp  = pcb != NULL ? tcp_sndbuf(pcb) : 0;
            res  = vpnsock->sock_dispatch(vpnsock, VPNSOCKET_EVENT_RECV, q->payload, &outBuffer, q->len, &tmp);
            tmp2 = res;

            if (res < 0) {
                goto recv_except;
            }

            if (pcb != NULL && outBuffer) {
                err = tcp_write(pcb, outBuffer, tmp, TCP_WRITE_FLAG_COPY);

                if (err == ERR_MEM) {
                    pocket_vpn_debug_string(10, "VPNSOCKET_EVENT_RECV tcp_write too larget !");
                    res = -2;
                    goto recv_except;
                }

                res = vpnsock->sock_dispatch(vpnsock, VPNSOCKET_EVENT_SENT, NULL, NULL, 0, NULL);

                if (res < 0) {
                    goto recv_except;
                }
            }

            if (tmp2 != q->len) {
                count = count - q->len + res;
                q->payload += res;
                q->len -= res;
                err = ERR_WOULDBLOCK;
                break;
            }
        }

        if (err == ERR_OK) {
            pbuf_free(p);
            vpnsock->restore_pbuf = NULL;
        }

        if (pcb) {
            tcp_recved(pcb, count);
            vpnsock->sock_dispatch(vpnsock, VPNSOCKET_EVENT_RECVD, NULL, NULL, 0, NULL);
        }

        else {
            goto recv_except;
        }
    }

    if (socket_event == VPNSOCKET_EVENT_LOOP) {

        tmp = pcb != NULL ? tcp_sndbuf(pcb) : 0;

        res = vpnsock->sock_dispatch(vpnsock, VPNSOCKET_EVENT_LOOP, NULL, &outBuffer, tmp, &tmp);
        pcb = vpnsock->pcb;

        if (res < 0) {
            goto except_exit;
        }

        if (res == 0) {
            goto end;
        }

        err = tcp_write(pcb, outBuffer, (uint32_t)res, TCP_WRITE_FLAG_COPY);

        if (err == ERR_OK && tmp == (uint32_t)res) {
            tcp_output(pcb);
        }

        if (err == ERR_MEM) {
            pocket_vpn_debug_string(10, "VPNSOCKET_EVENT_LOOP tcp_write too larget!");
            res = -2;
            goto except_exit;
        }

        res = vpnsock->sock_dispatch(vpnsock, VPNSOCKET_EVENT_SENT, NULL, NULL, 0, NULL);

        if (res < 0) {
            goto except_exit;
        }
    }

    if (socket_event == VPNSOCKET_EVENT_CLEAN) {
        goto event_clean;
    }

end:
    return err;

recv_except:

    pbuf_free(p);
    if (pcb == NULL) {
        goto event_clean;
    }

except_exit:
    if (res == -1 && tcp_close(vpnsock->pcb) == ERR_OK) {
        goto event_clean;
    }

    tcp_abort(vpnsock->pcb);
    return ERR_ABRT;

event_clean:
    vpnsock->sock_dispatch(vpnsock, VPNSOCKET_EVENT_CLEAN, NULL, NULL, 0, NULL);
    vpnsock->flag |= VPNSOCK_FLAG_STOP;
    return ERR_OK;
}

err_t tcp_loop_service(void *vpnsock_obj, struct tcp_pcb *pcb) {

    vpnsock_t *vpnsock = (vpnsock_t *)vpnsock_obj;

    if (vpnsock->flag & VPNSOCK_FLAG_STOP) {

        if (vpnsock_working_list->next == vpnsock_working_list) {
            vpnsock_working_list = NULL;
        }

        else {
            vpnsock->prev->next = vpnsock->next;
            vpnsock->next->prev = vpnsock->prev;
        }

        pocketvpn_free(vpnsock);
        return ERR_OK;
    }

    return tcp_dispatch_service(vpnsock, pcb, VPNSOCKET_EVENT_LOOP, NULL);
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

    vpnsock->sock_dispatch = (vpnsock_dispatch_fn)arg;

    tcp_arg(newpcb, vpnsock);
    tcp_recv(newpcb, tcp_recv_service_fn);
    tcp_err(newpcb, tcp_err_service_fn);

    if (vpnsock_working_list == NULL) {
        vpnsock_working_list = vpnsock;
        vpnsock->prev        = vpnsock;
        vpnsock->next        = vpnsock;
    }

    else {
        vpnsock_working_list->prev->next = vpnsock;
        vpnsock->prev                    = vpnsock_working_list;
        vpnsock->next                    = vpnsock_working_list;
        vpnsock_working_list->prev       = vpnsock;
    }

    err_t err = tcp_dispatch_service(vpnsock, newpcb, VPNSOCKET_EVENT_ACCESS, NULL);

    return err;
}

err_t tcp_connected_service_fn(void *arg, struct tcp_pcb *tpcb, err_t err){

    vpnsock_t *vpnsock = (vpnsock_t *)pocketvpn_malloc(sizeof(vpnsock_t));
    if (vpnsock == NULL) {
        tcp_abort(tpcb);
        return ERR_ABRT;
    }

    vpnsock->sock_dispatch = (vpnsock_dispatch_fn)arg;

    tcp_arg(tpcb, vpnsock);
    tcp_recv(tpcb, tcp_recv_service_fn);
    tcp_err(tpcb, tcp_err_service_fn);

    if (vpnsock_working_list == NULL) {
        vpnsock_working_list = vpnsock;
        vpnsock->prev        = vpnsock;
        vpnsock->next        = vpnsock;
    }

    else {
        vpnsock_working_list->prev->next = vpnsock;
        vpnsock->prev                    = vpnsock_working_list;
        vpnsock->next                    = vpnsock_working_list;
        vpnsock_working_list->prev       = vpnsock;
    }

    err = tcp_dispatch_service(vpnsock, tpcb, VPNSOCKET_EVENT_CONNECT, NULL);

    return err;
}

struct tcp_pcb* tcp_connect_service(
    uint8_t ip1,
    uint8_t ip2,
    uint8_t ip3,
    uint8_t ip4,
    uint16_t port,
    vpnsock_dispatch_fn vpnsock_dispatch_func) 
{
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
    vpnsock_dispatch_fn vpnsock_dispatch_func

) {

    struct tcp_pcb *tpcb = tcp_new();

    ip_addr_t addr;

    IP_ADDR4(&addr, ip1, ip2, ip3, ip4);

    if (tpcb == NULL) {
        pocket_vpn_debug_string(10, "tcp_new failed!");
        return ERR_MEM;
    }

    err_t err = tcp_bind(tpcb, &addr, port);

    if (err == ERR_USE) {
        pocket_vpn_debug_string(10, "port used!");
        return err;
    }

    if (err != ERR_OK) {
        pocket_vpn_debug_string(10, "tcp_bind failed!");
        return err;
    }

    tpcb = tcp_listen(tpcb);

    tcp_arg(tpcb, (void *)vpnsock_dispatch_func);
    tcp_accept(tpcb, tcp_accept_service_fn);

    return ERR_OK;
}

void pocketvpn_urandom(void *buffer, uint32_t size) {

    int ret;

    ret = mbedtls_ctr_drbg_random(&ctr_drbg, buffer, size);

    if (ret != 0) {
        pocket_vpn_failed();
    }
}

uint32_t get_rand32() {
    uint32_t n;
    pocketvpn_urandom(&n, sizeof(uint32_t));
    return n;
}
