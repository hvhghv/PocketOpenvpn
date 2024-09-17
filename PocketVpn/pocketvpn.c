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

extern int pocketvpn_arch_init();
uint32_t get_rand32();

#if defined POCKETVPN_DEBUG && POCKETVPN_DEBUG > 0
void pocketvpn_mbedtls_debug(void *ctx, int level, const char *file, int line, const char *str) {
    pocketvpn_printf("[MBEDTLS:%s:%04d: %s\n]", file, line, str);
};

#endif

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
    SSL_CONTEXT *tls_context = tls_obj;

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
    SSL_CONTEXT *tls_context = tls_obj;

    int ret = mbedtls_ssl_write(&tls_context->ssl, buffer, size);

    if (ret <= 0) {
        pocket_vpn_debug_string("pocketvpn_tls_write error! code: %d", ret);
        pocket_vpn_failed();
    }
}

uint32_t pocketvpn_tls_do_handshark(void *tls_obj) {
    SSL_CONTEXT *tls_context = tls_obj;
    int ret;

    do {

        ret = mbedtls_ssl_handshake(&tls_context->ssl);

        if (ret != 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret != MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS && ret != MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS) {

            pocket_vpn_debug_string("pocketvpn_tls_do_handshark error! code: %d", ret);
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

    pocket_vpn_debug_string("pocketvpn_tls_do_handshark error! code: %d", ret);
    pocket_vpn_failed();
    return 0;
}

void pocketvpn_tls_incoming(PocketVpnContext *pocketvpn_context_obj, void *tls_bio_obj, uint8_t *buffer, uint32_t size) {
    SSL_CONTEXT *tls_context       = tls_bio_obj;
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
        pocket_vpn_debug_string("pocketvpn_hmac_digest error! code: %d", mode);
        pocket_vpn_failed();
    }

    uint32_t ret_size = mbedtls_md_get_size(info);
    if (ret_size > buffer_size) {
        pocket_vpn_debug_string("pocketvpn_hmac_digest failed! code: %d", ret_size);
        pocket_vpn_failed();
    }

    int ret;

    ret = mbedtls_md_setup(&ctx, info, 1);
    if (ret != 0) {
        pocket_vpn_debug_string("mbedtls_md_setup failed! code: %d", ret);
        pocket_vpn_failed();
    }

    ret = mbedtls_md_hmac_starts(&ctx, key, key_size);
    if (ret != 0) {
        pocket_vpn_debug_string("mbedtls_md_hmac_starts failed! code: %d", ret);
        pocket_vpn_failed();
    }

    ret = mbedtls_md_hmac_update(&ctx, msg, msg_size);
    if (ret != 0) {
        pocket_vpn_debug_string("mbedtls_md_hmac_update failed! code: %d", ret);
        pocket_vpn_failed();
    }

    ret = mbedtls_md_hmac_finish(&ctx, buffer);
    if (ret != 0) {
        pocket_vpn_debug_string("mbedtls_md_hmac_finish failed! code: %d", ret);
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
        pocket_vpn_debug_string("mbedtls_md_info_from_type error! code: %d", mode);
        pocket_vpn_failed();
    }

    int ret;

    ret = mbedtls_cipher_setup(&ctx, info);
    if (ret != 0) {
        pocket_vpn_debug_string("mbedtls_cipher_setup error! code: %d", ret);
        pocket_vpn_failed();
    }

    ret = mbedtls_cipher_setkey(&ctx, key, key_size * 8, en);
    if (ret != 0) {
        pocket_vpn_debug_string("mbedtls_cipher_setkey error! code: %d", ret);
        pocket_vpn_failed();
    }

    ret = mbedtls_cipher_set_iv(&ctx, iv, iv_length);
    if (ret != 0) {
        pocket_vpn_debug_string("mbedtls_cipher_set_iv error! code: %d", ret);
        pocket_vpn_failed();
    }

    mbedtls_cipher_set_padding_mode(&ctx, MBEDTLS_PADDING_NONE);
    if (ret != 0) {
        pocket_vpn_debug_string("mbedtls_cipher_set_padding_mode! code: %d", ret);
        pocket_vpn_failed();
    }

    ret = mbedtls_cipher_update(&ctx, text, text_size, buffer, &t_len);
    if (ret != 0) {
        pocket_vpn_debug_string("mbedtls_cipher_update error! code: %d", ret);
        pocket_vpn_failed();
    }

    output_len += t_len;

    ret = mbedtls_cipher_finish(&ctx, buffer, &t_len);
    if (ret != 0) {
        pocket_vpn_debug_string("mbedtls_cipher_finish error! code: %d, text_size: %d, key_size: %d, iv_size: %d\n", ret, text_size, key_size, iv_length);
        pocket_vpn_failed();
    }
    output_len += t_len;

    if (output_len > buffer_size) {
        pocket_vpn_debug_string("mbedtls_cipher overflow error! code: %d", output_len);
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
    Tun_table *tun_obj = driver_obj;
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
    PocketVpnContext *pocketvpn_context = socket_obj;
    vBuffer vbuffer;
    uint32_t payload_size;

    pocket_vpn_debug_string("lwip_tun_out");
    pocket_vpn_debug_bytes(buffer, size);

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
        pocket_vpn_application_output(socket_obj, &vbuffer);
    }
}

void pocketvpn_driver_init(void *driver_obj, uint8_t *ifconfig) {
    struct netif *infer;
    Tun_table *tun = driver_obj;

    pocketvpn_memcpy(tun->ifconfig, ifconfig, 12);

    infer = tun_active(tun, 1);

    if (infer == NULL) {

        pocket_vpn_debug_string("m_lwip_init failed!\n");
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

#if defined POCKETVPN_DEBUG && POCKETVPN_DEBUG > 0
    mbedtls_debug_set_threshold(3);
#endif

    psa_crypto_init();

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)&seed, sizeof(seed));
    if (ret != 0) {
        pocket_vpn_debug_string("mbedtls_ctr_drbg_seed error!\n");
        return 1;
    }

    ret = mbedtls_ssl_config_defaults(&ssl_context->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        pocket_vpn_debug_string("mbedtls_ssl_config_defaults error!\n");
        return 2;
    }

    mbedtls_ssl_conf_authmode(&ssl_context->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_rng(&ssl_context->conf, mbedtls_ctr_drbg_random, &ctr_drbg);

#if defined POCKETVPN_DEBUG && POCKETVPN_DEBUG > 0
    mbedtls_ssl_conf_dbg(&ssl_context->conf, pocketvpn_mbedtls_debug, NULL);
#endif
    ret = mbedtls_ssl_setup(&ssl_context->ssl, &ssl_context->conf);

    if (ret != 0) {
        pocket_vpn_debug_string("mbedtls_ssl_setup error!");
        return 3;
    }

    ret = mbedtls_x509_crt_parse(&ssl_context->cert, (const unsigned char *)cert, cert_size);
    if (ret != 0) {
        pocket_vpn_debug_string("mbedtls_x509_crt_parse error!");
        return 4;
    }

#if defined MBEDTLS_PK_FN_IS_OLD && MBEDTLS_PK_FN_IS_OLD == 1
    ret = mbedtls_pk_parse_key(&ssl_context->pkey, (const unsigned char *)key, key_size, NULL, 0);
#else
    ret = mbedtls_pk_parse_key(&ssl_context->pkey, (const unsigned char *)key, key_size, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
#endif

    if (ret != 0) {
        pocket_vpn_debug_string("mbedtls_pk_parse_key error!");
        return 5;
    }

    ret = mbedtls_ssl_conf_own_cert(&ssl_context->conf, &ssl_context->cert, &ssl_context->pkey);
    if (ret != 0) {
        pocket_vpn_debug_string("mbedtls_ssl_conf_own_cert error!");
        return 6;
    }

    ret = mbedtls_x509_crt_parse(&ssl_context->cacert, (const unsigned char *)ca, ca_size);
    if (ret != 0) {
        pocket_vpn_debug_string("mbedtls_x509_crt_parse error!");
        return 7;
    }

    mbedtls_ssl_conf_ca_chain(&ssl_context->conf, &ssl_context->cacert, NULL);

    mbedtls_ssl_set_bio(&ssl_context->ssl, ssl_context, pocket_vpn_mbedtls_ssl_send, pocket_vpn_mbedtls_ssl_recv, NULL);

    return 0;
}

int pocketvpn_init(){

    int ret;

    if (pocketvpn_arch_init() != 0){
        pocket_vpn_debug_string("pocketvpn_arch_init failed!");
        return 1;
    }

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)POCKETVPN_SEED, sizeof(POCKETVPN_SEED));

    if (ret != 0) {
        pocket_vpn_failed();
    }

    lwip_init();
    return 0;
}

int pocketvpn_new(
    pocketvpn_t *pocketvpn,
    void *socket_obj,
    uint32_t (*socket_read)(void *socket_obj, uint8_t *buffer, uint32_t size),
    void (*socket_write)(void *socket_obj, uint8_t *buffer, uint32_t size),
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
        pocket_vpn_debug_string("MTU too large, setting to max");
        mtu = MTU_MAX;
    }

    if (pocket_vpn_mbedtls_init(&pocketvpn->ssl, &pocketvpn->pocketvpn, ca, ca_size, cert, cert_size, key, key_size) != 0) {
        pocket_vpn_failed();
    }

    
    pocket_vpn_lwip_init(&pocketvpn->tun, &pocketvpn->pocketvpn);

    pocketvpn->pocketvpn.socket_read       = socket_read;
    pocketvpn->pocketvpn.socket_write      = socket_write;
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

