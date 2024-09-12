#ifndef _H_POCKETVPN_H
#define _H_POCKETVPN_H

#include "PocketVpn/define.h"

#ifdef EX_INCLUDE
#include EX_INCLUDE
#endif

extern void pocketvpn_urandom(void *buffer, uint32_t size);

#define MAX_PACKET(n) (n - PACKET_HEAD_SIZE_RESERVER)
#define MAX_APPLICATION_PACKET(n) (n - PACKET_HEAD_SIZE_RESERVER - APPLICATION_PACKET_TAIL_SIZE_RESERVER)

typedef struct _PocketVpnContext {

    uint32_t (*socket_read)(void *socket_obj, uint8_t *buffer, uint32_t size);
    void (*socket_write)(void *socket_obj, uint8_t *buffer, uint32_t size);
    uint32_t (*tls_read)(void *tls_obj, uint8_t *buffer, uint32_t size);
    void (*tls_write)(struct _PocketVpnContext *pocketvpn_context_obj, void *tls_obj, uint8_t *buffer, uint32_t size);
    void (*tls_bio_incoming)(struct _PocketVpnContext *pocketvpn_context_obj, void *tls_bio_obj, uint8_t *buffer, uint32_t size);
    uint32_t (*tls_bio_outcoming)(void *tls_bio_obj, uint8_t *buffer, uint32_t size);
    uint32_t (*tls_do_handshark)(void *tls_obj);
    uint32_t (*hmac_digest)(uint8_t *key, uint32_t key_size, uint8_t *msg, uint32_t msg_size, uint8_t *buffer, uint32_t buffer_size, uint8_t mode);
    uint32_t (*encrypto)(uint8_t *key, uint32_t key_size, uint8_t *iv, uint32_t iv_length, uint8_t *text, uint32_t text_size, uint8_t *buffer, uint32_t buffer_size, uint8_t mode);
    uint32_t (*decrypto)(uint8_t *key, uint32_t key_size, uint8_t *iv, uint32_t iv_length, uint8_t *en_text, uint32_t en_text_size, uint8_t *buffer, uint32_t buffer_size, uint8_t mode);
    void (*driver_init)(void *driver_obj, uint8_t *ifconfig);
    void (*driver_incoming)(void *driver_obj, uint8_t *buffer, uint32_t size);
    uint32_t (*driver_outcoming)(void *driver_obj, uint8_t *buffer, uint32_t size);

    void *socket_obj;
    void *tls_obj;
    void *tls_bio_obj;
    void *driver_obj;

    uint8_t cipher_mode;
    uint8_t auth_mode;
    uint8_t key_direction;

    uint16_t mtu;
    uint32_t max_run_time;

    // -------------------------------------------------------------



    uint8_t status;

    uint8_t client_occ_string[MAX_OCC_STRING];
    uint16_t client_occ_string_length;
    
    uint8_t client_random1[KEY_RANDOM_SIZE];
    uint8_t client_random2[KEY_RANDOM_SIZE];
    uint8_t pre_master_secret[PRE_MASTER_SIZE];
    uint64_t LocalSessionId;
    uint64_t RemoteSessionId;

    uint8_t Encrypto_Cipher_Key[MAX_CIPHER_KEY_LENGTH];
    uint8_t Decrypto_Cipher_Key[MAX_CIPHER_KEY_LENGTH];
    uint8_t Encrypto_Hmac_Key[MAX_HMAC_KEY_LENGTH];
    uint8_t Decrypto_Hmac_Key[MAX_HMAC_KEY_LENGTH];
    uint32_t cipher_key_size;
    uint32_t hmac_key_size;
    uint32_t iv_length;
    uint32_t hmac_msg_length;
    uint32_t align_length;

    uint32_t encrypto_count;
    uint32_t decrypto_count;

    /*
        TODO: 登陆认证

        const char* username;
        const char* password;
        const uint16_t username_length;
        const uint16_t password_length;

    */
    uint32_t MessagePacketId;
    uint32_t RemoteOnePacketID;

    uint32_t start_time;

    uint32_t flag;

} PocketVpnContext;

typedef struct _VBUFFER {
    uint8_t *buf;
    uint8_t *s;
    uint8_t *e;
    uint8_t *c;
    uint8_t *boundary;
    uint32_t flag;
} vBuffer;

enum HMAC_MODE {
    HMAC_MODE_MD5,
    HMAC_MODE_SHA1,
    HMAC_MODE_SHA256,
    HMAC_MODE_SHA512,
};

enum CIPHER_MODE {
    CIPHER_AES_128_CBC,
    CIPHER_AES_256_CBC
};

void pocket_vpn_check(PocketVpnContext *self);
void pocket_vpn_application_output(PocketVpnContext *self, vBuffer *vbuffer);
void pocket_vpn_socket_input(PocketVpnContext *self, vBuffer *vbuffer);
void pocket_vpn_init(PocketVpnContext *self);
void pocket_vpn_tls_output(PocketVpnContext *self, vBuffer *buffer);
void pocket_vpn_tls_outcoming(PocketVpnContext *self, uint8_t *buffer, uint32_t size);
void pocket_vpn_tls_read(PocketVpnContext *self, uint8_t *buffer, uint32_t size);
void pocket_vpn_debug_bytes(void *buffer, uint32_t size);
#endif