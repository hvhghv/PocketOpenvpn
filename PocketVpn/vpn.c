#include "PocketVpn/vpn.h"

#define KEY_PRE_MASTER_SECRET_SIZE 48
#define KEY_MASTER_SECRET_SIZE 48
#define KEY_LABEL_PRE_MASTER "OpenVPN master secret"
#define KEY_LABEL_MASTER "OpenVPN key expansion"
#define KEY_OUT_LENGTH 256
#define TLS_PACKET_MIN_SIZE 10
#define TLS_PACKET_PUSH_REQUEST "PUSH_REQUEST"
#define TLS_PACKET_PUSH_REPLAY "PUSH_REPLY"
#define TLS_PACKET_PUSH_GATEWAY_OPT "route-gateway"
#define TLS_PACKET_PUSH_IFCONFIG_OPT "ifconfig"
#define CLIENT_OCC_STRING_1 "V4,dev-type tun,link-mtu 1559,tun-mtu 1500,proto TCPv4_CLIENT,"

enum _POCKET_VPN_STATUS {
    VPN_STATUS_INIT,
    VPN_STATUS_SEND_CLIENT_HARD_RESET,
    VPN_STATUS_RECV_SERVER_HARD_RESET,
    VPN_STATUS_DO_HANDSHARK,
    VPN_STATUS_FINISH_TLS_HANDSHARK,
    VPN_STATUS_SEND_KEY_EXCHANGE_DONE,
    VPN_STATUS_RECV_KEY_EXCHANGE,
    VPN_STATUS_SEND_PUSH_REPLAY_DONE,
    VPN_STATUS_RUNNING,
    VPN_STATUS_CLIENT_PREPARE_HARD_RESET,
    VPN_STATUS_CLIENT_DONE_PREPARE_HARD_RESET,
};

enum _VPN_OPCODE {

    P_CONTROL_SOFT_RESET_V1        = 0x03,
    P_CONTROL_V1                   = 0x04,
    P_ACK_V1                       = 0x05,
    P_DATA_V1                      = 0x06,
    P_CONTROL_HARD_RESET_CLIENT_V2 = 0x07,
    P_CONTROL_HARD_RESET_SERVER_V2 = 0x08,
    P_DATA_V2                      = 0x09,

};

#define POCKETVPN_FLAG_ERROR (1 << 0)

typedef struct _VpnRecordPacket {

    uint16_t PacketLength;
    uint8_t Opcode;
    uint8_t KeyId;
    uint32_t PeerId;
    uint64_t SessionId;
    uint8_t PacketIdArrayLength;
    uint32_t *PacketIdArray; // 解包时这个需要ntoll
    uint64_t RemoteSessionId;
    uint32_t MessagePacketId;

} VpnRecordPacket;

typedef struct _VpnTlsMethod2Packet_AdditionalInformation {

    struct _VpnTlsMethod2Packet_AdditionalInformation *prev;
    struct _VpnTlsMethod2Packet_AdditionalInformation *next;
    uint8_t *buffer;
    uint16_t len;

} VpnTlsMethod2Packet_AdditionalInformation;

typedef struct _VpnTlsMethod2Packet {
    uint32_t Zero;
    uint8_t Method;
    uint8_t *pre_master_secret;
    uint8_t *random_1;
    uint8_t *random_2;
    uint8_t *occ;
    uint16_t occ_size;
    uint8_t *username;
    uint16_t username_size;
    uint8_t *password;
    uint16_t password_size;
    VpnTlsMethod2Packet_AdditionalInformation *additionalInformation;

} VpnTlsMethod2Packet;

typedef struct _PFR_CONFIG {
    PocketVpnContext *pocket_vpn_context;
    uint8_t *secret;
    uint32_t secret_size;
    uint8_t *seed;
    uint32_t seed_size;
    uint8_t *buffer;
    uint32_t buffer_size;
    uint32_t buffer_cur;
    uint8_t *last_a_value;
    uint32_t last_a_value_size;
    uint32_t buf_limit_size;
    uint8_t mode;
} PFR_CONFIG;

void pocket_vpn_debug_bytes(void *buffer, uint32_t size) {
#if defined POCKETVPN_DEBUG && POCKETVPN_DEBUG > 0

    uint8_t *p = buffer;
    while (size--) {
        printf("%02x", *p);
        p++;
    }
    printf("\n");
#endif
}

void pocket_vpn_new_session(PocketVpnContext *self) {
    self->RemoteOnePacketID = 0;
    self->MessagePacketId   = 0;

    pocketvpn_urandom(&self->LocalSessionId, sizeof(self->LocalSessionId));
    pocketvpn_urandom(&self->pre_master_secret, KEY_PRE_MASTER_SECRET_SIZE);
    pocketvpn_urandom(&self->client_random1, KEY_RANDOM_SIZE);
    pocketvpn_urandom(&self->client_random2, KEY_RANDOM_SIZE);
    self->start_time = pocketvpn_time();
}

void pocket_vpn_do_handshark(PocketVpnContext *self) {

    if (self->tls_do_handshark(self->tls_obj)) {
        self->status = VPN_STATUS_FINISH_TLS_HANDSHARK;
    }
}

uint16_t pack_vpn_recode_packet(
    VpnRecordPacket *packet,
    uint8_t *buffer,
    uint16_t payload_size) {
    uint8_t *packet_buffer = buffer + 2;

    *packet_buffer = (packet->Opcode << 3) | packet->KeyId;
    packet_buffer++;

    if (packet->Opcode == P_DATA_V1) {
        goto end;
    }

    if (packet->Opcode == P_DATA_V2) {

        *packet_buffer = (packet->PeerId >> 16);
        packet_buffer++;

        *packet_buffer = (packet->PeerId >> 8) & 0xFF;
        packet_buffer++;

        *packet_buffer = packet->PeerId & 0xFF;
        packet_buffer++;

        goto end;
    }

    *(uint64_t *)(packet_buffer) = pocketvpn_htonll(packet->SessionId);
    packet_buffer += 8;

    *packet_buffer = packet->PacketIdArrayLength;
    packet_buffer++;

    for (uint8_t i = 0; i < packet->PacketIdArrayLength; i++) {
        *(uint32_t *)(packet_buffer) = pocketvpn_htonl(packet->PacketIdArray[i]);
        packet_buffer += 4;
    }

    if (packet->PacketIdArrayLength != 0) {
        *(uint64_t *)(packet_buffer) = pocketvpn_htonll(packet->RemoteSessionId);
        packet_buffer += 8;
    }

    if (packet->Opcode != P_ACK_V1) {
        *(uint32_t *)(packet_buffer) = pocketvpn_htonl(packet->MessagePacketId);
        packet_buffer += 4;
    }

end:

    uint16_t size         = packet_buffer - buffer;
    packet->PacketLength  = size - 2 + payload_size;
    *(uint16_t *)(buffer) = pocketvpn_htons(packet->PacketLength);

    return size;
}

void pack_vpn_recode_packent_with_send(PocketVpnContext *self, uint8_t Opcode, uint8_t keyId, vBuffer *buffer) {

    uint8_t recode_buffer[PACK_RECODE_RESERVER];
    VpnRecordPacket packet;
    packet.Opcode              = Opcode;
    packet.KeyId               = keyId;
    packet.PeerId              = 0;
    packet.SessionId           = self->LocalSessionId;
    packet.PacketIdArrayLength = 1;
    packet.PacketIdArray       = &self->RemoteOnePacketID;
    packet.RemoteSessionId     = self->RemoteSessionId;

    if (buffer->s - PACK_RECODE_RESERVER < buffer->buf) {
        pocket_vpn_debug_string("pack recode error!");
        pocket_vpn_failed();
    }

    while (1) {

        uint16_t buffer_size  = buffer->e - buffer->s;
        uint16_t payload_size = buffer_size > MAX_PACKET(self->mtu) ? MAX_PACKET(self->mtu) : buffer_size;

        packet.MessagePacketId = self->MessagePacketId;
        uint16_t size          = pack_vpn_recode_packet(&packet, recode_buffer, payload_size);

        if (Opcode != P_DATA_V1 && Opcode != P_DATA_V2 && Opcode != P_ACK_V1) {
            self->MessagePacketId++;
        }

        buffer->s -= size;
        pocketvpn_memcpy(buffer->s, recode_buffer, size);
        self->socket_write(self->socket_obj, buffer->s, size + payload_size);

        buffer->s += size + payload_size;
        buffer->c = buffer->s;

        if (buffer->e == buffer->s) {
            return;
        }
    }
}

uint16_t unpack_vpn_recode_packet(VpnRecordPacket *packet, uint8_t *buffer) {

    uint8_t *buffer_ptr = buffer;
    uint8_t packetid_length;

    packet->PacketLength = pocketvpn_ntohs(*(uint16_t *)(buffer_ptr));
    buffer_ptr += 2;

    packet->Opcode = *buffer_ptr >> 3;
    packet->KeyId  = *buffer_ptr & 0x07;
    buffer_ptr++;

    if (packet->Opcode == P_DATA_V1) {
        return buffer_ptr - buffer;
    }

    if (packet->Opcode == P_DATA_V2) {
        packet->PeerId = *buffer_ptr << 16 | *(buffer_ptr + 1) << 8 | *(buffer_ptr + 2);
        buffer_ptr += 3;
        return buffer_ptr - buffer;
    }

    packet->SessionId = pocketvpn_ntohll(*(uint64_t *)buffer_ptr);
    buffer_ptr += 8;

    packet->PacketIdArrayLength = *buffer_ptr;
    buffer_ptr++;

    if (packet->PacketIdArrayLength > 0) {

        packet->PacketIdArray = (uint32_t *)buffer_ptr;
        packetid_length       = packet->PacketIdArrayLength;

        while (packetid_length--) {
            *(uint32_t *)buffer_ptr = pocketvpn_ntohl(*(uint32_t *)buffer_ptr);
            buffer_ptr += 4;
        }
    }

    if (packet->PacketIdArrayLength > 0) {
        packet->RemoteSessionId = pocketvpn_ntohll(*(uint64_t *)buffer_ptr);
        buffer_ptr += 8;
    }

    if (packet->Opcode != P_ACK_V1) {
        packet->MessagePacketId = pocketvpn_ntohl(*(uint32_t *)buffer_ptr);
        buffer_ptr += 4;
    }

    return buffer_ptr - buffer;
}

uint16_t pack_vpn_tls_method2_packet(VpnTlsMethod2Packet *packet, uint8_t *buffer) {
    uint8_t *buffer_ptr = buffer;

    *(uint32_t *)buffer_ptr = packet->Zero;
    buffer_ptr += 4;

    *buffer_ptr = packet->Method;
    buffer_ptr++;

    pocketvpn_memcpy(buffer_ptr, packet->pre_master_secret, KEY_PRE_MASTER_SECRET_SIZE);
    buffer_ptr += KEY_PRE_MASTER_SECRET_SIZE;

    pocketvpn_memcpy(buffer_ptr, packet->random_1, KEY_RANDOM_SIZE);
    buffer_ptr += KEY_RANDOM_SIZE;

    pocketvpn_memcpy(buffer_ptr, packet->random_2, KEY_RANDOM_SIZE);
    buffer_ptr += KEY_RANDOM_SIZE;

    *(uint16_t *)buffer_ptr = pocketvpn_ntohs(packet->occ_size);
    buffer_ptr += 2;

    pocketvpn_memcpy(buffer_ptr, packet->occ, packet->occ_size);
    buffer_ptr += packet->occ_size;

    if (packet->username == NULL) {
        return buffer_ptr - buffer;
    }

    *(uint16_t *)buffer_ptr = pocketvpn_ntohs(packet->username_size);
    buffer_ptr += 2;

    pocketvpn_memcpy(buffer_ptr, packet->username, packet->username_size);
    buffer_ptr += packet->username_size;

    *(uint16_t *)buffer_ptr = pocketvpn_ntohs(packet->password_size);
    buffer_ptr += 2;

    pocketvpn_memcpy(buffer_ptr, packet->password, packet->password_size);
    buffer_ptr += packet->password_size;

    while (packet->additionalInformation != NULL) {
        VpnTlsMethod2Packet_AdditionalInformation *additionalInformation = packet->additionalInformation;

        *(uint16_t *)buffer_ptr = pocketvpn_ntohs(additionalInformation->len);
        buffer_ptr += 2;

        pocketvpn_memcpy(buffer_ptr, additionalInformation->buffer, additionalInformation->len);
        buffer_ptr += additionalInformation->len;
    }

    return buffer_ptr - buffer;
}

uint16_t unpack_vpn_tls_method2_packet(VpnTlsMethod2Packet *packet, uint8_t *buffer, uint32_t size) {

    uint8_t *buffer_ptr = buffer;
    uint32_t cur_size;

    packet->Zero = *(uint32_t *)buffer_ptr;
    buffer_ptr += 4;

    packet->Method = *buffer_ptr;
    buffer_ptr++;

    packet->random_1 = buffer_ptr;
    buffer_ptr += KEY_RANDOM_SIZE;

    packet->random_2 = buffer_ptr;
    buffer_ptr += KEY_RANDOM_SIZE;

    packet->occ_size = pocketvpn_ntohs(*(uint16_t *)buffer_ptr);
    buffer_ptr += 2;

    packet->occ = buffer_ptr;
    buffer_ptr += packet->occ_size;

    cur_size = buffer_ptr - buffer;

    if (cur_size > size) {
        pocket_vpn_debug_string("unpack_vpn_tls_method2_packet stack error! (1)");
        pocket_vpn_failed();
    }

    if (cur_size == size) {
        packet->username              = NULL;
        packet->username_size         = 0;
        packet->password              = NULL;
        packet->password_size         = 0;
        packet->additionalInformation = NULL;
        return cur_size;
    }

    packet->username_size = pocketvpn_ntohs(*(uint16_t *)buffer_ptr);
    buffer_ptr += 2;

    packet->username = buffer_ptr;
    buffer_ptr += packet->username_size;

    packet->password_size = pocketvpn_ntohs(*(uint16_t *)buffer_ptr);
    buffer_ptr += 2;

    packet->password = buffer_ptr;
    buffer_ptr += packet->password_size;

    cur_size = buffer_ptr - buffer;

    if (cur_size > size) {
        pocket_vpn_debug_string("unpack_vpn_tls_method2_packet stack error! (2)");
        while (1)
            ;
    }

    // TODO: unpack additionalInformation;

    packet->additionalInformation = NULL;

    return cur_size;
}

void pocket_vpn_send_push_request(PocketVpnContext *self) {

    if (self->status != VPN_STATUS_RECV_KEY_EXCHANGE) {
        return;
    }

    self->tls_write(self, self->tls_obj, (uint8_t *)TLS_PACKET_PUSH_REQUEST, sizeof(TLS_PACKET_PUSH_REQUEST));
}

int pocket_vpn_get_ifconfig_opt(uint8_t *buf, uint8_t *str, uint32_t size) {

    int status = 0;
    uint8_t tmp[8];
    int tmp_pos = 0;
    int count   = 0;
    int pos;

    for (pos = 0; pos < size; pos++) {

        if (status == 0 && '0' <= str[pos] && str[pos] <= '9') {
            status = 1;
        }

        if (status == 1) {

            if (str[pos] == '.') {

                tmp[tmp_pos] = 0;
                *buf         = (uint8_t)pocketvpn_atoi((const char *)tmp);

                buf++;
                count++;
                tmp_pos = 0;
                continue;
            }

            if (str[pos] == ' ' || str[pos] == '\0') {
                break;
            }

            if (str[pos] < '0' || str[pos] > '9') {
                return 0;
            }

            tmp[tmp_pos++] = str[pos];

            if (tmp_pos == 4) {
                return 0;
            }
        }
    }

    if (count != 3) {
        return 0;
    }

    tmp[tmp_pos] = 0;
    *buf         = (uint8_t)pocketvpn_atoi((const char *)tmp);
    return pos;
}

int pocket_vpn_get_push_opt(uint8_t *push_str, uint32_t push_str_size, uint8_t *push_opt, uint8_t push_opt_size, uint32_t *pos, uint32_t *len) {

    uint32_t n = push_str_size - push_opt_size;

    if (push_str_size < push_opt_size + 1) {
        return 1;
    }

    if (push_opt_size == 0) {
        return 1;
    }

    while (n--) {

        if (push_str[n] == ',' && push_str[n + 1] == push_opt[0] && push_str[n + 1 + push_opt_size] == ' ' && pocketvpn_memcmp(push_str + n + 1, push_opt, push_opt_size) == 0) {
            goto get_pos;
        }
    }

    return 1;

get_pos:

    n    = n + push_opt_size + 1;
    *pos = n;

    while (n != push_str_size) {

        if (push_str[n] == ',' || push_str[n] == '\0') {
            break;
        }

        n++;
    }

    *len = n - *pos;

    return 0;
}

void pocket_vpn_cipher_init(PocketVpnContext *self) {

    char *cipher_name;
    char *auth_name;

    if (self->cipher_mode == CIPHER_AES_128_CBC) {

        self->cipher_key_size = 16;
        self->iv_length       = 16;
        self->align_length    = 16;
        cipher_name           = "AES-128-CBC";

    }

    else if (self->cipher_mode == CIPHER_AES_256_CBC) {

        self->cipher_key_size = 32;
        self->iv_length       = 16;
        self->align_length    = 16;
        cipher_name           = "AES-256-CBC";
    }

    else {
        pocket_vpn_debug_string("cipher_mode error!");
        pocket_vpn_failed();
    }

    if (self->auth_mode == HMAC_MODE_SHA1) {
        self->hmac_key_size   = 20;
        self->hmac_msg_length = 20;
        auth_name             = "SHA1";
    }

    else if (self->auth_mode == HMAC_MODE_SHA256) {

        self->hmac_key_size   = 32;
        self->hmac_msg_length = 32;
        auth_name             = "SHA256";

    }

    else {
        pocket_vpn_debug_string("auth_mode error!");
        pocket_vpn_failed();
    }

    uint32_t occ_size = pocketvpn_sprintf((char *)self->client_occ_string, "V4,dev-type tun,link-mtu 1559,tun-mtu 1500,proto TCPv4_CLIENT,cipher %s,auth %s,keysize %d,key-method %d,tls-client", cipher_name, auth_name, self->cipher_key_size * 8, self->key_direction);
    self->client_occ_string[occ_size++] = 0;
    self->client_occ_string_length = (uint16_t)occ_size;

}

void pocket_vpn_init(PocketVpnContext *self) {

    if (self->mtu == 0) {
        self->mtu = 1400;
    }

    if (self->mtu > MTU_MAX) {
        pocket_vpn_debug_string("MTU too large, setting to max");
        self->mtu = MTU_MAX;
    }

    self->status = VPN_STATUS_INIT;
    pocket_vpn_new_session(self);
    pocket_vpn_cipher_init(self);

    self->flag = 0;
}

void pocket_vpn_soft_reset(PocketVpnContext *self) {
    pocket_vpn_new_session(self);
}

void pocket_vpn_send_client_reset(PocketVpnContext *self) {

    uint8_t buffer[MTU_MAX + 32];

    VpnRecordPacket packet;
    packet.Opcode              = P_CONTROL_HARD_RESET_CLIENT_V2;
    packet.KeyId               = 0;
    packet.PeerId              = 0;
    packet.SessionId           = self->LocalSessionId;
    packet.PacketIdArrayLength = 0;
    packet.PacketIdArray       = NULL;
    packet.RemoteSessionId     = 0;
    packet.MessagePacketId     = 0;

    uint16_t size = pack_vpn_recode_packet(&packet, buffer, 0);

    self->MessagePacketId++;
    self->socket_write(self->socket_obj, buffer, size);
}

void pocket_vpn_send_key_exchange(PocketVpnContext *self) {

    uint8_t buffer[PACK_RECODE_RESERVER + KEY_EXCHANGE_STACK_SIZE];

    VpnTlsMethod2Packet packet;

    packet.Zero                  = 0;
    packet.Method                = 2;
    packet.pre_master_secret     = self->pre_master_secret;
    packet.random_1              = self->client_random1;
    packet.random_2              = self->client_random2;
    packet.occ_size              = self->client_occ_string_length;
    packet.occ                   = self->client_occ_string;
    packet.username              = NULL;
    packet.username_size         = 0;
    packet.password              = NULL;
    packet.password_size         = 0;
    packet.additionalInformation = NULL;

    if (KEY_RANDOM_SIZE * 2 + PRE_MASTER_SIZE + self->client_occ_string_length > PACK_RECODE_RESERVER + KEY_EXCHANGE_STACK_SIZE) {
        self->flag |= POCKETVPN_FLAG_ERROR;
        pocket_vpn_debug_string("Not enough space to send key exchange!");
        return;
    }

    uint16_t size = pack_vpn_tls_method2_packet(&packet, buffer);

    pocket_vpn_debug_string("send client occ packet");
    pocket_vpn_debug_bytes(buffer, size);

    self->tls_write(self, self->tls_obj, buffer, size);
}

void pocket_vpn_tls_outcoming(PocketVpnContext *self, uint8_t *buffer, uint32_t size) {
    uint32_t tls_packet_size;
    vBuffer vbuffer;

    if (size < PACK_RECODE_RESERVER) {
        pocket_vpn_debug_string("Not enough space to send tls data!");
        pocket_vpn_failed();
    }

    vbuffer.buf  = buffer;
    vbuffer.s    = buffer + PACK_RECODE_RESERVER;
    vbuffer.c    = vbuffer.s;
    vbuffer.flag = 0;

    for (tls_packet_size = self->tls_bio_outcoming(self->tls_obj, buffer, size);
         tls_packet_size != 0;
         tls_packet_size = self->tls_bio_outcoming(self->tls_obj, buffer, size)) {

        vbuffer.e        = vbuffer.s + tls_packet_size;
        vbuffer.boundary = buffer + sizeof(buffer);

        pack_vpn_recode_packent_with_send(self, P_CONTROL_V1, 0, &vbuffer);
    }
}

void pocket_vpn_prepare_hard_reset(PocketVpnContext *self) {
    // TODO
}

int pocket_vpn_hard_reset_check(PocketVpnContext *self) {

    pocket_vpn_new_session(self);
    pocket_vpn_send_client_reset(self);
    return 1;
}

void pocket_vpn_send_ack(PocketVpnContext *self, uint8_t keyId) {

    uint8_t buffer[PACK_RECODE_RESERVER];
    vBuffer vbuffer;
    vbuffer.buf      = buffer;
    vbuffer.s        = buffer + PACK_RECODE_RESERVER;
    vbuffer.e        = vbuffer.s;
    vbuffer.c        = vbuffer.s;
    vbuffer.boundary = vbuffer.s;
    vbuffer.flag     = 0;
    pack_vpn_recode_packent_with_send(self, P_ACK_V1, keyId, &vbuffer);
}

void pocket_vpn_p_hash(PFR_CONFIG *pfr_config) {

    while (1) {

        pfr_config->last_a_value_size = pfr_config->pocket_vpn_context->hmac_digest(
            pfr_config->secret,
            pfr_config->secret_size,
            pfr_config->last_a_value,
            pfr_config->last_a_value_size,
            pfr_config->last_a_value,
            pfr_config->buf_limit_size,
            pfr_config->mode);

        // TODO: seed without memcpy

        pocketvpn_memcpy(
            pfr_config->last_a_value + pfr_config->last_a_value_size,
            pfr_config->seed,
            pfr_config->seed_size);

        uint32_t res_size = pfr_config->pocket_vpn_context->hmac_digest(
            pfr_config->secret,
            pfr_config->secret_size,
            pfr_config->last_a_value,
            pfr_config->last_a_value_size + pfr_config->seed_size,
            &pfr_config->buffer[pfr_config->buffer_cur],
            pfr_config->buf_limit_size - pfr_config->buffer_cur,
            pfr_config->mode);

        pfr_config->buffer_cur += res_size;

        if (pfr_config->buffer_cur > pfr_config->buffer_size) {
            pfr_config->buffer_cur = 0;
            return;
        }
    }
}

void pocket_vpn_pre_md5_sha1(
    PocketVpnContext *self,
    uint8_t *secret,
    uint32_t secret_size,
    uint8_t *label,
    uint32_t label_size,
    uint8_t *seed,
    uint32_t seed_size,
    uint8_t *buffer,
    uint32_t buffer_size) {

    uint8_t *secret_md5_end   = secret + (secret_size / 2 + secret_size % 2);
    uint8_t *secret_sh1_start = secret + (secret_size / 2);
    uint8_t a_value[PRF_STACK_SIZE];
    uint8_t seed_prf[PRF_STACK_SIZE];
    uint8_t buffer_md5[PRF_STACK_SIZE];
    uint8_t buffer_sha1[PRF_STACK_SIZE];

    uint32_t seed_prf_size = label_size + seed_size;

    if (buffer_size > PRF_STACK_SIZE || seed_prf_size > PRF_STACK_SIZE) {
        pocket_vpn_debug_string("error! stack too small");
    }

    pocketvpn_memcpy(seed_prf, label, label_size);
    pocketvpn_memcpy(seed_prf + label_size, seed, seed_size);
    memcpy(a_value, seed_prf, seed_prf_size);

    PFR_CONFIG pfr_config_md5 = {
        .pocket_vpn_context = self,
        .secret             = secret,
        .secret_size        = secret_md5_end - secret,
        .seed               = seed_prf,
        .seed_size          = seed_prf_size,
        .buffer             = buffer_md5,
        .buffer_size        = buffer_size,
        .buffer_cur         = 0,
        .last_a_value       = a_value,
        .last_a_value_size  = seed_prf_size,
        .buf_limit_size     = PRF_STACK_SIZE,
        .mode               = HMAC_MODE_MD5};

    pocket_vpn_p_hash(&pfr_config_md5);

    pocketvpn_memcpy(seed_prf, label, label_size);
    pocketvpn_memcpy(seed_prf + label_size, seed, seed_size);
    memcpy(a_value, seed_prf, seed_prf_size);

    PFR_CONFIG pfr_config_sha1 = {
        .pocket_vpn_context = self,
        .secret             = secret_sh1_start,
        .secret_size        = secret + secret_size - secret_sh1_start,
        .seed               = seed_prf,
        .seed_size          = seed_prf_size,
        .buffer             = buffer_sha1,
        .buffer_size        = buffer_size,
        .buffer_cur         = 0,
        .last_a_value       = a_value,
        .last_a_value_size  = seed_prf_size,
        .buf_limit_size     = PRF_STACK_SIZE,
        .mode               = HMAC_MODE_SHA1};

    pocket_vpn_p_hash(&pfr_config_sha1);

    while (buffer_size--) {
        buffer[buffer_size] = pfr_config_md5.buffer[buffer_size] ^ pfr_config_sha1.buffer[buffer_size];
    }
}

void pocket_vpn_tls_occ_read(PocketVpnContext *self, uint8_t *buffer, uint32_t size) {

    VpnTlsMethod2Packet packet;

    if (self->status != VPN_STATUS_SEND_KEY_EXCHANGE_DONE) {
        return;
    }

    unpack_vpn_tls_method2_packet(&packet, buffer, size);

    pocket_vpn_debug_string("server occ :");
    pocket_vpn_debug_bytes(packet.occ, packet.occ_size);

    pocket_vpn_debug_string("key generated");

    uint8_t *client_random1 = self->client_random1;
    uint8_t *client_random2 = self->client_random2;
    uint8_t *server_random1 = packet.random_1;
    uint8_t *server_random2 = packet.random_2;

    uint8_t seed_buffer[KEY_GENGRATE_SEED_STACK_SIZE];
    uint8_t *seed_buffer_ptr = seed_buffer;

    uint8_t master_secret[KEY_MASTER_SECRET_SIZE];
    uint8_t generate_key[KEY_OUT_LENGTH];

    pocket_vpn_debug_string("pre_master_secret");
    pocket_vpn_debug_bytes(self->pre_master_secret, PRE_MASTER_SIZE);

    pocket_vpn_debug_string("client_random1");
    pocket_vpn_debug_bytes(self->client_random1, KEY_RANDOM_SIZE);

    pocket_vpn_debug_string("client_random2");
    pocket_vpn_debug_bytes(self->client_random2, KEY_RANDOM_SIZE);

    pocket_vpn_debug_string("server_random1");
    pocket_vpn_debug_bytes(server_random1, KEY_RANDOM_SIZE);

    pocket_vpn_debug_string("server_random2");
    pocket_vpn_debug_bytes(server_random2, KEY_RANDOM_SIZE);

    pocketvpn_memcpy(seed_buffer_ptr, client_random1, KEY_RANDOM_SIZE);
    seed_buffer_ptr += KEY_RANDOM_SIZE;

    pocketvpn_memcpy(seed_buffer_ptr, server_random1, KEY_RANDOM_SIZE);
    seed_buffer_ptr += KEY_RANDOM_SIZE;

    pocket_vpn_pre_md5_sha1(
        self,
        self->pre_master_secret,
        sizeof(self->pre_master_secret),
        (uint8_t *)KEY_LABEL_PRE_MASTER,
        sizeof(KEY_LABEL_PRE_MASTER) - 1,
        seed_buffer,
        seed_buffer_ptr - seed_buffer,
        master_secret,
        KEY_MASTER_SECRET_SIZE);

    seed_buffer_ptr = seed_buffer;

    pocketvpn_memcpy(seed_buffer_ptr, client_random2, KEY_RANDOM_SIZE);
    seed_buffer_ptr += KEY_RANDOM_SIZE;

    pocketvpn_memcpy(seed_buffer_ptr, server_random2, KEY_RANDOM_SIZE);
    seed_buffer_ptr += KEY_RANDOM_SIZE;

    uint64_t t_local_seesion  = pocketvpn_htonll(self->LocalSessionId);
    uint64_t t_remote_seesion = pocketvpn_htonll(self->RemoteSessionId);

    pocketvpn_memcpy(seed_buffer_ptr, &t_local_seesion, sizeof(t_local_seesion));
    seed_buffer_ptr += sizeof(t_local_seesion);

    pocketvpn_memcpy(seed_buffer_ptr, &t_remote_seesion, sizeof(t_remote_seesion));
    seed_buffer_ptr += sizeof(t_remote_seesion);

    pocket_vpn_debug_string("LocalSessionId");
    pocket_vpn_debug_bytes(&t_local_seesion, sizeof(t_local_seesion));

    pocket_vpn_debug_string("RemoteSessionId");
    pocket_vpn_debug_bytes(&t_remote_seesion, sizeof(t_remote_seesion));

    pocket_vpn_pre_md5_sha1(
        self,
        master_secret,
        KEY_MASTER_SECRET_SIZE,
        (uint8_t *)KEY_LABEL_MASTER,
        sizeof(KEY_LABEL_MASTER) - 1,
        seed_buffer,
        seed_buffer_ptr - seed_buffer,
        generate_key,
        KEY_OUT_LENGTH);

    uint8_t *generate_key_ptr = generate_key;

    uint8_t *cipher_1 = generate_key_ptr;
    generate_key_ptr += MAX_CIPHER_KEY_LENGTH;

    uint8_t *hmac_1 = generate_key_ptr;
    generate_key_ptr += MAX_HMAC_KEY_LENGTH;

    uint8_t *cipher_2 = generate_key_ptr;
    generate_key_ptr += MAX_CIPHER_KEY_LENGTH;

    uint8_t *hmac_2 = generate_key_ptr;

    generate_key_ptr += MAX_HMAC_KEY_LENGTH;

    if (self->key_direction == 0) {
        pocketvpn_memcpy(self->Encrypto_Cipher_Key, cipher_1, self->cipher_key_size);
        pocketvpn_memcpy(self->Encrypto_Hmac_Key, hmac_1, self->hmac_key_size);
        pocketvpn_memcpy(self->Decrypto_Cipher_Key, cipher_2, self->cipher_key_size);
        pocketvpn_memcpy(self->Decrypto_Hmac_Key, hmac_2, self->hmac_key_size);
    }

    else if (self->key_direction == 1) {
        pocketvpn_memcpy(self->Encrypto_Cipher_Key, cipher_2, self->cipher_key_size);
        pocketvpn_memcpy(self->Encrypto_Hmac_Key, hmac_2, self->hmac_key_size);
        pocketvpn_memcpy(self->Decrypto_Cipher_Key, cipher_1, self->cipher_key_size);
        pocketvpn_memcpy(self->Decrypto_Hmac_Key, hmac_1, self->hmac_key_size);
    }

    else {
        pocketvpn_memcpy(self->Encrypto_Cipher_Key, cipher_1, self->cipher_key_size);
        pocketvpn_memcpy(self->Encrypto_Hmac_Key, hmac_1, self->hmac_key_size);
        pocketvpn_memcpy(self->Decrypto_Cipher_Key, cipher_1, self->cipher_key_size);
        pocketvpn_memcpy(self->Decrypto_Hmac_Key, hmac_1, self->hmac_key_size);
    }

    self->encrypto_count = 1;
    self->decrypto_count = 1;

    self->status = VPN_STATUS_RECV_KEY_EXCHANGE;

    pocket_vpn_debug_string("master_secret");
    pocket_vpn_debug_bytes(master_secret, KEY_MASTER_SECRET_SIZE);

    pocket_vpn_debug_string("Key Generate");
    pocket_vpn_debug_bytes(generate_key, KEY_OUT_LENGTH);

    pocket_vpn_debug_string("Encrypto_Cipher_Key");
    pocket_vpn_debug_bytes(self->Encrypto_Cipher_Key, MAX_CIPHER_KEY_LENGTH);

    pocket_vpn_debug_string("Encrypto_Hmac_Key");
    pocket_vpn_debug_bytes(self->Encrypto_Hmac_Key, MAX_HMAC_KEY_LENGTH);

    pocket_vpn_debug_string("Decrypto_Cipher_Key");
    pocket_vpn_debug_bytes(self->Decrypto_Cipher_Key, MAX_CIPHER_KEY_LENGTH);

    pocket_vpn_debug_string("Decrypto_Hmac_Key");
    pocket_vpn_debug_bytes(self->Decrypto_Hmac_Key, MAX_HMAC_KEY_LENGTH);

    pocket_vpn_debug_string("Key direction: %d", self->key_direction);
    

    pocketvpn_memset(self->pre_master_secret, 0, PRE_MASTER_SIZE);
    pocketvpn_memset(master_secret, 0, KEY_MASTER_SECRET_SIZE);
    pocketvpn_memset(server_random1, 0, KEY_RANDOM_SIZE);
    pocketvpn_memset(server_random2, 0, KEY_RANDOM_SIZE);
    pocketvpn_memset(self->client_random1, 0, KEY_RANDOM_SIZE);
    pocketvpn_memset(self->client_random2, 0, KEY_RANDOM_SIZE);
}

void pocket_vpn_tls_push_read(PocketVpnContext *self, uint8_t *buffer, uint32_t size) {

    if (self->status != VPN_STATUS_SEND_PUSH_REPLAY_DONE) {
        return;
    }

    uint8_t tmp[12];
    uint8_t *p = tmp;
    uint32_t pos;
    uint32_t len;
    int res;

    if (pocket_vpn_get_push_opt(buffer, size, (uint8_t *)TLS_PACKET_PUSH_IFCONFIG_OPT, sizeof(TLS_PACKET_PUSH_IFCONFIG_OPT) - 1, &pos, &len) != 0) {
        return;
    }

    res = pocket_vpn_get_ifconfig_opt(p, &buffer[pos], len);

    if (res == 0) {
        return;
    }

    pos += res;
    len -= res;
    p += 4;

    res = pocket_vpn_get_ifconfig_opt(p, &buffer[pos], len);

    if (res == 0) {
        return;
    }

    p += 4;

    if (pocket_vpn_get_push_opt(buffer, size, (uint8_t *)TLS_PACKET_PUSH_GATEWAY_OPT, sizeof(TLS_PACKET_PUSH_GATEWAY_OPT) - 1, &pos, &len) != 0) {
        return;
    }

    res = pocket_vpn_get_ifconfig_opt(p, &buffer[pos], len);

    if (res == 0) {
        return;
    }

    self->driver_init(self->driver_obj, tmp);
    self->status = VPN_STATUS_RUNNING;
}

void pocket_vpn_tls_read(PocketVpnContext *self, uint8_t *buffer, uint32_t size) {

    pocket_vpn_debug_string("start tls read");
    uint32_t tls_read_size = self->tls_read(self->tls_obj, buffer, size);

    if (tls_read_size == 0) {
        return;
    }

    pocket_vpn_debug_string("tls packet read");
    pocket_vpn_debug_bytes(buffer, tls_read_size);

    if (tls_read_size < TLS_PACKET_MIN_SIZE) {
        return;
    }

    if (self->status < VPN_STATUS_SEND_KEY_EXCHANGE_DONE) {
        return;
    }

    if (*(uint32_t *)buffer == 0) {
        pocket_vpn_tls_occ_read(self, buffer, tls_read_size);
    }

    if (pocketvpn_memcmp(buffer, TLS_PACKET_PUSH_REPLAY, sizeof(TLS_PACKET_PUSH_REPLAY) - 1) == 0) {
        pocket_vpn_tls_push_read(self, buffer + sizeof(TLS_PACKET_PUSH_REPLAY) - 1, tls_read_size);
    }
}

void pocket_vpn_application_input(PocketVpnContext *self, vBuffer *vbuffer) {

    uint8_t buffer[MTU_MAX];

    if (self->status != VPN_STATUS_RUNNING &&
        self->status != VPN_STATUS_CLIENT_PREPARE_HARD_RESET &&
        self->status != VPN_STATUS_CLIENT_DONE_PREPARE_HARD_RESET)

    {
        return;
    }

    pocket_vpn_debug_string("recv packet");
    pocket_vpn_debug_string("packet en_text");

    pocket_vpn_debug_bytes(vbuffer->s, vbuffer->e - vbuffer->s);

    uint8_t *en_text_ptr = vbuffer->s;
    self->hmac_digest(self->Decrypto_Hmac_Key, self->hmac_key_size, en_text_ptr + self->hmac_msg_length, vbuffer->e - vbuffer->s - self->hmac_msg_length, buffer, sizeof(buffer), self->auth_mode);

    if (pocketvpn_memcmp(en_text_ptr, buffer, self->hmac_msg_length) != 0) {
        pocket_vpn_debug_string("hmac auth error!");

        pocket_vpn_debug_string("packet hmac");
        pocket_vpn_debug_bytes(en_text_ptr, self->hmac_msg_length);

        pocket_vpn_debug_string("count hmac");
        pocket_vpn_debug_bytes(buffer, self->hmac_msg_length);

        pocket_vpn_debug_string("decrypto hmac key");
        pocket_vpn_debug_bytes(self->Decrypto_Hmac_Key, self->hmac_key_size);

        pocket_vpn_debug_string("en_text");
        pocket_vpn_debug_bytes(en_text_ptr + self->hmac_msg_length, vbuffer->e - vbuffer->s - self->hmac_msg_length);

        return;
    }

    en_text_ptr += self->hmac_msg_length;

    uint8_t *iv = en_text_ptr;
    en_text_ptr += self->iv_length;

    uint32_t en_text_size = vbuffer->e - en_text_ptr;

    if (en_text_size % self->align_length != 0) {
        pocket_vpn_debug_string("align error! en_text_size: %d (1)", en_text_size);
        return;
    }

    if (en_text_size > sizeof(buffer)) {
        pocket_vpn_debug_string("decrypto error! stack overflow! en_text_size: %d", en_text_size);
        return;
    }

    uint32_t text_size = self->decrypto(self->Decrypto_Cipher_Key, self->cipher_key_size, iv, self->iv_length, en_text_ptr, en_text_size, buffer, sizeof(buffer), self->cipher_mode);

    if (text_size % self->align_length != 0) {
        pocket_vpn_debug_string("align error! en_text_size: %d (2)", text_size);
        return;
    }

    if (text_size > sizeof(buffer)) {
        pocket_vpn_debug_string("decrypto error! stack overflow! text_size: %d", text_size);
        return;
    }

    uint32_t padding_len = buffer[text_size - 1];

    if (padding_len > self->align_length || text_size < padding_len) {
        pocket_vpn_debug_string("padding length error! padding_len: %d, text_size: %d", padding_len, text_size);
        return;
    }

    text_size -= padding_len;

    uint32_t packet_id = pocketvpn_ntohl(*(uint32_t *)buffer);
    if (packet_id != self->decrypto_count) {
        pocket_vpn_debug_string("packet id error!");
        return;
    }

    self->decrypto_count++;
    text_size -= 4;

    pocket_vpn_debug_string("packet text");
    pocket_vpn_debug_bytes(buffer + 4, text_size);
    self->driver_incoming(self->driver_obj, buffer + 4, text_size);
}

void pocket_vpn_dispatch_packet(PocketVpnContext *self, vBuffer *vbuffer) {

    vBuffer vbuffer_t;
    VpnRecordPacket packet;
    uint16_t recode_packet_size = unpack_vpn_recode_packet(&packet, vbuffer->s);

    if (packet.Opcode == P_ACK_V1) {
        return;
    }

    if (packet.Opcode == P_DATA_V1 || packet.Opcode == P_DATA_V2) {

        vbuffer_t.buf      = vbuffer->s + recode_packet_size;
        vbuffer_t.s        = vbuffer_t.buf;
        vbuffer_t.e        = vbuffer->e;
        vbuffer_t.c        = vbuffer_t.s;
        vbuffer_t.boundary = vbuffer_t.e;
        vbuffer_t.flag     = vbuffer->flag;
        pocket_vpn_application_input(self, &vbuffer_t);
        return;
    }

    if (packet.MessagePacketId != self->RemoteOnePacketID + 1) {
        if (packet.MessagePacketId == 0 && (packet.Opcode == P_CONTROL_HARD_RESET_SERVER_V2 ||
                                            packet.Opcode == P_CONTROL_SOFT_RESET_V1)) {
            ;
        }

        else {
            return;
        }
    }

    self->RemoteOnePacketID = packet.MessagePacketId;
    self->RemoteSessionId   = packet.SessionId;
    pocket_vpn_send_ack(self, packet.KeyId);

    if (packet.Opcode == P_CONTROL_HARD_RESET_SERVER_V2) {
        if (self->status == VPN_STATUS_SEND_CLIENT_HARD_RESET) {
            self->status = VPN_STATUS_RECV_SERVER_HARD_RESET;
        }

        if (self->status == VPN_STATUS_CLIENT_DONE_PREPARE_HARD_RESET) {
            self->status = VPN_STATUS_RECV_SERVER_HARD_RESET;
        }
    }

    else if (packet.Opcode == P_CONTROL_SOFT_RESET_V1) {
        if (packet.Opcode == VPN_STATUS_RUNNING ||
            packet.Opcode == VPN_STATUS_CLIENT_PREPARE_HARD_RESET ||
            packet.Opcode == VPN_STATUS_CLIENT_DONE_PREPARE_HARD_RESET) {

            pocket_vpn_prepare_hard_reset(self);
            self->status = VPN_STATUS_CLIENT_PREPARE_HARD_RESET;
        }
    }

    if (packet.Opcode == P_CONTROL_V1) {

        uint8_t *tls_incoming_buf  = vbuffer->s + recode_packet_size;
        uint32_t tls_incoming_size = vbuffer->e - vbuffer->s - recode_packet_size;

        pocket_vpn_debug_string("tls incoming pack");
        pocket_vpn_debug_bytes(tls_incoming_buf, tls_incoming_size);

        self->tls_bio_incoming(self, self->tls_bio_obj, tls_incoming_buf, tls_incoming_size);

        if (self->status < VPN_STATUS_FINISH_TLS_HANDSHARK) {
            pocket_vpn_do_handshark(self);
        }
    }
}

void pocket_vpn_socket_input(PocketVpnContext *self, vBuffer *vbuffer) {

    vBuffer vbuffer_t;
    uint32_t size = self->socket_read(self->socket_obj, vbuffer->c, vbuffer->boundary - vbuffer->c);
    vbuffer->c += size;

    uint8_t *src_buffer_s = vbuffer->s;
    uint16_t packet_size;

    while (vbuffer->c - vbuffer->s >= 2) {

        packet_size = pocketvpn_ntohs(*(uint16_t *)vbuffer->s);

        if (vbuffer->c - vbuffer->s < packet_size + 2) {
            return;
        }

        vbuffer_t.buf = vbuffer->s;
        vbuffer_t.s = vbuffer->s;
        vbuffer_t.c = vbuffer->c;
        vbuffer_t.e = vbuffer->s + packet_size + 2;
        vbuffer_t.boundary = vbuffer->s + packet_size + 2;
        vbuffer_t.flag = 0;

        pocket_vpn_dispatch_packet(self, &vbuffer_t);

        vbuffer->s += packet_size + 2;

    }

    pocketvpn_memcpy(src_buffer_s, vbuffer->s, vbuffer->c - vbuffer->s);
    vbuffer->c  = src_buffer_s + (vbuffer->c - vbuffer->s);
    vbuffer->s = src_buffer_s;

    return;
}

void pocket_vpn_tls_output(PocketVpnContext *self, vBuffer *buffer) {

    pack_vpn_recode_packent_with_send(self, P_CONTROL_V1, 0, buffer);
}

void pocket_vpn_application_output(PocketVpnContext *self, vBuffer *vbuffer) {

    uint8_t iv[MAX_CIPHER_KEY_LENGTH];
    uint8_t buf[MTU_MAX];

    vBuffer send_buf;
    send_buf.buf      = buf;
    send_buf.s        = buf + PACKET_HEAD_SIZE_RESERVER;
    send_buf.c        = send_buf.s;
    send_buf.e        = send_buf.s + MAX_APPLICATION_PACKET(MTU_MAX);
    send_buf.boundary = buf + sizeof(buf);
    send_buf.flag     = 0;

    if (vbuffer->s - PACKET_HEAD_SIZE_RESERVER < vbuffer->buf) {
        pocket_vpn_debug_string("pocket_vpn_application_output head size too small!");
        pocket_vpn_failed();
    }

    if (vbuffer->e + APPLICATION_PACKET_TAIL_SIZE_RESERVER > vbuffer->boundary) {
        pocket_vpn_debug_string("pocket_vpn_application_output tail size too small!");
        pocket_vpn_failed();
    }

    if (self->status != VPN_STATUS_RUNNING) {
        return;
    }

    uint32_t outcoming_length = self->driver_outcoming(self->driver_obj, vbuffer->s, vbuffer->e - vbuffer->s);

    if (outcoming_length == 0) {
        return;
    }

    if (outcoming_length > MAX_APPLICATION_PACKET(self->mtu)) {
        pocket_vpn_debug_string("pocket_vpn_application_output outcoming size too big!");
        pocket_vpn_failed();
    }

    vbuffer->e = vbuffer->s + outcoming_length;

    vbuffer->s -= 4;
    outcoming_length += 4;
    *(uint32_t *)vbuffer->s = pocketvpn_ntohl(self->encrypto_count);

    uint8_t padding_length = self->align_length - (outcoming_length % self->align_length);
    outcoming_length += padding_length;
    pocketvpn_memset(vbuffer->e, padding_length, padding_length);
    vbuffer->e += padding_length;

    pocketvpn_urandom(iv, self->iv_length);

    outcoming_length = self->encrypto(self->Encrypto_Cipher_Key, self->cipher_key_size, iv, self->iv_length, vbuffer->s, outcoming_length, send_buf.s, send_buf.boundary - send_buf.s, self->cipher_mode);
    self->encrypto_count += 1;

    send_buf.s -= self->iv_length;
    outcoming_length += self->iv_length;
    pocketvpn_memcpy(send_buf.s, iv, self->iv_length);

    send_buf.s -= self->hmac_msg_length;
    self->hmac_digest(self->Encrypto_Hmac_Key, self->hmac_key_size, send_buf.s + self->hmac_msg_length, outcoming_length, send_buf.s, self->hmac_msg_length, self->auth_mode);
    outcoming_length += self->hmac_msg_length;

    vbuffer->c = vbuffer->s;
    send_buf.c = send_buf.s;
    send_buf.e = send_buf.s + outcoming_length;

    if (send_buf.s < send_buf.buf) {
        pocket_vpn_debug_string("send_buf stack overflow!");
        pocket_vpn_failed();
    }

    pocket_vpn_debug_string("encoding appliaction packet");

    pocket_vpn_debug_string("hmac");
    pocket_vpn_debug_bytes(send_buf.s, self->hmac_msg_length);

    pocket_vpn_debug_string("iv");
    pocket_vpn_debug_bytes(iv, self->iv_length);

    pocket_vpn_debug_string("cipher_key");
    pocket_vpn_debug_bytes(self->Encrypto_Cipher_Key, self->cipher_key_size);

    pocket_vpn_debug_string("hmac_key")
    pocket_vpn_debug_bytes(self->Encrypto_Hmac_Key, self->hmac_key_size);

    pocket_vpn_debug_string("text");
    pocket_vpn_debug_bytes(vbuffer->s, vbuffer->e - vbuffer->s);

    pocket_vpn_debug_string("packet-nohmac-noiv");
    pocket_vpn_debug_bytes(send_buf.s + self->hmac_msg_length + self->iv_length, outcoming_length - self->hmac_msg_length - self->iv_length);
    pack_vpn_recode_packent_with_send(self, P_DATA_V1, 0, &send_buf);
}

void pocket_vpn_check(PocketVpnContext *self) {

    if (self->flag & POCKETVPN_FLAG_ERROR) {
        return;
    }

    switch (self->status) {

    case VPN_STATUS_INIT:
        pocket_vpn_send_client_reset(self);
        self->status = VPN_STATUS_SEND_CLIENT_HARD_RESET;
        break;

    case VPN_STATUS_RECV_SERVER_HARD_RESET:
        pocket_vpn_do_handshark(self);
        self->status = VPN_STATUS_DO_HANDSHARK;
        break;

    case VPN_STATUS_DO_HANDSHARK:
        pocket_vpn_do_handshark(self);
        break;

    case VPN_STATUS_FINISH_TLS_HANDSHARK:
        pocket_vpn_send_key_exchange(self);
        self->status = VPN_STATUS_SEND_KEY_EXCHANGE_DONE;
        break;

    case VPN_STATUS_RECV_KEY_EXCHANGE:

        pocket_vpn_send_push_request(self);
        self->status = VPN_STATUS_SEND_PUSH_REPLAY_DONE;

    case VPN_STATUS_RUNNING:

        if (self->max_run_time > 0 && pocketvpn_time() - self->start_time > self->max_run_time) {
            pocket_vpn_prepare_hard_reset(self);
            self->status = VPN_STATUS_CLIENT_PREPARE_HARD_RESET;
        }

        break;

    case VPN_STATUS_CLIENT_PREPARE_HARD_RESET:

        int toContinue = pocket_vpn_hard_reset_check(self);

        if (toContinue) {
            self->status = VPN_STATUS_CLIENT_DONE_PREPARE_HARD_RESET;
        }
        break;
    }
}
