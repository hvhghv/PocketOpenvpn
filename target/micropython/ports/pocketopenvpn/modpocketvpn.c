#include "PocketVpn/pocketvpn.h"
#include "micropythonutil.h"

typedef struct _mp_pocketvpn_t {
    mp_obj_base_t base;
    pocketvpn_t pocketvpn;
    mp_obj_t socket_read_fn;
    mp_obj_t socket_write_fn;
    mp_obj_t socket_write_ready_fn;
} mp_pocketvpn_t;


MP_UTIL_REGISTER_FUNC(pocketvpn_loop, 1) {
    mp_pocketvpn_t *self = (mp_pocketvpn_t *)MP_OBJ_TO_PTR(args[0]);
    pocketvpn_loop(&self->pocketvpn);
    return mp_const_none;
}

static uint32_t mp_socket_read_fn(void *socket_obj, uint8_t *buffer, uint32_t size) {

    mp_pocketvpn_t *self = (mp_pocketvpn_t *)socket_obj;
    mp_obj_t item        = mp_obj_new_bytearray_by_ref(size, buffer);
    mp_obj_t res         = mp_call_function_1(self->socket_read_fn, item);
    return (uint32_t)mp_obj_int_get_truncated(res);
}

static void mp_socket_write_fn(void *socket_obj, uint8_t *buffer, uint32_t size) {

    mp_pocketvpn_t *self = (mp_pocketvpn_t *)socket_obj;
    mp_obj_t item        = mp_obj_new_bytearray_by_ref(size, buffer);
    mp_call_function_1(self->socket_write_fn, item);

}


static uint32_t mp_socket_write_ready_fn(void *socket_obj) {

    mp_pocketvpn_t *self = (mp_pocketvpn_t *)socket_obj;
    mp_obj_t res = mp_call_function_0(self->socket_write_ready_fn);
    return (uint32_t)mp_obj_int_get_truncated(res);

}

MP_UTIL_REGISTER_FUNC(pocketvpn_new, 11) {
    size_t str_len = 0;
    int cur        = 0;

    mp_pocketvpn_t *self                     = (mp_pocketvpn_t *)m_new_obj(mp_pocketvpn_t);
    pocketvpn_t *pocketvpn                   = &self->pocketvpn;
    void *socket_obj                         = (void *)self;
    socket_read_fn socket_read               = mp_socket_read_fn;
    socket_write_fn socket_write             = mp_socket_write_fn;
    socket_write_ready_fn socket_write_ready = mp_socket_write_ready_fn;
    self->socket_read_fn                     = args[cur++];
    self->socket_write_fn                    = args[cur++];
    self->socket_write_ready_fn              = args[cur++];
    const void *ca                           = (const void *)mp_obj_str_get_data(args[cur++], &str_len);
    uint32_t ca_size                         = (uint32_t)str_len;
    const void *cert                         = (const void *)mp_obj_str_get_data(args[cur++], &str_len);
    uint32_t cert_size                       = (uint32_t)str_len;
    const void *key                          = (const void *)mp_obj_str_get_data(args[cur++], &str_len);
    uint32_t key_size                        = (uint32_t)str_len;
    uint8_t cipher_mode                      = (uint8_t)mp_obj_int_get_truncated(args[cur++]);
    uint8_t auth_mode                        = (uint8_t)mp_obj_int_get_truncated(args[cur++]);
    uint8_t key_direction                    = (uint8_t)mp_obj_int_get_truncated(args[cur++]);
    uint16_t mtu                             = (uint16_t)mp_obj_int_get_truncated(args[cur++]);
    uint32_t max_run_time                    = (uint32_t)mp_obj_int_get_truncated(args[cur++]);

    pocketvpn_new(pocketvpn, socket_obj, socket_read, socket_write, socket_write_ready, ca, ca_size, cert, cert_size, key, key_size, cipher_mode, auth_mode, key_direction, mtu, max_run_time);
    return MP_OBJ_FROM_PTR(self);
}



MP_UTIL_REGISTER_MODULE_START(_pocketvpn)
MP_UTIL_ADD_FUNC(pocketvpn_loop, pocketvpn_loop)
MP_UTIL_ADD_FUNC(pocketvpn_new, pocketvpn_new)
MP_UTIL_REGISTER_MODULE_END(_pocketvpn)
