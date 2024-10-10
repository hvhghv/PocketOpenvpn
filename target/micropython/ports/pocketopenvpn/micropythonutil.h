#ifndef _MICROPYTHON_UTIL_H
#define _MICROPYTHON_UTIL_H

#include "py/runtime.h"
#include "py/obj.h"

#define MP_UTIL_REGISTER_CALLBACK_FUNC()

#define MP_UTIL_REGISTER_FUNC(FUNC, ARGS_N)                                                 \
    static mp_obj_t MP_##FUNC(size_t n_args, const mp_obj_t *args);                         \
    static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(MP_##FUNC##_obj, ARGS_N, ARGS_N, MP_##FUNC); \
    static mp_obj_t MP_##FUNC(size_t n_args, const mp_obj_t *args)

#define MP_UTIL_REGISTER_OBJ_START(NAME, STRUCT_OBJ)                                                       \
    mp_obj_t NAME##_makenew(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) { \
        return MP_OBJ_FROM_PTR(mp_obj_malloc(TYPE, STRUCT_OBJ));                                           \
    };                                                                                                     \
    const mp_rom_map_elem_t NAME##_local_dict_table[] = {

#define MP_UTIL_ADD_FUNC(NAME, FUNC) {MP_ROM_QSTR(MP_QSTR_##NAME), MP_ROM_PTR(&MP_##FUNC##_obj)},

#define MP_UTIL_REGISTER_OBJ_END(NAME, MAKE_NEW_FUNC)                                                                                              \
    }                                                                                                                                              \
    ;                                                                                                                                              \
    static MP_DEFINE_CONST_DICT(NAME##_local_dict, NAME##_local_dict_table);                                                                       \
    MP_DEFINE_CONST_OBJ_TYPE(mp_##NAME##_type, MP_QSTR_##NAME, MP_TYPE_FLAG_NONE, make_new, MAKE_NEW_FUNC, TABLE, locals_dict, NAME##_local_dict); \
    static mp_obj_base_t NAME##_obj = {&mp_##NAME##_type};

#define MP_UTIL_REGISTER_MODULE_START(NAME)                   \
    const mp_rom_map_elem_t NAME##_module_globals_table[] = { \
        {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_##NAME)},

#define MP_UTIL_ADD_OBJ(NAME) \
    {MP_ROM_QSTR(MP_QSTR_##NAME##), MP_ROM_PTR(&NAME##_obj)},

#define MP_UTIL_REGISTER_MODULE_END(NAME)                                     \
    }                                                                         \
    ;                                                                         \
    MP_DEFINE_CONST_DICT(NAME##_module_globals, NAME##_module_globals_table); \
    const mp_obj_module_t NAME##_module = {                                   \
        .base    = {&mp_type_module},                                         \
        .globals = (mp_obj_dict_t *)&NAME##_module_globals,                   \
    };                                                                        \
    MP_REGISTER_MODULE(MP_QSTR_##NAME, NAME##_module);

#endif