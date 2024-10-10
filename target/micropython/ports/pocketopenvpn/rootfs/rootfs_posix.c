#include "extmod/vfs_posix.h"

mp_obj_t root_disk_init() {
    return MP_OBJ_TYPE_GET_SLOT(&mp_type_vfs_posix, make_new)(&mp_type_vfs_posix, 0, 0, NULL);
}