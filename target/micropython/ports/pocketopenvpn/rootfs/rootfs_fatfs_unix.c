#include "extmod/vfs_fat.h"

typedef struct {

    void *null;

} root_disk_obj;

mp_obj_t root_disk_read(mp_obj_t self, mp_obj_t block_num, mp_obj_t buf) {
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(buf, &bufinfo, MP_BUFFER_WRITE);

    FILE *fp = fopen("./disk.img", "rb+");
    fseek(fp, mp_obj_get_int(block_num) * BLOCK_SECTION_SIZE, SEEK_SET);
    mp_uint_t ret = fread(bufinfo.buf, 1, bufinfo.len, fp);
    fclose(fp);

    return mp_obj_new_int(ret);
}

MP_DEFINE_FUN_OBJ_3(root_disk_read_obj, root_disk_read);

mp_obj_t root_disk_write(mp_obj_t self, mp_obj_t block_num, mp_obj_t buf) {
    mp_buffer_info_t bufinfo;

    mp_get_buffer_raise(buf, &bufinfo, MP_BUFFER_READ);
    FILE *fp = fopen("./disk.img", "rb+");
    fseek(fp, mp_obj_get_int(block_num) * BLOCK_SECTION_SIZE, SEEK_SET);
    mp_uint_t ret = fwrite(bufinfo.buf, 1, bufinfo.len, fp);
    fclose(fp);

    return mp_obj_new_int(ret);
}

MP_DEFINE_FUN_OBJ_3(root_disk_write_obj, root_disk_write);

mp_obj_t root_disk_ioctl(mp_obj_t self, mp_obj_t cmd, mp_obj_t arg) {

    switch (mp_obj_get_int(cmd)) {

    case MP_BLOCKDEV_IOCTL_INIT:

        return mp_obj_new_int(0);

    case MP_BLOCKDEV_IOCTL_DEINIT:

        return mp_obj_new_int(0);

    case MP_BLOCKDEV_IOCTL_SYNC:
        return mp_obj_new_int(0);

    case MP_BLOCKDEV_IOCTL_BLOCK_COUNT:
        return mp_obj_new_int(BLOCK_COUNT);

    case MP_BLOCKDEV_IOCTL_BLOCK_SIZE:
        return mp_obj_new_int(BLOCK_SECTION_SIZE);

    default:
        return mp_const_none;
    }
}

MP_DEFINE_FUN_OBJ_3(root_disk_ioctl_obj, root_disk_ioctl);



mp_obj_t root_disk_makenew(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    root_disk_obj *self = mp_obj_malloc(root_disk_obj, type);
    return MP_OBJ_FROM_PTR(self);
}

const mp_rom_map_elem_t machine_root_disk_local_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_readblocks), MP_ROM_PTR(&root_disk_read_obj)},
    {MP_ROM_QSTR(MP_QSTR_writeblocks), MP_ROM_PTR(&root_disk_write_obj)},
    {MP_ROM_QSTR(MP_QSTR_ioctl), MP_ROM_PTR(&root_disk_ioctl_obj)},
};

MP_DEFINE_CONST_DICT(machine_root_disk_local_dict, machine_root_disk_local_dict_table);

MP_DEFINE_CONST_OBJ_TYPE(
    mp_root_disk_type,
    MP_QSTR_RootDisk,
    MP_TYPE_FLAG_NONE,
    make_new,
    root_disk_makenew,
    locals_dict,
    &machine_root_disk_local_dict);

mp_obj_base_t machine_root_disk_obj = {&mp_root_disk_type};

mp_obj_t root_disk_init() {

    fs_user_mount_t *vfs_fs = m_new_obj(fs_user_mount_t);

    unsigned char mkfs_buffer[0x8000]; // must >= 0x8000

    vfs_fs->blockdev.flags          = MP_BLOCKDEV_FLAG_FREE_OBJ | MP_BLOCKDEV_FLAG_HAVE_IOCTL;
    vfs_fs->base.type               = &mp_fat_vfs_type;
    vfs_fs->fatfs.drv               = vfs_fs;
    vfs_fs->blockdev.block_size     = BLOCK_SECTION_SIZE;
    vfs_fs->blockdev.readblocks[0]  = MP_ROM_PTR(&root_disk_read_obj);
    vfs_fs->blockdev.readblocks[1]  = MP_ROM_PTR(&machine_root_disk_obj);
    vfs_fs->blockdev.writeblocks[0] = MP_ROM_PTR(&root_disk_write_obj);
    vfs_fs->blockdev.writeblocks[1] = MP_ROM_PTR(&machine_root_disk_obj);
    vfs_fs->blockdev.u.ioctl[0]     = MP_ROM_PTR(&root_disk_ioctl_obj);
    vfs_fs->blockdev.u.ioctl[1]     = MP_ROM_PTR(&machine_root_disk_obj);

    if (f_mount(&vfs_fs->fatfs) != FR_OK) {

        if (f_mkfs(&vfs_fs->fatfs, FS_EXFAT, 0, mkfs_buffer, sizeof(mkfs_buffer)) != FR_OK) {
            mp_raise_OSError(MP_ENOENT);
        }

        if (f_mount(&vfs_fs->fatfs) != FR_OK) {
            mp_raise_OSError(MP_ENOENT);
        }
    }

    return MP_OBJ_FROM_PTR(vfs_fs);
}

DWORD get_fattime() {
    // 在用于在vfs文件系统中提供时间戳服务
    // 返回一个时间戳

    return 12345678;
}

mp_rom_map_elem_t machine_module_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_machine)},
    {MP_ROM_QSTR(MP_QSTR_RootDisk), MP_ROM_PTR(&machine_root_disk_obj)}};

MP_DEFINE_CONST_DICT(machine_module_globals, machine_module_globals_table);

const mp_obj_module_t machine_module = {
    .base    = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&machine_module_globals,
};

MP_REGISTER_MODULE(MP_QSTR_machine, machine_module);