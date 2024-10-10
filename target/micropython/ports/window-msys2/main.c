#include "py/gc.h"
#include "py/runtime.h"
#include "py/builtin.h"
#include "py/compile.h"
#include "py/mperrno.h"
#include "shared/runtime/pyexec.h"
#include "mphalport.h"
#include "extmod/modnetwork.h"
#include "extmod/vfs.h"
#include "PocketVpn/pocketvpn.h"
#include <fcntl.h>

uint8_t heap[HEAP_SIZE];
static char *stack_top;

extern void mp_hal_stdout_tx_str(const char *str);
extern int readline(vstr_t *line, const char *prompt);
extern bool mp_repl_continue_with_input(const char *input);
void before_mp_init();
void mount_root();
void network_init();
mp_obj_t root_disk_init();
void mount_root_vfs(mp_obj_t device);

#define MP_DEFINE_FUN_OBJ_3(obj_name, fun_name) \
    mp_obj_fun_builtin_fixed_t obj_name =       \
        {{&mp_type_fun_builtin_3}, .fun._3 = fun_name}

#include "stdio.h"

#define BLOCK_SECTION_SIZE 512
#define BLOCK_COUNT 1024 * 1024 * 64 / BLOCK_SECTION_SIZE

#include "mphaltimer.h"

int main() {
    int stack_dummy;
    stack_top = (char *)&stack_dummy;

#ifdef MICROPY_STACK_CHECK

    MP_STATE_THREAD(stack_top)   = stack_top;
    MP_STATE_THREAD(stack_limit) = STACK_SIZE;

#endif
    before_mp_init();
    gc_init(heap, heap + sizeof(heap));
    mp_init();
    mount_root();
    network_init();
    timer_init();

    int ret = pyexec_file_if_exists("boot.py");

    if (ret & PYEXEC_FORCED_EXIT) {
        goto mp_exit;
    }

    if (pyexec_friendly_repl() != 0) {
        goto mp_exit;
    }

mp_exit:
    mp_deinit();
}

void gc_collect(void) {
    // WARNING: This gc_collect implementation doesn't try to get root
    // pointers from CPU registers, and thus may function incorrectly.
    void *dummy;
    gc_collect_start();
    gc_collect_root(&dummy, ((mp_uint_t)stack_top - (mp_uint_t)&dummy) / sizeof(mp_uint_t));
    gc_collect_end();
    gc_dump_info(&mp_plat_print);
}

void mount_root() {
    mp_obj_t device = root_disk_init();
    mount_root_vfs(device);
}

void mount_root_vfs(mp_obj_t device) {

    mp_vfs_mount_t *vfs = m_new_obj(mp_vfs_mount_t);

    vfs->str  = "/";
    vfs->len  = 1;
    vfs->obj  = device;
    vfs->next = NULL;

    for (mp_vfs_mount_t **m = &MP_STATE_PORT(vfs_mount_table);; m = &(*m)->next) {
        if (*m == NULL) {
            *m = vfs;
            break;
        }
    }

    MP_STATE_PORT(vfs_cur) = vfs;
}

// ---------------------------------------------------------------------------------


void before_mp_init() {
    _fmode = O_BINARY; // 这行代码十分十分重要，不然read()返回字节会出错
    pocketvpn_init();
}

void network_init(){
    mod_network_init();
}


#include "ports/pocketopenvpn/rootfs/rootfs_posix.c"

void nlr_jump_fail(void *val) {

    mp_hal_stdout_tx_strn("nlr_jump_fail\n", 14);

    while (1) {
        ;
    }

}

void NORETURN __fatal_error(const char *msg) {

    mp_hal_stdout_tx_strn("__fatal_error\n", 14);

    while (1) {
        ;
    }
}



