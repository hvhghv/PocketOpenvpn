#ifndef _H_MP_HAL_PORT
#define _H_MP_HAL_PORT

#include "py/mpconfig.h"
#include "mpconfigport.h"


mp_uint_t mp_hal_ticks_ms(void);
void mp_hal_set_interrupt_char(char c);

mp_uint_t mp_hal_stdout_tx_strn(const char *str, mp_uint_t len);
int mp_hal_stdin_rx_chr();

void mp_hal_get_random(void *buf, size_t n);
uint32_t get_rand32();

#define MP_HAL_RETRY_SYSCALL(ret, syscall, raise) \
    {                                             \
        for (;;) {                                \
            MP_THREAD_GIL_EXIT();                 \
            ret = syscall;                        \
            MP_THREAD_GIL_ENTER();                \
            if (ret == -1) {                      \
                int err = errno;                  \
                if (err == EINTR) {               \
                    mp_handle_pending(true);      \
                    continue;                     \
                }                                 \
                raise;                            \
            }                                     \
            break;                                \
        }                                         \
    }

#endif
