
#include "mphaltimer.h"
#include "windows.h"
#include "py/runtime.h"
#include "lwip/timeouts.h"
#include "stdio.h"


void CALLBACK onTimeFunc(UINT uTimerID, UINT uMsg, DWORD_PTR dwUser, DWORD_PTR dw1, DWORD_PTR dw2) {
    void (*callback)(int);
    callback = (void *)dwUser;
    callback(0);
}

void mp_set_timer_ms(uint32_t ms, void (*callback)(int)) {

    timeSetEvent(
        ms,
        1,
        &onTimeFunc,
        (DWORD_PTR)callback,
        TIME_PERIODIC);
}

void timer_callback(int num) {

    // sys_check_timeouts();
}

void timer_init() {
    // mp_set_timer_ms(5, timer_callback);
}