include ../../py/mkenv.mk

MICROPY_ROM_TEXT_COMPRESSION ?= 1
MICROPY_PY_SSL = 1
MICROPY_SSL_MBEDTLS = 1
MICROPY_PY_LWIP = 1

include $(TOP)/py/py.mk
include $(TOP)/extmod/extmod.mk

POCKETOPENVPNTOP = $(TOP)/../..

INC += -I.
INC += -I$(TOP)
INC += -I$(BUILD)
INC += -I./modules
INC += -I$(TOP)/ports/pocketopenvpn
INC += -I$(POCKETOPENVPNTOP)
INC += -I$(POCKETOPENVPNTOP)/PocketVpn

CFLAGS += $(INC) -Wall -Werror -Wdouble-promotion -Wfloat-conversion -std=c99 $(COPT)
CFLAGS += -g -O0 -DLWIP_DEBUG

ifeq ($(DEBUG), 1)
CFLAGS += -g -O0 -DMBEDTLS_SSL_DEBUG_ALL -DMBEDTLS_DEBUG_C -DLWIP_DEBUG -DPOCKETVPN_DEBUG=1
else
CFLAGS += -O3
endif


LD = $(CC)
LDFLAGS += -Wl,-Map=$@.map,--cref -Wl,--gc-sections
CXXFLAGS += $(filter-out -std=c99,$(CFLAGS))



SRC_C = \
	main.c \
	mphalport.c \
	shared/libc/printf.c \
	custom_readline.c \
	mphaltimer.c  \
	port_layer.c \
	shared/runtime/pyexec.c \
	shared/runtime/stdout_helpers.c \
	shared/timeutils/timeutils.c \
	$(BUILD)/_frozen_mpy.c \
	ports/pocketopenvpn/modpocketvpn.c \
	ports/pocketopenvpn/moddebug.c \
	$(addprefix $(BUILD)/PocketVpn/, $(notdir $(wildcard $(POCKETOPENVPNTOP)/PocketVpn/*.c))) \
	

SRC_QSTR += \
	main.c \
	custom_readline.c \
	shared/runtime/pyexec.c \
	ports/pocketopenvpn/modpocketvpn.c \
	ports/pocketopenvpn/moddebug.c \

LIBS += -lBcrypt -lws2_32 -lWinmm


OBJ += $(PY_O)
OBJ += $(addprefix $(BUILD)/, $(SRC_C:.c=.o))
OBJ += $(addprefix $(BUILD)/, $(SRC_CXX:.cpp=.o))

TARGET = pocketvpn-micropython.exe
BOOT_FILE = boot.py
CMODULE_FILE = cmodules

all: $(BUILD)/$(TARGET) $(BUILD)/$(BOOT_FILE) $(BUILD)/$(CMODULE_FILE)

$(BUILD)/$(TARGET): $(OBJ)
	$(ECHO) "LINK $@"
	$(Q)$(LD) $(LDFLAGS) -o $@ $^ $(LIBS)
	$(Q)$(SIZE) $@

$(BUILD)/$(BOOT_FILE): $(BOOT_FILE)
	$(CP) $(BOOT_FILE) $(BUILD)/

$(BUILD)/$(CMODULE_FILE): $(CMODULE_FILE)
	$(CP) -r $(CMODULE_FILE) $(BUILD)/

$(BUILD)/PocketVpn/%.c: $(POCKETOPENVPNTOP)/PocketVpn/%.c
	$(MKDIR) -p $(dir $@) && $(CP) $< $@

$(BUILD)/_frozen_mpy.c: $(TOP)/tests/frozen/frozentest.mpy $(BUILD)/genhdr/qstrdefs.generated.h
	$(ECHO) "MISC freezing bytecode"
	$(Q)$(TOP)/tools/mpy-tool.py -f -q $(BUILD)/genhdr/qstrdefs.preprocessed.h -mlongint-impl=none $< > $@

include $(TOP)/py/mkrules.mk