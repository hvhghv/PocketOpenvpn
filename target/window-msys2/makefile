WORKSPACE = $(shell pwd)
TOP = ../..
BUILDFLODER = build

export WORKSPACE
export TOP
export BUILDFLODER

CFLAGS_MBEDTLS = -D"MBEDTLS_CONFIG_FILE=<mbedtls_config_port.h>" -I"$(WORKSPACE)/mbedtls/" $(CFLAGS)
LDFLAGS_MBEDTLS = -L"$(WORKSPACE)" -l"$(TARGET_PORT_LIB:.lib=)" -lBcrypt -lws2_32 $(LDFLAGS)

export CFLAGS_MBEDTLS
export LDFLAGS_MBEDTLS

LWIP_SRC_C = \
	$(wildcard $(TOP)/lwip/src/core/*.c) \
	$(wildcard $(TOP)/lwip/src/core/ipv4/*.c)

LWIP_CFLAGS = -I. -I"$(TOP)/lwip/src/include"  $(CFLAGS) 

CC = gcc
AR = ar
LD = $(CC)


ifeq ($(DEBUG), 1)
CFLAGS += -g -O0 -DMBEDTLS_SSL_DEBUG_ALL -DMBEDTLS_DEBUG_C -DLWIP_DEBUG -DPOCKETVPN_DEBUG=1
else
CFLAGS += -O3
endif

CFLAGS +=  -Wall -Wdouble-promotion -Wfloat-conversion -Wdiscarded-qualifiers -std=c99 -DNO_INET_H -DEX_INCLUDE=\<port_layer.h\> 

LDFLAGS = 

LIB = -lBcrypt -lws2_32 

LIBPATH = 

SRC_C = \
	$(wildcard $(TOP)/PocketVpn/*.c) \
	main.c \

INC += -I.
INC += -I"$(TOP)"
INC += -I"$(TOP)/lwip/src/include"
INC += -I"$(TOP)/mbedtls/include"

PORT_C = port_layer.c

OUTPUT_FILE = $(BUILDFLODER)/test.exe

TARGET_PORT_LIB = \
	$(BUILDFLODER)/$(PORT_C:.c=.lib) \

TARGET_MBEDTLS_LIB = \
	$(BUILDFLODER)/mbedtls/libmbedcrypto.a \
	$(BUILDFLODER)/mbedtls/libmbedx509.a \
	$(BUILDFLODER)/mbedtls/libmbedtls.a \

TARGET_LWIP_OBJ = \
	$(patsubst %.c, $(BUILDFLODER)/lwip/%.o, $(notdir $(LWIP_SRC_C)))\

TARGET_LWIP_LIB = \
	$(BUILDFLODER)/liblwip.a \

TARGET_POCKETVPN_OBJ = \
	$(patsubst %.c, $(BUILDFLODER)/pocketvpn/%.o, $(notdir $(SRC_C)))\


all: build_folder $(OUTPUT_FILE)

mbedtls_test: build_folder build_mbedtls_lib
	+ cd "$(TOP)/mbedtls" && export CFLAGS=$$CFLAGS_MBEDTLS && export LDFLAGS=$$LDFLAGS_MBEDTLS && make check

clean:
	- cd $(TOP)/mbedtls && make clean
	- rm -rf $(BUILDFLODER)

build_folder:
	- mkdir $(BUILDFLODER)
	- mkdir $(BUILDFLODER)/lwip
	- mkdir $(BUILDFLODER)/pocketvpn
	- mkdir $(BUILDFLODER)/mbedtls

build_mbedtls_lib: $(TARGET_PORT_LIB)
	+ cd "$(TOP)/mbedtls" && export CFLAGS=$$CFLAGS_MBEDTLS && export LDFLAGS=$$LDFLAGS_MBEDTLS && make lib


$(TARGET_PORT_LIB):
	$(CC) $(CFLAGS) $(LIB) -c $(PORT_C) -o "$(BUILDFLODER)/$(PORT_C:.c=.lib)"

$(TARGET_LWIP_LIB): $(TARGET_PORT_LIB) $(TARGET_LWIP_OBJ)
	$(AR) rcs $(TARGET_LWIP_LIB) $(TARGET_LWIP_OBJ)

$(OUTPUT_FILE): $(TARGET_POCKETVPN_OBJ) $(TARGET_MBEDTLS_LIB) $(TARGET_LWIP_LIB) $(TARGET_PORT_LIB)
	$(LD) $(LDFLAGS) $(TARGET_POCKETVPN_OBJ) $(TARGET_MBEDTLS_LIB) $(TARGET_LWIP_LIB) $(TARGET_PORT_LIB) $(LIBPATH) $(LIB) -o "$(OUTPUT_FILE)"

$(BUILDFLODER)/mbedtls/%.a: build_mbedtls_lib
	cp $(TOP)/mbedtls/library/$(notdir $@) $@

vpath %.c $(dir $(LWIP_SRC_C))
$(BUILDFLODER)/lwip/%.o: %.c
	$(CC) $(LWIP_CFLAGS) -c -o $@ $<

vpath %.c $(dir $(SRC_C))
$(BUILDFLODER)/pocketvpn/%.o: %.c
	$(CC) $(CFLAGS) $(POCKETVPN_CFLAGS) $(INC) -c -o $@ $<





