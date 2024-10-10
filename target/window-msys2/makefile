WORKSPACE = $(shell pwd)
TOP = ../..
BUILDFLODER = build

export WORKSPACE
export TOP
export BUILDFLODER

CFLAGS_MBEDTLS = -D"MBEDTLS_CONFIG_FILE=<mbedtls_config_port.h>" -I"$(WORKSPACE)/mbedtls/" $(CFLAGS)
LDFLAGS_MBEDTLS = $(LIB) $(LDFLAGS)

export CFLAGS_MBEDTLS
export LDFLAGS_MBEDTLS

LWIP_SRC_C = \
	$(wildcard $(TOP)/lwip/src/core/*.c) \
	$(wildcard $(TOP)/lwip/src/core/ipv4/*.c)

LWIP_CFLAGS = -I. -I"$(TOP)/lwip/src/include" $(CFLAGS) 

POCKETVPN_SRC_C = \
	$(wildcard $(TOP)/PocketVpn/*.c) \

POCKETVPN_CFLAGS =


CC = gcc
AR = ar
LD = $(CC)


ifeq ($(DEBUG), 1)
CFLAGS += -g -O0 -DMBEDTLS_SSL_DEBUG_ALL -DMBEDTLS_DEBUG_C -DLWIP_DEBUG -DPOCKETVPN_DEBUG=1
else
CFLAGS += -O3
endif

CFLAGS += -Wall -Wdouble-promotion -Wfloat-conversion -Wdiscarded-qualifiers -std=c99 -DNO_INET_H -DEX_INCLUDE=\<port_layer.h\> 


LDFLAGS = 

LIB = -lBcrypt -lws2_32 

LIBPATH = 

SRC_C = \
	main.c \

INC += -I.
INC += -I"$(TOP)"
INC += -I"$(TOP)/lwip/src/include"
INC += -I"$(TOP)/mbedtls/include"
INC += -I"$(TOP)/PocketVpn"

PORT_C = port_layer.c

OUTPUT_FILE = $(BUILDFLODER)/test.exe

TARGET_PORT_OBJ = \
	$(BUILDFLODER)/port/$(PORT_C:.c=.o) \

TARGET_MBEDTLS_LIB = \
	$(BUILDFLODER)/mbedtls/libmbedcrypto.a \
	$(BUILDFLODER)/mbedtls/libmbedx509.a \
	$(BUILDFLODER)/mbedtls/libmbedtls.a \


TARGET_LWIP_OBJ = \
	$(patsubst %.c, $(BUILDFLODER)/lwip/%.o, $(notdir $(LWIP_SRC_C)))\

TARGET_POCKETVPN_OBJ = \
	$(patsubst %.c, $(BUILDFLODER)/pocketvpn/%.o, $(notdir $(POCKETVPN_SRC_C)))\

TARGET_POCKETVPN_LIB = \
	$(BUILDFLODER)/libpocketvpn.a

TARGET_POCKETVPN_SO = \
	$(BUILDFLODER)/libpocketvpn.so

TARGET_POCKETVPN_DLL = \
	$(BUILDFLODER)/pocketvpn.dll


TARGET_MAIN_OBJ = \
	$(patsubst %.c, $(BUILDFLODER)/pocketvpn/%.o, $(notdir $(SRC_C)))\

all: build_folder $(OUTPUT_FILE)

mbedtls_test: build_folder build_mbedtls_lib
	+ cd "$(TOP)/mbedtls" && export CFLAGS=$$CFLAGS_MBEDTLS && export LDFLAGS=$$LDFLAGS_MBEDTLS && make check

clean:
	- cd $(TOP)/mbedtls && make clean
	- rm -rf $(BUILDFLODER)

build_folder:
	- mkdir $(BUILDFLODER)
	- mkdir $(BUILDFLODER)/port
	- mkdir $(BUILDFLODER)/lwip
	- mkdir $(BUILDFLODER)/pocketvpn
	- mkdir $(BUILDFLODER)/mbedtls
	- mkdir $(BUILDFLODER)/main

build_mbedtls_lib:
	+ cd "$(TOP)/mbedtls" && export CFLAGS=$$CFLAGS_MBEDTLS && export LDFLAGS=$$LDFLAGS_MBEDTLS && make lib



$(TARGET_PORT_OBJ):
	$(CC) $(CFLAGS) $(INC) $(LIB) -c $(PORT_C) -o "$(BUILDFLODER)/port/$(PORT_C:.c=.o)"

$(BUILDFLODER)/mbedtls/%.a: build_mbedtls_lib
	cp $(TOP)/mbedtls/library/$(notdir $@) $@

$(TARGET_POCKETVPN_LIB): $(TARGET_LWIP_OBJ) $(TARGET_POCKETVPN_OBJ) $(TARGET_PORT_OBJ)
	AR -rcs $(TARGET_POCKETVPN_LIB) $(TARGET_LWIP_OBJ) $(TARGET_POCKETVPN_OBJ) $(TARGET_PORT_OBJ)

# $(TARGET_POCKETVPN_DLL): $(TARGET_POCKETVPN_LIB)
# 	$(LD) -shared $(LDFLAGS) $(TARGET_POCKETVPN_LIB) -o $@
# 	cp $(TARGET_POCKETVPN_SO) $@

$(OUTPUT_FILE): $(TARGET_MBEDTLS_LIB) $(TARGET_POCKETVPN_LIB) $(TARGET_MAIN_OBJ)
	$(LD) $(LDFLAGS) $(TARGET_MAIN_OBJ) $(TARGET_POCKETVPN_LIB) $(TARGET_MBEDTLS_LIB) $(LIBPATH) $(LIB) -o "$(OUTPUT_FILE)"

vpath %.c $(dir $(LWIP_SRC_C))
$(BUILDFLODER)/lwip/%.o: %.c
	$(CC) $(LWIP_CFLAGS) -c -o $@ $<

vpath %.c $(dir $(POCKETVPN_SRC_C))
$(BUILDFLODER)/pocketvpn/%.o: %.c
	$(CC) $(CFLAGS) $(POCKETVPN_CFLAGS) $(INC) -c -o $@ $<

vpath %.c $(dir $(SRC_C))
$(BUILDFLODER)/main/%.o: %.c
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<





