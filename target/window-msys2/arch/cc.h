#ifndef _LWIP_ARCH_CC_H
#define _LWIP_ARCH_CC_H

#include <stdint.h>

typedef uint8_t u8_t;
typedef int8_t s8_t;
typedef uint16_t u16_t;
typedef int16_t s16_t;
typedef uint32_t u32_t;
typedef int32_t s32_t;

#define U16_F "hu"
#define S16_F "hd"
#define X16_F "hx"
#define U32_F "u"
#define S32_F "d"
#define X32_F "x"
#define X8_F  "02x"
#define SZT_F "u"

#define LWIP_CHKSUM_ALGORITHM 2
#define BYTE_ORDER LITTLE_ENDIAN

#include <assert.h>
#define LWIP_PLATFORM_DIAG(x)
#define LWIP_PLATFORM_ASSERT(x)  { assert(1); }

#define PACK_STRUCT_FIELD(x) x
#define PACK_STRUCT_STRUCT __attribute__((packed))
#define PACK_STRUCT_BEGIN
#define PACK_STRUCT_END

typedef int sys_prot_t;


#endif
