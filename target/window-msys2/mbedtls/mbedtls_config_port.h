
#ifndef MBEDTLS_MBEDTLS_CONFIG_H
#define MBEDTLS_MBEDTLS_CONFIG_H

#define MBEDTLS_CIPHER_MODE_CTR
#define MBEDTLS_AES_ROM_TABLES
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_SHA256_SMALLER
#define MBEDTLS_SSL_PROTO_TLS1
#define MBEDTLS_SSL_PROTO_TLS1_1
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_PROTO_TLS1_3
#define MBEDTLS_SSL_SERVER_NAME_INDICATION

// 这里调小会分片导致无法通过测试，但即使无法通过测试也可能可以正常工作
// #define MBEDTLS_SSL_MAX_CONTENT_LEN (16384)
// #define MBEDTLS_SSL_IN_CONTENT_LEN (MBEDTLS_SSL_MAX_CONTENT_LEN)
// #define MBEDTLS_SSL_OUT_CONTENT_LEN (4096)  

#define MBEDTLS_BASE64_C
#define MBEDTLS_AES_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_ERROR_C
#define MBEDTLS_GCM_C
#define MBEDTLS_MD_C
#define MBEDTLS_MD5_C
#define MBEDTLS_OID_C
#define MBEDTLS_PKCS5_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_RSA_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA224_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA384_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_SSL_CLI_C // 启动ssl客户端
#define MBEDTLS_SSL_SRV_C // 启动ssl服务端
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_PEM_PARSE_C // pem证书格式，常用
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_USE_C


#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_TEST_SW_INET_PTON
#define MBEDTLS_PLATFORM_C

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
#define MBEDTLS_SSL_KEEP_PEER_CERTIFICATE
#define MBEDTLS_PSA_CRYPTO_C
#define MBEDTLS_HKDF_C
#define MBEDTLS_SSL_SESSION_TICKETS
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
#define MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE // 开启兼容模式，重要，不然一些程序直接无法握手

#if defined(MBEDTLS_HKDF_C)
#define MBEDTLS_PSA_BUILTIN_ALG_HMAC 1
#define PSA_WANT_ALG_HMAC 1
#define MBEDTLS_PSA_BUILTIN_ALG_HKDF 1
#define PSA_WANT_ALG_HKDF 1
#define MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT 1
#define PSA_WANT_ALG_HKDF_EXTRACT 1
#define MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXPAND 1
#define PSA_WANT_ALG_HKDF_EXPAND 1
#endif /* MBEDTLS_HKDF_C */

#if defined(MBEDTLS_SHA256_C)
#define MBEDTLS_PSA_BUILTIN_ALG_SHA_256 1
#define PSA_WANT_ALG_SHA_256 1
#endif

// tls密码套件
#define MBEDTLS_ECP_DP_SECP192R1_ENABLED
#define MBEDTLS_ECP_DP_SECP224R1_ENABLED
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_DP_SECP521R1_ENABLED
#define MBEDTLS_ECP_DP_SECP192K1_ENABLED
#define MBEDTLS_ECP_DP_SECP224K1_ENABLED
#define MBEDTLS_ECP_DP_SECP256K1_ENABLED
#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_CAN_ECDH
#define MBEDTLS_PK_CAN_ECDSA_SIGN

// 一般证书签名算法
#define MBEDTLS_X509_RSASSA_PSS_SUPPORT
#define MBEDTLS_PKCS1_V21

#endif

// 移植层
#define MBEDTLS_TIMING_C
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_HAVE_TIME_DATE
// #define MBEDTLS_NET_C

#define MBEDTLS_ENTROPY_HARDWARE_ALT

#endif