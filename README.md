# PocketVPN

通过mbedtls库与lwip库实现openvpn协议客户端。

支持RAW,TCP,UDP

仅支持tls-client模式,支持tls1.3

仅支持subnet选项

数据加密通道仅支持AES-128-CBC, AES-256-CBC

编译后，会在build目录下生成静态库
    * liblwip
    * port_layer
    * mbedtls/libmbedcrypto.a
    * mbedtls/libmbedtls.a
    * mbedtls/libmbedx509.a

### 开发中...仍未进行测试