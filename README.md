# PocketVPN

通过mbedtls库与lwip库实现openvpn协议客户端。

可移植性强

支持RAW,TCP,UDP

仅支持tls-client模式,支持tls1.3

仅支持subnet选项

数据加密通道仅支持AES-128-CBC, AES-256-CBC
支持SHA1, SHA256, SHA512

目前实现了`windows msys2`平台与`esp32`平台

目前封装了`tcp`的api，对于`raw`与`udp`，需参考`lwip`的`raw api`进行开发

window平台进行编译后，会在build目录下生成静态库

- liblwip
- port_layer
- mbedtls/libmbedcrypto.a
- mbedtls/libmbedtls.a
- mbedtls/libmbedx509.a

之后根据需要，链接该静态库，进行开发

### 开发中...不保证稳定性