一个用python编写，可连接openvpn服务端的程序，而无需创建tun设备。提供tcp端口转发功能。也可调用其中的库，实现udp通信功能

### dev分支正采用c语言重构中

### 特点

* 无需创建tun设备
* 只需要python3标准库+libcrypto动态链接库（若能重写项目中的aes加解密方法，就能无需依赖libcrypto动态链接库）

### 不足

* 目前只支持特定的openvpn配置文件
* 不支持openvpn密钥过渡（即无法软重置，只可硬重置）
* 只支持tun模式，tcp模式
* 只支持AES-128-CBC加密模式与SHA1信息摘要模式（连none也不支持）
* 不支持dhcp动态获取虚拟ip地址，需要手动设置
* 不支持ipv6地址与域名
* 速率只有 0.3 m/s

简单来说，能用，但仅仅只是玩具而已

## 使用方法

### TCP端口转发

#### 服务端

1. 将项目放置于执行openvpn程序的服务器内部，如`/root/PocketOpenvpn`

2. 修改`server_config.py`配置文件
    修改`bind_ip`，填入监听地址，
    一般为`0.0.0.0`或openvpn服务器
    分配的虚拟ip地址，如`10.8.1.1`

    修改`bind_port`，填入监听端口，例如`6672`

3. 启动
   `python3 server.py`

#### 客户端

1. 下载该项目

2. 修改`client_config.py`配置文件
   
   修改`forward_default_Table`，填入转发配置，如
   `forward_default_Table = (('127.0.0.1',8099,8768),)`

   修改`forward_server_ip`，填入
   服务端中由openvpn服务器分配的
   虚拟ipv4地址，如`10.8.1.1`

   修改`forward_server_port`，填入服务端监听端口
   如`6672`

   修改`virtual_local_ip`，静态设置虚拟ip地址，如
   `10.8.1.2`

   修改`dstAddress`，填入openvpn服务器地址

   修改`dstPort`，填入openvpn服务器端口

   修改`ca_file_path`,`crt_file_path`,`privateKey_file_path`
   填入ca证书，客户端证书，私钥文件路径

   修改`library_path`，填入libcrypto动态链接库路径

   修改`occ_string`,填入occ信息

   修改`key_direction`，根据openvpn的配置文件填入。
   若openvpn的配置文件没有配置此选项，则填`0`即可

3. 启动
   `python3 client.py`

根据上述例子，服务端`10.8.1.1:8768`的tcp流量会转发到客户端`127.0.0.1:8099`上


### UDP通信支持

参考`Test/test2.py`

调用`from PocketVpn import VpnSocket`

通过recv_callback_add方法添加钩子来监听数据包
当接收数据包时，会调用其回调函数

通过send_udp方法发送给udp数据包

Loop函数为主循环函数,需要持续调用使其运作

### 调试日志

若需要调试日志，请修改`client_config.py`与`server_config.py`的`logging_level`为`logging.DEBUG`


### 对于libcrypto动态链接库的补充

对于windows x64位环境，可尝试本项目自带的动态链接库

对于linux x64环境，可在/usr/lib中查找当前平台使用的libcrypto动态链接库,也可尝试本项目自带的动态链接库
其他环境，需要自行下载解决

该项目自带的libcrypto.so.1.0.0为ubuntu20.02 x64 wsl2平台下的libcrypto动态链接库

该项目自带的libcrypto-3-x64.dll为windows x64平台下的libcrypto动态链接库

若能重写项目中`simpleVpn/simpleVpn/VpnCrypto.py`aes加解密方法，可无需依赖libcrypto动态链接库

### 对于occ_string的补充

客户端occ信息，可以通过官方的openvpn程序来查看。官方openvpn客户端加载时，会生成需匹配的occ信息（如图）
可先用openvpn客户端配置文件来对接其服务端，查看其所需匹配的occ信息
再填入此配置文件中

注：是需要`Local Options String`而非`Remote Options String`

![1710840228902](image/Readme/1710840228902.jpg)

### 本项目采用的openvpn服务器配置文件如下

基本上只支持这配置文件了，只能小修小补，不能大改

```
port 1194
proto tcp
dev tun
topology subnet
server 10.8.1.0 255.255.255.0
client-to-client
cipher AES-128-CBC
data-ciphers AES-128-CBC
auth SHA1
user nobody
group nobody
persist-key
persist-tun
verb 3
reneg-sec 9600

<ca>
-----BEGIN CERTIFICATE-----
MIIDrDCCApSgAwIBAgIIPuqcv8afrcIwDQYJKoZIhvcNAQELBQAwWzELMAkGA1UE
BhMCQ04xCjAIBgNVBAgTATExCjAIBgNVBAcTATExCjAIBgNVBAoTATExCjAIBgNV
BAsTATExCjAIBgNVBAMTATExEDAOBgkqhkiG9w0BCQEWATEwIBcNMjQwMTE4MDQx
NjAwWhgPMjEyNDAxMTgwNDE2MDBaMFsxCzAJBgNVBAYTAkNOMQowCAYDVQQIEwEx
MQowCAYDVQQHEwExMQowCAYDVQQKEwExMQowCAYDVQQLEwExMQowCAYDVQQDEwEx
MRAwDgYJKoZIhvcNAQkBFgExMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAiNZtLunAfLK9dShI9D/GjRwTGRChP6ZRSokos65BVHVfvYONaaIjRRz3iAAt
fMIR/ZzpJZzZLHtVxsnqOZn6u7D8ZInCtXSoab/3au5j+3pXYxjiWbzkH6tHznW5
nXBfKuE3cpKkfmjUI3MeX2IRgQc+I0AUkIOofntPHkehqqw0Fc4RkiMEk3cv7Xt6
ZsD8uuqoqUz0e6h2AS30H+tDk9Nsu3NHyTpscfvHjS4Nimz37Pc6+IoOoYkZlYmE
/2jja6R3PdpDwgjsbkxcvaaivgGPPQLkV1YxnrYFpnmKvVBHbEfOMVXmaaqMKtbe
3h/Ql534kAUU6ITQL5/7DiZvHQIDAQABo3IwcDAPBgNVHRMBAf8EBTADAQH/MB0G
A1UdDgQWBBRng909LeB6CXGLCV+9Lt3/JxOjKTALBgNVHQ8EBAMCAQYwEQYJYIZI
AYb4QgEBBAQDAgAHMB4GCWCGSAGG+EIBDQQRFg94Y2EgY2VydGlmaWNhdGUwDQYJ
KoZIhvcNAQELBQADggEBAFXgIKtT5bqtoTTzZW9yzFBiA4nsk3uAKLq4jUWNY22U
YdR1S8QHVAsDXaaFf7KZHd5yfvcGo63pM6YL7skUsByLc7Gt2EiptvTevmtZ2KvD
EatYovXWB6Sjsi+jWBbIplyr8WmqbUTGeFLs4c72AVlhN230sBR//4Wglae9fFH6
M7OSPqVP/9zlJKJ2dmioUcmgcOkDliaoOwL6jqmjGgFs+Ci+Sjr60mDYQ8KiFc+L
38tbxqecmncDIUk8ODROrjeiPbGyUuWd+UMDtUD7qivlKfYvX1VhlfvLgDTE4zOt
ZdYeBQ2BqRzk4gP0ovs947gCkn8tj34WCgz+LAfjatg=
-----END CERTIFICATE-----
</ca>

<cert>
-----BEGIN CERTIFICATE-----
MIIDzjCCAragAwIBAgIIPdA7ac1C4OMwDQYJKoZIhvcNAQELBQAwWzELMAkGA1UE
BhMCQ04xCjAIBgNVBAgTATExCjAIBgNVBAcTATExCjAIBgNVBAoTATExCjAIBgNV
BAsTATExCjAIBgNVBAMTATExEDAOBgkqhkiG9w0BCQEWATEwIBcNMjQwMTE4MDQx
ODAwWhgPMjEyMzAxMTgwNDE4MDBaMFsxCzAJBgNVBAYTAkNOMQowCAYDVQQIEwEy
MQowCAYDVQQHEwEyMQowCAYDVQQKEwEyMQowCAYDVQQLEwEyMQowCAYDVQQDEwEy
MRAwDgYJKoZIhvcNAQkBFgEyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAzZSFLOIOtpUL7FVMQCX4ATSI+/PkYH3P8Z5zwrzu5CDTSAAXX2LvgZZ7AGRJ
V+tTG8yKduJII4NTQ3rz8eEzJ1ggWaqJ5Zbxln411zS0qOtWzZ45BoSk7U5LMZxw
R9bLfcWA6cZnvpU9i8zHOlnRIQFCu3ssbMRySV+EltdZ79fg1YS24/GN8lD8qljB
QBxySYAK83iQjY9xUnWqKdJHHv0ksR3Jk6afRgPPU/wtDBe2e/TeSAAxpp89BpHy
bKAJWne6tWnTlOxxCr39+tx6/X0/4C8S+gRqltt8DoOnPzwyG0DCn/IYt8+HyeeK
QWDNfkvQ3E4fpU4H7exlM+DjtwIDAQABo4GTMIGQMAwGA1UdEwEB/wQCMAAwHQYD
VR0OBBYEFNTPwmWHejXu7ZBoO6/jwWBJtscLMAsGA1UdDwQEAwID6DATBgNVHSUE
DDAKBggrBgEFBQcDATAMBgNVHREEBTADggEyMBEGCWCGSAGG+EIBAQQEAwIGQDAe
BglghkgBhvhCAQ0EERYPeGNhIGNlcnRpZmljYXRlMA0GCSqGSIb3DQEBCwUAA4IB
AQCCVUdpZNT45TwOB9Qfsb0d0LLXJB3ZSUC+6vcN+yeplzEqyha6dPtGEJvAMEXz
O9Ug4RwvmUzh+FoDM1g1+tveRy8yCa2Ryw46pMJZD+GJ6JOlRSsmETktu33PFwdq
En0RijqAAyMr0kty0SgGPfbvhOOQUhuSesgJ5GE5OEczu2f5uwAIS540Jt6Jlykk
G3o0L5m8/V/QSGfIRAijJRys03tDgfaoXYbUMR/xqlv+oCxO+oEh5+IlIZmd4e98
6sJy1hvj2UfTXJwgFxI85lIW7WcaRV8ylXxk1NXd2/arzJTk3eACzUqSC+xUuHar
/nfmrFbwuuhD3SY+SNjr6rDh
-----END CERTIFICATE-----
</cert>

<key>
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAzZSFLOIOtpUL7FVMQCX4ATSI+/PkYH3P8Z5zwrzu5CDTSAAX
X2LvgZZ7AGRJV+tTG8yKduJII4NTQ3rz8eEzJ1ggWaqJ5Zbxln411zS0qOtWzZ45
BoSk7U5LMZxwR9bLfcWA6cZnvpU9i8zHOlnRIQFCu3ssbMRySV+EltdZ79fg1YS2
4/GN8lD8qljBQBxySYAK83iQjY9xUnWqKdJHHv0ksR3Jk6afRgPPU/wtDBe2e/Te
SAAxpp89BpHybKAJWne6tWnTlOxxCr39+tx6/X0/4C8S+gRqltt8DoOnPzwyG0DC
n/IYt8+HyeeKQWDNfkvQ3E4fpU4H7exlM+DjtwIDAQABAoIBABMDmRuxHtZBS9SE
gSRvvpPx9XeEM8u+5zQ8SQ2qZtf/tzryEzdV0bwlHGRJYkU49TtdfDMJs81hEJrt
rNFi2FXbv0Y70TxEbTzTmIw6ijkTZzhmWXTiYNS4CJlilDn4wmJ0GXvFx4OnjwU2
n/ikJQUN9kub1VyMANwLcxp2eZGGte3hgPIkYkTGOwEUOrpZc+TUwd7kEjtMznbx
Ter7uASOgekI+qRd60GNL2+iYpUOWeEay3+95Mpml5MfWRssC5u2lHSE1pXtT75w
VgKAd6xH6DpvnsQPWL9VEokOpYIHLol7egnKmpaEBMZJQMoOd7ingB8e/7+SNgH+
+/bdHiECgYEA9wKIxvlKExSo/hBkqw2mMiwrnJbN/TGBUxmQCcuX01sZverU33nf
060/6xExVevd85snWs0YsjUG5xMnWJqewURCRhB8xfc1j1vhOAuJ2PCnSJRUhcrJ
iWVHE28xmoSfmuxgwxzLz8fPb0wo2UVX/k009ZZP4FDweJZ6lAlZldcCgYEA1Q/4
944Fic9WydE03D/CB1ckNnWWMVG/nYvqzlPP2qf4f6YAdHcMGIF0Yxi2xShr+txh
yr9/GDZC9hI1RWTopcAWEZ98jyLGtkb8LRkCK5hUn+vXdby1WDjUlqbUl3A64UZ7
q8BchKaoLH9DnnOxZRMCbMN8V4FjbVWrzkInpSECgYAKrm9fu1P6s0ADjI3t3686
KDLSmKrbshJXl5lk8wrjtuLMFaWS7GBDdRB4h8vMXWDBsgnnoUraGfTsdSWUbUtE
LEF5aikbHm+QfXalx8n0OaPiPZfSGUzRxjFmo75PYkDMoEAm783YdFmCBJcXnioJ
8yjBHfjiSF29uTQfxq+7DQKBgQCANsJtxotSqPDjNgAHYl7Sp//kvdIKD9Wtaxt7
2jfErzv9JNo1O8aNoKl3UNH7xx1jsucuaRqEaXLWPZLNFbJivDsLk9wTDqxh2Em8
ocYKkfqq2fOoqEzAsEJN/ksEbscf9ZhKfNGwCdI+JL9+RMTFvDDDXsgeqIA6tUlU
L79HwQKBgQC0dvGeA8fRqPh3R4UvrJC0deLsSUVJdk4FzZI/jopW0oJJ7xZHwEap
NabOOFOUAAVwrnK4+CERfuIFstIczL6vRC2VMlOTISEhDro5Q6qdCRL4RxGScDr3
Ntxa0hLheQ2EyELdW+bYrxkngbDOmASJPv0lVuZCQowZI3+r3Br1Kw==
-----END RSA PRIVATE KEY-----
</key>

<dh>
-----BEGIN DH PARAMETERS-----
MIIBDAKCAQEA2vK/8rL4lJujNy8OT5jz14jehGMD2dhhAUrMBesF18OqsbQAi5vk
PF5xVPph5Brcg8c/LYZLNY7T5cdWvfxK5YjjCsscG+m0Hx4wijSTMCJ/1nfzQ2qi
VmLrr72u2KNtftOlaCYvJ7F85tPVRQl7bC0hWogYx5yVe/gzkMsk6K4Rm/yh085Z
ivci5mupGFmwmKObdDmCZQSPB7QIfMiSDPIUjn5zU3poSElcNZcHIJqKkMsLs0yv
Jsa4SF7lytMWilxOYchPDQjmh7tnOA/N1/mf2Btmr0V4Qv+/Tf9WCLeHl6QCFxgF
hGP3YjKbSnnJWnjKxW48leiUMEPFdP1yFwIBAgICAOE=
-----END DH PARAMETERS-----
</dh>
```
