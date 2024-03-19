from PocketVpn.Vpn.VpnCrypto import VpnCrypto

# ___________________以下配置为重要参数，需按实际填写_____________________________

# 初始化化转发表
# (本地地址,本地端口,远程端口),
# 如:
# forward_default_Table = （
#   ('127.0.0.1','1234','2345'),
#   ('192.168.1.1','5678','6789'),
# )
# 服务端2345端口的数据转发到本地'127.0.0.1'的1234端口
# 服务端6789端口的数据转发到本地'192.168.1.1'的5678端口
# 注意，逗号不建议省略（参考python的元组机制）

forward_default_Table = (
    ('192.168.1.1', 80, 8767),
    ('127.0.0.1',8099,8768),
)

forward_server_ip = '10.8.1.1'  # 服务端虚拟ipv4地址

forward_server_port = 6672  # 服务端服务端口

virtual_local_ip = '10.8.1.2'  # 本地虚拟ip地址

forward_local_port = 4721  # 本地服务端口，随便绑定一个未占用的就行

dstAddress = "127.0.0.1"  # openvpn服务器地址

dstPort = 1194  # openvpn服务器端口

ca_file_path = "Cert/TestCa.crt"  # ca证书路径

crt_file_path = "Cert/TestCert.crt"  # 客户端证书路径

privateKey_file_path = "Cert/TestKey.pem"  # 客户端私钥路径

cipher = VpnCrypto.CBC_128  # openvpn加密模式

auth = VpnCrypto.HMAC_SHA1  # openvpn信息摘要模式

# libcrypto加密库路径
# 对于windows 64位环境，可尝试本项目自带的动态链接库
# 对于linux环境，可在/usr/lib中查找当前平台使用的libcrypto动态链接库,也可尝试本项目自带的动态链接库
# 其他环境，需要自行下载解决
# 该项目自带的libcrypto.so.1.0.0为ubuntu20.02 x64 wsl2平台下的libcrypto动态链接库
# 该项目自带的libcrypto-3-x64.dll为windows x64平台下的libcrypto动态链接库
library_path = 'Lib/libcrypto.so.1.0.0'  

# 客户端occ信息，在openvpn客户端加载时，会生成需匹配的occ信息
# 可先用openvpn程序对接其服务端，查看其所需匹配的occ信息
# 再填入此配置文件中
occ_string = b'V4,dev-type tun,link-mtu 1559,tun-mtu 1500,proto TCPv4_CLIENT,cipher AES-128-CBC,auth SHA1,keysize 128,key-method 2,tls-client'  

key_direction = 0  # 密钥方向，参考openvpn配置文件。若其配置文件无此选项，则为0

# ___________________以下配置为非重要参数，按默认参数即可_____________________________

Wait_Init_Time = 3  # 开始进行连接初始化的等待时间，目的是防止在openvpn未完成握手的情况下就启动，若无法初始化连接，可尝试将该值调高

VpnMtu = 1450  # openvpn mtu

vpn_reset_time = 7200  # 重置openvpn连接时间

udp_update_count_max = 16  # udp的最大等待更新轮次，用于判断是否丢弃该超时包

forward_recv_buffer_size = 256  # 单轮接收数据的大小，此值应保持在合理范围内，不宜过大过小

base_send_buffer_size = 10240  # 发送数据的缓冲区大小，此值应保持在合理范围内，不宜过大过小

recv_ack_timeout = 0.1  # ack超时时间

connect_timeout = 3  # 连接超时时间

fragment = 1400  # udp包单个分包最大大小

reliableUdpCapacity = 192  # 可缓存的udp包数量

socketBuffer = 0xffff  # socket的tcp接收缓冲区大小

# 其他参数
kwargs = {}
