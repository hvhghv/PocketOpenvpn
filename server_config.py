import logging



bind_ip = "0.0.0.0"  # 服务端服务地址

bind_port = 6672  # 服务端服务端口

bind_port_listen = 16  # 单个转发端口最大连接数

tcpRecvBufferSize = 256  # 单轮单个应用通讯的最大接收大小

base_send_buffer_size = 10240  # 发送数据的缓冲区大小，此值应保持在合理范围内，不宜过大过小

recv_ack_timeout = 0.1  # ack超时时间

connect_timeout = 3  # 连接超时时间

fragment = 1400  # udp包单个分包最大大小

reliableUdpCapacity = 192  # 可缓存的udp包数量

# 其他参数
kwargs = {}

# 日志等级
# 0:logging.DEBUG 打印调试日志
# 1:logging.INFO  打印一般日志
logging_level = logging.INFO
