from server_config import *
from PocketVpn import ForwardServer
import logging


log = logging.getLogger()
log.setLevel(logging_level)

log_head = logging.StreamHandler()
log_head.setFormatter(
    logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

log.addHandler(log_head)

logging.info(f"""

bind_ip={bind_ip}
bind_port={bind_port}
tcpRecvBufferSize={tcpRecvBufferSize}
base_send_buffer_size={base_send_buffer_size}
recv_ack_timeout={recv_ack_timeout}
connect_timeout={connect_timeout}
fragment={fragment}
reliableUdpCapacity={reliableUdpCapacity}
bind_port_listen={bind_port_listen}

             """)



server_object = ForwardServer(bind_ip=bind_ip,
                              bind_port=bind_port,
                              tcpRecvBufferSize=tcpRecvBufferSize,
                              base_send_buffer_size=base_send_buffer_size,
                              recv_ack_timeout=recv_ack_timeout,
                              connect_timeout=connect_timeout,
                              fragment=fragment,
                              reliableUdpCapacity=reliableUdpCapacity,
                              bind_port_listen=bind_port_listen,
                              **kwargs)

try:
    while 1:
        server_object.Loop()
except Exception as e:
    log.critical(e)
    input("程序已终止，输入回车键退出")
