from server_config import *
from PocketVpn import ForwardServer

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

while 1:
    server_object.Loop()
