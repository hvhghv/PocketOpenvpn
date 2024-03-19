from client_config import *
from PocketVpn import ForwardClient

client_object = ForwardClient(
    library_path=library_path,
    occ_string=occ_string,
    virtual_local_ip=virtual_local_ip,
    ca_file_path=ca_file_path,
    crt_file_path=crt_file_path,
    privateKey_file_path=privateKey_file_path,
    dstAddress=dstAddress,
    dstPort=dstPort,
    socketBuffer=socketBuffer,
    cipher=cipher,
    auth=auth,
    key_direction=key_direction,
    VpnMtu=VpnMtu,
    vpn_reset_time=vpn_reset_time,
    udp_update_count_max=udp_update_count_max,
    forward_default_Table=forward_default_Table,
    forward_server_ip=forward_server_ip,
    forward_server_port=forward_server_port,
    forward_local_port=forward_local_port,
    forward_recv_buffer_size=forward_recv_buffer_size,
    base_send_buffer_size=base_send_buffer_size,
    recv_ack_timeout=recv_ack_timeout,
    connect_timeout=connect_timeout,
    fragment=fragment,
    reliableUdpCapacity=reliableUdpCapacity,
    Wait_Init_Time=Wait_Init_Time,
    **kwargs)

while 1:
    client_object.Loop()
