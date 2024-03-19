from ..include.ContextHead import *
from ..include.ProjectContextContentType import *
from .vpnForwardClient import SimpleForwardClient
from .VpnContextClass import VpnContextClass
from ..Vpn.VpnCrypto import VpnCrypto


class ProjectContext(Context):

    VPN_Context_Object = None
    Forward_Client_Context_Object = None

    def __init__(self,
                 library_path,
                 occ_string,
                 virtual_local_ip='10.8.1.2',
                 ca_file_path="ca.crt",
                 crt_file_path="client.crt",
                 privateKey_file_path="client.pem",
                 dstAddress="127.0.0.1",
                 dstPort=1194,
                 socketBuffer=1024,
                 cipher=VpnCrypto.CBC_128,
                 auth=VpnCrypto.HMAC_SHA1,
                 key_direction=0,
                 VpnMtu=1450,
                 UdpMtu=0xffff,
                 vpn_reset_time=3600,
                 udp_update_count_max=16,
                 forward_default_Table=(),
                 forward_server_ip='10.8.1.1',
                 forward_server_port=6672,
                 forward_local_port=6672,
                 forward_recv_buffer_size=256,
                 base_send_buffer_size=1024 * 10,
                 recv_ack_timeout=0.1,
                 connect_timeout=3,
                 fragment=1400,
                 reliableUdpCapacity=192,
                 Wait_Init_Time = 3,
                 **kwargs):

        self.VPN_Context_Object = VpnContextClass(
            self,
            library_path,
            occ_string,
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
            UdpMtu=UdpMtu,
            vpn_reset_time=vpn_reset_time,
            udp_update_count_max=udp_update_count_max,
            )

        self.Forward_Client_Context_Object = SimpleForwardClient(
            self,
            default_Table=forward_default_Table,
            forward_server_address=forward_server_ip,
            forward_server_bind_port=forward_server_port,
            forward_client_bind_port=forward_local_port,
            recv_buffer_size=forward_recv_buffer_size,
            base_send_buffer_size=base_send_buffer_size,
            recv_ack_timeout=recv_ack_timeout,
            connect_timeout=connect_timeout,
            fragment=fragment,
            capacity=reliableUdpCapacity,
            Wait_Init_Time=Wait_Init_Time)

        self.event_cur_id += 1
        self.EventBus(Event(self.event_cur_id,CONTEXT_INIT, None))

    def EventBus(self, event: Event):
        self.EventStation0(event)

    def EventStation0(self, event: Event):

        self.EventHook(self.VPN_Context_Object.send_udp, (VPN_UDP_SEND, ),
                       event)

        self.EventHook(self.Forward_Client_Context_Object.recv_data,
                       (VPN_UDP_RECV, ), event)

    def Loop(self):
        self.VPN_Context_Object.check()
        self.Forward_Client_Context_Object.check()
