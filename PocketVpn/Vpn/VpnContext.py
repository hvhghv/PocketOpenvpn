from PocketVpn.include.ContextHead import Event
from ..include.ContextHead import *
from .Vpn import Vpn, VpnCrypto
from .TLS import SimpleTLS
from .simpleSocket import SimpleSocket
from .AppCommunicate import SimpleUdp
from ..include.VpnContextContentType import *


class VpnContext(Context):
    VPN_Object = None
    TLS_Object = None
    Socket_Object = None
    UDP_Object = None

    def __init__(self,
                 library_path,
                 occ_string,
                 virtual_local_ip='10.8.1.2',
                 ca_file_path="ca.crt",
                 crt_file_path="client.crt",
                 privateKey_file_path="client.pem",
                 dstAddress="127.0.0.1",
                 dstPort=1194,
                 socketBuffer=0xffff,
                 cipher=VpnCrypto.CBC_128,
                 auth=VpnCrypto.HMAC_SHA1,
                 key_direction=0,
                 VpnMtu=1152,
                 UdpMtu=1024,
                 vpn_reset_time=3600,
                 udp_update_count_max=192
                 ):
        """vpn

        Args:
            library_path (str): libcrypto动态库路径
            occ_string (bytes): occ信息
            virtual_local_ip (str, optional): 本地虚拟地址。由于不支持dhcp，所以需要手动指定虚拟ip
            ca_file_path (str, optional): ca证书路径
            crt_file_path (str, optional): 客户端证书路径. Defaults to "client.crt".
            privateKey_file_path (str, optional): 客户端私钥路径. Defaults to "client.pem".
            dstAddress (str, optional): openvpn服务器地址. Defaults to "127.0.0.1".
            dstPort (int, optional): openvpn服务器端口. Defaults to 1194.
            socketBuffer (hexadecimal, optional): tcp接收缓冲区大小. Defaults to 0xffff.
            cipher (_type_, optional): _description_. 加密算法 to VpnCrypto.CBC_128.
            auth (_type_, optional): _description_. 信息摘要算法 to VpnCrypto.HMAC_SHA1.
            key_direction (int, optional): 键方向，见openvpn文档. Defaults to 0.
            VpnMtu (int, optional): openvpn mtu. Defaults to 1152.
            UdpMtu (int, optional): udp mtu. Defaults to 1024.
            vpn_reset_time (int, optional): openvpn连接重置时间. Defaults to 3600.
            udp_update_count_max (int, optional): 可缓存的udp包数量. Defaults to 192.
        """

        self.VPN_Object = Vpn(self,
                              library_path,
                              occ_string,
                              mtu=VpnMtu,
                              max_run_time=vpn_reset_time,
                              cipher=cipher,
                              auth=auth,
                              key_direction=key_direction
                              )

        self.TLS_Object = SimpleTLS(
            self,
            ca_file_path=ca_file_path,
            crt_file_path=crt_file_path,
            privateKey_file_path=privateKey_file_path,
        )

        self.Socket_Object = SimpleSocket(
            self,
            dstAddress=dstAddress,
            dstPort=dstPort,
            buffer=socketBuffer,
        )

        self.UDP_Object = SimpleUdp(self,
                                    srcAddress=virtual_local_ip,
                                    mtu=UdpMtu,
                                    update_count_max=udp_update_count_max)

        self.event_cur_id += 1
        self.EventBus(Event(self.event_cur_id,CONTEXT_INIT, None))

    def EventBus(self, event: Event):

        self.EventStation1(event)
        self.EventStation0(event)

    def EventStation1(self, event: Event):

        self.EventHook(
            self.VPN_Object.openvpn_record_unpack,
            (SOCKET_RECV, VPN_RECORD_DATA_RECV_RESTRUCT),
            event,
        )  # VPN_CONTROL_RECV, VPN_DATA_RECV

        self.EventHook(self.VPN_Object.vpn_decrypto_application_data,
                       (VPN_DATA_RECV, ), event)

        self.EventHook(
            self.VPN_Object.openvpn_record_tls_pack, (TLS_SEND_DATA, ),
            event)  # TLS_SEND_DATA, VPN_RECORD_CONTROL_SEND_RESTRUCT

        self.EventHook(
            self.VPN_Object.openvpn_record_data_pack,
            (VPN_APPLICATION_DATA_SEND, ), event
        )  # VPN_APPLICATION_DATA_SEND , VPN_RECORD_APPLICATION_SEND_RESTRUCT

    def EventStation0(self, event: Event):

        self.EventHook(
            self.Socket_Object.Send,
            (VPN_SEND_DATA, TLS_SEND_DATA, VPN_RECORD_CONTROL_SEND_RESTRUCT,
             VPN_APPLICATION_DATA_SEND, VPN_RECORD_APPLICATION_SEND_RESTRUCT),
            event,
        )

        self.EventHook(self.VPN_Object.simplvpn_hook_tls_handshark_finish,
                       (TLS_HANDSHARK_DONE, ), event)

        self.EventHook(self.TLS_Object.do_handshark, (TLS_DO_HANDSHARK, ),
                       event)

        self.EventHook(self.TLS_Object.incoming, (VPN_CONTROL_RECV, ), event)
        self.EventHook(self.TLS_Object.write, (TLS_SEND_APPLICATION_DATA, ),
                       event)

        self.EventHook(self.VPN_Object.vpn_encrypto_appliaction_data,
                       (COMMUNICATE_SEND_DATA, ), event)

        self.EventHook(self.VPN_Object.recv_tls_text,
                       (TLS_RECV_APPLICATION_DATA, ), event)

        self.EventHook(self.UDP_Object.recv, (VPN_DATA_RECV, ), event)
        self.EventHook(self.UDP_Object.send_udp, (COMMUNICATE_SEND_UDP_DATA, ),
                       event)
        self.EventHook(self._RecvUdp, (COMMUNICATE_RECV_UDP_DATA, ), event)
        self.EventHook(self._PrepareHardReset, (VPN_PREPARE_HARD_RESET,),event)

        self.EventHook(self.VPN_Object.soft_reset, (CONTEXT_INIT, ), event)
        self.EventHook(self.TLS_Object.soft_reset,
                       (CONTEXT_INIT, VPN_HARD_RESET), event)
        self.EventHook(self.Socket_Object.soft_reset, (CONTEXT_INIT, ), event)

    def Loop(self):
        self.VPN_Object.check()
        self.TLS_Object.check()
        self.Socket_Object.check()

    def _SendUdp(self, package):
        """发送udp包

        Args:
            package (Communicate_Package): CommunicationPackage文件中的Communicate_Package实例
            
        事件类型 : COMMUNICATE_SEND_UDP_DATA
        事件内容 : Communicate_Package
        """
        
        self.event_cur_id += 1
        self.EventBus(Event(self.event_cur_id,COMMUNICATE_SEND_UDP_DATA, package))

    def _RecvUdp(self, event: Event):
        """在事件链中监听UDP数据包,event.Payload为Communicate_Package实例
        """

        pass

    def _PrepareHardReset(self,event:Event):
        """在事件链中监听vpn连接重置事件
        """
        pass
