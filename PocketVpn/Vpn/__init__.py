from .VpnContext import VpnContext
from .VpnCrypto import VpnCrypto
from ..include.CommunicationPackage import *
from ..include.ContextHead import *


class VpnSocket(VpnContext):

    _Hook_Table = None

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
                 socketTimeout=0.2,
                 cipher=VpnCrypto.CBC_128,
                 auth=VpnCrypto.HMAC_SHA1,
                 key_direction=0,
                 VpnMtu=1152,
                 UdpMtu=1024,
                 vpn_reset_time=3600,
                 udp_update_count_max=192):

        super().__init__(library_path, occ_string, virtual_local_ip,
                         ca_file_path, crt_file_path, privateKey_file_path,
                         dstAddress, dstPort, socketBuffer, cipher, auth,
                         key_direction, VpnMtu, UdpMtu, vpn_reset_time,
                         udp_update_count_max)
        """
        提供在openvpn网络下的通信功能，目前仅支持udp通信
        只建议调用该子类的方法，不建议调用父类方法
        
        使用方法
        
        1. 通过recv_callback_add方法添加钩子来监听数据包
           接收数据包后，会调用其回调函数
        
        2. 通过send_udp方法发送给udp数据包
        
        3. Loop函数为主循环函数,需要持续调用使其运作

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

        self._Hook_Table = {}

    def __len__(self):
        """返回当前的监听个数
        """
        return len(self._Hook_Table)

    def __getitem__(self, key):
        """返回其相应的回调函数

        Args:
            key (tuple[str,int,int]): 远程地址，远程端口，本地端口，如('10.8.1.1',3456,7890)

        Returns:
            function : 返回其相应的回调函数
        """

        remoteAddress, remotePort, localPort = key

        return self._Hook_Table[(self._strIp2tupleIp(remoteAddress),
                                 remotePort, localPort)]

    def __setitem__(self, key, value):
        """添加钩子，实质调用了recv_callback_add方法

        Args:
            key (tuple[str,int,int]: 远程地址，远程端口，本地端口，如('10.8.1.1',3456,7890)
            value (function): 绑定的回调函数
        """
        
        self.recv_callback_add(*key, value)

    def __delitem__(self, key):
        """解除钩子，实质调用了recv_callback_del方法

        Args:
            key (tuple[str,int,int]): 远程地址，远程端口，本地端口，如('10.8.1.1',3456,7890)
        """
        self.recv_callback_del(*key)

    def _strIp2tupleIp(self, ip: str):
        """将ipv4地址字符串转换为ipv4地址元组

        Args:
            ip (str): ipv4地址字符串

        Returns:
            tuple[int,int,int,int]: 返回ipv4地址元组
        """
        ip = ip.split(".")
        return (int(ip[0]), int(ip[1]), int(ip[2]), int(ip[3]))

    def _RecvUdp(self, event: Event):
        """
        监听事件链上的udp数据包,并检查是否有对应的钩子，若有则调用其回调函数
        """
        communicate_Package: Communicate_Package = event.Payload

        remoteAddress, remotePort, localPort, data = communicate_Package.unpack_addr_tuple(
        )

        if (remoteAddress, remotePort, localPort) not in self._Hook_Table:
            return

        self._Hook_Table[(remoteAddress, remotePort, localPort)](data)

    def recv_callback_add(self, remoteAddress, remotePort, localPort, func):
        """添加钩子，监听udp数据包，接收到相应数据包后，传入udp数据字节流并调用其回调函数

        Args:
            remoteAddress (str): 监听的远程地址
            remotePort (int):    监听的远程端口
            localPort (int):     监听的本地端口
            func (function):     回调函数
        
        Callbacks:
            func (bytes) : 传入udp数据字节流并调用其回调函数
        """
        self._Hook_Table[(self._strIp2tupleIp(remoteAddress), remotePort,
                          localPort)] = func

    def recv_callback_del(self, remoteAddress, remotePort, localPort):
        """解除钩子

        Args:
            remoteAddress (str): 监听的远程地址
            remotePort (int):    监听的远程端口
            localPort (int):     监听的本地端口
        """
        del self._Hook_Table[(self._strIp2tupleIp(remoteAddress), remotePort,
                              localPort)]

    def send_udp(self, remoteAddress, remotePort, localPort, data):
        """在openvpn网络中发送udp数据包
        
        如
        send_udp('10.8.1.1',4757,6877,b"hello world")

        Args:
            remoteAddress (str): udp数据包的远程地址
            remotePort (int):    udp数据包的远程端口
            localPort (int):     udp数据包的本地端口
            data (bytes):        udp数据包的数据内容
        """
        communicate_Package = Communicate_Package().pack_addr_str(
            remoteAddress, remotePort, localPort, data)

        self._SendUdp(communicate_Package)

    def Loop(self):
        """
        主循环函数,需要持续调用使其运作
        """
        return super().Loop()
