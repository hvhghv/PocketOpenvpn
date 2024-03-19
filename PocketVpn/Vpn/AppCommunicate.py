from ..include.ContextHead import *
from ..include.simpleFunc import *
from ..include.VpnContextContentType import *
from ..include.CommunicationPackage import *


def countCheckSum(data: bytes, diff: int = 0):
    """计算网络网络数据包校验和

    Args:
        data (bytes): 需要校验的数据字节流
        diff (int, optional): 若参数data字节流内已包含了校验和，则需要传入该校验和，若无则不需要。注意此校验和的值要求大端序

    Returns:
        int: 计算校验和
    """

    data = bytes(data)

    if len(data) % 2 == 1:
        data = data + b'\x00'

    count = 0
    sum = -diff

    while count < len(data):
        sum += getWord(data, count, "big")
        count += 2

    sum = (sum >> 16) + (sum & 0xffff)
    sum = (sum >> 16) + (sum & 0xffff)
    sum = 0xffff - sum

    return sum


class ERROR:
    PACK_FORM_ERROR = 0x01
    PACK_VERSION_ERROR = 0x02
    PACK_SIZE_ERROR = 0x03
    PACK_CHECKSUM_ERROR = 0x04
    PACK_MAGIC_ERROR = 0x05
    PACK_DECODE_ERROR = 0x07
    SOCKET_NOT_CONNECTION_ERROR = 0x06
    SOCKET_NOT_MSG = 0x08


class PROTOCOL:
    """Ipv4中protocol字段可能的值
    """
    ICMP = 1
    IGMP = 2
    TCP = 6
    UDP = 17


class IPV4Struct:
    """ipv4包结构

    """
    Version = 0
    HeaderLength = 0
    TypeofService = 0
    TootalLength = 0
    Identification = 0
    Flag = 0
    FragmentOffset = 0
    TTL = 0
    Protocol = 0
    Checksum = 0
    SrcAddress = (0, 0, 0, 0)
    DstAddress = (0, 0, 0, 0)
    Options = []

    def __str__(self):
        return f"""
    IPV4Struct:
    
    Version: {self.Version}
    HeaderLength: {self.HeaderLength}
    TypeofService: {self.TypeofService}
    TootalLength: {self.TootalLength}
    Identification: {self.Identification}
    Flag: {self.Flag}
    FragmentOffset: {self.FragmentOffset}
    TTL: {self.TTL}
    Protocol: {self.Protocol}
    Checksum: {hex(self.Checksum)}
    SrcAddress: {self.SrcAddress}
    DstAddress: {self.DstAddress}
    Options: {self.Options}
    
    """

    def create(self,
               srcAddress,
               dstAddress,
               Protocol,
               payloadSize,
               Identification,
               Flag=0,
               FragmentOffset=0,
               TTL=128):
        """在当前实例中创建一个ipv4结构包
        
        Returns:
            返回当前实例
        """
        self.Version = 4
        self.HeaderLength = 5
        self.TypeofService = 0
        self.TootalLength = payloadSize + 20
        self.Identification = Identification
        self.Flag = Flag
        self.FragmentOffset = FragmentOffset
        self.TTL = TTL
        self.Protocol = Protocol
        self.SrcAddress = srcAddress
        self.DstAddress = dstAddress
        self.Options = []
        self.Checksum = self.countCheckSum()
        return self

    def countCheckSum(self):
        """返回当前实例的校验和

        Returns:
            int: 返回当前实例的校验和
        """
        return countCheckSum(self.to_bytes(), self.Checksum)

    def to_bytes(self):
        """将当前实例转换为字节流

        Returns:
            bytes: 转换后的字节流
        """
        data = b""

        data += (self.Version << 4 | self.HeaderLength).to_bytes(
            1, byteorder='big')
        data += (self.TypeofService).to_bytes(1, byteorder='big')
        data += (self.TootalLength).to_bytes(2, byteorder='big')
        data += (self.Identification).to_bytes(2, byteorder='big')
        data += (self.Flag << 5
                 | self.FragmentOffset >> 11 & 0b11111).to_bytes(
                     1, byteorder='big')
        data += (self.FragmentOffset >> 3 & 0xff).to_bytes(1, byteorder='big')
        data += (self.TTL).to_bytes(1, byteorder='big')
        data += (self.Protocol).to_bytes(1, byteorder='big')
        data += (self.Checksum).to_bytes(2, byteorder='big')
        data += bytes(self.SrcAddress) + bytes(self.DstAddress)
        data += bytes(self.Options)
        return data

    def getHeadSize(self):
        """获取当前实例的ipv4包头部字节长度

        Returns:
            int: 返回当前实例的ipv4包头部字节长度
        """
        return 20 + len(self.Options)

    def from_bytes(self, data, usechecksum=True):
        """根据字节流在当前实例生成ipv4包

        Args:
            data (bytes): 字节流
            usechecksum (bool, optional): 是否进行校验和异常判断，True则进行校验，False则不进行校验

        Returns:
            int : 0为表示成功，其他表示失败。失败的返回值在ERROR定义
        """
        data = list(data)

        if (len(data) < 20):
            return ERROR.PACK_FORM_ERROR

        self.Version = data[0] >> 4

        if (self.Version != 4):
            return ERROR.PACK_VERSION_ERROR

        self.HeaderLength = data[0] & 0b1111
        self.TypeofService = data[1]
        self.TootalLength = getWord(data, 2, 'big')
        self.Identification = getWord(data, 4, 'big')
        self.Flag = data[6] >> 5
        self.FragmentOffset = getWord(data, 6, 'big') << 3 & 0xffff
        self.TTL = data[8]
        self.Protocol = data[9]
        self.Checksum = getWord(data, 10, 'big')
        self.SrcAddress = (data[12], data[13], data[14], data[15])
        self.DstAddress = (data[16], data[17], data[18], data[19])

        Opthons_Size = self.HeaderLength * 4 - 20
        Padding = Opthons_Size % 4
        Opthons_Size += Padding

        if (len(data) < Opthons_Size + 20):
            return ERROR.PACK_SIZE_ERROR

        for i in range(Opthons_Size):
            self.Options.append(data[20 + i])

        if (usechecksum):
            if (self.countCheckSum() != self.Checksum):
                return ERROR.PACK_CHECKSUM_ERROR

        return 0


class UdpPacket:
    """udp包结构
    """
    srcPort = 0
    dstPort = 0
    size = 0
    checkSum = 0
    data = b""

    SrcAddress = (0, 0, 0, 0)
    DstAddress = (0, 0, 0, 0)

    def __str__(self) -> str:
        return f"""
    UdpPacket:
    
    srcPort: {self.srcPort}
    dstPort: {self.dstPort}
    size: {self.size}
    checkSum: {hex(self.checkSum)}
    data: {bytes2HexList(self.data)}
    
    """

    def countCheckSum(self, SrcAddress, DstAddress):
        """返回当前实例的校验和

        Args:
            SrcAddress (tuple): 源ip地址，如 (127,0,0,1)
            DstAddress (tuple): 目标ip地址，如 (127,0,0,1) 

        Returns:
            int: 当前实例的校验和
        """

        return countCheckSum(
            bytes(SrcAddress) + bytes(DstAddress) +
            self.size.to_bytes(2, "big") + PROTOCOL.UDP.to_bytes(2, "big") +
            self.to_bytes(), self.checkSum)

    def create(self, data: bytes, SrcAddress: tuple, DstAddress: tuple,
               srcPort: int, dstPort: int):
        '''
        在当前实例创建udp包
        '''
        self.data = bytes(data)
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.size = len(self.data) + 8
        self.checkSum = self.countCheckSum(SrcAddress, DstAddress)

        return self

    def from_bytes(self, data: bytes):
        '''
        根据字节流在当前实例生成udp包
        '''
        data = bytes(data)
        if len(data) < 8:
            return ERROR.PACK_SIZE_ERROR
        self.srcPort = getWord(data, 0, 'big')
        self.dstPort = getWord(data, 2, 'big')
        self.size = getWord(data, 4, 'big')
        self.checkSum = getWord(data, 6, 'big')
        self.data = data[8:]
        return 0

    def to_bytes(self):
        """根据当前实例生成字节流

        Returns:
            bytes: 返回生成的字节流
        """

        data = b""
        data += self.srcPort.to_bytes(2, "big")
        data += self.dstPort.to_bytes(2, "big")
        data += self.size.to_bytes(2, "big")
        data += self.checkSum.to_bytes(2, "big")
        data += self.data
        return data


class Ipv4_Fragment_Table:
    """
    用于将多个ipv4分包重组为一个完整的数据包

    """
    list_data = []              # 存放ipv4分包与对应的数据
    offset_index_list = []      # 存放ipv4分包的FragmentOffset偏移值
    buffer = b""                # 目前已重组好的数据
    last_update_count = 0       # 记录上一次更新该实例的一个值，其功能由上层定义，目前用于判断该实例是否已超时丢弃
    recv_final_package = False  # 确认是否收到了最后一个分包
    protocol = 0
    srcAddress = (0, 0, 0, 0)
    dstAddress = (0, 0, 0, 0)

    def __init__(self, ipv4_package: IPV4Struct, data, last_update_count):
        self.list_data = []
        self.offset_index_list = []
        self.protocol = ipv4_package.Protocol
        self.srcAddress = ipv4_package.SrcAddress
        self.dstAddress = ipv4_package.DstAddress
        self.append(ipv4_package, data, last_update_count)

    def append(self, ipv4_package: IPV4Struct, data, last_update_count):
        """将一个ipv4分包添加到实例中

        Args:
            ipv4_package (IPV4Struct): ipv4分包
            data (bytes): ipv4分包对应的数据
            last_update_count (int): 一个值，功能由上层定义

        Returns:
            Ipv4_Fragment_Table : 当前实例
        """

        self.list_data.append((ipv4_package, data))
        self.offset_index_list.append(ipv4_package.FragmentOffset)
        self.last_update_count = last_update_count

        if ipv4_package.Flag == 0:
            self.recv_final_package = True

        return self

    def restruct(self):
        """通过当前实例的ipv4分包重组为一个完整的数据包

        Returns:
            bytes|None: 若重组成功，返回重组后的字节流数据，若缺少相应的分包或重组失败，返回None
        """

        while 1:
            try:
                index = self.offset_index_list.index(len(self.buffer))
            except ValueError:
                return None

            self.buffer += self.list_data[index][1]

            if self.list_data[index][0].Flag & 1 == 0:
                return self.buffer


class SimpleUdp(Context_Child):
    '''
    处理openvpn的数据包并包装其中的udp包，发往下游

    '''

    Sign = "SIM_UDP"
    srcAddress = (10, 8, 1, 2)
    mtu = 1024
    update_count = 0
    update_count_max = 16
    ipv4_fragment = {
    }  # ipv4分包重组表，以ipv4包的Identification为key值，Ipv4_Fragment_Table实例为value值

    def __init__(self,
                 context,
                 srcAddress: str = '10.8.1.2',
                 mtu=1024,
                 update_count_max=16):
        super().__init__(context)

        self.mtu = mtu
        self.update_count_max = update_count_max
        self.ipv4_fragment = {}

        ip = srcAddress.split('.')
        self.srcAddress = (int(ip[0]), int(ip[1]), int(ip[2]), int(ip[3]))

    def recv(self, event: Event):
        '''
        挂钩事件链上openvpn中数据通道发来的数据包，对该数据包进行处理
        '''

        data = event.Payload
        self._unpack_ipv4struct(data)

        # 检查并清除ipv4分包重组表中过期的实例
        self._check_fragment()

    def _unpack_ipv4struct(self, data):
        """
        解包ipv4数据包并进行处理
        """

        ipv4_head_packet = IPV4Struct()
        offset = 0

        if ipv4_head_packet.from_bytes(data, False) != 0:
            return

        if ipv4_head_packet.DstAddress != self.srcAddress:
            return

        offset += ipv4_head_packet.getHeadSize()

        if ipv4_head_packet.Flag & 1 == 0 and ipv4_head_packet.FragmentOffset == 0:
            # 执行到这里，说明该ipv4包没有进行分片

            self.dispatch(ipv4_head_packet.SrcAddress,
                          ipv4_head_packet.DstAddress,
                          ipv4_head_packet.Protocol, data[offset:])
            return

        else:
            # 执行到这里，说明该ipv4包进行了分片
            one_ipv4_fragment = self.ipv4_fragment.get(
                ipv4_head_packet.Identification, None)

            # 判断该ipv4分包是否存在对应的Ipv4_Fragment_Table实例，若无，则创建
            if not one_ipv4_fragment:

                self.ipv4_fragment[
                    ipv4_head_packet.Identification] = Ipv4_Fragment_Table(
                        ipv4_head_packet, data[offset:], self.update_count)
                return

            # 若有，则把将该ipv4分包添加到Ipv4_Fragment_Table实例中
            one_ipv4_fragment.append(ipv4_head_packet, data[offset:],
                                     self.update_count)

    def _check_fragment(self):
        """
        检查ipv4_fragment里的Ipv4_Fragment_Table实例是否过期，若过期，则清除
        
        每次调用，会进行
        update_count = (update_count+1) % update_count_max
        
        之后比对每个Ipv4_Fragment_Table实例，若其last_update_count
        与当前的update_count相同，会判断此实例已经超时过期，进行清除
        """

        self.update_count = (self.update_count + 1) % self.update_count_max
        to_del = []

        for i in self.ipv4_fragment.keys():

            # 最后一次尝试重组该实例的分包，若仍然失败，则进行清除
            if self.ipv4_fragment[i].recv_final_package == True:
                buffer = self.ipv4_fragment[i].restruct()

                if buffer:
                    self.dispatch(self.ipv4_fragment[i].srcAddress,
                                  self.ipv4_fragment[i].dstAddress,
                                  self.ipv4_fragment[i].protocol, buffer)

                    to_del.append(i)
                    continue

            if self.update_count == self.ipv4_fragment[i].last_update_count:
                to_del.append(i)
                continue

        for i in to_del:
            del self.ipv4_fragment[i]

    def dispatch(self, srcAddress, dstAddress, protocol, data):
        '''
        对重组好的数据包，根据其协议进行分发
        '''

        if protocol == PROTOCOL.UDP:
            self._unpack_udpstruct(srcAddress, dstAddress, data)

    def _unpack_udpstruct(self, SrcAddress, DstAddress, data):
        '''
        重新包装udp协议包并发往下游
        
        事件类型 : COMMUNICATE_RECV_UDP_DATA
        事件内容 : Communicate_Package 包装后的udp协议包
        '''
        udpPacket = UdpPacket()
        if udpPacket.from_bytes(data) != 0:
            return

        self.createEvent(
            COMMUNICATE_RECV_UDP_DATA,
            Communicate_Package().pack_addr_tuple(SrcAddress,
                                                  udpPacket.srcPort,
                                                  udpPacket.dstPort,
                                                  udpPacket.data))

    def send_udp(self, event: Event):
        '''
        挂钩事件链上需要发送的udp协议数据包，包装成ipv4协议包
        '''

        dstaddress, dstport, srcport, data = event.Payload.unpack_addr_tuple()
        self._send_udp(data, dstaddress, dstport, srcport)

    def _send_udp(self, data, dstaddress, dstport, srcport):
        '''
        发送的udp协议数据包
        
        事件类型 : COMMUNICATE_SEND_DATA
        事件内容 : bytes 包装后的ipv4数据包的字节流
        '''

        # send_data = b""

        udpPacket = UdpPacket().create(data, self.srcAddress, dstaddress,
                                       srcport, dstport)

        # send_data = udpPacket.to_bytes() + send_data

        send_data = udpPacket.to_bytes()
        offset = 0
        send_data_size = len(send_data)
        Identification = int.from_bytes(urandom(2), 'big')

        # 将数据包进行分包
        while offset + self.mtu < send_data_size:

            # 包装非最后一个的分包
            to_pack_data = send_data[offset:offset + self.mtu]
            ipv4Packet = IPV4Struct().create(self.srcAddress, dstaddress,
                                             PROTOCOL.UDP, self.mtu,
                                             Identification, 1, offset)
            self.createEvent(COMMUNICATE_SEND_DATA,
                             ipv4Packet.to_bytes() + to_pack_data)
            offset += self.mtu

        # 包装最后一个分包
        to_pack_data = send_data[offset:offset + self.mtu]
        ipv4Packet = IPV4Struct().create(self.srcAddress,
                                         dstaddress, PROTOCOL.UDP,
                                         len(to_pack_data), Identification, 0,
                                         offset)

        self.createEvent(COMMUNICATE_SEND_DATA,
                         ipv4Packet.to_bytes() + to_pack_data)
