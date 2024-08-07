'''

将udp添加一层可靠层，提供丢包重传与超时重传功能，并保证数据包为按顺序到达

该可靠层又分为两层，内层是为两个对等体提供可靠性连接，而外层则是用于实现client与server之间的连接

各数据包均为大端序

'''

from time import time

from .CommunicationPackage import Communicate_Package

from .simpleFunc import *

import logging

log = logging.getLogger()

# ContentType的类型

TYPE_ACK = 0

TYPE_DATA = 1

TYPE_MAX_NUM = 2  # 指示目前ContentType的类型数量

# 自定义CommunicationPackage的Flag类型

FLAG_CONNECT = (1 << 0)

FLAG_CLOSED = (1 << 1)

# 数据包头大小

HEAD_SIZE = 7


class LostPacketCache(Exception):
    '''

    当丢包后发生重传但却没有需要重传的数据包缓存时，触发该异常

    '''

    def __str__(self):

        return "cache lost"


class ConnectClosed(Exception):
    '''

    当连接超时，中断，关闭时触发该异常

    '''

    def __str__(self):

        return "connect closed"


class PacketIDError(Exception):
    '''

    当收到的ack包所确认的packetId错误时触发该异常

    '''

    def __str__(self):

        return "packet id error"


class AckPacket:
    '''

    ack包结构

    '''

    ContentType = 0  # 字节数为1，ack时置为0

    PacketId = 0  # 字节数为4，ack时置为0

    Length = 0  # 字节数为2，指示后面数据的总长度

    RecvMaxPacketId = 0  # 字节数为4，指示对端已收到的最大packetId

    RecvBufferSize = 0  # 字节数为8，指示目前已收到数据总长度

    LostPacketNum = 0  # 字节数为1，指示LostPacketIdArray数组元素个数

    LostPacketIdArray = None  # 字节数为LostPacketNum*4，指示已丢失的packetId

    def pack(self, PacketId, RecvMaxPacketId, RecvBufferSize,
             LostPacketIdArray):
        '''

        打包一个ack包，修改当前实例

        返回当前实例
        

        例：

        packet = AckPacket().pack(0,2,128,[0,1])

        '''

        self.PacketId = PacketId

        self.RecvMaxPacketId = RecvMaxPacketId

        self.RecvBufferSize = RecvBufferSize

        self.LostPacketNum = len(LostPacketIdArray)

        self.LostPacketIdArray = LostPacketIdArray

        self.Length = 8 + 4 + 1 + self.LostPacketNum * 4
        return self

    def unpack(self):
        """解包一个ack包


        Returns:

            tuple[int,int,list]:返回该包的RecvMaxPacketId，RecvBufferSize，LostPacketIdArray

        """

        return self.RecvMaxPacketId, self.RecvBufferSize, self.LostPacketIdArray

    def from_bytes(self, dataBytes: bytes):
        """根据字节流生成一个ack包


        Args:

            dataBytes (bytes): 用于生成ack包的字节流。其中字节流可存在非ack包所需要的数据，但要求其数据处于尾部。


        Returns:

            AckPacket: 返回当前实例

        """

        offset = 1

        LostPacketIdArray = []

        self.PacketId = int.from_bytes(dataBytes[offset:offset + 4], 'big')

        offset += 4

        self.Length = int.from_bytes(dataBytes[offset:offset + 2], 'big')

        offset += 2

        self.RecvMaxPacketId = int.from_bytes(dataBytes[offset:offset + 4],
                                              'big')

        offset += 4

        self.RecvBufferSize = int.from_bytes(dataBytes[offset:offset + 8],
                                             'big')

        offset += 8

        self.LostPacketNum = int.from_bytes(dataBytes[offset:offset + 1],
                                            'big')

        offset += 1

        for i in range(self.LostPacketNum):

            LostPacketIdArray.append(
                int.from_bytes(dataBytes[offset:offset + 4], 'big'))

            offset += 4

        self.LostPacketIdArray = LostPacketIdArray
        return self

    def to_bytes(self):
        """根据该ack包生成字节流


        Returns:

            bytes: 返回生成的字节流

        """

        res = b""

        res += self.ContentType.to_bytes(1, 'big')

        res += self.PacketId.to_bytes(4, 'big')

        res += self.Length.to_bytes(2, 'big')

        res += self.RecvMaxPacketId.to_bytes(4, 'big')

        res += self.RecvBufferSize.to_bytes(8, 'big')

        res += self.LostPacketNum.to_bytes(1, 'big')

        for i in self.LostPacketIdArray:

            res += i.to_bytes(4, 'big')

        return res

    def size(self):
        '''

        返回该ack包的字节大小

        '''

        return HEAD_SIZE + self.Length


class DataPacket:
    '''

    数据包结构

    '''

    ContentType = 1  # 字节数为1，数据包恒为1

    PacketId = 0  # 字节数为4，该packId指示数据包的顺序，每次发送一个新数据包（非重传包）时自增1

    Length = 0  # 字节数为2，指示后面数据的总长度

    Reserve = 0  # 字节数为1，置为0，保留

    Data = b""  # 字节数为Length-1，数据内容

    DATA_OFFSET = 8

    def pack(self, packetId: int, data: bytes = b"", Status=0):
        """打包一个数据包，会修改当前实例


        Args:

            packetId (int): 数据包的packetId

            data (bytes, optional): 打包数据包的数据内容，默认为data

            Status (int, optional): 保留，置为0，可忽略


        Returns:

            DataPacket: 返回当前实例

        """

        self.PacketId = packetId

        self.Length = len(data) + 1

        self.Reserve = Status

        self.Data = data
        return self

    def unpack(self):
        """解包当前实例


        Returns:

            tuple[int,bytes]: 返回该数据包的packetId和data

        """

        return self.PacketId, self.Data

    def from_bytes(self, dataBytes):
        """根据字节流打包一个数据包


        Args:

            dataBytes (bytes): 字节流


        Returns:

            AckPacket: 返回当前实例

        """

        offset = 1

        self.PacketId = int.from_bytes(dataBytes[offset:offset + 4], 'big')

        offset += 4

        self.Length = int.from_bytes(dataBytes[offset:offset + 4], 'big')

        offset += 2

        self.Reserve = int.from_bytes(dataBytes[offset:offset + 1], 'big')

        self.Data = dataBytes[offset + 1:offset + self.Length]

        return self

    def to_bytes(self):
        """根据当前实例生成字节流


        Returns:

            bytes: 返回生成的字节流

        """

        res = b""

        res += self.ContentType.to_bytes(1, 'big')

        res += self.PacketId.to_bytes(4, 'big')

        res += self.Length.to_bytes(2, 'big')

        res += self.Reserve.to_bytes(1, 'big')

        res += self.Data
        return res

    def size(self):
        """根据当前实例生成字节流的大小


        Returns:

            int: 返回生成的字节流的大小

        """

        return HEAD_SIZE + self.Length


class SendPacketFactory:
    '''

    处理，加工待发送数据，实现超时重发与丢包重发的类

    这个类是整个可靠层实现的核心，大多数的bug基本都出现在这里
    

    工作流程如下：

    1. 上层调用recommentMaxDataPut方法，获取可传入数据量的大小

    2. 上层调用pack_data方法，将待发送的数据传入。在pack_data中，将数据打包成数据包，转换成字节流，存入cache_table中

    3. 上层调用get方法，取出在cache_table中待发送的字节流与需重传的字节流，返回字节流列表

    4. 上层调用putAck方法，将与本轮对应的ack包传入putAck方法中，更新工作状态 
    

    无论cache_table有无加工处理好的字节流，都要不断调用get方法，来实现SendPacketFactory的正常运作
    

    '''

    cache_table = None  # cache_table用于缓存数据包，字典类型，key为packetId，value为元组，元素为处理加工后的字节流和该字节流在已处理字节流的偏移

    packet_id_start = 1  # 用于记录当前缓存中最小的packetId，用于判断是否处于发送状态

    packet_id_end = 0  # 用于记录当前缓存中最大的packetId，用于判断是否处于发送状态

    send_packet_id_cur = 1  # 指示当前该发送的数据包

    buffer_size = 1024 * 100  # 缓冲区大小

    send_buffer_size = 0  # 记录已发送的数据大小，也可以表示当前发送的数据在整个已发送字节流的偏移

    recv_buffer_size = 0  # 记录已接收的数据大小

    put_buffer_size = 0  # 记录已传入数据的总大小

    fragment = 1400  # 分包大小，当数据包超过该值时，将数据分包发送

    put_ack_timeout = 0.1  # ack超时临界值，当ack数据包超时时，会触发超时重传

    last_check_time = 0  # 上次检查时间

    last_ack_time = 0  # 上次收到ack数据包的时间

    isBusy = False  # 是否处于发送状态

    connect_timeout = 3  # 连接超时临界值，当连接超时时，会触发连接断开异常

    cur_time = 0  # 当前时间

    lost_packet_id_table = None  # lost_packet_id_table，为None时为暂未收到ack数据包，为列表时为收到ack数据包。若列表为空，则未发生丢包。非空，则发生丢包。

    ack_max_recv_packet_id = 0  # 指示对端目前收到的数据包中packetId最大值

    ack_count = 0  # 指示从上一次检查开始，目前已经收到的ack包个数

    # cache_table中value元组的索引

    CACHE_DATA_INDEX = 0

    CACHE_OFFSET_INDEX = 1

    # 定义get方法的两种模式

    GET_NORMAL = 0

    GET_WITH_ACK = 1

    def __init__(self,
                 base_send_buffer_size=1024 * 10,
                 recv_ack_timeout=0.1,
                 connect_timeout=3,
                 fragment=1400,
                 **kwargs):
        """初始化发送数据包工厂


        Args:

            base_send_buffer_size (int, optional): 初始缓冲区大小

            recv_ack_timeout (float, optional): 超时重发临界值

            connect_timeout (int, optional): 超时断开连接临界值

            fragment (int, optional): 分包大小

        """

        self.cache_table = {}

        self.buffer_size = base_send_buffer_size

        self.put_ack_timeout = recv_ack_timeout

        self.connect_timeout = connect_timeout

        self.fragment = fragment

    def pack_data(self, data=b""):
        """传入待发送的数据。将数据打包并存入缓存。当数据大小超过分包大小时，

        会将数据根据拆分成多个包


        Args:

            data (bytes): 传入待发送的数据

        """

        offset = 0

        while offset < len(data):

            self.packet_id_end += 1

            buf = data[offset:offset + self.fragment]

            packet = DataPacket().pack(self.packet_id_end, buf)

            self.cache_table[self.packet_id_end] = (packet.to_bytes(),
                                                    self.put_buffer_size)

            self.put_buffer_size += len(buf)

            offset += self.fragment

    def putAck(self, Packet: AckPacket):
        """传入收到的ack包，根据ack包同步工作状态


        Args:

            Packet (AckPacket): 传入收到的ack包

        """

        ack_max_recv_packet_id, RecvBufferSize, lost_packet_id_table = Packet.unpack(
        )

        # 若该ack包的packetid小于当前已收到的ack包的packetid，说明这个ack包

        # 并非最新的ack包，忽略

        if ack_max_recv_packet_id < self.ack_max_recv_packet_id:
            return

        # 更新丢包表

        self.lost_packet_id_table = lost_packet_id_table

        # 更新实例的最大ack包指示数据包的packetid

        self.ack_max_recv_packet_id = ack_max_recv_packet_id

        # 当触发了超时重传后收到ack数据包，就重新设置待发送数据包指针

        if time() - self.last_ack_time > self.put_ack_timeout and self.isBusy:

            self.send_packet_id_cur = ack_max_recv_packet_id + 1

        self.recv_buffer_size = RecvBufferSize

        self.ack_count += 1

        self.last_ack_time = time()

        return

    def recommentMaxDataPut(self):
        """获取可传入数据量的大小。这个大小只是建议，并无强制性，实际传入大小可剩余也可超出该大小。

        传入过多会可能导致在断开连接后却仍然发送该数据的现象


        Returns:

            int: 返回建议传入的数据量

        """

        res = self.buffer_size + self.send_buffer_size - self.put_buffer_size

        if res < 0:

            res = 0

        return res

    def send_list_add(self, send_list: list, cache, onlyOnePacket=False):
        """将需要添加的数据缓存添加到分包列表上，添加的数据首先会尝试与最后一个分包合并，

        若合并后大于设定的分包大小，则通过append单独添加成为一个分包


        Args:

            send_list (list): 指定需要添加到的分包列表

            cache (tuple): 缓存元素

            onlyOnePacket (bool, optional): 设置列表中是否最多只为一个分包. 默认为False


        Returns:

            bool : 指示是否添加成功，True为添加成功，False为添加失败

        """

        data = cache[SendPacketFactory.CACHE_DATA_INDEX]

        if not send_list:

            send_list.append(data)

            return True

        data_size = len(data)

        last_send_data_size = len(send_list[-1])

        if last_send_data_size + data_size <= self.fragment:

            send_list[-1] += data

            return True

        # 此时合并后大于设定的分包大小，则通过append单独添加成为一个数据包

        else:

            if onlyOnePacket:

                # 由于设定了最多只能为一个数据包，直接返回False

                return False

            else:

                send_list.append(data)

                return True

    def get(self, way=GET_NORMAL):
        """从缓冲中获取待发送的数据包，并清除缓存中多余的数据


        Args:

            way (_type_, optional): 指定从缓存中取数据的方法，GET_NORMAL会根据send_buffer_size,

            recv_buffer_size,buffer_size调整本轮发送数据的大小，而且GET_WITH_ACK则不考虑，最多发送

            单个分包大小的数据


        Returns:

            list : 返回本轮需发送数据的分包列表

        """

        res_list = []

        self.cur_time = time()

        self._get_prepared()

        self._get_send_lost(res_list)

        self._get_send_packet(res_list, way)

        self._get_send_check_ack(res_list)

        return res_list

    def _get_prepared(self):
        '''

        判断是否处于发送状态

        '''

        if self.packet_id_start == self.packet_id_end + 1:

            # 执行到这里就代表缓存中没有数据，此时将isBusy置为False

            self.isBusy = False

        elif not self.isBusy:

            # 假若是正好从空闲状态切换到发送状态，则初始化下列值

            self.isBusy = True

            self.ack_count = 0

            self.last_check_time = time()

            self.last_ack_time = time()

        if self.ack_max_recv_packet_id > self.packet_id_end:

            raise PacketIDError()

    def _get_send_packet(self, send_list, way):
        '''

        发送数据包

        '''

        # 每轮最多添加32份缓存元素

        for i in range(32):

            if self.send_packet_id_cur <= self.ack_max_recv_packet_id:

                self.send_packet_id_cur = self.ack_max_recv_packet_id + 1

            if self.send_packet_id_cur > self.packet_id_end:

                break

            one_cache = self.cache_table[self.send_packet_id_cur]

            self.send_buffer_size = one_cache[
                SendPacketFactory.CACHE_OFFSET_INDEX]

            if way == SendPacketFactory.GET_NORMAL:

                if self.send_buffer_size - self.recv_buffer_size > self.buffer_size:

                    break

                self.send_list_add(send_list, one_cache)

            if way == SendPacketFactory.GET_WITH_ACK:

                if not self.send_list_add(
                        send_list, one_cache, onlyOnePacket=True):

                    break

            self.send_packet_id_cur += 1

    def _get_send_lost(self, send_list):
        '''

        根据丢包表来重发丢失的数据包，并删除不需要的缓存

        这个丢包表从ack包来

        '''

        if self.lost_packet_id_table:

            for i in self.lost_packet_id_table:

                lost_cache = self.cache_table.get(i, None)

                if not lost_cache:

                    raise LostPacketCache()

                self.send_list_add(send_list, lost_cache)

            for i in range(self.packet_id_start, self.lost_packet_id_table[0]):

                del self.cache_table[i]

                self.packet_id_start += 1

            self.lost_packet_id_table = None

        elif self.lost_packet_id_table == []:

            for i in range(self.packet_id_start,
                           self.ack_max_recv_packet_id + 1):

                del self.cache_table[i]

                self.packet_id_start += 1

            self.lost_packet_id_table = None

    def _get_send_check_ack(self, send_list):
        '''

        每隔一段时间检测一次是否需要重发数据包

        重发的方式就是直接发一个packet_id_start的数据包，等待对端的ack

        之后再根据ack来处理丢包

        '''

        if self.cur_time - self.last_check_time > self.put_ack_timeout and self.isBusy:

            if self.ack_count == 0:

                if self.cur_time - self.last_ack_time > self.connect_timeout:

                    raise ConnectClosed()

                if not send_list:

                    self.send_list_add(send_list,
                                       self.cache_table[self.packet_id_start])

            self.ack_count = 0

            self.last_check_time = time()


class RecvPacketFactory:
    '''

    解包，处理收到的数据
    

    其工作流程如下:

    1. 上层调用unpack方法，将接收到的数据传入。

    2. 上层调用get方法，获取解包后的数据
    

    '''

    cache_table = None  # 缓存表

    cur = 1  # 当前准备处理的索引

    recv_max_packet_id = 0  # 已收到的最大packet_id

    capacity = 192  # 缓存表的容量

    recv_buffer_size = 0  # 已收到的解包后总数据大小

    data_put = False  # 指示本轮是否收到了数据

    to_deal_buffer = b""  # 待处理的数据

    def __init__(self, capacity=192, **kwargs):

        self.cache_table = {}

        self.capacity = capacity

    def unpack(self, data):
        """将待解包的数据传入进行处理


        Args:

            data (bytes): 传入待解包的数据


        Returns:

            None

        """

        self.to_deal_buffer += data

        New_Ack_Packet = None

        while 1:

            buffer_size = len(self.to_deal_buffer)

            if buffer_size < HEAD_SIZE:

                break

            contentType = self.to_deal_buffer[0]

            Length = int.from_bytes(self.to_deal_buffer[5:7], 'big')

            if buffer_size < Length + HEAD_SIZE:

                break

            buffer = self.to_deal_buffer[:Length + HEAD_SIZE]

            self.to_deal_buffer = self.to_deal_buffer[Length + HEAD_SIZE:]

            if contentType == TYPE_ACK:

                packet = AckPacket().from_bytes(buffer)

                if not New_Ack_Packet:

                    New_Ack_Packet = packet
                    continue

                if New_Ack_Packet.RecvMaxPacketId < packet.RecvMaxPacketId:

                    New_Ack_Packet = packet
                    continue

                else:
                    continue

            if contentType == TYPE_DATA:

                packet = DataPacket().from_bytes(buffer)

                self._put(packet)

        return New_Ack_Packet

    def _put(self, packet: DataPacket):
        """处理数据包


        Args:

            packet (DataPacket): 待处理的数据包

        """

        packid, data = packet.unpack()

        # 指明有数据传入，表明需要回应ack包

        self.data_put = True

        if packid < self.cur:
            return

        if packid > self.cur + self.capacity:
            return

        if packid > self.recv_max_packet_id:

            self.recv_max_packet_id = packid

        one_cache = self.cache_table.get(packid, None)

        if not one_cache:

            self.cache_table[packid] = data

    def get(self):
        """获取解包后的数据


        Returns:

            tuple[bytes,AckPacket|None]: 返回解包后的数据与回复的ack包

        """

        res = b""

        ack_packet = None

        lost_packet_id_list = []

        if self.cur <= self.recv_max_packet_id:

            while 1:

                one_cache = self.cache_table.get(self.cur, None)

                if one_cache == None:

                    break

                else:

                    res += one_cache

                    del self.cache_table[self.cur]

                    self.cur += 1

            for i in range(self.cur, self.recv_max_packet_id + 1):

                one_cache = self.cache_table.get(i, None)

                if not one_cache:

                    lost_packet_id_list.append(i)
                    continue

            self.recv_buffer_size += len(res)

        if self.data_put:

            self.data_put = False

            ack_packet = AckPacket().pack(0, self.recv_max_packet_id,
                                          self.recv_buffer_size,
                                          lost_packet_id_list)

        return res, ack_packet


class P2PDecoratedReliableUdp:
    """

    将SendPacketFactory与RecvPacketFactory进行封装成通信实例。工作于可靠层内层

    """

    send_factory_object = None

    recv_factory_object = None

    out_buffer = b""

    def __init__(self, **kwargs):

        self.send_factory_object = SendPacketFactory(**kwargs)

        self.recv_factory_object = RecvPacketFactory(**kwargs)

    def _OutComing(self):

        if self.out_buffer:

            out = self.send_factory_object.get(SendPacketFactory.GET_WITH_ACK)

        else:

            out = self.send_factory_object.get(SendPacketFactory.GET_NORMAL)

        if out and self.out_buffer:

            out[0] = self.out_buffer + out[0]

            self.out_buffer = b""

        elif self.out_buffer:

            out = [self.out_buffer]

            self.out_buffer = b""

        return out

    def _Incoming(self, data):

        recv_ack_packet = self.recv_factory_object.unpack(data)

        if recv_ack_packet:

            self.send_factory_object.putAck(recv_ack_packet)

    def _Read(self):

        data, send_ack_packet = self.recv_factory_object.get()

        if send_ack_packet:

            self.out_buffer = send_ack_packet.to_bytes()

        return data

    def _Write(self, data):

        self.send_factory_object.pack_data(data)

    def _RecommendMaxSendDataSize(self):

        return self.send_factory_object.recommentMaxDataPut()


class ReliableUdpPacket:
    '''

    可靠层外层数据包格式

    '''

    ContentType = None

    Session = None

    Data = b""

    HEAD_SIZE = 6

    TYPE_START = 0

    TYPE_START_DONE = 1

    TYPE_END = 2

    TYPE_DATA = 3

    def pack(self, ContentType, session, Data=b""):

        self.ContentType = ContentType

        self.Session = session

        self.Data = Data
        return self

    def to_bytes(self):

        return self.ContentType.to_bytes(2, 'big') + self.Session + self.Data

    def from_bytes(self, buffer):

        self.ContentType = int.from_bytes(buffer[0:2], 'big')

        self.Session = buffer[2:6]

        self.Data = buffer[6:]

        return self


class ReliableUdpSocket:
    '''

    由ReliableUdpFactory进行实例化的会话实例

    实现类似于套接字的功能

    提供send,recv,close函数实现该实例的通信

    提供getStatus获取当前工作状态

    提供getDstAddress获取目标地址和端口

    提供getRecommendMaxSendDataSize获取推荐最大发送数据大小

    '''

    srcPort = 0

    dstAddress = None

    dstPort = 0

    factory_object = None  # 该会话实例所属的工厂实例

    P2PDecoratedReliableUdp_object = None  # 该会话实例的通信实例

    session = None  # 会话id

    status = 0  # 当前工作状态

    last_status_time = None  # 上一次状态更新时间

    STATUS_INIT = 0  # 指示正在建立连接中

    STATUS_CONNECT = 1  # 指示连接建立成功，可以收发数据

    STATUS_CLOSE = 2  # 指示连接已经断开

    def __init__(self, srcPort, dstAddress, dstPort, session,
                 **kwargs) -> None:

        self.P2PDecoratedReliableUdp_object = P2PDecoratedReliableUdp(**kwargs)

        self.srcPort = srcPort

        self.dstAddress = dstAddress

        self.dstPort = dstPort
        self.session = session

        self.last_status_time = time()

    def _setStatus(self, status: int):
        self.status = status

    def _resetStatusTime(self):

        self.last_status_time = time()

    def recv(self):
        """

        接收数据
        

        Raises:

            ConnectClosed: 当连接正在建立连接或已经断开时，抛出该异常


        Returns:

            bytes: 接收到的数据，若没有收到数据，则返回b''

        """

        if self.status == ReliableUdpSocket.STATUS_INIT:

            raise ConnectClosed()

        if self.status == ReliableUdpSocket.STATUS_CLOSE:

            raise ConnectClosed()

        return self.P2PDecoratedReliableUdp_object._Read()

    def send(self, data: bytes):
        """

        发送数据


        Args:

            data (bytes): 需要发送的数据


        Raises:

            ConnectClosed: 当连接正在建立连接或已经断开时，抛出该异常

        """

        if self.status == ReliableUdpSocket.STATUS_INIT:

            raise ConnectClosed()

        if self.status == ReliableUdpSocket.STATUS_CLOSE:

            raise ConnectClosed()

        self.P2PDecoratedReliableUdp_object._Write(data)

    def getStatus(self):
        """获取当前工作状态


        Returns:

            int: 当前的工作状态

        """
        return self.status

    def close(self):
        """

        关闭连接

        """

        self.status = ReliableUdpSocket.STATUS_CLOSE

    def getRecommendMaxSendDataSize(self):
        """获取推荐发送数据大小，实际发送数据的大小可大于此推荐值，也可小于

        但过实际发送数据过远远过大时，会影响其他连接正常运行


        Returns:

            int: 返回推荐发送数据大小

        """

        return self.P2PDecoratedReliableUdp_object._RecommendMaxSendDataSize()

    def getDstAddress(self):
        """返回目标地址和端口


        Returns:

            tuple[str,int]: 目标端口与地址

        """

        return (self.dstAddress, self.dstPort)


class ReliableUdpFactory:
    """
    实现udp可靠层的工厂类，工作于可靠层外层，通过处理可靠层外层来创建会话实例，负责处理传入数据并分发到各会话实例，从会话实例中获取传出数据

    """

    session_table = None

    to_send_packet_list = None  # 待发送列表

    to_accept_packet_table = None  # 待接受会话列表

    connectTimeout = 3

    def __init__(self, connectTimeout=3, **kwargs) -> None:
        """初始化可靠层工厂类


        Args:

            connectTimeout (int, optional): 连接超时时间

        """

        self.session_table = {}

        self.to_send_packet_list = []

        self.to_accept_packet_table = {}

        self.connectTimeout = connectTimeout

        self.kwargs = kwargs

    def Incoming(self, packet: Communicate_Package):
        """

        传入所有运作于该协议的数据包，根据该数据包进行工作，处理与分发


        Args:

            packet (Communicate_Package): 传入所有运作于该协议的数据包

        """

        # 解包

        dstAddress, dstPort, srcPort, Data = packet.unpack_addr_str()

        reliableUdpPacket = ReliableUdpPacket().from_bytes(Data)

        session = reliableUdpPacket.Session

        if reliableUdpPacket.ContentType == ReliableUdpPacket.TYPE_DATA:

            # 若为TYPE_DATA包，传入到对应的会话实例

            socket = self.session_table.get(session, None)

            if socket:

                socket.P2PDecoratedReliableUdp_object._Incoming(
                    Data[ReliableUdpPacket.HEAD_SIZE:])

            else:

                self._put(dstAddress, dstPort, srcPort,
                          ReliableUdpPacket.TYPE_END, session)

        if reliableUdpPacket.ContentType == ReliableUdpPacket.TYPE_START:

            # 若为TYPE_START包，新建会话实例

            if self.session_table.get(session, None):

                self._put(dstAddress, dstPort, srcPort,
                          ReliableUdpPacket.TYPE_END, session)
                return

            socket = ReliableUdpSocket(srcPort=srcPort,
                                       dstAddress=dstAddress,
                                       dstPort=dstPort,
                                       session=session,
                                       **self.kwargs)

            socket._setStatus(ReliableUdpSocket.STATUS_CONNECT)

            socket._resetStatusTime()

            log.debug(f"socket-{socket.session.hex()}:TYPE_START包，新建会话实例")

            self.session_table[socket.session] = socket

            # 把该会话实例加入待接受会话列表

            accept_list = self.to_accept_packet_table.get(srcPort, None)

            if not accept_list:

                self.to_accept_packet_table[srcPort] = [socket]

            else:

                accept_list.append(socket)

        if reliableUdpPacket.ContentType == ReliableUdpPacket.TYPE_START_DONE:

            # 若为TYPE_START_DONE包，指示对端已建立好会话实例，此时将此会话实例的工作状态由STATUS_INIT转变为STATUS_CONNECT


            socket: ReliableUdpSocket = self.session_table.get(session, None)

            if not socket:

                self._put(socket.dstAddress, socket.dstPort, socket.srcPort,
                          ReliableUdpPacket.TYPE_END, socket.session)

            if socket.status == ReliableUdpSocket.STATUS_INIT:

                socket._setStatus(ReliableUdpSocket.STATUS_CONNECT)

                socket._resetStatusTime()

            log.debug(f"socket-{socket.session.hex()}: TYPE_START_DONE包")

        if reliableUdpPacket.ContentType == ReliableUdpPacket.TYPE_END:

            # 若为TYPE_END包，则将该会话实例状态设置为关闭

            socket: ReliableUdpSocket = self.session_table.get(session, None)

            if not socket:
                return

            log.debug(f"socket-{socket.session.hex()}: TYPE_END包")

            socket._setStatus(ReliableUdpSocket.STATUS_CLOSE)

    def Outcoming(self) -> tuple:
        """获取发送的数据包

        Returns:
            tuple: 返回需发送的数据包元组
        """

        res = tuple(self.to_send_packet_list)

        self.to_send_packet_list.clear()
        return res

    def _clean_one_socket(self, session):
        """清理单个会话实例

        Args:
            session (bytes): 该会话实例的会话id
        """

        if self.session_table.get(session, None):

            socket = self.session_table[session]

            self._put(socket.dstAddress,
                      socket.dstPort,
                      socket.srcPort,
                      ReliableUdpPacket.TYPE_END,
                      socket.session,
                      flag=FLAG_CLOSED)

            del self.session_table[session]

    def _clean_all_socket(self):
        """
        清理该工厂实例所有的会话实例
        """

        for i in self.session_table.keys():

            self._clean_one_socket(i)

    def check(self):
        """
        负责整个工厂的正常运作，检查，更新，清理会话实例
        需要不间断调用
        """

        to_del_session_list = []

        cur_time = time()

        # 检查待接受会话列表中的会话实例，若超时仍未被接受，则关闭
        for i in self.to_accept_packet_table.keys():

            for j in self.to_accept_packet_table[i]:

                one_accept_socket: ReliableUdpSocket = j

                if cur_time - one_accept_socket.last_status_time > self.connectTimeout:

                    log.debug(
                        f"session-{one_accept_socket.session.hex()}: 待接受会话列表中的会话实例超时，关闭"
                    )

                    one_accept_socket.close()

        # 检查会话实例
        for i in self.session_table:

            socket: ReliableUdpSocket = self.session_table[i]

            if socket.status == ReliableUdpSocket.STATUS_CONNECT:

                # 获取每个会话实例需要传出的数据，添加到待发送列表中
                try:

                    outComing_data_list = socket.P2PDecoratedReliableUdp_object._OutComing(
                    )

                    for i in outComing_data_list:

                        self._put(socket.dstAddress, socket.dstPort,
                                  socket.srcPort, ReliableUdpPacket.TYPE_DATA,
                                  socket.session, i)

                except ConnectClosed:

                    log.debug(f"session-{socket.session.hex()}: 会话实例连接关闭")
                    socket._setStatus(ReliableUdpSocket.STATUS_CLOSE)

                except PacketIDError:

                    log.debug(f"session-{socket.session.hex()}: 包ID错误")
                    socket._setStatus(ReliableUdpSocket.STATUS_CLOSE)

            if socket.status == ReliableUdpSocket.STATUS_INIT:

                # 对于正在建立连接的会话实例，检查是否超时

                if cur_time - socket.last_status_time > self.connectTimeout:

                    log.debug(f"session-{socket.session.hex()}: 连接超时")

                    socket._setStatus(ReliableUdpSocket.STATUS_CLOSE)

                    to_del_session_list.append(i)
                    continue

            if socket.status == ReliableUdpSocket.STATUS_CLOSE:

                # 对于已经关闭的会话实例，添加到待删除列表中

                to_del_session_list.append(i)
                continue

        # 遍历待删除列表中的会话实例，进行清理
        for i in to_del_session_list:

            self._clean_one_socket(i)

    def _put(self,
             dstAddress,
             dstPort,
             srcPort,
             contentType,
             session,
             data=b"",
             flag=0):
        """对待发送数据包进行可靠层外层打包，并转换成Communicate_Package，并添加到待发送列表中

        Args:
            dstAddress (str): 目标地址
            dstPort (int): 目标端口
            srcPort (int): 本地端口
            contentType (int): 包类型
            session (bytes): 会话id
            data (bytes, optional): 待打包的数据
            flag (int, optional): Communicate_Package的flag值
        """

        reliableUdpPacket = ReliableUdpPacket().pack(contentType, session,
                                                     data)

        communicate_Package = Communicate_Package().pack_addr_str(
            dstAddress, dstPort, srcPort, reliableUdpPacket.to_bytes())

        communicate_Package.setFlag(flag)

        self.to_send_packet_list.append(communicate_Package)

    def accept(self, bind_port) -> "ReliableUdpSocket | None":
        """类似于非阻塞的socket.accept()，但未接受到连接时返回None而非抛出异常

        Args:
            bind_port (int): 绑定监听的端口

        Returns:
            ReliableUdpSocket|None: 返回一个会话实例，若未接受到连接则返回None
        """

        accept_list = self.to_accept_packet_table.get(bind_port, None)

        if not accept_list:

            return None

        socket: ReliableUdpSocket = accept_list.pop(0)

        self._put(socket.dstAddress, socket.dstPort, socket.srcPort,
                  ReliableUdpPacket.TYPE_START_DONE, socket.session)

        if len(accept_list) == 0:

            del self.to_accept_packet_table[bind_port]

        return socket

    def connect(self, dstAddress, dstPort, bind_port) -> ReliableUdpSocket:
        """类似于非阻塞的socket.connect()，但必定返回一个会话实例

        Args:
            dstAddress (str): 目标地址
            dstPort (int): 目标端口
            bind_port (int): 本地绑定端口

        Returns:
            ReliableUdpSocket: 返回一个状态为STATUS_INIT的会话实例
            
        """

        session = (int(time()) & 0xffffffff).to_bytes(4, 'big')

        self._put(dstAddress,
                  dstPort,
                  bind_port,
                  ReliableUdpPacket.TYPE_START,
                  session,
                  flag=FLAG_CONNECT)

        socket = ReliableUdpSocket(bind_port,
                                   dstAddress=dstAddress,
                                   dstPort=dstPort,
                                   session=session,
                                   **self.kwargs)


        socket._setStatus(ReliableUdpSocket.STATUS_INIT)

        self.session_table[socket.session] = socket

        log.debug(f"create socket, session: {socket.session.hex()}")

        return socket
