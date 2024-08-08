from ..include.ContextHead import *
from ..include.simpleFunc import *
from ..include.VpnContextContentType import *
from .VpnCrypto import *
from time import time
from queue import Queue

import logging

log = logging.getLogger()


class OPCODE:
    """openvpn packet opcode_
    """
    P_CONTROL_SOFT_RESET_V1 = 0x03
    P_CONTROL_V1 = 0x04
    P_ACK_V1 = 0x05
    P_DATA_V1 = 0x06
    P_CONTROL_HARD_RESET_CLIENT_V2 = 0x07
    P_CONTROL_HARD_RESET_SERVER_V2 = 0x08
    P_DATA_V2 = 0x09



class VpnRecordPacket:
    """openvpn 控制通道记录层包结构

    """

    PacketLength = 0
    Opcode = 0
    KeyId = 0
    PeerId = 0
    SessionId = b''
    PacketIdArrayLength = 0
    PacketIdArray = []
    RemoteSessionId = 0
    MessagePacketId = 0

    def __str__(self) -> str:
        return f"""
    [VpnRecordPacket]
    
    PacketLength: {self.PacketLength}
    Opcode: {self.Opcode}
    KeyId: {self.KeyId}
    PeerId: {self.PeerId}
    SessionId: {self.SessionId}
    PacketIdArrayLength: {self.PacketIdArrayLength}
    PacketIdArray: {self.PacketIdArray}
    RemoteSessionId: {self.RemoteSessionId}
    MessagePacketId: {self.MessagePacketId}

    """

    def __init__(self,
                 dataBytes: bytes = None,
                 Opcode=OPCODE.P_ACK_V1,
                 payloadLength=None,
                 KeyId=0,
                 PeerId=0,
                 SessionId=b'',
                 PacketIdArray=[],
                 RemoteSessionId=b'',
                 MessagePacketId=0):

        """
        初始化一个控制通道包
        当存在dataBytes时，会根据dataBytes字节流初始化当前实例
        若不存在，会根据剩下的参数来初始化当前实例
        """

        if dataBytes:
            offset = 0

            self.PacketLength = getWord(dataBytes, offset, 'big')
            offset += 2

            self.Opcode = dataBytes[offset] >> 3 & 0x1f
            self.KeyId = dataBytes[offset] & 0x7
            offset += 1

            if self.Opcode == OPCODE.P_DATA_V1:
                return

            if self.Opcode == OPCODE.P_DATA_V2:
                self.PeerId = int.from_bytes(dataBytes[offset:offset + 3],
                                             'big')
                return

            self.SessionId = dataBytes[offset:offset + 8]
            offset += 8

            self.PacketIdArrayLength = dataBytes[offset]
            offset += 1

            for i in range(offset, offset + 4 * self.PacketIdArrayLength, 4):
                self.PacketIdArray.append(getDword(dataBytes, i, 'big'))

            offset += 4 * self.PacketIdArrayLength

            if self.PacketIdArrayLength != 0:
                self.RemoteSessionId = dataBytes[offset:offset + 8]
                offset += 8

            if self.Opcode != OPCODE.P_ACK_V1:
                self.MessagePacketId = getDword(dataBytes, offset, 'big')

        else:

            self.Opcode = Opcode
            self.KeyId = KeyId
            self.PeerId = PeerId
            self.SessionId = SessionId
            self.PacketIdArrayLength = len(PacketIdArray)
            self.PacketIdArray = PacketIdArray
            self.RemoteSessionId = RemoteSessionId
            self.MessagePacketId = MessagePacketId

            if payloadLength:
                self.PacketLength = self.size() + payloadLength - 2

            else:
                self.PacketLength = self.size() - 2

    def B(self):
        """根据当前实例生成字节流

        Returns:
            bytes: 返回生成的字节流
        """

        res = b""
        res += self.PacketLength.to_bytes(2, 'big')
        res += (self.Opcode << 3 | self.KeyId).to_bytes(1, 'big')

        if self.Opcode == OPCODE.P_DATA_V1:
            return res

        if self.Opcode == OPCODE.P_DATA_V2:
            res += self.PeerId.to_bytes(3, 'big')
            return res

        res += self.SessionId
        res += self.PacketIdArrayLength.to_bytes(1, 'big')

        for i in range(self.PacketIdArrayLength):
            res += self.PacketIdArray[i].to_bytes(4, 'big')

        if self.PacketIdArrayLength != 0:
            res += self.RemoteSessionId

        if self.Opcode != OPCODE.P_ACK_V1:
            res += self.MessagePacketId.to_bytes(4, 'big')

        return res

    def size(self):
        """返回当前实例的字节流长度

        Returns:
            int: 返回当前实例的字节流长度
        """
        return len(self.B())


class VpnTLSMethod2Packet:
    """openvpn 控制通道信息包
    """

    Zero = 0
    master_secret = b''
    random_1 = b''
    random_2 = b''
    occ = b''
    username = b''
    password = b''
    additionalInformation = []

    mode = 0
    MODE_CLIENT = 0
    MODE_SERVER = 1

    def __str__(self) -> str:
        return f"""
    [VpnPacket]
    
    master_secret: {bytes2HexList(self.master_secret)}
    random_1: {bytes2HexList(self.random_1)}
    random_2: {bytes2HexList(self.random_2)}
    occ: {self.occ}
    username: {self.username}
    password: {bytes2HexList(self.password)}
    additionalInformation: {self.additionalInformation}
    
    """

    def __init__(self,
                 mode=MODE_CLIENT,
                 dataBytes: bytes = None,
                 master_secret=b"",
                 random_1=b"",
                 random_2=b"",
                 occ=b"",
                 username=b"",
                 password=b"",
                 additionalInformation=[]):
        '''
        初始化当前实例
        '''
        self.mode = mode

        if dataBytes:
            offset = 5

            if mode == self.MODE_CLIENT:
                self.master_secret = dataBytes[offset:offset + 48]
                offset += 48

            self.random_1 = dataBytes[offset:offset + 32]
            offset += 32

            self.random_2 = dataBytes[offset:offset + 32]
            offset += 32

            occ_size = getWord(dataBytes, offset, 'big')
            offset += 2

            self.occ = dataBytes[offset:offset + occ_size]
            offset += occ_size

            if len(dataBytes) == offset:
                self.username = None
                self.password = None
                return

            username_length = getWord(dataBytes, offset, 'big')
            offset += 2

            self.username = dataBytes[offset:offset + username_length]
            offset += username_length

            password_length = getWord(dataBytes, offset, 'big')
            offset += 2

            self.password = dataBytes[offset:offset + password_length]
            offset += password_length

            while offset < len(dataBytes):
                additionalInformation_length = getWord(dataBytes, offset,
                                                       'big')
                offset += 2

                self.additionalInformation.append(
                    dataBytes[offset:offset + additionalInformation_length])
                offset += additionalInformation_length

        else:
            self.master_secret = master_secret
            self.random_1 = random_1
            self.random_2 = random_2
            self.occ = occ

            if username:
                self.username = username
                self.password = password
                self.additionalInformation = additionalInformation

    def to_bytes(self):
        """根据当前实例生成字节流
        """

        res = b"\x00\x00\x00\x00\x02"

        if self.mode == self.MODE_CLIENT:
            res += self.master_secret

        res += self.random_1 + self.random_2
        res += len(self.occ).to_bytes(2, 'big') + self.occ

        if self.username == None:
            return res

        res += len(self.username).to_bytes(2, 'big') + self.username
        res += len(self.password).to_bytes(2, 'big') + self.password

        for i in self.additionalInformation:
            res += len(i).to_bytes(2, 'big') + i

        return res

    def size(self):
        """
        返回当前实例的字节流长度
        """
        return len(self.to_bytes())

class Vpn(Context_Child):

    record_buffer = b""     # 保存上轮解包openvpn记录层后剩下的数据

    LocalSessionId = b""    # 记录层本地会话id
    RemoteSessionId = b''   # 记录层远程会话id
    RemoteOnePacketId = -1  # 记录层远程packetId
    MessagePacketId = 0     # 记录层MessagePacketId

    pre_master_secret = b"" # openvpn加密用的预主密钥
    client_random_1 = b""   # 客户端随机数1
    client_random_2 = b""   # 客户端随机数2
    client_occ = b''        # 客户端的occ信息
    server_random_1 = b''   # 服务端随机数1
    server_random_2 = b''   # 服务端随机数2
    server_occ = b''        # 服务端的occ信息

    cipher = 0              # 加密算法
    auth = 0                # hmac算法
    key_direction = 0       # 密钥方向，见openvpn文档

    Status = 0

    # 工作状态
    VPN_STATUS_INIT = 0
    VPN_STATUS_SEND_CLIENT_HARD_RESET = 1
    VPN_STATUS_RECV_SERVER_HARD_RESET = 2
    VPN_STATUS_DO_HANDSHARK = 3
    VPN_STATUS_FINISH_TLS_HANDSHARK = 4
    VPN_STATUS_SEND_KEY_EXCHANGE = 5
    VPN_STATUS_RECV_KEY_EXCHANGE = 6
    VPN_STATUS_KEY_GENERATED = 7
    VPN_STATUS_CLIENT_PREPARE_HARD_RESET = 8
    VPN_STATUS_CLIENT_DONE_PREPARE_HARD_RESET = 9

    mtu = 1024
    library_path = ''
    start_time = 0
    max_run_time = 0

    appliaction_send_msg_queue = None

    def __init__(self,
                 context,
                 library_path,
                 occ_string,
                 cipher=VpnCrypto.CBC_128,
                 auth=VpnCrypto.HMAC_SHA1,
                 key_direction=0,
                 mtu=1024,
                 max_run_time=3600,
                 ):

        super(Vpn, self).__init__(context=context)
        self.cipher = cipher
        self.auth = auth
        self.key_direction = key_direction
        self.mtu = mtu
        self.library_path = library_path
        self.appliaction_send_msg_queue = Queue()
        self.max_run_time = max_run_time

        if occ_string:
            self.client_occ = occ_string + b"\x00"

    def soft_reset(self, event: Event):
        """
        重新初始化当前实例
        """
        self._new_session()

    def _new_session(self):
        """
        初始化一个新会话
        """

        log.info("vpn 新会话初始化")

        self.RemoteOnePacketId = 0
        self.MessagePacketId = 0

        self.LocalSessionId = urandom(8)
        self.pre_master_secret = urandom(48)
        self.client_random_1 = urandom(32)
        self.client_random_2 = urandom(32)
        self.start_time = time()

    def openvpn_record_tls_pack(self, event: Event):
        """将事件链上的tls传出数据包包装一层openvpn记录层

        """

        if len(event.Payload) < self.mtu:
            data = self._pack_openvpn_record(OPCODE.P_CONTROL_V1,
                                             event.Payload)
            self.package_reset(event, contentType=TLS_SEND_DATA, payload=data)
            return

        offset = 0

        while offset < len(event.Payload):
            data = self._pack_openvpn_record(
                OPCODE.P_CONTROL_V1, event.Payload[offset:offset + self.mtu])
            self.createEvent(VPN_RECORD_CONTROL_SEND_RESTRUCT, data)
            offset += self.mtu

        self.package_throw(event)
        return

    def openvpn_record_data_pack(self, event: Event):
        """对事件链上的应用数据包装一层openvpn记录层
        
        """

        data = self._pack_openvpn_record(OPCODE.P_DATA_V1, event.Payload)

        self.package_reset(event, payload=data)

    def openvpn_record_unpack(self, event: Event):
        """对事件链上的传入数据进行openvpn记录层解包
        
        """

        self.record_buffer = self.record_buffer + event.Payload

        # 判断是否接收到足够的数据
        if len(self.record_buffer) < 2:
            self.package_throw(event)
            return

        size = getWord(self.record_buffer, 0, 'big')

        if len(self.record_buffer) < size + 2:
            self.package_throw(event)
            return

        data = self.record_buffer[:size + 2]
        self.record_buffer = self.record_buffer[size + 2:]

        package = VpnRecordPacket(dataBytes=data)

        if package.Opcode == OPCODE.P_ACK_V1:
            # 对ack包进行处理
            self.package_throw(event)
            return

        if package.Opcode == OPCODE.P_DATA_V1 or package.Opcode == OPCODE.P_DATA_V2:
            # 对数据通道包进行处理
            payload = data[package.size():]
            self.package_reset(event, VPN_DATA_RECV, payload)
            return

        # 执行到这里，则该数据包为控制通道包

        # 判断是否为重置包
        if package.MessagePacketId != (self.RemoteOnePacketId + 1):

            if package.MessagePacketId == 0 and (
                    package.Opcode == OPCODE.P_CONTROL_HARD_RESET_SERVER_V2
                    or package.Opcode == OPCODE.P_CONTROL_SOFT_RESET_V1):
                pass
            else:
                self.package_throw(event)
                return

        # 根据数据包同步一些变量，并回复ack
        self.RemoteOnePacketId = package.MessagePacketId
        self.RemoteSessionId = package.SessionId
        self._send_ack(package.KeyId)

        # 根据控制通道包的记录层类型进行处理
        if package.Opcode == OPCODE.P_CONTROL_HARD_RESET_SERVER_V2:
            if self.Status == Vpn.VPN_STATUS_SEND_CLIENT_HARD_RESET:
                self.Status = Vpn.VPN_STATUS_RECV_SERVER_HARD_RESET
                self.package_throw(event)

            elif self.Status == Vpn.VPN_STATUS_CLIENT_DONE_PREPARE_HARD_RESET:
                self.Status = Vpn.VPN_STATUS_RECV_SERVER_HARD_RESET
                self.createEvent(VPN_HARD_RESET)

        elif package.Opcode == OPCODE.P_CONTROL_SOFT_RESET_V1:

            if self.Status in (Vpn.VPN_STATUS_KEY_GENERATED,Vpn.VPN_STATUS_CLIENT_PREPARE_HARD_RESET,Vpn.VPN_STATUS_CLIENT_DONE_PREPARE_HARD_RESET):
                self._prepare_hard_reset()
                self.Status = Vpn.VPN_STATUS_CLIENT_PREPARE_HARD_RESET


        else:
            payload = data[package.size():]
            self.package_reset(event, VPN_CONTROL_RECV, payload)

    def simplvpn_hook_tls_handshark_finish(self, event: Event):
        """当事件链中触发，tls握手完成事件，执行此函数

        """
        if self.Status == Vpn.VPN_STATUS_DO_HANDSHARK:
            self.Status = Vpn.VPN_STATUS_FINISH_TLS_HANDSHARK

    def recv_tls_text(self, event: Event):
        """
        接收事件链中，openvpn控制通道数据包，进行openvpn的密钥协商，occ信息交换等
        """
        if self.Status == Vpn.VPN_STATUS_SEND_KEY_EXCHANGE:
            self.Status = Vpn.VPN_STATUS_KEY_GENERATED

        # elif self.Status == Vpn.VPN_STATUS_RECV_KEY_EXCHANGE:
        #     self.Status = Vpn.VPN_STATUS_KEY_GENERATED

        else:
            log.debug(f"recv_tls_text in error status:{event.Payload}")
            return

        package = VpnTLSMethod2Packet(VpnTLSMethod2Packet.MODE_SERVER,
                                      event.Payload)


        self.server_occ = package.occ
        self.server_random_1 = package.random_1
        self.server_random_2 = package.random_2


        log.debug(f"server_occ={self.server_occ}")
        log.debug(f"server_random_1={self.server_random_1.hex()}")
        log.debug(f"server_random_2={self.server_random_2.hex()}")

        self._cipher_init()



    def vpn_decrypto_application_data(self, event: Event):
        """将事件链中传入的应用数据进行解密
        并修改事件实例，将事件内容修改为解密后的字节流
        """

        if self.Status not in (Vpn.VPN_STATUS_KEY_GENERATED,Vpn.VPN_STATUS_CLIENT_PREPARE_HARD_RESET,Vpn.VPN_STATUS_CLIENT_DONE_PREPARE_HARD_RESET):
            self.package_throw(event)
            return

        data = self._decrypto(event.Payload)
        self.package_reset(event, payload=data)


    def vpn_encrypto_appliaction_data(self, event: Event):
        """将事件链中传出的应用数据放入到待加密队列中去
        """

        self.appliaction_send_msg_queue.put(event.Payload)


    def _cipher_init(self):
        """密钥协商完成后，初始化加密解密实例
        """
        self.Crypto_Object = VpnCrypto(
            self.library_path, self.cipher, self.auth, self.pre_master_secret,
            self.client_random_1, self.client_random_2, self.server_random_1,
            self.server_random_2, self.LocalSessionId, self.RemoteSessionId,
            self.key_direction)

    def _encrypto(self, data):
        """根据上下文对数据进行加密

        Args:
            data (bytes): 待加密字节流

        Returns:
            bytes: 返回加密后的字节流
        """
        return self.Crypto_Object.encrypto(data)

    def _decrypto(self, data):
        """根据上下文对数据进行解密

        Args:
            data (bytes): 待解密字节流

        Returns:
            bytes: 返回解密后的字节流
        """

        return self.Crypto_Object.decrypto(data)

    def _pack_openvpn_record(self, Opcode, data=b"", keyId=0):
        """用openvpn记录层包装数据

        Args:
            Opcode (int): 记录层的Opcode
            data (bytes, optional): 待包装的数据
            keyId (int, optional): 记录层的keyId

        Returns:
            bytes : 返回包装后的字节流
        """

        package = VpnRecordPacket(Opcode=Opcode,
                                  KeyId=keyId,
                                  payloadLength=len(data),
                                  SessionId=self.LocalSessionId,
                                  PacketIdArray=[self.RemoteOnePacketId],
                                  RemoteSessionId=self.RemoteSessionId,
                                  MessagePacketId=self.MessagePacketId)

        if Opcode != OPCODE.P_DATA_V1 and Opcode != OPCODE.P_DATA_V2 and Opcode != OPCODE.P_ACK_V1:
            self.MessagePacketId += 1

        return package.B() + data

    def _send_ack(self, keyId=0):
        """发送ack包

        Args:
            keyId (int, optional): 记录层keyId值
        """
        ack_bytes_data = self._pack_openvpn_record(OPCODE.P_ACK_V1,
                                                   keyId=keyId)
        self.createEvent(VPN_SEND_DATA, ack_bytes_data)

    def _send_client_hard_reset(self):
        """发送状态重置包
        """
        client_hard_reset_bytes_data = VpnRecordPacket(
            Opcode=OPCODE.P_CONTROL_HARD_RESET_CLIENT_V2,
            SessionId=self.LocalSessionId).B()
        self.MessagePacketId += 1
        self.createEvent(VPN_SEND_DATA, client_hard_reset_bytes_data)

    def _send_key_exchange(self):
        """
        发送密钥协商包
        """

        log.debug(f"pre_master_secret={self.pre_master_secret.hex()}")
        log.debug(f"client_random_1={self.client_random_1.hex()}")
        log.debug(f"client_random_2={self.client_random_2.hex()}")
        log.debug(f"client_occ={self.client_occ}")

        package = VpnTLSMethod2Packet(master_secret=self.pre_master_secret,
                                      random_1=self.client_random_1,
                                      random_2=self.client_random_2,
                                      occ=self.client_occ)
        self.createEvent(TLS_SEND_APPLICATION_DATA, package.to_bytes())

    def _check_send_application_data(self):
        """检查是否有应用数据需要发送
        若有，则尝试进行加密并发送
        
        事件类型 : VPN_APPLICATION_DATA_SEND
        事件内容 : bytes 待发送的加密后应用数据
        """
        while 1:
            if self.appliaction_send_msg_queue.empty():
                break

            data = self.appliaction_send_msg_queue.get()
            data = self._encrypto(data)
            self.createEvent(VPN_APPLICATION_DATA_SEND, data)

    def _prepare_hard_reset(self):
        """进行状态重置前置
        
        事件类型 : VPN_PREPARE_HARD_RESET
        事件内容 : None
        """
        self.createEvent(VPN_PREPARE_HARD_RESET)

    def _prepare_hard_reset_check(self):
        """进行状态重置前置准备
        
        Returns:
            bool: 若为True，说明前置完成，否则返回False
        """
        self._new_session()
        self._send_client_hard_reset()
        return True


    def check(self):
        """检查当前的运行状态并进行相应处理
        """

        if len(self.record_buffer) >= 2:
            if len(self.record_buffer) >= getWord(self.record_buffer, 0,
                                                  'big') + 2:
                self.createEvent(VPN_RECORD_DATA_RECV_RESTRUCT, b"")

        if self.Status == Vpn.VPN_STATUS_INIT:

            log.debug("VPN_STATUS_INIT")

            self._send_client_hard_reset()
            self.Status = Vpn.VPN_STATUS_SEND_CLIENT_HARD_RESET

        elif self.Status == Vpn.VPN_STATUS_RECV_SERVER_HARD_RESET:

            log.debug("VPN_STATUS_RECV_SERVER_HARD_RESET")

            self.createEvent(TLS_DO_HANDSHARK)
            self.Status = Vpn.VPN_STATUS_DO_HANDSHARK

        elif self.Status == Vpn.VPN_STATUS_DO_HANDSHARK:

            log.debug("VPN_STATUS_DO_HANDSHARK")

            self.createEvent(TLS_DO_HANDSHARK)

        elif self.Status == Vpn.VPN_STATUS_FINISH_TLS_HANDSHARK:

            log.debug("VPN_STATUS_FINISH_TLS_HANDSHARK")

            self._send_key_exchange()
            self.Status = Vpn.VPN_STATUS_SEND_KEY_EXCHANGE

        elif self.Status == Vpn.VPN_STATUS_KEY_GENERATED:

            self._check_send_application_data()

            if self.max_run_time > 0 and time(
            ) - self.start_time > self.max_run_time:
                self._prepare_hard_reset()
                self.Status = Vpn.VPN_STATUS_CLIENT_PREPARE_HARD_RESET

        elif self.Status == Vpn.VPN_STATUS_CLIENT_PREPARE_HARD_RESET:


            toContinue = self._prepare_hard_reset_check()

            if toContinue:
                self.Status = Vpn.VPN_STATUS_CLIENT_DONE_PREPARE_HARD_RESET

        elif self.Status == Vpn.VPN_STATUS_CLIENT_DONE_PREPARE_HARD_RESET:

            self._check_send_application_data()
