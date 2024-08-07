from ..include.ContextHead import *
from ..include.ProjectContextContentType import *
from ..include.DecoratedReliableUdp import *
from ..include.ForwardHead import *
from ..include.simpleFunc import *
from time import time
import socket
import logging

log = logging.getLogger()

class oneConnect:

    Init_Start_Time = 0  # 生成实例时的时间，用于判断处于INIT_STATUS的应用会话是否超时
    Status = 0  # 当前的工作状态
    Identification = b""  # Forward包标识一个应用连接的IDENTIFICATION
    send_in_buffer = b""  # 待发送到应用的数据
    Socket_Object = None  # 与应用通信的套接字对象

    INIT_STATUS = 0
    RUNTIME_STATUS = 1
    CLOSE_STATUS = 2

    def __init__(self, identfication, socket_object):
        self.Init_Start_Time = time()
        self.send_in_buffer = b""
        self.Identification = identfication
        self.Socket_Object = socket_object


class SimpleForwardClient(Context_Child):

    reliableUdpFactory = None  # 可靠UDP工厂实例
    communicate_socket = None  # 与server通信的可靠udp通信实例
    connectTimeout = 3  # 连接超时时间
    cur_time = 0  # 当前时间
    status = 0  # 当前的工作状态
    recv_buffer_size = 256  # 单次从套接字接收tcp数据大小

    default_Table = None  # 默认的端口转发表
    forward_client_table = None  # 远程绑定端口与本地绑定端口地址的映射表
    socket_table = None  # 应用会话与oneConnect实例的映射表

    Wait_Init_Time = 3    # 开始进行连接初始化的等待时间，目的是防止在openvpn未完成握手的情况下就启动
    Last_Status_Time = 0  # 原本打算用于上一次更改工作状态的时间，目前只在实例初始化时赋值，没有在其他地方修改其值

    forward_server_address = b""   # 服务端地址
    forward_server_bind_port = 0   # 服务端端口
    forward_client_bind_port = 0   # 本地通讯端口

    STATUS_PRE_INIT = 0
    STATUS_INIT = 1
    STATUS_RUN = 2

    BIND_IP_INDEX = 0
    BIND_PORT_INDEX = 1
    REMOTE_PORT_INDEX = 2
    buffer = b""

    def __init__(self,
                 context: Context,
                 forward_client_bind_port=6672,
                 forward_server_bind_port=6672,
                 forward_server_address='127.0.0.1',
                 default_Table=(),
                 recv_buffer_size=256,
                 Wait_Init_Time = 3,
                 **kwargs):
        super().__init__(context)

        self.reliableUdpFactory = ReliableUdpFactory(**kwargs)
        self.forward_client_bind_port = forward_client_bind_port
        self.forward_server_bind_port = forward_server_bind_port
        self.forward_server_address = forward_server_address
        self.default_Table = default_Table
        self.forward_client_table = {}
        self.socket_table = {}
        self.recv_buffer_size = recv_buffer_size
        self.Wait_Init_Time = Wait_Init_Time
        self.Last_Status_Time = time()

    def recv_data(self, event: Event):
        """从事件链中获取udp数据并处理
        
        """
        self.reliableUdpFactory.Incoming(event.Payload)

    def _check_outcoming(self):
        """检查是否有需要发送的udp数据
        
        事件类型 : VPN_UDP_SEND
        事件内容 : Communicate_Package实例
        """
        outPut_list = self.reliableUdpFactory.Outcoming()
        for i in outPut_list:
            self.createEvent(VPN_UDP_SEND, i)

    def _clean(self):
        """进行清理当前实例的工作
        """
        for i in self.socket_table.keys():
            self.socket_table[i].Socket_Object.close()

        self.forward_client_table = {}
        self.socket_table = {}

    def _clean_socket_object(self, identification):
        """清理释放一个应用会话

        Args:
            identification (bytes): 待释放的应用会话
        """
        if self.socket_table.get(identification, None):
            self._send(TYPE_CLOSE_ONE_CONNECT, identification)
            self.socket_table[identification].Socket_Object.close()
            del self.socket_table[identification]

    def _append_bind_socket(self, data_tuple):
        """添加端口转发
        初始化一个端口转发，将bind_port映射到remote_port

        Args:
            data_tuple (tuple): (bind_ip, bind_port, remote_port)元祖
        """

        bind_ip: str = data_tuple[SimpleForwardClient.BIND_IP_INDEX]
        bind_port: int = data_tuple[SimpleForwardClient.BIND_PORT_INDEX]
        remote_port: int = data_tuple[SimpleForwardClient.REMOTE_PORT_INDEX]

        if self.forward_client_table.get(remote_port, None):
            return

        self.forward_client_table[remote_port] = (bind_ip, bind_port)

        self._send(TYPE_CLIENT_OPEN_REMOTE_PORT,
                   remote_port.to_bytes(2, 'big'))

        log.info(
            f"添加端口转发：{self.forward_server_address}:{remote_port} -> {bind_ip}:{bind_port}"
        )

    def _send(self, type, data=b""):
        """通过可靠udp通信实例发送数据包

        Args:
            type (int):  Forward_Package的包类型
            data (bytes, optional): 发送的数据. Defaults to b"".
        """

        if self.communicate_socket.getStatus(
        ) == ReliableUdpSocket.STATUS_CLOSE:
            self.raiseException(FORWARD_CONNECT_CLOSE)

        packet = Forward_Package(type, data)

        self.communicate_socket.send(packet.to_bytes())

    def handle_buffer(self, buffer):
        """对从可靠udp通信实例接收到的数据进行处理

        Args:
            buffer (bytes): 接收到的数据
        """

        self.buffer += buffer

        while 1:
            if len(self.buffer) < Forward_Package.HEAD_SIZE:
                return

            length = getWord(
                self.buffer[Forward_Package.
                            LENGTH_OFFSET:Forward_Package.LENGTH_OFFSET + 2],
                0, 'big')

            if len(self.buffer) < Forward_Package.HEAD_SIZE + length:
                return

            package = Forward_Package().from_bytes(self.buffer)
            self.buffer = self.buffer[package.size():]

            # 检查包类型是否合法
            if package.Type >= TYPR_NUM_MAX:
                log.debug("包错误")
                self.raiseException(FORWARD_PIPE_BROKED)
                return

            # 服务端打开指定端口时发生错误
            if package.Type == TYPE_SERVER_ERROR_REMOTE_PORT:
                remotePort = getWord(package.Data, 0, 'big')

                log.debug(f"服务端打开{remotePort}端口时发生错误")

                if self.forward_client_table.get(remotePort, None):
                    del self.forward_client_table[remotePort]

                continue

            # 服务端关闭了一个特定端口
            if package.Type == TYPE_SERVER_CLOSE_REMOTE_PORT:

                remotePort = getWord(package.Data, 0, 'big')

                log.debug(f"服务端关闭{remotePort}端口")

                if self.forward_client_table.get(remotePort, None):
                    del self.forward_client_table[remotePort]
                continue

            # 服务端开启了一个应用会话
            if package.Type == TYPE_SERVER_ONE_CONNECT_START:
                remotePort = getWord(package.Data, 0, 'big')
                identification = package.Data[2:6]

                log.debug(f"服务端开启了一个应用会话, remotePort:{remotePort}, identification:{identification.hex()}")
                if not self.forward_client_table.get(remotePort, None):
                    self._send(TYPE_CLIENT_CREATE_SOCKET_ERROR, identification)
                    continue

                if self.socket_table.get(identification, None):
                    self._send(TYPE_CLIENT_CREATE_SOCKET_ERROR, identification)

                one_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                one_socket.setblocking(False)

                try:
                    one_socket.connect(self.forward_client_table[remotePort])
                except BlockingIOError:
                    pass
                except IOError as e:
                    log.debug(f"[Forward Client] connect error {e}")
                    self._send(TYPE_CLIENT_CREATE_SOCKET_ERROR,
                               package.Data[2:6])
                    continue

                self.socket_table[identification] = oneConnect(
                    identification, one_socket)

            # 服务端发来了应用会话的转发数据
            if package.Type == TYPE_SEND_ONE_CONNECT_MSG:
                identification = package.Data[:4]
                data = package.Data[4:]

                one_connect: oneConnect = self.socket_table.get(
                    identification, None)

                if not one_connect:
                    self._send(TYPE_CLOSE_ONE_CONNECT)
                    continue

                one_connect.send_in_buffer += data

            # 服务端关闭了一个应用会话
            if package.Type == TYPE_CLOSE_ONE_CONNECT:
                identification = package.Data[:4]

                log.debug(
                    f"服务端关闭了一个应用会话, identification:{identification.hex()}"
                )
                one_connect: oneConnect = self.socket_table.get(
                    identification, None)

                if not one_connect:
                    continue

                one_connect.Status = oneConnect.CLOSE_STATUS
                self._clean_socket_object(identification)

    def _check_socket(self):
        """检查每一个应用会话，处理其当前的工作状态
        """
        to_del_socket = []
        maxSendSize = self.communicate_socket.getRecommendMaxSendDataSize()

        while 1:

            # 判断此时是否可发送数据
            if maxSendSize <= 0:
                break

            continueRecv = False  # 用于判断是否应继续接收数据

            # 遍历每一个应用会话
            for i in self.socket_table.keys():
                isConnect = True
                one_connect: oneConnect = self.socket_table[i]

                # 尝试接收数据，若有一个应用会话成功接收了数据
                # 将continveRecv置为True，继续接收数据
                try:

                    data = one_connect.Socket_Object.recv(
                        self.recv_buffer_size)

                    if data == b"":
                        one_connect.Status = oneConnect.CLOSE_STATUS

                    else:

                        self._send(TYPE_SEND_ONE_CONNECT_MSG, i + data)
                        maxSendSize -= len(data)
                        continueRecv = True

                except BlockingIOError:
                    pass
                except IOError as e:
                    isConnect = False

                    if one_connect.Status != oneConnect.INIT_STATUS or self.cur_time - one_connect.Init_Start_Time > self.connectTimeout:
                        one_connect.Status = oneConnect.CLOSE_STATUS
                        log.debug(f"[Forward Client] {i.hex()} runtime error {e}")

                if isConnect and one_connect.Status == oneConnect.INIT_STATUS:
                    one_connect.Status = oneConnect.RUNTIME_STATUS

                elif one_connect.Status == oneConnect.CLOSE_STATUS:
                    to_del_socket.append(i)

            for i in to_del_socket:
                self._clean_socket_object(i)

            if not continueRecv:
                break

        # 将sendd_buffer的数据发送到应用
        for i in self.socket_table.keys():
            one_connect: oneConnect = self.socket_table[i]
            if one_connect.Status == oneConnect.RUNTIME_STATUS:
                if one_connect.send_in_buffer:
                    try:
                        size = one_connect.Socket_Object.send(
                            one_connect.send_in_buffer)

                        one_connect.send_in_buffer = one_connect.send_in_buffer[
                            size:]
                    except BlockingIOError:
                        pass

                    except Exception as e:
                        log.debug(f"[Forward Client] {i.hex()} close {e}")
                        one_connect.Status = oneConnect.CLOSE_STATUS

    def check(self):
        """检查当前工作状态，根据当前状态执行操作
        """

        self.cur_time = time()
        self.reliableUdpFactory.check()
        self._check_outcoming()

        if self.status == SimpleForwardClient.STATUS_PRE_INIT:

            if self.cur_time - self.Last_Status_Time > self.Wait_Init_Time:

                self.communicate_socket = self.reliableUdpFactory.connect(
                    self.forward_server_address, self.forward_server_bind_port,
                    self.forward_client_bind_port)

                log.debug("SimpleForwardClient.STATUS_PRE_INIT")

                self.status = SimpleForwardClient.STATUS_INIT


        if self.status == SimpleForwardClient.STATUS_INIT:


            if self.communicate_socket.getStatus(
            ) == ReliableUdpSocket.STATUS_CONNECT:

                for i in self.default_Table:
                    self._append_bind_socket(i)

                self.status = SimpleForwardClient.STATUS_RUN

            if self.communicate_socket.getStatus() == ReliableUdpSocket.STATUS_CLOSE:
                self.raiseException(FORWARD_CONNECT_CLOSE)

        if self.status == SimpleForwardClient.STATUS_RUN:

            self._check_socket()

            recv_buf = self.communicate_socket.recv()

            if recv_buf:
                self.handle_buffer(recv_buf)
