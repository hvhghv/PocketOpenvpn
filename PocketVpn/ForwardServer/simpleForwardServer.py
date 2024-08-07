from ..include.ForwardHead import *
from ..include.simpleFunc import *
from ..include.DecoratedReliableUdp import *
import socket


class OneClientSession:
    """
    客户端会话类
    每个客户端会话对应一个此实例
    
    sendPackage方法用于发送数据到客户端
    getPackage方法用于获取客户端发来的数据
    isClosed方法判断会话是否关闭
    close方法关闭此会话
    
    """

    Address = None  # (str,int)客户端ip地址与端口
    # Status = 0
    buffer = b""  # 上轮未处理的数据会保存于此
    reliable_udp_socket: ReliableUdpSocket = None  # 此会话对应的ReliableUdpSocket实例

    # Identification_Count = 0                    # 用于生成应用的会话id，每建立一个应用会话，此值加1

    # CLIENT_SESSION_STATUS_RUN = 0

    def __init__(self, address, reliable_udp_socket: ReliableUdpSocket):
        """初始化会话

        Args:
            address (tuple[str,int]): 目标地址与目标端口
            reliable_udp_socket (ReliableUdpSocket): 此会话对应的ReliableUdpSocket实例
        """
        self.Address = address
        self.reliable_udp_socket = reliable_udp_socket

    def sendPackage(self, contentType, data=b""):
        """将数据打包并通过ReliableUdpSocket实例发送

        Args:
            contentType (int): 转发数据包的type类型
            data (bytes, optional): 需要发送的数据
        """

        if self.reliable_udp_socket.getStatus(
        ) == self.reliable_udp_socket.STATUS_CLOSE:
            return

        package = Forward_Package(contentType, data)

        self.reliable_udp_socket.send(package.to_bytes())

    def getPackage(self):
        """从ReliableUdpSocket实例中获取转发数据包

        Returns:
            Forward_Package|None : 返回来自客户端的转发数据包，无数据时，返回None
        """

        if self.reliable_udp_socket.getStatus(
        ) == self.reliable_udp_socket.STATUS_CLOSE:
            return None

        self.buffer += self.reliable_udp_socket.recv()

        if len(self.buffer) < Forward_Package.HEAD_SIZE:
            return None

        length = int.from_bytes(
            self.buffer[Forward_Package.
                        LENGTH_OFFSET:Forward_Package.LENGTH_OFFSET + 2],
            byteorder='big')

        if len(self.buffer) < Forward_Package.HEAD_SIZE + length:
            return None

        packet = Forward_Package().from_bytes(self.buffer)
        self.buffer = self.buffer[Forward_Package.HEAD_SIZE + length:]
        return packet

    def isClosed(self):
        """判断会话是否关闭

        Returns:
            bool: True表示连接已关闭，False表示正常运行
        """

        return self.reliable_udp_socket.getStatus(
        ) == self.reliable_udp_socket.STATUS_CLOSE

    def close(self):
        """关闭该会话
        """
        self.reliable_udp_socket.close()

    def getRecommandMaxSendSize(self):
        """获取该会话当前可以发送的数据量

        Returns:
            int: 返回该会话当前可以发送的数据量，可适量超出该数据量大小。
        """
        return self.reliable_udp_socket.getRecommendMaxSendDataSize()


class OneAppSocket:
    """转发一个应用tcp连接对应的应用会话实例
    """

    Socket_Object = None  # socket.socket实例
    Bind_Port = 0  # 绑定的端口
    ClientSessionAddress = None  # 所属的OneClientSession实例
    send_in_buffer = b""  # 需要通过Socket_Object进行send的数据
    status = 0  # 当前的工作状态

    # 工作状态
    APP_STATUS_RUNNING = 0
    APP_STATUS_CLOSE = 1
    APP_STATUS_ERROR = 2

    def __init__(self, socket: socket.socket, Bind_Port,
                 clientSession: OneClientSession):

        self.Socket_Object = socket
        self.Bind_Port = Bind_Port
        self.ClientSessionAddress = clientSession.Address
        self.send_in_buffer = b""
        self.status = OneAppSocket.APP_STATUS_RUNNING

    def put(self, data):
        """传入来自客户端的待转发数据，保存到send_in_buffer中

        Args:
            data (bytes): 来自客户端的待转发数据
        """
        self.send_in_buffer += data

    def setStatus(self, status):
        """设置其当前状态

        Args:
            status (int): 工作状态
        """
        self.status = status


class ForwardServer():
    """
    tcp端口转发服务端
    
    提供类似于frps的端口转发功能
    
    通过不间断调用Loop方法，启动服务
    
    """

    bind_ip = "10.8.1.1"  # 服务端ip地址
    bind_port = 6672  # 服务端端口
    udpRecvBufferSize = 0xffff  # udp接收缓冲区大小
    tcpRecvBufferSize = 256  # tcp单次接收一个应用数据的大小，建议取较低的值
    Login_Client_Session_Table = None  # 记录登录客户端的会话表
    Port_Table = None  # 记录绑定端口与登录客户端映射表
    Identification_Socket_Table = None  # 记录应用会话id的表
    bind_port_listen = 10  # 每个绑定端口最多允许的应用会话数量
    Identification_Count = 0  # 用于生成应用的会话id，每建立一个应用会话，此值加1

    # Login_Client_Session_Table的值索引
    PORT_TABLE_SOCKET_INDEX = 0
    PORT_TABLE_CLIENT_SESSION_INDEX = 1

    def __init__(self,
                 bind_ip="10.8.1.1",
                 bind_port: int = 6672,
                 udpRecvBufferSize=0xffff,
                 tcpRecvBufferSize=256,
                 base_send_buffer_size=1024 * 10,
                 recv_ack_timeout=0.1,
                 connect_timeout=3,
                 fragment=1400,
                 reliableUdpCapacity=192,
                 bind_port_listen=16,
                 **kwargs):

        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.udpRecvBufferSize = udpRecvBufferSize
        self.tcpRecvBufferSize = tcpRecvBufferSize

        self.ForwardServer_Socket_Object = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM)

        self.ForwardServer_Socket_Object.bind((self.bind_ip, self.bind_port))
        self.ForwardServer_Socket_Object.setblocking(False)

        self.Login_Client_Session_Table = {}
        self.Port_Table = {}
        self.Identification_Socket_Table = {}

        self.bind_port_listen = bind_port_listen

        self.ReliableUdpFactory = ReliableUdpFactory(
            base_send_buffer_size=base_send_buffer_size,
            recv_ack_timeout=recv_ack_timeout,
            connect_timeout=connect_timeout,
            fragment=fragment,
            capacity=reliableUdpCapacity)

        log.info("服务端初始化成功")
        
    def _create_bind_port(self, port):
        """根据客户端的请求，绑定指定端口

        Args:
            port (int): 需绑定的端口

        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            s.bind((self.bind_ip, port))
        except Exception as e:
            log.debug(f"[forward server] {port} create one port error {e}")
            return None

        s.listen(self.bind_port_listen)
        s.setblocking(False)
        return s

    def _clean_one_client_session(self, _Address):
        """当客户端断开连接时，清理其绑定的端口和应用会话

        Args:
            _Address (tuple[str,int]): 客户端的地址
        """

        to_del_port_list = []
        to_del_identification_list = []

        # 获取其绑定的端口
        for i in self.Port_Table.keys():
            oneClientSession: OneClientSession = self.Port_Table[i][
                ForwardServer.PORT_TABLE_CLIENT_SESSION_INDEX]
            if oneClientSession.Address == _Address:
                to_del_port_list.append(i)

        # 获取其生成的应用会话
        for i in self.Identification_Socket_Table.keys():
            oneAppSocket: OneAppSocket = self.Identification_Socket_Table[i]
            if oneAppSocket.ClientSessionAddress == _Address:
                to_del_identification_list.append(i)

        # 清理其绑定的端口
        for i in to_del_port_list:
            self._clean_one_port(i)

        # 清理其生成的应用会话
        for i in to_del_identification_list:
            self._clean_one_app_socket(i)

        # 最后清理其自身
        oneClientSession: OneClientSession = self.Login_Client_Session_Table[
            _Address]
        oneClientSession.close()

        del self.Login_Client_Session_Table[_Address]

    def _clean_one_port(self, port: int):
        """清理一个绑定端口

        Args:
            port (int): 一个绑定端口
        """

        if self.Port_Table.get(port, None):
            bind_socket: socket.socket = self.Port_Table[port][
                ForwardServer.PORT_TABLE_SOCKET_INDEX]

            oneClientSession: OneClientSession = self.Port_Table[port][
                ForwardServer.PORT_TABLE_CLIENT_SESSION_INDEX]

            oneClientSession.sendPackage(TYPE_SERVER_CLOSE_REMOTE_PORT,
                                         port.to_bytes(2, "big"))

            try:
                bind_socket.close()
            except Exception as e:
                log.debug(f"[forward server] {port} clean one port error {e}")

            del self.Port_Table[port]

    def _clean_one_app_socket(self, identification_id):
        """清理一个应用会话

        Args:
            identification_id (bytes): 一个应用会话id
        """

        if self.Identification_Socket_Table.get(identification_id, None):
            oneAppSocket: OneAppSocket = self.Identification_Socket_Table[
                identification_id]

            oneClientSession: OneClientSession = self.Login_Client_Session_Table[
                oneAppSocket.ClientSessionAddress]

            oneClientSession.sendPackage(TYPE_CLOSE_ONE_CONNECT,
                                         identification_id)

            try:
                oneAppSocket.Socket_Object.close()
            except Exception as e:
                log.debug(
                    f"[forward server] {identification_id} clean one identification_id error {e}"
                )

            del self.Identification_Socket_Table[identification_id]

    def _check_outcoming(self):
        """检查是否有数据需要发送
        会将data_tuple里所有数据包发送出去
        """

        self.ReliableUdpFactory.check()
        data_tuple = self.ReliableUdpFactory.Outcoming()

        # 发送所有数据包
        for i in data_tuple:
            packet: Communicate_Package = i

            dstAddress, dstPort, srcPort, data = packet.unpack_addr_str()

            try:
                self.ForwardServer_Socket_Object.sendto(
                    data, (dstAddress, dstPort))

            except BlockingIOError:
                pass

    def _check_forward_socket_incoming(self):
        """检查ForwardServer_Socket_Object是否有数据传入
        若有数据，就将数据传入可靠udp工厂实例
        """

        while 1:
            try:
                data, _addr = self.ForwardServer_Socket_Object.recvfrom(
                    self.udpRecvBufferSize)

            except socket.timeout:
                break
            except BlockingIOError:
                break
            except Exception as e:
                log.error(
                    f"check forward server socket error {e}")
                break

            packet = Communicate_Package().pack_addr_str(
                _addr[0], _addr[1], self.bind_port, data)

            self.ReliableUdpFactory.Incoming(packet)

    def _check_reliable_udp_accept(self):
        """检查是否有新连接
        存在新连接时，创建OneClientSession实例并添加到Login_Client_Session_Table表中
        """

        while 1:
            one_socket = self.ReliableUdpFactory.accept(self.bind_port)

            if not one_socket:
                break

            address = one_socket.getDstAddress()
            one_client_socket: OneClientSession = self.Login_Client_Session_Table.get(
                address, None)

            if one_client_socket:
                one_client_socket.reliable_udp_socket.close()

            self.Login_Client_Session_Table[address] = OneClientSession(
                address, one_socket)

            log.debug(f"新客户端连接: f{address}")

    def _check_every_client(self):
        """检查每个客户端会话，从每个客户端会话读取数据包并处理
        
        """

        to_del_list = []

        # 遍历每个客户端会话
        for address in self.Login_Client_Session_Table.keys():

            one_client_socket: OneClientSession = self.Login_Client_Session_Table[
                address]

            # 检查连接是否关闭
            if one_client_socket.isClosed():

                log.debug(f"{one_client_socket.Address}客户端会话已关闭")

                to_del_list.append(address)
                continue

            while 1:

                # 获取转发数据包
                package = one_client_socket.getPackage()

                if not package:
                    break

                if package.Type == TYPE_CLIENT_OPEN_REMOTE_PORT:
                    # 客户端请求服务端打开指定端口
                    port = getWord(package.Data, 0, 'big')

                    log.debug(f"{one_client_socket.Address}客户端请求服务端打开指定端口,port:{port}")

                    if self.Port_Table.get(port, None):

                        log.debug(f"端口已被占用")

                        one_client_socket.sendPackage(
                            TYPE_SERVER_ERROR_REMOTE_PORT, package.Data)
                        continue

                    port_socket = self._create_bind_port(port)
                    if not port_socket:

                        log.debug(f"绑定端口错误")
                        one_client_socket.sendPackage(
                            TYPE_SERVER_ERROR_REMOTE_PORT, package.Data)
                        continue

                    self.Port_Table[port] = (port_socket, one_client_socket)
                    continue

                if package.Type == TYPE_CLIENT_CLOSE_REMOTE_PORT:
                    # 客户端请求服务端关闭指定端口
                    port = getWord(package.Data, 0, 'big')


                    log.debug(f"收到客户端{one_client_socket.Address}请求关闭端口{port}")
                    table = self.Port_Table.get(port, None)
                    if not table:
                        continue

                    port_socket: socket.socket = table[
                        ForwardServer.PORT_TABLE_SOCKET_INDEX]
                    port_socket.close()
                    del self.Port_Table[port]
                    continue

                if package.Type == TYPE_CLIENT_CREATE_SOCKET_ERROR:
                    # 客户端创建应用会话时出错

                    identification = package.Data[:4]

                    log.debug(f"{one_client_socket.Address}客户端创建应用会话{identification.hex()}时出错")

                    oneAppSocket: OneAppSocket = self.Identification_Socket_Table.get(
                        identification, None)

                    if not oneAppSocket:
                        continue

                    oneAppSocket.setStatus(OneAppSocket.APP_STATUS_ERROR)
                    continue

                if package.Type == TYPE_SEND_ONE_CONNECT_MSG:
                    # 接收到客户端的应用转发数据包
                    identification = package.Data[:4]
                    payload = package.Data[4:]

                    oneAppSocket: OneAppSocket = self.Identification_Socket_Table.get(
                        identification, None)

                    if not oneAppSocket:

                        one_client_socket.sendPackage(TYPE_CLOSE_ONE_CONNECT,
                                                      package.Data[:4])

                        continue

                    oneAppSocket.put(payload)
                    continue

                if package.Type == TYPE_CLOSE_ONE_CONNECT:
                    # 客户端关闭了一个应用会话
                    identification = package.Data[:4]

                    log.debug(
                        f"{one_client_socket.Address}客户端关闭了一个应用会话{identification.hex()}"
                    )
                    oneAppSocket: OneAppSocket = self.Identification_Socket_Table.get(
                        identification, None)

                    if not oneAppSocket:
                        one_client_socket.sendPackage(TYPE_CLOSE_ONE_CONNECT,
                                                      package.Data[:4])
                        continue

                    oneAppSocket.setStatus(OneAppSocket.APP_STATUS_CLOSE)

                if package.Type >= TYPR_NUM_MAX:


                    log.debug(
                        f"{one_client_socket.Address} package.Type error : {package.Type}"
                    )

                    to_del_list.append(address)
                    continue

        # 清理已关闭的客户端会话
        for i in to_del_list:
            self._clean_one_client_session(i)

    def _check_every_bind_port(self):
        """检查每个绑定的端口，查看是否有应用连接
        """

        to_del_list = []

        for i in self.Port_Table.keys():

            port_socket: socket.socket = self.Port_Table[i][
                ForwardServer.PORT_TABLE_SOCKET_INDEX]

            clientSession: OneClientSession = self.Port_Table[i][
                ForwardServer.PORT_TABLE_CLIENT_SESSION_INDEX]

            while 1:

                try:
                    new_app_socket, _ = port_socket.accept()
                    new_app_socket.setblocking(False)
                except BlockingIOError:
                    break
                except Exception as e:
                    log.debug(
                        f"[forward server] {i} check bind port error, close {e}"
                    )
                    to_del_list.append(i)
                    break

                # 执行到这里，则有应用连接，根据Identification_Count分配会话id
                new_identification_id = 0
                while 1:
                    new_identification_id = self.Identification_Count.to_bytes(
                        4, 'big')
                    if self.Identification_Socket_Table.get(
                            new_identification_id, None):

                        self.Identification_Count = (
                            self.Identification_Count + 1) & 0xffffffff
                    else:
                        break

                self.Identification_Socket_Table[
                    new_identification_id] = OneAppSocket(
                        new_app_socket, i, clientSession)

                clientSession.sendPackage(
                    TYPE_SERVER_ONE_CONNECT_START,
                    i.to_bytes(2, 'big') + new_identification_id)

        for i in to_del_list:
            self._clean_one_port(i)

    def _check_every_app_socket(self):
        """检查每个应用会话，处理每个应用的转发数据
        """

        to_del_list = []

        for i in self.Identification_Socket_Table.keys():

            appSocket: OneAppSocket = self.Identification_Socket_Table[i]
            oneClientSession: OneClientSession = self.Login_Client_Session_Table.get(
                appSocket.ClientSessionAddress, None)

            if not oneClientSession:
                appSocket.setStatus(OneAppSocket.APP_STATUS_CLOSE)

            if appSocket.status == OneAppSocket.APP_STATUS_ERROR:
                to_del_list.append(i)
                continue

            # 处理待传入数据
            # if appSocket.send_in_buffer:

            try:
                size = appSocket.Socket_Object.send(appSocket.send_in_buffer)
                appSocket.send_in_buffer = appSocket.send_in_buffer[size:]

            except BlockingIOError:
                pass

            except IOError as e:
                log.debug(f"[forward server] {i} : send error {e}")
                appSocket.setStatus(OneAppSocket.APP_STATUS_CLOSE)

            # 读取应用待转发的数据
            maxSendSize = oneClientSession.getRecommandMaxSendSize()

            while 1:
                if maxSendSize <= 0:
                    break

                try:

                    data = appSocket.Socket_Object.recv(self.tcpRecvBufferSize)

                    if not data:
                        log.debug(f"[forward server] {i} : close")
                        appSocket.setStatus(OneAppSocket.APP_STATUS_CLOSE)
                        break

                    maxSendSize -= len(data)
                    oneClientSession.sendPackage(TYPE_SEND_ONE_CONNECT_MSG,
                                                 i + data)

                except BlockingIOError:
                    break
                except Exception as e:
                    log.debug(f"[forward server] {i} : recv error {e}")
                    appSocket.setStatus(OneAppSocket.APP_STATUS_CLOSE)
                    break

            if appSocket.status == OneAppSocket.APP_STATUS_CLOSE:
                oneClientSession.sendPackage(TYPE_CLOSE_ONE_CONNECT, i)
                to_del_list.append(i)

        # 清理
        for i in to_del_list:
            self._clean_one_app_socket(i)

    def Loop(self):
        """服务的主循环函数，整个服务的运行函数
        """
        self._check_forward_socket_incoming()
        self._check_reliable_udp_accept()
        self._check_every_client()
        self._check_every_bind_port()
        self._check_every_app_socket()
        self._check_outcoming()
