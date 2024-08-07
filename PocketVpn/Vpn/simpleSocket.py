import socket
from ..include.ContextHead import *
from ..include.VpnContextContentType import *
import logging

log = logging.getLogger()


class SimpleSocket(socket.socket, Context_Child):

    """为Context提供套接字功能
    """

    isconnect_flag = False
    dstAddress = '127.0.0.1'
    dstPort = 1194
    buffer = 1024
    cur_send_buffer = b""

    def __init__(self,
                 context=None,
                 dstAddress='127.0.0.1',
                 dstPort=1194,
                 buffer=0xffff
                 ) -> None:
        super(socket.socket, self).__init__(socket.AF_INET, socket.SOCK_STREAM)
        self.setContext(context)

        self.dstAddress = dstAddress
        self.dstPort = dstPort
        self.buffer = buffer

        log.debug("SimpleSocket 初始化完成")

    def soft_reset(self, event: Event):
        """
        连接重置，重新连接目标地址
        
        异常类型: SOCKET_CONNECT_CLOSE
        """

        log.debug("socket 连接重置")

        self.setblocking(True)
        try:
            self.connect((self.dstAddress, self.dstPort))

        except Exception as e:

            log.error("socket 连接错误")

            self.raiseException(SOCKET_CONNECT_CLOSE,e)
            return

        self.setblocking(False)
        self.isconnect_flag = True

    def Send(self, event: Event):
        """
        将事件链上的传出数据用socket.sendall发送到目标地址
        若连接正忙(指cur_send_buffer仍存在数据)，则什么事都不干
        
        异常类型: SOCKET_CONNECT_CLOSE
        
        """

        if self.isconnect_flag == False:
            return

        if not event.Payload:
            return

        self.cur_send_buffer += event.Payload

    def _Send_Msg(self):
        """发送cur_send_buffer中的数据，若一次发不完，会保留未发送的数据
        
        异常类型: SOCKET_CONNECT_CLOSE
        """

        try:
            size = self.send(self.cur_send_buffer)
            self.cur_send_buffer = self.cur_send_buffer[size:]

        except BlockingIOError:
            pass

        except Exception as e:
            self.isconnect_flag = False
            self.raiseException(SOCKET_CONNECT_CLOSE, e)


    def check(self):
        """检查是否有数据到达,是否有数据发送
        """
        self._simple_recv()
        self._Send_Msg()

    def _simple_recv(self):
        """检查是否有数据到达，若有，接收后创建事件
        
        事件类型: SOCKET_RECV
        事件内容：接收的数据(bytes)
        
        异常类型: SOCKET_CONNECT_CLOSE
        """

        if self.isconnect_flag == False:
            return

        try:
            data = self.recv(self.buffer)
        except BlockingIOError:
            return
        except:
            return

        if data == b'':
            self.isconnect_flag = False
            self.raiseException(SOCKET_CONNECT_CLOSE)
            return

        self.createEvent(SOCKET_RECV, data)
