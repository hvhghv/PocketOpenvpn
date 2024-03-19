import ssl
from ..include.ContextHead import *
from ..include.VpnContextContentType import *


class SimpleTLS(Context_Child):
    """
    为Context类提供TLS功能
    """

    SSL_Context_Object = None    # SSLContext 上下文对象
    SSL_Object = None            # SSL BIO 对象
    BIO_Incoming_Object = None   # MemoryBIO 对象
    BIO_Outgoing_Object = None   # MemoryBIO 对象

    ca_file_path = ""
    crt_file_path = ""
    privateKey_file_path = ""

    handshark_done = False

    def __init__(self,
                 context: Context,
                 ca_file_path="ca.crt",
                 crt_file_path="client.crt",
                 privateKey_file_path="client.pem"):
        super().__init__(context)
        self.ca_file_path = ca_file_path
        self.crt_file_path = crt_file_path
        self.privateKey_file_path = privateKey_file_path

    def soft_reset(self, event: Event):
        '''
        重新初始化TLS
        '''
        self.handshark_done = False

        self.SSL_Context_Object = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.SSL_Context_Object.load_cert_chain(self.crt_file_path,
                                                self.privateKey_file_path)
        self.SSL_Context_Object.load_verify_locations(self.ca_file_path)
        self.SSL_Context_Object.check_hostname = False

        self.BIO_Incoming_Object = ssl.MemoryBIO()
        self.BIO_Outgoing_Object = ssl.MemoryBIO()

        self.SSL_Object = self.SSL_Context_Object.wrap_bio(
            self.BIO_Incoming_Object, self.BIO_Outgoing_Object)

    def incoming(self, event: Event):
        '''
        将事件链上的TLS数据流写入MemoryBIO
        '''
        self.BIO_Incoming_Object.write(event.Payload)

    def do_handshark(self, event: Event):
        """
        尝试进行TLS握手，当握手成功时，创建TLS_HANDSHARK_DONE事件，
        若需要更多的握手包数据，则则创建TLS_HANDSHARK_DATA_NEED事件，
        若握手失败，则创建TLS_HANDSHARK_ERROR事件
        
        事件类型 : TLS_HANDSHARK_DONE 握手成功
        事件类型 : TLS_HANDSHARK_DATA_NEED 需要更多的握手包数据
        事件类型 : TLS_HANDSHARK_ERROR 握手失败
        
        """
        try:
            self.SSL_Object.do_handshake()
            self.handshark_done = True
            self.createEvent(TLS_HANDSHARK_DONE)
        except ssl.SSLWantReadError:
            self.createEvent(TLS_HANDSHARK_DATA_NEED)
        except ssl.SSLError as e:
            self.raiseException(TLS_SSL_ERROR, e)

    def write(self, event: Event):
        """
        对事件链上待tls加密数据进行tls加密
        """

        self.SSL_Object.write(event.Payload)

    def check(self):
        '''
        检查并处理当前的工作状态
        
        若握手未完成，会尝试进行握手
        若握手完成，会尝试解密接收到的tls密文
        
        事件类型 : TLS_SEND_DATA 
        事件内容 : bytes 需要向对等端发送的数据
        
        事件类型 : TLS_RECV_APPLICATION_DATA
        事件内容 : bytes 从Tls密文中解密出的应用数据
        
        异常类型 : TLS_SSL_ERROR TLS触发异常
        
        '''

        data = self.BIO_Outgoing_Object.read()
        if data:
            self.createEvent(TLS_SEND_DATA, data)

        if self.handshark_done:
            try:
                data = self.SSL_Object.read()
                self.createEvent(TLS_RECV_APPLICATION_DATA, data)
            except ssl.SSLWantReadError:
                pass
            except ssl.SSLError as e:
                self.raiseException(TLS_SSL_ERROR, e)
