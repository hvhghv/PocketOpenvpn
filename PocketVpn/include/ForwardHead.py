from .simpleFunc import *

# Forward_Package的Type类型
TYPE_CLIENT_OPEN_REMOTE_PORT = 0x0001     #REMOTE PORT 客户端请求服务端绑定指定端口
TYPE_SERVER_ERROR_REMOTE_PORT = 0x0002    #REMOTE PORT 服务端绑定指定端口时发生错误
TYPE_CLIENT_CLOSE_REMOTE_PORT = 0x0003    #REMOTE PORT 客户端请求关闭服务端绑定的一个端口
TYPE_SERVER_CLOSE_REMOTE_PORT = 0x0004    #REMOTE PORT 服务端关闭了一个绑定端口

TYPE_SERVER_ONE_CONNECT_START = 0x0005    #REMOTE PORT + IDENTIFICATION  服务端创建了一个应用会话
TYPE_CLIENT_CREATE_SOCKET_ERROR = 0x0006  #IDENTIFICATION                客户端创建应用会话时发送错误
TYPE_SEND_ONE_CONNECT_MSG = 0x0007        #IDENTIFICATION + PAYLOAD      应用转发数据包
TYPE_CLOSE_ONE_CONNECT = 0x0008           #IDENTIFICATION                应用会话已关闭

TYPR_NUM_MAX = 0x0009


class Forward_Package:

    '''
    tcp转发数据包结构
    '''

    Type = 0      # 2字节，见上文定义
    Length = 0    # 2字节，指示后面的数据长度
    Data = b""    # Length字节，数据

    HEAD_SIZE = 4

    LENGTH_OFFSET = 2

    def __init__(self, Type=0, Data=b""):
        '''
        初始化转发数据包
        '''
        self.Type = Type
        self.Data = Data
        self.Length = len(Data)

    def from_bytes(self, dataBytes):
        """根据字节流更新当前实例

        Args:
            dataBytes (bytes): 字节流

        Returns:
            Forward_Package : 返回当前实例
        """
        self.Type = getWord(dataBytes, 0, "big")
        self.Length = getWord(dataBytes, 2, "big")
        self.Data = dataBytes[4:4 + self.Length]
        return self

    def size(self):
        """返回数据包生成字节流后的数据长度

        Returns:
            int: 数据长度
        """
        return 4 + self.Length

    def to_bytes(self):
        """根据当前实例生成字节流

        Returns:
            bytes: 字节流
        """
        res_data = b""
        res_data += self.Type.to_bytes(2, "big")
        res_data += self.Length.to_bytes(2, "big")
        res_data += self.Data
        return res_data
