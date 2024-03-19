"""
用于封装数据包的类
目前并不支持目标地址为域名
"""


class Communicate_Package:
    Dst_Address = (0, 0, 0, 0)
    Dst_Port = 0
    Src_Port = 0
    data = b""
    flag = 0 # 指示这个包的标志信息，具体含义由调用者定义

    def pack_addr_str(self, dstAddress: str, dstPort: int, srcPort: int,
                      data: bytes):
        
        """打包数据包，其中dstaddress为字符串，返回打包后的Communicate_Package对象
        
        如pack_addr_str("127.0.0.1", 1234, 5678, b"Hello")

        Returns:
            Communicate_Package : 打包后的Communicate_Package对象
        """

        # 将ip地址转化为tuple元组
        split_dst = dstAddress.split('.')
        split_dst = (int(split_dst[0]), int(split_dst[1]), int(split_dst[2]),
                     int(split_dst[3]))

        return self._pack(dstAddress=split_dst,
                          dstPort=dstPort,
                          srcPort=srcPort,
                          data=data)

    def pack_addr_tuple(self, dstAddress: tuple, dstPort: int, srcPort: int,
                        data: bytes):

        """打包数据包，其中address为元组，返回打包后的Communicate_Package对象
        
        如pack_addr_str((127,0,0,1), 1234, 5678, b"Hello")

        Returns:
            Communicate_Package : 打包后的Communicate_Package对象
        """

        return self._pack(dstAddress=dstAddress,
                          dstPort=dstPort,
                          srcPort=srcPort,
                          data=data)

    def _pack(self, dstAddress: tuple, dstPort: int, srcPort: int,
              data: bytes):

        """打包数据包的方法

        Returns:
            Communicate_Package : 打包后的Communicate_Package对象
        """

        self.Dst_Address = dstAddress
        self.Dst_Port = dstPort
        self.Src_Port = srcPort
        self.data = data

        return self

    def unpack_addr_str(self) -> "tuple[str,int,int,bytes]":
        
        """解包数据包，其中返回的address为字符串，返回解包后的Communicate_Package对象

        Returns:
            tuple[str,int,int,bytes]: 返回远程地址，远程端口，本地端口，数据。这里的远程地址，远程端口，本地端口是相对于本机的。
        """

        dstAddress = "%s.%s.%s.%s" % (self.Dst_Address[0], self.Dst_Address[1],
                                          self.Dst_Address[2], self.Dst_Address[3])

        return dstAddress, self.Dst_Port, self.Src_Port, self.data

    def unpack_addr_tuple(self) -> "tuple[tuple,int,int,bytes]":

        """解包数据包，其中返回的address为字符串，返回解包后的Communicate_Package对象

        Returns:
            tuple[tuple,int,int,bytes]: 返回远程地址，远程端口，本地端口，数据。这里的远程地址，远程端口，本地端口是相对于本机的。
        """
        return self.Dst_Address, self.Dst_Port, self.Src_Port, self.data

    def setFlag(self, flag):
        
        """设置该数据包的flag，调用后会对该包的flag与参数flag进行或操作

        Args:
            flag (int): flag值
        """
        
        self.flag |= flag

    def isFlagSet(self, flag):
        
        """判断flag是否被设置，调用后后对该包的flag与参数flag进行与操作，如果结果为1，返回True，否则返回False

        Args:
            flag (int): flag值

        Returns:
            bool: 返回结果
        """
        return (self.flag & flag) > 0
