'''
openvpn 加密层算法

目前通过加载libcrypto动态库的aes-cbc-128算法来实现加密
需要通过ctypes加载libcrypto动态库

若能手写一个aes算法，可重写VpnCrypto._AES_CBC_encrypto与VpnCrypto._AES_CBC_decrypto方法
就无需libcrypto动态库的依赖
也无需ctypes库的支持

'''
import hashlib
import hmac
from ..include.simpleFunc import *
from ctypes import *
from .PRF import *

import logging

log = logging.getLogger()

class VpnCrypto:

    Encrypto_Cipher_Key = b""    # 加密用cipher密钥
    Encrypto_Hmac_Key = b""      # 加密用hmac密钥
    Decrypto_Cipher_Key = b""    # 解密用cipher密钥
    Decrypto_Hmac_Key = b""      # 解密用hmac密钥

    cipher_key_length = 0         # cipher密钥长度
    hmac_key_length = 0          # hmac密钥长度
    hmac_msg_length = 0          # hmac消息长度
    iv_length = 0                # iv长度
    align_length = 0             # 进行加密时要求的字节对齐长度

    cipher = 0                   # 加密算法
    auth = 0                     # hmac算法

    hmac_mode = None             # hmac用的哈希算法

    pre_master_secret = b"",     # 协商后的预主密钥
    client_random_1 = b"",       # 客户端随机数1
    client_random_2 = b"",       # 客户端随机数2
    server_random_1 = b"",       # 服务端随机数1
    server_random_2 = b"",       # 服务端随机数2
    client_session_id = b"",     # 客户端会话id
    server_session_id = b"",     # 服务端会话id
    key_direction = 0            # 密钥方向，见openvpn文档

    CBC_128 = 1
    HMAC_SHA1 = 1

    encrypto_count = 1           # 加密计算器，每加密一次，自增1
    decrypto_count = 1           # 解密计算器，每解密一次，自增1

    MASTER_SECRET_OUT_LENGTH = 48
    MAX_CIPHER_KEY_LENGTH = 64
    MAX_HMAC_KEY_LENGTH = 64
    MAX_KEY_NUMS = 2
    KEY_OUT_LENGTH = (MAX_CIPHER_KEY_LENGTH + MAX_HMAC_KEY_LENGTH) * MAX_KEY_NUMS
    ENCRYPTO = 1
    DECRYPTO = 0

    libcrypto = None             # 加载的动态库对象，若重写了加密算法，可注释该行


    def __init__(self,
                 libpath,
                 cipher = CBC_128,
                 auth = HMAC_SHA1,
                 pre_master_secret = b"",
                 client_random_1 = b"",
                 client_random_2 = b"",
                 server_random_1 = b"",
                 server_random_2 = b"",
                 client_session_id = b"",
                 server_session_id = b"",
                 key_direction = 0
                ):
        """将openvpn协商后的材料传入，初始化加解密实例

        Args:
            libpath (str): libcrypto动态链接库路径
            cipher (int, optional): 加密算法. Defaults to CBC_128.
            auth (int, optional): hmac算法. Defaults to HMAC_SHA1.
            pre_master_secret (bytes, optional): 协商的预主密钥. Defaults to b"".
            client_random_1 (bytes, optional): 客户端随机数1. Defaults to b"".
            client_random_2 (bytes, optional): 客户端随机数2. Defaults to b"".
            server_random_1 (bytes, optional): 服务端随机数1. Defaults to b"".
            server_random_2 (bytes, optional): 服务端随机数2. Defaults to b"".
            client_session_id (bytes, optional): 客户端会话id. Defaults to b"".
            server_session_id (bytes, optional): 服务端会话id. Defaults to b"".
            key_direction (int, optional): 键方向. Defaults to 0.
        """

        log.debug("Cipher 初始化")

        self.cipher = cipher
        self.auth = auth
        self.pre_master_secret = pre_master_secret
        self.client_random_1 = client_random_1
        self.client_random_2 = client_random_2
        self.server_random_1 = server_random_1
        self.server_random_2 = server_random_2
        self.client_session_id = client_session_id
        self.server_session_id = server_session_id
        self.key_direction = key_direction
        self.libcrypto = cdll.LoadLibrary(libpath)  # 加载动态库对象，若重写了加密算法，可注释该行

        self._initKeyLength()
        self._generateKeys()
        self._init()

    def encrypto(self,data:bytes):
        """对传入数据进行包装openvpn加密层

        Args:
            data (bytes): 传入待加密的数据

        Returns:
            bytes: 返回包装加密层后的字节流
        """

        res_data = b""
        iv = self._urandom(16)

        data = self.encrypto_count.to_bytes(4,'big') + data

        padding_length = self.align_length - (len(data)%self.align_length)
        data = data + padding_length.to_bytes(1,'big') * padding_length

        res_data = self._aes_encrypto(data,iv) + res_data
        res_data = iv + res_data
        res_data = self._hmac_encrypto(res_data) + res_data

        self.encrypto_count += 1

        return res_data

    def decrypto(self,data:bytes):
        """对传入数据进行解包openvpn加密层

        Args:
            data (bytes): 传入待解密的数据

        Returns:
            bytes: 返回解包后的字节流
        """

        offset = 0

        hmac_data = data[offset:offset+self.hmac_msg_length]
        offset += self.hmac_msg_length

        if hmac_data != self._hmac_decrypto(data[offset:]):
            return b""

        iv = data[offset:offset+self.iv_length]
        offset += self.iv_length

        text = self._aes_decrypto(data[offset:],iv)
        text_length = len(text)
        padding_length = text[text_length-1]
        if padding_length > self.align_length or padding_length < 1:
            raise Exception("padding_length %s > self.align_length %s or padding_length < 1"%(padding_length,self.align_length))

        text = text[:text_length-padding_length]

        pakcage_id = int.from_bytes(text[0:4],'big')

        if pakcage_id != self.decrypto_count:
            raise Exception("pakcage_id  %s != self.decrypto_count %s Decrypto Error"%(pakcage_id,self.decrypto_count))

        self.decrypto_count += 1

        return text[4:]

    def _AES_CBC_encrypto(self,data:bytes,key:bytes,iv:bytes) -> bytes:
        """aes加密算法
        可重写该方式以去除对libcrypto动态库的依赖

        Args:
            data (bytes): 待加密数据
            key (bytes): 密钥
            iv (bytes): iv值

        Returns:
            bytes: 加密后的数据
        """

        bits_c = c_int(len(key)*8)
        data_c = create_string_buffer(data)
        data_size_c = c_size_t(len(data))
        key_c = create_string_buffer(key)
        iv_c = create_string_buffer(iv)
        aes_key_c = create_string_buffer(b"",256)
        encrypto_c = c_int(VpnCrypto.ENCRYPTO)
        out_c = create_string_buffer(b"",len(data))

        self.libcrypto.AES_set_encrypt_key(key_c,bits_c,aes_key_c)
        self.libcrypto.AES_cbc_encrypt(data_c, out_c, data_size_c, aes_key_c,
                                       iv_c, encrypto_c)
        return out_c.raw

    def _AES_CBC_decrypto(self,data:bytes,key:bytes,iv:bytes) -> bytes:
        """aes解密算法
        可重写该方式以去除对libcrypto动态库的依赖

        Args:
            data (bytes): 待解密数据
            key (bytes): 密钥
            iv (bytes): iv值

        Returns:
            bytes: 解密后的数据
        """

        bits_c = c_int(len(key)*8)
        data_c = create_string_buffer(data)
        data_size_c = c_size_t(len(data))
        key_c = create_string_buffer(key)
        iv_c = create_string_buffer(iv)
        aes_key_c = create_string_buffer(b"",256)
        encrypto_c = c_int(VpnCrypto.DECRYPTO)
        out_c = create_string_buffer(b"",len(data))

        self.libcrypto.AES_set_decrypt_key(key_c, bits_c, aes_key_c)
        self.libcrypto.AES_cbc_encrypt(data_c, out_c,data_size_c,aes_key_c,iv_c,encrypto_c)

        return out_c.raw

    def _aes_encrypto(self,data:bytes,iv):
        '''
        根据当前的上下文，选择相应的加密算法进行加密
        '''

        if self.cipher == VpnCrypto.CBC_128:
            return self._AES_CBC_encrypto(data,self.Encrypto_Cipher_Key,iv)

        else:
            raise Exception("cipher error")

    def _aes_decrypto(self,data:bytes,iv):
        '''
        根据当前的上下文，选择相应的加密算法进行解密
        '''

        if self.cipher == VpnCrypto.CBC_128:
            return self._AES_CBC_decrypto(data, self.Decrypto_Cipher_Key, iv)

        else:
            raise Exception("cipher error")

    def _hmac_encrypto(self,data:bytes):
        '''
        对传入数据，通过加密用hmac密钥进行hmac运算
        
        Args:
            data (bytes): 待计算的数据
            
        Returns:
            bytes: 返回hmac运算后的数据
        '''
        return hmac.new(key = self.Encrypto_Hmac_Key, msg = data, digestmod = self.hmac_mode).digest()

    def _hmac_decrypto(self,data:bytes):
        '''
        对传入数据，通过解密用hmac密钥进行hmac运算
        
        Args:
            data (bytes): 待计算的数据
            
        Returns:
            bytes: 返回hmac运算后的数据
        '''
        return hmac.new(key = self.Decrypto_Hmac_Key, msg = data, digestmod = self.hmac_mode).digest()

    def _urandom(self,size:int):
        return urandom(size)

    def _initKeyLength(self):
        """根据加密算法与hmac算法设定密钥长度

        Raises:
            Exception: cipher error
            Exception: auth error
        """

        if self.cipher == VpnCrypto.CBC_128:
            self.cipher_key_length = 16
            self.iv_length = 16
            self.align_length = 16

        else:
            raise Exception("cipher error")

        if self.auth == VpnCrypto.HMAC_SHA1:
            self.hmac_key_length = 20
            self.hmac_msg_length = 20

        else:
            raise Exception("auth error")

        log.debug(f"cipher_key_length={self.cipher_key_length}")
        log.debug(f"iv_length={self.iv_length}")
        log.debug(f"align_length={self.align_length}")
        log.debug(f"hmac_key_length={self.hmac_key_length}")
        log.debug(f"hmac_msg_length={self.hmac_msg_length}")

    def _generateKeys(self):

        """
        根据当前上下文初始化加解密上下文
        """
        master_secret = PRF_MD5_SHA1(self.pre_master_secret,
                                     b"OpenVPN master secret",
                                     self.client_random_1+self.server_random_1,
                                     VpnCrypto.MASTER_SECRET_OUT_LENGTH)

        key = PRF_MD5_SHA1(master_secret,
                           b"OpenVPN key expansion",
                           self.client_random_2+self.server_random_2+self.client_session_id+self.server_session_id,
                           VpnCrypto.KEY_OUT_LENGTH)

        offset = 0

        cipher_1 = key[offset:offset+self.cipher_key_length]
        offset += self.MAX_CIPHER_KEY_LENGTH

        hmac_1 = key[offset:offset+self.hmac_key_length]
        offset += self.MAX_HMAC_KEY_LENGTH

        cipher_2 = key[offset:offset+self.cipher_key_length]
        offset += self.MAX_CIPHER_KEY_LENGTH

        hmac_2 = key[offset:offset+self.hmac_key_length]
        offset += self.MAX_HMAC_KEY_LENGTH

        if self.key_direction == 0:
            self.Encrypto_Cipher_Key = cipher_1
            self.Encrypto_Hmac_Key = hmac_1
            self.Decrypto_Cipher_Key = cipher_2
            self.Decrypto_Hmac_Key = hmac_2

        elif self.key_direction == 1:
            self.Encrypto_Cipher_Key = cipher_2
            self.Encrypto_Hmac_Key = hmac_2
            self.Decrypto_Cipher_Key = cipher_1
            self.Decrypto_Hmac_Key = hmac_1

        else:
            self.Encrypto_Cipher_Key = cipher_1
            self.Encrypto_Hmac_Key = hmac_1
            self.Decrypto_Cipher_Key = cipher_1
            self.Decrypto_Hmac_Key = hmac_1

        log.debug(f"pre_master_secret={self.pre_master_secret.hex()}")
        log.debug(f"master_secret={master_secret.hex()}")
        log.debug(f"key={key.hex()}")
        log.debug(f"Encrypto_Cipher_Key={self.Encrypto_Cipher_Key.hex()}")
        log.debug(f"Encrypto_Hmac_Key={self.Encrypto_Hmac_Key.hex()}")
        log.debug(f"Decrypto_Cipher_Key={self.Decrypto_Cipher_Key.hex()}")
        log.debug(f"Decrypto_Hmac_Key={self.Decrypto_Hmac_Key.hex()}")


    def _init(self):
        """
        初始化剩余的上下文
        
        这里初始化了hmac的哈希算法
        """
        if self.auth == VpnCrypto.HMAC_SHA1:
            self.hmac_mode = hashlib.sha1

        else:
            raise Exception("auth error")
