'''
TLS1.1,TLS1.2的PRF算法
'''

import hashlib
import hmac
from math import ceil,floor
from ..include.simpleFunc import *

def P_Hash(secret:bytes,seed:bytes,outLength:int,mode,LastRes = b"",Last_A_Value = b""):
    
    if Last_A_Value == b"":
        Last_A_Value = seed

    a_value = hmac.new(secret, Last_A_Value, mode).digest()
    now_res = hmac.new(secret, a_value + seed, mode).digest()

    res = LastRes + now_res
    
    if len(res) >= outLength:
        return res[:outLength]
    
    else:
        return P_Hash(secret, seed, outLength, mode, res, a_value)
def PRF_SHA256(secret:bytes, label:bytes, seed:bytes,outLength:int):
    return P_Hash(secret, label+seed, outLength, hashlib.sha256)

def PRF_SHA384(secret:bytes, label:bytes, seed:bytes,outLength:int):
    return P_Hash(secret, label+seed, outLength, hashlib.sha384)

def PRF_MD5_SHA1(secret:bytes, label:bytes, seed:bytes,outLength:int):
    
    secret_md5_end = ceil(len(secret) / 2)
    secret_sh1_start = floor(len(secret) / 2)
    
    p_hash_md5_res = P_Hash(secret[:secret_md5_end], label + seed, outLength, hashlib.md5)
    p_hash_sh1_res = P_Hash(secret[secret_sh1_start:], label + seed, outLength, hashlib.sha1)
    
    res_int =  int.from_bytes(p_hash_md5_res,'big') ^ int.from_bytes(p_hash_sh1_res,'big')
    
    return res_int.to_bytes(outLength,'big')
    


