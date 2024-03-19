from os import urandom
# from .debug import *

def list2int(data:list,order='little'):
    return int.from_bytes(bytes(data), byteorder=order)

def getWord(data:list,cur, order='little'):
    return list2int(data[cur:cur+2],order)

def getDword(data:list,cur, order='little'):
    return list2int(data[cur:cur+4],order)

def bytes2HexList(data:bytes):
    return [','.join([hex(i) for i in data])]
