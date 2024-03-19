"""
调试用
"""

import socket
import sys
import datetime
from time import time

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 5573))
s.setblocking(False)

def getNowTime():
    nowtime = datetime.datetime.now()
    return f"{nowtime.hour}:{nowtime.minute}:{nowtime.second}:{nowtime.microsecond}"

def debug(*args):

    data_str = ""
    for i in args:
        data_str += str(i) + ' '

    data_str += '\n'
    try:
        s.sendall(data_str.encode())
    except BlockingIOError:
        pass


class Test_Data:

    cur = 0
    buffer = b""


    def __init__(self, size):

        self.buffer = ("\n".join(map(str, list(range(size))))).encode()

    def get(self, size):

        if self.cur > len(self.buffer):
            self.cur = 0

        res = b"START\n" + self.buffer[self.cur:self.cur + size] + b"END\n"
        self.cur += size
        return res

class Test_Trace:

    count = 0
    Event = False
    Timer_Table = None
    Tag = ""

    def __init__(self) -> None:
        self.Timer_Table = {}

    def start(self,tag=""):
        self.Event = True
        self.Tag = tag

    def check(self,*args,callback=print,end='\n',**kwargs):

        if self.Event:
            callback(self.Tag,*args,end,**kwargs)

    def watch(self,*args,callback=print,timer=1,timerTag='defined',end='\n',**kwargs):

        cur_time = time()

        if not self.Timer_Table.get(timerTag,None):
            self.Timer_Table[timerTag] = cur_time
            return False


        if cur_time - self.Timer_Table[timerTag] >= timer and self.isSet():
            self.Timer_Table[timerTag] = cur_time
            self.check(*args,callback=callback,end=end,**kwargs)
            return True
        
        return False



    def isSet(self):
        return self.Event

    def end(self):
        self.Event = False

class DebugStorage:

    storage = {}

    def __init__(self) -> None:
        self.storage = {}

    def update(self,debugStorage):
        pass
        # self.storage = debugStorage.storage

    def createItem(self,key,value):
        if not self.storage.get(key,None):
            self.storage[key] = value

    def __getitem__(self,key):
        return self.storage[key]

    def __setitem__(self,key,value):
        self.storage[key] = value

def BreakPoint(*args):

    print("breakpoint!")
    print(*args)
    a = 0
    while 1:
        a = a + 1

debug_storage = DebugStorage()
debug_trace = Test_Trace()
debug_trace0 = Test_Trace()
debug_trace1 = Test_Trace()
debug_trace2 = Test_Trace()
debug_trace3 = Test_Trace()
debug_trace4 = Test_Trace()
