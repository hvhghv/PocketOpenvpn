"""
调试用
"""

import socket
import sys
import datetime
from time import time
import pickle
import re
import json

s = None

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(('127.0.0.1', 5573))
s.setblocking(False)

debug_recode_list = []

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
        if self.storage.get(key,None) == None:
            self.storage[key] = value

    def __getitem__(self,key):
        return self.storage[key]

    def __setitem__(self,key,value):
        self.storage[key] = value

def debug_hook_class_all_save():
    for i in Debug_Hook_Class.CHILD_LIST:
        i.debug_save_recode()


class Debug_Hook_Class():

    MODE_NORMAL = 0
    MODE_RAISE_ERROR = 1
    CHILD_LIST = []

    def __init__(self, test_class, save_path='debug_recode.pkl', args=(), kwargs={}):

        self.record = []
        self.save_path = save_path

        self.test_class = test_class(*args, **kwargs)
        Debug_Hook_Class.CHILD_LIST.append(self)

        for i in dir(self.test_class):

            if not callable(getattr(self.test_class, i)):
                continue

            if re.match(r'__.*__', i):
                continue

            setattr(self.test_class, i, Debug_Hook_Class_Function(self, i, getattr(self.test_class, i)))

        self.debug_put_recode({
            "name": '__init__',
            "args": args,
            "kwargs": kwargs,
            "return": None
        },self.MODE_NORMAL)


    def __getattr__(self, name):
        return getattr(self.test_class, name)

    def debug_put_recode(self, recode, mode):
        self.record.append(recode)

        if mode == self.MODE_RAISE_ERROR:
            self.debug_save_recode()

    def debug_save_recode(self):

        with open(self.save_path, "wb") as f:
            pickle.dump(self.record, f)



class Debug_Hook_Class_Function():

    entry = False

    def __init__(self, parent_debug:Debug_Hook_Class, name, hook_function):
        self.recode = []
        self.parent_debug = parent_debug
        self.hook_function = hook_function
        self.name = name
        self.entry = False

    def __call__(self, *arg, **kwds):

        if Debug_Hook_Class_Function.entry:
            return self.hook_function(*arg, **kwds)

        Debug_Hook_Class_Function.entry = True

        one_recode = {
            "name":self.name,
            "args":arg,
            "kwargs":kwds,
            "return":"RECODE_NULL"

        }

        try:
            res = self.hook_function(*arg, **kwds)

        except Exception as e:

            self.parent_debug.debug_put_recode(one_recode, self.parent_debug.MODE_RAISE_ERROR)
            raise e

        one_recode["return"] = res

        self.parent_debug.debug_put_recode(one_recode, self.parent_debug.MODE_NORMAL)

        Debug_Hook_Class_Function.entry = False

        return res


def args2str(args, space):

    if not args:
        return 'None'

    res = '\n'

    for i in args:
        res += ' ' * space + '- ' + str(i) + '\n'

    return res

def kwargs2str(kwargs, space):

    if not kwargs:
        return 'None'

    res = '\n'

    for k, v in kwargs.items():
        res += ' ' * space + '- ' + f'{str(k)}:{str(v)}' + '\n'

    return res

def debug_hook_reshow(recode_class, filepath='debug_recode.pkl', break_point=-1):

    with open(filepath, 'rb') as f:
        recode = pickle.load(f)

    if break_point == 0:
        b = 1

    recode_obj = recode_class(*recode[0]['args'], **recode[0]['kwargs'])

    for i in range(1, len(recode)):

        if i == break_point:
            b = 1

        recode_obj_function = getattr(recode_obj, recode[i]['name'])
        recode_obj_function(*recode[i]['args'], **recode[i]['kwargs'])


def debug_hook_class_pkl2yaml(filepath='debug_recode.pkl',
                           output_filepath='debug_recode.yml',
                           buffer_size=0xffffff):


    with open(filepath, 'rb') as f:
        recode = pickle.load(f)

    buffer_s = bytearray(buffer_size)
    buffer = memoryview(buffer_s)
    offset = 0

    with open(output_filepath, 'wb') as f:
        pass


    for i in range(len(recode)):

        one_recode = f"""
- index: {i}
  name: {recode[i]['name']}

  args:{args2str(recode[i]['args'], 4)}
  kwargs:{kwargs2str(recode[i]['kwargs'], 4)}

  return: {recode[i]['return']}

        """

        one_recode_b = one_recode.encode('utf-8')

        buffer[offset:offset + len(one_recode_b)] = one_recode_b
        offset += len(one_recode_b)

        if offset > buffer_size // 2:
            with open(output_filepath, 'ab') as f:
                f.write(bytes(buffer_s[:offset]))
                offset = 0

    with open(output_filepath, 'ab') as f:
        f.write(bytes(buffer_s[:offset]))


def debug_hook_recode(name, *args, **kwargs):
    debug_recode_list.append([name, args, kwargs])

def debug_hook_recode_save():


    with open('debug_recode_save.yaml', 'w') as f:
        for i in range(len(debug_recode_list)):
            f.write(f"""
- index:{i}
  name:{debug_recode_list[i][0]}

  args:{args2str(debug_recode_list[i][1], 4)}
  kwargs:{kwargs2str(debug_recode_list[i][2], 4)}

                    """)
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
