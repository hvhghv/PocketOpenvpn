'''
测试用例使用脚本:

1. 修改LIBCRYPTO

2. 执行下列命令，要求工作路径为项目根目录

ncat -l -k 127.0.0.1 5573
openvpn Test/server.ovpn
python3 Test/test1.py

'''


TEST_PATH = "Test/"
LIBCRYPTO = "Lib/libcrypto-3-x64.dll"
# LIBCRYPTO = "Lib/libcrypto.so.1.0.0"
CA_FILE = "Cert/TestCa.crt"
CERT_FILE = "Cert/TestCert.crt"
PRIVATE_KEY_FILE = "Cert/TestKey.pem"
OCC_STRING = b"V4,dev-type tun,link-mtu 1559,tun-mtu 1500,proto TCPv4_CLIENT,cipher AES-128-CBC,auth SHA1,keysize 128,key-method 2,tls-client"
VIRTUAL_LOCAL_IP = '10.8.1.2'
DST_ADDRESS = '127.0.0.1'
DST_PORT = 1194
LOOP_SLEEP = 0

TEST_TIME = 30
TEST_WAIT_RECV_TIME = 15
USE_COVERAGE = False

import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from PocketVpn import *
from PocketVpn.include.debug import *
import multiprocessing
import socket
import time
from datetime import datetime


def forward_client(event_list, debugStorage):

    debug_storage.update(debugStorage)

    forward_client_table = (('127.0.0.1', 8090, 4563), )

    forward_client_object = ForwardClient(
        LIBCRYPTO,
        OCC_STRING,
        VIRTUAL_LOCAL_IP,
        CA_FILE,
        CERT_FILE,
        PRIVATE_KEY_FILE,
        DST_ADDRESS,
        DST_PORT,
        forward_default_Table=forward_client_table,
    )

    while 1:

        if event_list[5].is_set():
            break

        debug_trace1.start('[forward_client]')
        forward_client_object.Loop()
        debug_trace1.end()


def forward_server(event_list, debugStorage):

    debug_storage.update(debugStorage)
    forward_server_object = ForwardServer()

    while 1:

        if event_list[5].is_set():
            break

        debug_trace.start('[forward_server]')
        forward_server_object.Loop()
        debug_trace.end()


def client(event_list, queue, debugStorage):

    debug_storage.update(debugStorage)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('10.8.1.1', 4563))

    client_send_data = b""
    client_recv_data = b""
    test_data_object = Test_Data(1024 * 1024 * 1)
    sock.setblocking(False)

    event_list[0].wait()
    while not event_list[2].is_set():

        if not event_list[1].is_set():
            test_data = test_data_object.get(10240)
        else:
            test_data = b""

        try:
            size = sock.send(test_data)
            client_send_data += test_data[0:size]
        except BlockingIOError:
            pass

        try:
            data = sock.recv(0xffffff)
            client_recv_data += data
        except BlockingIOError:
            pass

        time.sleep(LOOP_SLEEP)

    queue.put(('client', client_send_data, client_recv_data))


def server(event_list, queue, debugStorage):

    debug_storage.update(debugStorage)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 8090))
    s.listen(1)

    sock, _ = s.accept()

    server_send_data = b""
    server_recv_data = b""
    test_data_object = Test_Data(1024 * 1024 * 1)
    sock.setblocking(False)

    event_list[0].wait()
    while not event_list[2].is_set():

        if not event_list[1].is_set():
            test_data = test_data_object.get(1024)

        else:
            test_data = b""

        try:
            size = sock.send(test_data)
            server_send_data += test_data[0:size]
        except BlockingIOError:
            pass

        try:
            data = sock.recv(0xffffff)
            server_recv_data += data
        except BlockingIOError:
            pass

        time.sleep(LOOP_SLEEP)

    queue.put(('server', server_send_data, server_recv_data))


if __name__ == "__main__":

    event_list = []

    for i in range(7):
        event_list.append(multiprocessing.Event())

    Process_Queue = multiprocessing.Queue()

    t1 = multiprocessing.Process(target=forward_client,
                                 args=(
                                     event_list,
                                     debug_storage,
                                 ))
    t2 = multiprocessing.Process(target=forward_server,
                                 args=(
                                     event_list,
                                     debug_storage,
                                 ))
    t3 = multiprocessing.Process(target=server,
                                 args=(event_list, Process_Queue,
                                       debug_storage))
    t4 = multiprocessing.Process(target=client,
                                 args=(event_list, Process_Queue,
                                       debug_storage))

    t1.start()
    t2.start()
    t3.start()

    time.sleep(5)
    t4.start()

    time.sleep(1)

    event_list[0].set()

    print("start send/recv")
    time.sleep(TEST_TIME)
    event_list[1].set()

    print("stop send")

    time.sleep(TEST_WAIT_RECV_TIME)
    print("stop recv")
    print()

    event_list[2].set()

    client_send_data = None
    client_recv_data = None
    server_send_data = None
    server_recv_data = None

    for i in range(2):
        one_tuple = Process_Queue.get()

        if one_tuple[0] == 'client':
            client_send_data = one_tuple[1]
            client_recv_data = one_tuple[2]
        elif one_tuple[0] == 'server':
            server_send_data = one_tuple[1]
            server_recv_data = one_tuple[2]

    print('client_send_data', len(client_send_data))
    print('client_recv_data', len(client_recv_data))
    print('server_send_data', len(server_send_data))
    print('server_recv_data', len(server_recv_data))

    with open(TEST_PATH + 'client_send_data.txt', 'wb') as f:
        f.write(client_send_data)

    with open(TEST_PATH + 'client_recv_data.txt', 'wb') as f:
        f.write(client_recv_data)

    with open(TEST_PATH + 'server_send_data.txt', 'wb') as f:
        f.write(server_send_data)

    with open(TEST_PATH + 'server_recv_data.txt', 'wb') as f:
        f.write(server_recv_data)

    if client_send_data != server_recv_data:
        print("client send data != server recv data")
    if client_recv_data != server_send_data:
        print("client recv data != server send data")

    print()
    print("test finish")
    print(datetime.now())
    t1.kill()
    t2.kill()
    t3.kill()
    t4.kill()
