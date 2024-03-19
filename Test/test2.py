'''
测试用例使用脚本:

1. 修改LIBCRYPTO

2. 执行下列命令，要求工作路径为项目根目录

openvpn Test/server.ovpn
python3 Test/test2.py

'''

LIBCRYPTO = "Lib/libcrypto-3-x64.dll"
# LIBCRYPTO = "Lib/libcrypto.so.1.0.0"
CA_FILE = "Cert/TestCa.crt"
CERT_FILE = "Cert/TestCert.crt"
PRIVATE_KEY_FILE = "Cert/TestKey.pem"
OCC_STRING = b"V4,dev-type tun,link-mtu 1559,tun-mtu 1500,proto TCPv4_CLIENT,cipher AES-128-CBC,auth SHA1,keysize 128,key-method 2,tls-client"
VIRTUAL_LOCAL_IP = '10.8.1.2'
DST_ADDRESS = '127.0.0.1'
DST_PORT = 1194

import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from PocketVpn import VpnSocket
from time import time, sleep
from threading import Thread
import socket

run_flag = True


def recv_callback(data: bytes):
    print(data)

vpn = VpnSocket(LIBCRYPTO,
                OCC_STRING,
                virtual_local_ip=VIRTUAL_LOCAL_IP,
                ca_file_path=CA_FILE,
                crt_file_path=CERT_FILE,
                privateKey_file_path=PRIVATE_KEY_FILE,
                dstAddress=DST_ADDRESS,
                dstPort=DST_PORT)

# vpn[('10.8.1.1',5444,7989)] = recv_callback # 也可这样简写
vpn.recv_callback_add('10.8.1.1',5444,7989,recv_callback)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('10.8.1.1',5444))
sock.setblocking(False)

def thread_1_main():

    while run_flag:
        vpn.Loop()

def thread_2_main():

    last_send_time = time()

    while run_flag:
        if time() - last_send_time > 3:
            last_send_time = time()
            vpn.send_udp('10.8.1.1',5444,7989,b"vpn_send")

def thread_3_main():
    while run_flag:
        try:
            data, addr = sock.recvfrom(1024)
            print(data)
        except BlockingIOError:
            pass

def thread_4_main():

    last_send_time = time()

    while run_flag:

        if time() - last_send_time > 3:
            last_send_time = time()

            try:
                sock.sendto(b"sock_send",('10.8.1.2',7989))
            except BlockingIOError:
                pass

t1 = Thread(target=thread_1_main)
t2 = Thread(target=thread_2_main)
t3 = Thread(target=thread_3_main)
t4 = Thread(target=thread_4_main)

t1.start()
t2.start()
t3.start()
t4.start()

sleep(15)

# del vpn[('10.8.1.1',5444,7989)] # 可以这样简写
vpn.recv_callback_del('10.8.1.1',5444,7989)

print('del one listen')
sleep(15)

run_flag = False
t1.join()
t2.join()
t3.join()
t4.join()
