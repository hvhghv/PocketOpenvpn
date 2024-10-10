import socket
import debug
import threading
import time


test_way = 2
wait_time = 100

status = 0
task_table = []


def func1():

    data = debug.Test_Data(0xffffff)
    a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    a.bind(('127.0.0.1', 7890))
    a.listen(1)

    sock, _ = a.accept()

    def s1():
        with open("s1.text", "wb") as f:
            while status == 0:
                send_data = data.get(0xffff)
                sock.sendall(send_data)
                f.write(send_data)


    def r1():

        with open("r1.text", "wb") as f:
            while status == 0:
                recv_data = sock.recv(0xffff)
                f.write(recv_data)

    if (test_way == 0):
        t1 = threading.Thread(target=s1)
        t1.start()
        task_table.append(t1)

    if (test_way == 1):
        t2 = threading.Thread(target=r1)
        t2.start()
        task_table.append(t2)

    if (test_way == 2):
        t1 = threading.Thread(target=s1)
        t1.start()
        task_table.append(t1)

        t2 = threading.Thread(target=r1)
        t2.start()
        task_table.append(t2)


def func2():
    data = debug.Test_Data(0xffffff)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('10.8.1.2', 6789))


    def s1():
        with open("s2.text", "wb") as f:
            while status == 0:
                send_data = data.get(0xffff)
                sock.sendall(send_data)
                f.write(send_data)


    def r1():

        with open("r2.text", "wb") as f:
            while status == 0:
                recv_data = sock.recv(0xffff)
                f.write(recv_data)

    if (test_way == 0):
        t1 = threading.Thread(target=r1)
        t1.start()
        task_table.append(t1)

    if (test_way == 1):
        t2 = threading.Thread(target=s1)
        t2.start()
        task_table.append(t2)

    if (test_way == 2):
        t1 = threading.Thread(target=r1)
        t1.start()
        task_table.append(t1)

        t2 = threading.Thread(target=s1)
        t2.start()
        task_table.append(t2)

print("start")

t3 = threading.Thread(target=func1)
t3.start()
time.sleep(2)

t4 = threading.Thread(target=func2)
t4.start()


time.sleep(wait_time)
status = 1
print("stop")

for i in task_table: i.join()

print("end")

