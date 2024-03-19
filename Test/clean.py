import os
import shutil
root = os.path.dirname(os.path.dirname(__file__))




try:
    shutil.rmtree(root + '/__pycache__')
except:
    pass

try:
    shutil.rmtree(root + '/PocketVpn/__pycache__')
except:
    pass

try:
    shutil.rmtree(root + '/PocketVpn/include/__pycache__')
except:
    pass

try:
    shutil.rmtree(root + '/PocketVpn/Vpn/__pycache__')
except:
    pass

try:
    shutil.rmtree(root + '/PocketVpn/ForwardServer/__pycache__')
except:
    pass

try:
    shutil.rmtree(root + '/PocketVpn/VpnForwardClient/__pycache__')
except:
    pass

try:
    shutil.rmtree(root + '/Test/__pycache__')
except:
    pass

try:
    os.remove(root + '/Test/client_recv_data.txt')
except:
    pass

try:
    os.remove(root + '/Test/client_send_data.txt')
except:
    pass

try:
    os.remove(root + '/Test/server_recv_data.txt')
except:
    pass

try:
    os.remove(root + '/Test/server_send_data.txt')
except:
    pass
