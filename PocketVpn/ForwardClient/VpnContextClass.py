from ..Vpn.VpnContext import VpnContext
from ..Vpn.VpnCrypto import VpnCrypto
from ..include.ContextHead import *
from ..include.VpnContextContentType import *
from ..include.ProjectContextContentType import *


class VpnContextClass(VpnContext, Context_Child):

    def __init__(self,
                 context,
                 library_path,
                 occ_string,
                 virtual_local_ip='10.8.1.2',
                 ca_file_path="ca.crt",
                 crt_file_path="client.crt",
                 privateKey_file_path="client.pem",
                 dstAddress="127.0.0.1",
                 dstPort=1194,
                 socketBuffer=1024,
                 cipher=VpnCrypto.CBC_128,
                 auth=VpnCrypto.HMAC_SHA1,
                 key_direction=0,
                 VpnMtu=1480,
                 UdpMtu=0xffffff,
                 vpn_reset_time=3600,
                 udp_update_count_max=16):

        VpnContext.__init__(self, library_path, occ_string, virtual_local_ip,
                            ca_file_path, crt_file_path, privateKey_file_path,
                            dstAddress, dstPort, socketBuffer, cipher, auth,
                            key_direction, VpnMtu, UdpMtu, vpn_reset_time,
                            udp_update_count_max)

        Context_Child.__init__(self, context)

    def check(self):
        self.Loop()

    def send_udp(self, event: Event):
        self._SendUdp(event.Payload)

    def _RecvUdp(self, event: Event):
        self.createEvent(VPN_UDP_RECV, event.Payload)

    def _PrepareHardReset(self, event: Event):
        self.createEvent(VPN_PREPARE_RESET, event.Payload)
