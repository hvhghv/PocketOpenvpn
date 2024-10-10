#include <WinSock2.h>
#include <Windows.h>
#include "Pocketvpn/pocketvpn.h"
#include "io.h"
#include "string.h"

SOCKET s;

#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT 1194
#define BIND_PORT 5678

#define FORWARD_SERVER_ADDR "127.0.0.1"
#define FORWARD_SERVER_PORT 7890
#define FORWARD_BIND_PORT 6789

typedef struct {
    SOCKET* s;
    struct tcp_pcb *tpcb;
} forward_t;

const char certfile[] =
    "\
-----BEGIN CERTIFICATE-----\n\
MIIDwDCCAqigAwIBAgIILZVkbJHVQ/UwDQYJKoZIhvcNAQELBQAwWzELMAkGA1UE\n\
BhMCQ04xCjAIBgNVBAgTATExCjAIBgNVBAcTATExCjAIBgNVBAoTATExCjAIBgNV\n\
BAsTATExCjAIBgNVBAMTATExEDAOBgkqhkiG9w0BCQEWATEwIBcNMjQwMTE4MDQx\n\
OTAwWhgPMjEyMzAxMTgwNDE5MDBaMFsxCzAJBgNVBAYTAkNOMQowCAYDVQQIEwEz\n\
MQowCAYDVQQHEwEzMQowCAYDVQQKEwEzMQowCAYDVQQLEwEzMQowCAYDVQQDEwEz\n\
MRAwDgYJKoZIhvcNAQkBFgEzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n\
AQEApEu+QbsbFzUATlCxMIMz0LkqSaQX7xlrgNVq/qOTJTDX9cscCCfkvK01doXB\n\
a8XSxu6AbdppkboBmoKJMZ/aTp2Ja2BCHawtiysZY+NEVRulwqsaiddqFVvyMvJ2\n\
YAiU69728ULwEr92tGAb2p+xlAsg/ggoWd73o5DzC91f7JxH1oIH0NwnJJxYHZI2\n\
Ep8ovBsvzCshf4CS4Ihs9nIMYeZakIMZGTOn9ockxGMS3W3/7yxS0vBvTR7DP/0o\n\
uhKQsG6Hlf4VSM9fAvSTo3ZTg8ny/shIpXspoICkXgTxNAA8NkUWXzmflDS8GhA3\n\
j7owr9iOLic/XtkBIejJU9pFxwIDAQABo4GFMIGCMAwGA1UdEwEB/wQCMAAwHQYD\n\
VR0OBBYEFNEEf8RNk1SCSanar7/sMKFaYmAqMAsGA1UdDwQEAwIDuDATBgNVHSUE\n\
DDAKBggrBgEFBQcDAjARBglghkgBhvhCAQEEBAMCBaAwHgYJYIZIAYb4QgENBBEW\n\
D3hjYSBjZXJ0aWZpY2F0ZTANBgkqhkiG9w0BAQsFAAOCAQEAO9zheSjA+1WLHtxL\n\
bopX4BsocUZ4MfA3z+Au9EPZ4ZQBXDbA/UYswp6wUL715lidE/uUj/Q+mLrZizvc\n\
N2cO9IMKfQtM1xniMHhMpdo15bg6uOqkKHLjmt7Wk18AmtRFOIpMBAlTqfXLlfkS\n\
JElRzuzTVsmst5NexP/P+CL5c/wBLXfQgwTsxK6b1nZD8DpHxFbLCnOfyuqQoiFz\n\
yj5cUQOxIrEH3w/n/W2uS6c8SyvquKCL7i6Bbc3bEub9sBocgeL2XkhfdszOwKeS\n\
9iCN8swsNeDKFicvriQtY590o4Qx+HwEW52Eqx3rSu8+wcMZ5koV8juDZrpVPhRN\n\
RXF4CQ==\n\
-----END CERTIFICATE-----\n\
";

const char keyfile[] =
    "\
-----BEGIN RSA PRIVATE KEY-----\n\
MIIEowIBAAKCAQEApEu+QbsbFzUATlCxMIMz0LkqSaQX7xlrgNVq/qOTJTDX9csc\n\
CCfkvK01doXBa8XSxu6AbdppkboBmoKJMZ/aTp2Ja2BCHawtiysZY+NEVRulwqsa\n\
iddqFVvyMvJ2YAiU69728ULwEr92tGAb2p+xlAsg/ggoWd73o5DzC91f7JxH1oIH\n\
0NwnJJxYHZI2Ep8ovBsvzCshf4CS4Ihs9nIMYeZakIMZGTOn9ockxGMS3W3/7yxS\n\
0vBvTR7DP/0ouhKQsG6Hlf4VSM9fAvSTo3ZTg8ny/shIpXspoICkXgTxNAA8NkUW\n\
XzmflDS8GhA3j7owr9iOLic/XtkBIejJU9pFxwIDAQABAoIBAEh6j56wu7VDsPRb\n\
nadgogmovhKJnPNiW+4UeGSIZeAIyaTJqv6gFsTzhnvYaukv9pnC2o5bxam/jHiM\n\
sJhfRC/dSKPBbbloXRkhdMx/lIQVM82KrST1DnwIuXKnSvh3oLbjgD4TwRQMOgI9\n\
ydvrCixcsnvOvnpTJh0W01m/GdOnsgpFFzEfMUmasEziHn93da+t/2+47N7KbXl1\n\
Hx7N/6J6voJTuMOXz7Ei3i2J9disjmVK4FzBl0tTNibLHPNNrw+scY95WeuK/bcY\n\
kisCwRvhkajb2CRgPOXyZcWFl9FPAkwl/tg3Gx3g+aYG8mN7BOFWtGFGQ8PqD37m\n\
t5IhF9UCgYEA47uxdQB+uDFxHF7q2Gtqn8r4QeVGLSq2GmxR3ZCA98enYDP+m1Bv\n\
FgsxXf0170F8rThgfa6BUjvWwcS1vOFna3nkO6Med5g2LP8D3M3y2mjgz3Rd+0r+\n\
yXNSSWOs+IzeyE/kXTaVPylvkba5UpqYIjcg4R2xyDRrSb01/Yul7y0CgYEAuLBO\n\
UXA/zWCRWZjwM1GJia4YuSzbGA/j+5QUe4UwRr8Rp+ArlNfhyseUYncKeEseYRB0\n\
oGl15nCTE0rlIyxDgf9QYYu8XeFKawZnXRU/7daxdxI+sXYyiOEl+z4azzx94pJ/\n\
/Sxuq6VdXyKKYnjmNsHBBAVqdpoVEbuawYnjgUMCgYEAmdYdnyrxbx2/Ceo4fG+7\n\
fCwRHfpyOGqkzx6jAqft5vOQ5lTZRjPEhsCS3aoB+Bhlz2HJFL2AEHvpq8Vk+y3M\n\
vfZ+LacYGrPQzP6LrmnVBqNYUeuK3QkhKhZj3L2fh9spV2lYm3sWwK8N9gHYGKvj\n\
3yEcbdWwVczLOOm/AgKG2hUCgYA3I3veWHLT8Ba09zIPQDKdxjpfXoLyxhu8ilMr\n\
JXJqTLUKt6SLRYCFt9wXIY8gptylAfKvyYyHheiDBAMw4xAsiXsIBF3ycUZ0eW72\n\
nVd+vHAzKmFJPg6MSxu5zKrYYCj9MdvATDmmSTJ9KqTCDXI9us7TUoKcchgEOUxU\n\
p8QiXQKBgHsmJYt+NF6x5/66EoTSOKvEG8aWiIkLApatY+LAyxHfUU/A3nNIsbI9\n\
mvb3znqnCON/evzs9jAsVN5lcV2W0w5t6phArPgeGK/S6bCQJJswfPWHGYl7TNk7\n\
jZYtqa3Qfmez2FnVGh5KGtrLBbAqAC7Vew+lVc7oNXFm2VXNj/C6\n\
-----END RSA PRIVATE KEY-----\n\
";

const char cafile[] =
    "\
-----BEGIN CERTIFICATE-----\n\
MIIDrDCCApSgAwIBAgIIPuqcv8afrcIwDQYJKoZIhvcNAQELBQAwWzELMAkGA1UE\n\
BhMCQ04xCjAIBgNVBAgTATExCjAIBgNVBAcTATExCjAIBgNVBAoTATExCjAIBgNV\n\
BAsTATExCjAIBgNVBAMTATExEDAOBgkqhkiG9w0BCQEWATEwIBcNMjQwMTE4MDQx\n\
NjAwWhgPMjEyNDAxMTgwNDE2MDBaMFsxCzAJBgNVBAYTAkNOMQowCAYDVQQIEwEx\n\
MQowCAYDVQQHEwExMQowCAYDVQQKEwExMQowCAYDVQQLEwExMQowCAYDVQQDEwEx\n\
MRAwDgYJKoZIhvcNAQkBFgExMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n\
AQEAiNZtLunAfLK9dShI9D/GjRwTGRChP6ZRSokos65BVHVfvYONaaIjRRz3iAAt\n\
fMIR/ZzpJZzZLHtVxsnqOZn6u7D8ZInCtXSoab/3au5j+3pXYxjiWbzkH6tHznW5\n\
nXBfKuE3cpKkfmjUI3MeX2IRgQc+I0AUkIOofntPHkehqqw0Fc4RkiMEk3cv7Xt6\n\
ZsD8uuqoqUz0e6h2AS30H+tDk9Nsu3NHyTpscfvHjS4Nimz37Pc6+IoOoYkZlYmE\n\
/2jja6R3PdpDwgjsbkxcvaaivgGPPQLkV1YxnrYFpnmKvVBHbEfOMVXmaaqMKtbe\n\
3h/Ql534kAUU6ITQL5/7DiZvHQIDAQABo3IwcDAPBgNVHRMBAf8EBTADAQH/MB0G\n\
A1UdDgQWBBRng909LeB6CXGLCV+9Lt3/JxOjKTALBgNVHQ8EBAMCAQYwEQYJYIZI\n\
AYb4QgEBBAQDAgAHMB4GCWCGSAGG+EIBDQQRFg94Y2EgY2VydGlmaWNhdGUwDQYJ\n\
KoZIhvcNAQELBQADggEBAFXgIKtT5bqtoTTzZW9yzFBiA4nsk3uAKLq4jUWNY22U\n\
YdR1S8QHVAsDXaaFf7KZHd5yfvcGo63pM6YL7skUsByLc7Gt2EiptvTevmtZ2KvD\n\
EatYovXWB6Sjsi+jWBbIplyr8WmqbUTGeFLs4c72AVlhN230sBR//4Wglae9fFH6\n\
M7OSPqVP/9zlJKJ2dmioUcmgcOkDliaoOwL6jqmjGgFs+Ci+Sjr60mDYQ8KiFc+L\n\
38tbxqecmncDIUk8ODROrjeiPbGyUuWd+UMDtUD7qivlKfYvX1VhlfvLgDTE4zOt\n\
ZdYeBQ2BqRzk4gP0ovs947gCkn8tj34WCgz+LAfjatg=\n\
-----END CERTIFICATE-----\n\
";

int socket_init() {
    WSADATA ws;
    SOCKADDR_IN addr_dst;
    unsigned long ul = 1;

    WSAStartup(MAKEWORD(2, 2), &ws);
    s = socket(AF_INET, SOCK_STREAM, 0);

    if (ioctlsocket(s, FIONBIO, &ul) == SOCKET_ERROR) {
        pocketvpn_printf("set socket nonblocking failed!");
        return 1;
    };

    addr_dst.sin_addr.S_un.S_addr = inet_addr(SERVER_ADDR);

    addr_dst.sin_port   = htons(SERVER_PORT);
    addr_dst.sin_family = AF_INET;

    if (connect(s, (SOCKADDR *)&addr_dst, sizeof(addr_dst)) == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
        return 1;
    }

    return 0;
}

uint32_t socket_read(void *socket_obj, uint8_t *buffer, uint32_t size) {
    int res = recv(*(SOCKET *)socket_obj, (char *)buffer, size, 0);

    if (res == SOCKET_ERROR) {

        if (WSAGetLastError() == WSAEWOULDBLOCK) {
            return 0;
        }

        else {
            printf("pocketvpn_socket_read failed!\n");
            while (1) {
            };
        }
    }

    return (uint32_t)res;
}

void socket_write(void *socket_obj, uint8_t *buffer, uint32_t size) {

    int res;

    while (size) {
        res = send(*(SOCKET *)socket_obj, (const char *)buffer, size, 0);

        if (res == SOCKET_ERROR) {

            if (WSAGetLastError() == WSAEWOULDBLOCK) {
                Sleep(1);
                continue;
            }

            while (1) {
            };
        }

        buffer += res;
        size -= res;
    }
}

uint32_t socket_write_ready(void *socket_obj){
    return 0;
}

char vpnsock_send_buf1[200];
int m_vpnsock_dispatch_fn_1(vpnsock_t *vpnsock_obj, uint8_t event, uint8_t *buffer, void **outBuffer, uint32_t size, uint32_t *outSize){
    
    int res;

    if (event == VPNSOCKET_EVENT_RECV){
        res = sprintf(vpnsock_send_buf1, "[server recv]: ");
        memcpy(vpnsock_send_buf1 + res, buffer, size);
        vpnsock_send_buf1[res + size] = '\n';
        *outBuffer = vpnsock_send_buf1;
        *outSize = res + size + 1;


        if (size >= 5 && memcmp(buffer, "close", 5) == 0){
            return -1;
        }

        if (size >= 5 && memcmp(buffer, "abort", 5) == 0) {
            return -2;
        }

        return size;
    }

    return 0;

}


char vpnsock_send_buf2[4096];
int m_vpnsock_dispatch_fn_2(vpnsock_t *vpnsock_obj, uint8_t event, uint8_t *buffer, void **outBuffer, uint32_t size, uint32_t *outSize) {

    int res;
    SOCKET *forward_sock;
    uint32_t send_size;

    if (event == VPNSOCKET_EVENT_ACCESS){
        
        SOCKADDR_IN addr_dst;
        unsigned long ul = 1;

        forward_sock  = malloc(sizeof(SOCKET));
        *forward_sock = socket(AF_INET, SOCK_STREAM, 0);

        if (ioctlsocket(*forward_sock, FIONBIO, &ul) == SOCKET_ERROR) {
            pocketvpn_printf("set socket nonblocking failed!");
            return -2;
        };

        addr_dst.sin_addr.S_un.S_addr = inet_addr(FORWARD_SERVER_ADDR);
        addr_dst.sin_port             = htons(FORWARD_SERVER_PORT);
        addr_dst.sin_family           = AF_INET;

        if (connect(*forward_sock, (SOCKADDR *)&addr_dst, sizeof(addr_dst)) == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
            pocketvpn_printf("set forward connect failed!");
            return -2;
        }

        vpnsock_obj->user_mem = forward_sock;
        return 0;

    }

    forward_sock = vpnsock_obj->user_mem;

    if (event == VPNSOCKET_EVENT_CLEAN){
        closesocket(*forward_sock);
        free(vpnsock_obj->user_mem);
    }

    if (event == VPNSOCKET_EVENT_RECV){


        res = send(*forward_sock,(const char*)buffer, size, 0);

        if (res == SOCKET_ERROR) {

            if (WSAGetLastError() == WSAEWOULDBLOCK) {
                return 0;
            }

        return -2;

        }

        return res;

    }

    if (event == VPNSOCKET_EVENT_LOOP){
        send_size = size < sizeof(vpnsock_send_buf2) ? size : sizeof(vpnsock_send_buf2);
        res       = recv(*forward_sock, vpnsock_send_buf2, send_size, 0);
        *outBuffer = vpnsock_send_buf2;

        if (res == SOCKET_ERROR) {

            if (WSAGetLastError() == WSAEWOULDBLOCK) {
                return 0;
            }

            return -2;
        }

        return res;
    }


    return 0;
}


int server_init() {

    tcp_bind_service(0, 0, 0, 0, BIND_PORT, m_vpnsock_dispatch_fn_1);
    tcp_bind_service(0, 0, 0, 0, FORWARD_BIND_PORT, m_vpnsock_dispatch_fn_2);

    return 0;
}

int main() {

    if (socket_init() != 0) {

        printf("socket init failed!\n");
        while (1) {
        };
    }

    if (pocketvpn_init() != 0){
        printf("pocketvpn_init failed!\n");
        while (1) {
        };
    }

    if (server_init() != 0){
        printf("server_init failed!\n");
        while (1) {
        };
    }

    pocketvpn_t pocketvpn;
    int res;

    res = pocketvpn_new(&pocketvpn, &s, socket_read, socket_write, socket_write_ready, cafile, sizeof(cafile), certfile, sizeof(certfile), keyfile, sizeof(keyfile), CIPHER_AES_256_CBC, HMAC_MODE_SHA512, 0, 1300, 3600);

    if (res != 0){
        printf("pocketvpn_new failed!\n");
        while (1) {
        };
    }


    while (1) {
        pocketvpn_loop(&pocketvpn);
    }
}