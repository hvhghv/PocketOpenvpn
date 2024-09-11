#ifndef _MAIN_H
#define _MAIN_H

#include <winsock2.h>
#include <windows.h>

#define pocketvpn_htonll(n) htonll((unsigned __int64)n)
#define pocketvpn_htonl(n) htonl((unsigned __int32) n)
#define pocketvpn_htons(n) htons((unsigned __int16)n)
#define pocketvpn_ntohll(n) ntohll((unsigned __int64)n)
#define pocketvpn_ntohl(n) ntohl((unsigned __int32)n)
#define pocketvpn_ntohs(n) ntohs((unsigned __int16)n)

extern unsigned __int64 htonll(unsigned __int64 n);
extern unsigned __int64 ntohll(unsigned __int64 n);

#endif