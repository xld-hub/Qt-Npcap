#ifndef WINPCAP_H
#define WINPCAP_H

#include "pcap.h"
#include <QDebug>

#ifndef WIN32
    #include <sys/socket.h>
    #include <netinet/in.h>
#else
    #include <winsock.h>
#endif

class Winpcap
{
public:
    Winpcap();


    void ifprint(pcap_if_t *d);
    char *iptos(u_long in);
    char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);
};

#endif // WINPCAP_H
