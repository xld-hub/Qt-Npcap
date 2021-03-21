#include "winpcap.h"

Winpcap::Winpcap()
{

}

void Winpcap:: ifprint(pcap_if_t *d)
{
  pcap_addr_t *a;
  char ip6str[128];


  qDebug("%s\n",d->name);

  char *str=d->description;
  bool flag = false;
  qDebug("\tdescription: ");
  while (*str != 0)
  {
    if ('\'' == *str)
        flag = !flag;
    str++;
    if(flag)
        printf("%c",*str);

  }
  printf("\b");

  /* Loopback Address*/
  qDebug("\tLoopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");

  /* IP addresses */
  for(a=d->addresses;a;a=a->next) {
    qDebug("\tAddress Family: (%d)\n",a->addr->sa_family);

    switch(a->addr->sa_family)
    {
      case AF_INET:

        printf("\tAddress Family Name: AF_INET\n");
        if (a->addr)
            // printf("\tAddress: %s\n",inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr));
          qDebug("\tAddress: %s\n",iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
        if (a->netmask)
          qDebug("\tNetmask: %s\n",inet_ntoa(((struct sockaddr_in *)a->netmask)->sin_addr));
        if (a->broadaddr)
          qDebug("\tBroadcast Address: %s\n",inet_ntoa(((struct sockaddr_in *)a->broadaddr)->sin_addr));
        if (a->dstaddr)
          qDebug("\tDestination Address: %s\n",iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
        break;

      case AF_INET6:
        qDebug("\tAddress Family Name: AF_INET6\n");
        if (a->addr)
          qDebug("\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
       break;

      default:
        qDebug("\tAddress Family Name: Unknown\n");
        break;
    }
  }
  qDebug("\n");
}



#define IPTOSBUFFERS    12
char* Winpcap::iptos(u_long in)
{

    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;

    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    qDebug(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

char* Winpcap:: ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
    socklen_t sockaddrlen;

    #ifdef WIN32
    sockaddrlen = sizeof(struct sockaddr_in6);
    #else
    sockaddrlen = sizeof(struct sockaddr_storage);
    #endif


    if(getnameinfo(sockaddr,
        sockaddrlen,
        address,
        addrlen,
        NULL,
        0,
        NI_NUMERICHOST) != 0) address = NULL;

    return address;
}
