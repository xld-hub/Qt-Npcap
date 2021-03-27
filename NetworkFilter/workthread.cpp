#include "workthread.h"
#include <QDebug>

WorkThread::WorkThread(QObject *parent) : QObject(parent)
{

}

void WorkThread::start1()
{
    emit workStart(m_adhandle);
    doWork(m_adhandle);
}
void WorkThread::doWork(pcap_t * adhandle)
{

    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    int res;
//    res = pcap_next_ex(adhandle, &header,&pkt_data);

    while ((res = pcap_next_ex(adhandle, &header,&pkt_data))>=0)
    {
        if(res == 0)
            continue;
        char *data = new char[32];
        struct tm *ltime;
        char timestr[16];
        time_t local_tv_sec;
        ip_header *ih;
        udp_header *uh;
        u_int ip_len;
        u_short sport,dport;
        /* 将时间戳转换成可识别的格式 */
        local_tv_sec = header->ts.tv_sec;
        ltime=localtime(&local_tv_sec);
        strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

        /* 打印数据包的时间戳和长度 */
    //    qDebug("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

        /* 获得IP数据包头部的位置 */
        ih = (ip_header *) (pkt_data +14); //以太网头部长度

        //ping数据
        data = (char*)(pkt_data + 14 + 20 + 8);
        qDebug("ip包总长度为 %d,数据为 %s", ntohs(ih->tlen), data);


        /* 获得UDP首部的位置 */
        ip_len = (ih->ver_ihl & 0xf) * 4;
        uh = (udp_header *) ((u_char*)ih + ip_len);

        /* 将网络字节序列转换成主机字节序列 */
        sport = ntohs( uh->sport );
        dport = ntohs( uh->dport );

        /* 打印IP地址和UDP端口 */
        qDebug("源IP %d.%d.%d.%d.%d ---> 目的IP %d.%d.%d.%d.%d\n",
            ih->saddr.byte1,
            ih->saddr.byte2,
            ih->saddr.byte3,
            ih->saddr.byte4,
            sport,
            ih->daddr.byte1,
            ih->daddr.byte2,
            ih->daddr.byte3,
            ih->daddr.byte4,
            dport);
    }
    if(res == -1)
    {
        qDebug("接受数据帧错误: %s",pcap_geterr(adhandle));
    }

    emit workFinished();
}
