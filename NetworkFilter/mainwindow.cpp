#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "npcap.h"

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    Npcap npcap;
    pcap_if_t *alldevs;
    pcap_if_t **palldevs;
    palldevs = &alldevs;

    npcap.GetAllDevices(palldevs);

    pcap_if_t *d;
    int i = 0;
    for(d = alldevs; d; d=d->next)
      i++;
    string *s = npcap.GerDevicesInfo(alldevs,i);

    for (int j = 0; j < i; j++)
    {
        qDebug("%d. %s\n",j+1,s[j].c_str());
    }
    int inum;
    inum = 3;
    npcap.GoChoiceDevices(palldevs,inum,i);

    //用户输入 过滤字符串
    char packet_filter[] = "host 192.168.204.128";
    pcap_t *adhandle;
    pcap_t **padhandle;
    padhandle = &adhandle;
    npcap.PcapFilter(padhandle,alldevs,packet_filter);

    pcap_freealldevs(alldevs);
    //开始捕获
//    pcap_loop(adhandle, 0, packet_handler, NULL);

    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    int res;
    res = pcap_next_ex(adhandle, &header,&pkt_data);
    while ((res = pcap_next_ex(adhandle, &header,&pkt_data))>=0) {
        if(res == 0)
            continue;

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
        ih = (ip_header *) (pkt_data +
            14); //以太网头部长度

        /* 获得UDP首部的位置 */
        ip_len = (ih->ver_ihl & 0xf) * 4;
        uh = (udp_header *) ((u_char*)ih + ip_len);

        /* 将网络字节序列转换成主机字节序列 */
        sport = ntohs( uh->sport );
        dport = ntohs( uh->dport );

        /* 打印IP地址和UDP端口 */
        qDebug("%d.%d.%d.%d.%d ---> %d.%d.%d.%d.%d\n",
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
}
/* 回调函数，当收到每一个数据包时会被libpcap所调用 */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm *ltime;
    char timestr[16];
    ip_header *ih;
    udp_header *uh;
    u_int ip_len;
    u_short sport,dport;
    time_t local_tv_sec;

    /* 将时间戳转换成可识别的格式 */
    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

    /* 打印数据包的时间戳和长度 */
//    qDebug("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

    /* 获得IP数据包头部的位置 */
    ih = (ip_header *) (pkt_data +
        14); //以太网头部长度

    /* 获得UDP首部的位置 */
    ip_len = (ih->ver_ihl & 0xf) * 4;
    uh = (udp_header *) ((u_char*)ih + ip_len);

    /* 将网络字节序列转换成主机字节序列 */
    sport = ntohs( uh->sport );
    dport = ntohs( uh->dport );

    /* 打印IP地址和UDP端口 */
    qDebug("%d.%d.%d.%d.%d ---> %d.%d.%d.%d.%d\n",
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


MainWindow::~MainWindow()
{
    delete ui;
}


