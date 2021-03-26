#include "npcap.h"

Npcap::Npcap()
{
}
BOOL Npcap:: GetAllDevices(pcap_if_t **alldevs)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &*alldevs, errbuf) == -1)
    {
        qDebug("Error in pcap_findalldevs: %s\n", errbuf);
        return false;
    }
    return true;
}

string * Npcap:: GerDevicesInfo(pcap_if_t *alldevs,int devnum)
{
    pcap_if_t *d;
    string* str = new string[devnum];
    //存入数组
    int i = 0;
    for(d = alldevs; d; d=d->next)
    {
        //如果有描述
        if (d->description)
        {
            char *tstr =d->description;
            bool flag = false;
            string str_s;
            while (*tstr != 0)
            {
                if ('\'' == *tstr)
                {
                    flag = !flag;
                    if(flag)
                        tstr++;
                }
                if(flag)
                {
                    str_s += *tstr;
                }
                tstr++;
            }
            str[i++]=str_s;
            // i++;
        }
        else//如果没有描述
        {
            qDebug("No description available\n");
            str[0] = "No description available" ;
        }
    }

    if(i==0)
    {
        qDebug("\nNo interfaces found! Make sure WinPcap is installed.\n");
        str[0] = "No interfaces found! Make sure WinPcap is installed.";
    }
    return str;
}

BOOL Npcap:: GoChoiceDevices(pcap_if_t **alldevs,int inum,int alldevnum)
{
    //非法选择
    if(inum < 1 || inum > alldevnum)
    {
        qDebug("\nInterface number out of range.\n");
        return NULL;
    }

    /* 跳转到已选设备 */
    int i;
    for(i=0; i< inum-1 ; i++)
    {
        *alldevs = (*alldevs)->next;
    }

    return true;
}


BOOL Npcap:: PcapFilter(pcap_t **adhandle,pcap_if_t *d,char packet_filter[])
{
    u_int netmask;
    struct bpf_program fcode;

    char errbuf[PCAP_ERRBUF_SIZE];
    /* 打开适配器 返回adhandle*/
    *adhandle= pcap_open(
                d->name,  // 设备名
                65536,     // 要捕捉的数据包的部分
                // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                PCAP_OPENFLAG_PROMISCUOUS,         // 混杂模式
                1000,      // 读取超时时间
                NULL,      // 远程机器验证
                errbuf     // 错误缓冲池
            );

    if (*adhandle == NULL)
    {
        qDebug("\nUnable to open the adapter. %s is not supported by WinPcap\n",d->name);
        /* 释放设备列表 */
        pcap_freealldevs(d);
        return false;
    }

    /* 检查数据链路层，为了简单，我们只考虑以太网 */
    if(pcap_datalink(*adhandle) != DLT_EN10MB)
    {
        qDebug("\nThis program works only on Ethernet networks.\n");
        /* 释放设备列表 */
        pcap_freealldevs(d);
        return false;
    }

    if(d->addresses != NULL)
        /* 获得接口第一个地址的掩码 */
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* 如果接口没有地址，那么我们假设一个C类的掩码 */
        netmask=0xffffff;


    //编译过滤器 char packet_filter[] = "host 172.22.218.82";
    if (pcap_compile(*adhandle, &fcode, packet_filter, 1, netmask) <0 )
    {
        qDebug("\nUnable to compile the packet filter. Check the syntax.\n");
        /* 释放设备列表 */
        pcap_freealldevs(d);
        return false;
    }

    //设置过滤器
    if (pcap_setfilter(*adhandle, &fcode)<0)
    {
        qDebug("\nError setting the filter.\n");
        /* 释放设备列表 */
        pcap_freealldevs(d);
        return false;
    }

    qDebug("\nlistening on %s...\n", d->description);

    /* 释放设备列表 */
//    pcap_freealldevs(d);
    return true;
}