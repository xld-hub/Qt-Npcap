#ifndef NPCAP_H
#define NPCAP_H

#include "pcap.h"
#include <time.h>
#include <QDebug>
#include <string>

using std::string;


/* 4字节的IP地址 */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 首部 */
typedef struct ip_header{
    u_char  ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
    u_char  tos;            // 服务类型(Type of service)
    u_short tlen;           // 总长(Total length)
    u_short identification; // 标识(Identification)
    u_short flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
    u_char  ttl;            // 存活时间(Time to live)
    u_char  proto;          // 协议(Protocol)
    u_short crc;            // 首部校验和(Header checksum)
    ip_address  saddr;      // 源地址(Source address)
    ip_address  daddr;      // 目的地址(Destination address)
    u_int   op_pad;         // 选项与填充(Option + Padding)
}ip_header;

/* UDP 首部*/
typedef struct udp_header{
    u_short sport;          // 源端口(Source port)
    u_short dport;          // 目的端口(Destination port)
    u_short len;            // UDP数据包长度(Datagram length)
    u_short crc;            // 校验和(Checksum)
}udp_header;


class Npcap
{
public:
    Npcap();
    //获取所有设备
    BOOL GetAllDevices(pcap_if_t **alldevs);

    //获取设备信息
    /*
     * 函数描述:
     *      获取设备信息到字符串数组
     * 参数:
     *      1.设备列表 2.设备列表总数
     * 返回值:
     *      类型:string类型数组  含义:所有设备描述
     * 调用示例:
     *
     *      for(d = alldevs; d; d=d->next)
     *          i++;
     *      string *s = GerDevicesInfo(alldevs,i);
     *
     *      for (size_t j = 0; j < i; j++)
     *      {
     *          printf("%d. %s\n",j+1,s[j].c_str());
     *      }
    */
    string *GerDevicesInfo(pcap_if_t *alldevs,int devnum);

    //跳转到指定设备
    BOOL GoChoiceDevices(pcap_if_t **alldevs,int inum,int alldevnum);


    //开始捕获数据包
    BOOL PcapFilter(pcap_t **adhandle, pcap_if_t *d,char packet_filter[]);


};

#endif // NPCAP_H
