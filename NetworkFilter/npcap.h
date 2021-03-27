#ifndef NPCAP_H
#define NPCAP_H

#include "pcap.h"
#include <time.h>
#include <QDebug>
#include <string>

using std::string;



class Npcap
{
public:
    Npcap();
    //获取所有设备
    BOOL GetAllDevices(pcap_if_t *&alldevs);

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
    BOOL GoChoiceDevices(pcap_if_t *&alldevs,int inum,int alldevnum);


    //开始捕获数据包
    BOOL PcapFilter(pcap_t *&adhandle, pcap_if_t *d,char packet_filter[]);


};

#endif // NPCAP_H
