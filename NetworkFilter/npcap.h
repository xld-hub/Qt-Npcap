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
    ~Npcap();
    //初始化操作
    void init();
    //获取所有设备
    BOOL GetAllDevices();

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
    BOOL GetDevicesInfo();

    //跳转到指定设备
    BOOL GoChoiceDevices(int choicenum);


    //设置过滤器
    pcap_t * SetPcapFilter(const char packet_filter[]);

    //设置用户选择
    void SetChoiceNum(int con_choice_dev);

    //返回设备描述
    string * GetDevString();
    //返回设备总数
    int GetTotalNum();


private:
    pcap_if_t *alldevs;
    pcap_if_t *d;
    pcap_t *adhandle;
    int total_dev;
    int choice_dev;
    string *s;
};

#endif // NPCAP_H
