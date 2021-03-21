#include "mainwindow.h"
#include <QApplication>

#include <QDebug>
#include "winpcap.h"
#include <QPushButton>

void start();
void pushbutton();

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    w.setbuttontest();

    start();


    return a.exec();
}



void start()
{
    Winpcap winpcap;

    pcap_if_t *alldevs;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE+1];
    char source[PCAP_ERRBUF_SIZE+1] = "2";

    qDebug ("Enter the device you want to list:\n"
              "rpcap://              ==> lists interfaces in the local machine\n"
              "rpcap://hostname:port ==> lists interfaces in a remote machine\n"
              "                          (rpcapd daemon must be up and running\n"
              "                           and it must accept 'null' authentication)\n"
              "file://foldername     ==> lists all pcap files in the give folder\n\n"
              "Enter your choice: ");
//    fgets(source, PCAP_ERRBUF_SIZE, stdin);
    source[PCAP_ERRBUF_SIZE] = '\0';


    if (pcap_findalldevs_ex(source, NULL, &alldevs, errbuf) == -1)
    {
      fprintf(stderr,"Error in pcap_findalldevs: %s\n",errbuf);
      exit(1);
    }

    for(d=alldevs;d;d=d->next)
    {
      winpcap.ifprint(d);
    }

    pcap_freealldevs(alldevs);
}

