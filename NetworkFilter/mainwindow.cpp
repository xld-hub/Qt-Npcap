#include "mainwindow.h"
#include "ui_mainwindow.h"

void MainWindow::ThreadStart()
{
    m_workerThread->start();
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    ui->tableWidget->setColumnWidth(0,50);
    ui->tableWidget->setColumnWidth(1,200);

    Npcap npcap;
    pcap_if_t *alldevs;
    npcap.GetAllDevices(alldevs);

    pcap_if_t *d;
    int i = 0;
    for(d = alldevs; d; d=d->next)
      i++;
    //获取设备描述
    string *s = npcap.GerDevicesInfo(alldevs,i);

    for (int j = 0; j < i; j++)
    {
        qDebug("%d. %s\n",j+1,s[j].c_str());
    }
    int inum;
    inum = 3;
    //选择设备
    npcap.GoChoiceDevices(alldevs,inum,i);

    //用户输入 过滤字符串
    char packet_filter[] = "(ip and icmp) and (host 192.168.204.128)";
    pcap_t *adhandle;

    //设置过滤器
    npcap.PcapFilter(adhandle,alldevs,packet_filter);

    pcap_freealldevs(alldevs);


    //开始捕获

    m_workerThread = new QThread();
    WorkThread* worker = new WorkThread();
    worker->moveToThread(m_workerThread);

    worker->setadhandle(adhandle);
    //开始线程
    connect(ui->pushButton, &QPushButton::clicked, this, &MainWindow::ThreadStart);
    connect(m_workerThread, SIGNAL(started()), worker, SLOT(start1()));

    //销毁线程
    connect(worker, &WorkThread::workFinished, worker, &WorkThread::deleteLater);
    connect(worker, &WorkThread::destroyed, m_workerThread, &QThread::quit);
    connect(m_workerThread, &QThread::finished, m_workerThread, &QThread::deleteLater);
}



MainWindow::~MainWindow()
{
    delete ui;
}


