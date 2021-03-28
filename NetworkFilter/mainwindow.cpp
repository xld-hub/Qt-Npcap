#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "Header.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);


    ui->tableWidget->setColumnWidth(0,200);




    npcap.init();
    int totalnum = npcap.GetTotalNum();

    string *s = npcap.GetDevString();
    //下拉框
    for (int j = 0; j < totalnum; j++)
    {
        ui->comboBox->addItem(s[j].c_str());
    }




    //开始捕获

    m_workerThread = new QThread();
    worker = new WorkThread();
    worker->moveToThread(m_workerThread);

    //开始线程
    connect(ui->pushButton, &QPushButton::clicked, this, &MainWindow::ThreadStart);
    connect(m_workerThread, SIGNAL(started()), worker, SLOT(start1()));

    //设置table
    connect(worker, &WorkThread::packetcome,this, &MainWindow::SetTable);
    //销毁线程
    connect(worker, &WorkThread::workFinished, worker, &WorkThread::deleteLater);
//    connect(worker, &WorkThread::destroyed, m_workerThread, &QThread::quit);
    connect(m_workerThread, &QThread::finished, m_workerThread, &QThread::deleteLater);
}



MainWindow::~MainWindow()
{
    delete ui;
}
void MainWindow::SetTable(const u_char * pkt_data)
{
    int count = ui->tableWidget->rowCount();
    ui->tableWidget->insertRow(count);
    ip_header *ih = (ip_header *) (pkt_data +14);
    QString saddr =  QString().asprintf("%d.%d.%d.%d",
        ih->saddr.byte1,
        ih->saddr.byte2,
        ih->saddr.byte3,
        ih->saddr.byte4);
    QString daddr = QString().asprintf("%d.%d.%d.%d",
        ih->daddr.byte1,
        ih->daddr.byte2,
        ih->daddr.byte3,
        ih->daddr.byte4);
    ui->tableWidget->setItem(count,0,new QTableWidgetItem(saddr));
    ui->tableWidget->setItem(count,1,new QTableWidgetItem(daddr));

}
void MainWindow::ThreadStart()
{

    //选择设备

    npcap.GoChoiceDevices(ui->comboBox->currentIndex()+1);

    //用户输入 过滤字符串
    const char *packet_filter;
    QByteArray str;
    str = ui->lineEdit->text().toLatin1();
    packet_filter = str.data();
    pcap_t *adhandle;

    //设置过滤器
    adhandle = npcap.SetPcapFilter(packet_filter);

    worker->setadhandle(adhandle);

    m_workerThread->start();



}



