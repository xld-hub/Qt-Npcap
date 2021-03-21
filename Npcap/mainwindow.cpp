#include "mainwindow.h"
#include "ui_mainwindow.h"




MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->pushButton->setText("asdfas");
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::setbuttontest()
{
    ui->pushButton->setText("开始");



    QStringList header;
    header<<"源IP"<<"目的IP"<<"长度";
    ui->tableWidget->setColumnCount(header.length());
    ui->tableWidget->setHorizontalHeaderLabels(header);


//    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Fixed);
//    ui->tableWidget->horizontalHeader()->resizeSection(0,200);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);//使列完全
    ui->tableWidget->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);

    ui->tableWidget->horizontalHeader()->setStretchLastSection(true);

//    ui->tableWidget->resizeColumnsToContents();
//    ui->tableWidget->resizeRowsToContents();
    for (int i = 0; i<101 ;i++ ) {
         ui->tableWidget->insertRow(i);
    }
    ui->tableWidget->insertRow(0);

    ui->tableWidget->setItem(0, 0, new QTableWidgetItem("172.1.0.1"));
    ui->tableWidget->setItem(0, 1, new QTableWidgetItem("120.0.0.1"));
    ui->tableWidget->setItem(0, 2, new QTableWidgetItem("120"));

}
