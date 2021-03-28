#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QThread>

#include "npcap.h"
#include "workthread.h"

#include <QPushButton>


QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
public slots:
    void ThreadStart();
    void SetTable(const u_char *);
private:

    Ui::MainWindow *ui;
    QThread *m_workerThread ;
    WorkThread* worker;
    Npcap npcap;


};
#endif // MAINWINDOW_H
