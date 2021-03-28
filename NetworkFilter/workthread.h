#ifndef WORKTHREAD_H
#define WORKTHREAD_H

#include <QObject>
#include "pcap.h"
#include "Header.h"


class WorkThread : public QObject
{
    Q_OBJECT
public:
    explicit WorkThread(QObject *parent = nullptr);
    void setadhandle(pcap_t *con_adhandle){
        m_adhandle = con_adhandle;
    }

public slots:
    void start1();
    void doWork(pcap_t *);
    void sendpackcome(const u_char * pkt_data);
signals:
    void packetcome(const u_char *);
    void workFinished();
    void workStart(pcap_t *);

private:
    pcap_t *m_adhandle;

};

#endif // WORKTHREAD_H
