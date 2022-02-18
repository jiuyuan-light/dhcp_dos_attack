#ifndef DHCPCManage_H
#define DHCPCManage_H

#include "bind_info.h"

#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QNetworkInterface>
#include <QPushButton>
#include <QMessageBox>
#include <QProcess>
#include <QSharedMemory>

#define DHCPC_SHM_WITH_HANDLE_NAME "dhcpc_shm_with_keyname"
#define USER_NUMS (1000)
#define ONE_USER_USED  (256)
#define DHCPC_SHM_WITH_HANDLE_SIZE (ONE_USER_USED * USER_NUMS)

class DHCPC_CTRL:public QWidget
{
    Q_OBJECT

public:
    DHCPC_CTRL(QWidget *parent);
    ~DHCPC_CTRL();

    void shareMemory_init(void);
    void read_data(void);
    int get_dhcpc_nums();

    Bind_Info *bind_info;
    QProcess *RunPy;
    QSharedMemory *shareMemory;

public slots:
    void StartOperator();
    void StopOperator();
    void show_progressBar();

private:
    QComboBox *netbox;
    QLabel *netboxLabel;
    QLabel *client_cnt;
    QLineEdit *client_cnt_edit;
    QPushButton *StartBtn;
    QPushButton *StopBtn;
    QHBoxLayout *BtnLayout;
    QGridLayout *CtrlLayout;

    // 读取数据
    QStringList *datalist;
    QTimer *update_time;

    void GetNetworkCardName(QList<QString> &card);
};



#endif // DHCPCManage_H
