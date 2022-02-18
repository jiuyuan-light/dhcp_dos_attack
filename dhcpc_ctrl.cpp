#include "dhcpc_ctrl.h"

#include <QMessageBox>
#include <QDebug>
#include <QBuffer>
#include <QDir>
#include <QApplication>

DHCPC_CTRL::DHCPC_CTRL(QWidget *parent):QWidget(parent),datalist(new QStringList)
{
    netbox =new QComboBox;
    netboxLabel = new QLabel(tr("网卡:"));
    CtrlLayout = new QGridLayout(this);
    BtnLayout =new QHBoxLayout();

    client_cnt = new QLabel(tr("DHCP客户端数量:"));
    client_cnt_edit = new QLineEdit(tr("1"));
    bind_info = new Bind_Info(this, *datalist);

    shareMemory = nullptr;
    RunPy = nullptr;
    update_time = nullptr;

//    获取网卡名称
    QList<QString> card;
    GetNetworkCardName(card);

    for (auto &c : card) {
        netbox->addItem(c);
    }
    netbox->setCurrentIndex(-1);

    /* 创建两个按钮 */
    StartBtn =new QPushButton(tr("开始"));
    StopBtn =new QPushButton(tr("停止"));

    //网卡布局
    CtrlLayout->addWidget(netboxLabel,0,0);
    CtrlLayout->addWidget(netbox,0,1);
    CtrlLayout->addWidget(client_cnt,1,0);
    CtrlLayout->addWidget(client_cnt_edit,1,1);
    CtrlLayout->addLayout(BtnLayout, 2, 0);
    CtrlLayout->addWidget(bind_info, 3,2);

    CtrlLayout->setColumnStretch(0,1);
    CtrlLayout->setColumnStretch(1,1);
    CtrlLayout->setColumnStretch(2,5);

    BtnLayout->addWidget(StartBtn);
    BtnLayout->addWidget(StopBtn);
    StopBtn->setEnabled(false);

//    信号
    connect(StartBtn, SIGNAL(clicked()), this, SLOT(StartOperator()));
    connect(StopBtn, SIGNAL(clicked()), this, SLOT(StopOperator()));

    qDebug() << "DHCPC CONTROL INIT OK"  << endl;
}


DHCPC_CTRL::~DHCPC_CTRL()
{
//    不实现，不允许销毁
}

void DHCPC_CTRL::GetNetworkCardName(QList<QString> &card)
{
//    QString detail="";
    QList<QNetworkInterface> list=QNetworkInterface::allInterfaces();
    for(int i=0;i<list.count();i++)
    {
        QNetworkInterface itf = list.at(i);

        if (itf.type() == QNetworkInterface::Virtual
            || itf.flags().testFlag(QNetworkInterface::IsLoopBack)
            || !itf.flags().testFlag(QNetworkInterface::IsUp)    ) {
            continue;
        }

        card.append(itf.humanReadableName());

//        detail=detail+tr("设备：")+interface.humanReadableName()+"\n";
    }
//    QMessageBox::information(this,tr("Detail"),detail);
}

void DHCPC_CTRL::StartOperator()
{
    if (netbox->currentIndex() == -1) {
        QMessageBox::information(this, tr("提示"), tr("必须选择一个网卡"));
        return;
    }

    int nums = get_dhcpc_nums();
    if (nums > USER_NUMS) {
        QMessageBox::information(this, tr("提示"), tr("不允许超过")+ QString::number(USER_NUMS));
        return;
    }

    StartBtn->setEnabled(false);
    StopBtn->setEnabled(true);

    // shm初始化
    shareMemory_init();

    if (update_time == nullptr) {
        update_time = new QTimer(this);
    }
    connect(update_time,SIGNAL(timeout()),this,SLOT(show_progressBar()));

    QString py_scr = QCoreApplication::applicationDirPath().append("/py/dhcp_client.py ") + netbox->currentText() + " -n " + QString::number(nums);
//    QString exec = QCoreApplication::applicationDirPath().append("/python.exe ") + py_scr;
    QString exec = tr("python.exe ") + py_scr;

    qDebug() << "exec paht:" << exec << endl;

    RunPy = new QProcess();
    RunPy->start(exec);

    update_time->start(1000);
}

void DHCPC_CTRL::StopOperator()
{
    qDebug() << "StopOperator "  << endl;

    update_time->stop();
    StartBtn->setEnabled(true);
    StopBtn->setEnabled(false);

    if (RunPy) {
        if (RunPy->state() == QProcess::Running) {
            RunPy->kill();
        }

        delete RunPy;
        RunPy = nullptr;
    }

    if (shareMemory) {
        if (shareMemory->isAttached()) {
           shareMemory->detach();
        }
        delete shareMemory;
        shareMemory = nullptr;
    }
}

int DHCPC_CTRL::get_dhcpc_nums()
{
    return client_cnt_edit->text().toInt();
}

void DHCPC_CTRL::shareMemory_init(void)
{
    shareMemory = new QSharedMemory;

    shareMemory->setNativeKey(tr(DHCPC_SHM_WITH_HANDLE_NAME));
    if(!shareMemory->create(DHCPC_SHM_WITH_HANDLE_SIZE)) {
        qDebug()<< "shm create failed!";
        return;
    }

    if(!shareMemory->isAttached()){
        if(!shareMemory->attach(QSharedMemory::ReadOnly)){
            qDebug()<<tr("can't attach share memory");
            return;
        }
    }
}

void DHCPC_CTRL::read_data(void)
{
    QBuffer buffer;
    QDataStream in(&buffer);

    if (shareMemory == nullptr) {
        return;
    }
    shareMemory->lock();

    buffer.setData(static_cast<const char*>(shareMemory->constData()),shareMemory->size()); // 将shareMemeory里的数据放到buffer里
    buffer.open(QBuffer::ReadOnly);

    QString data = buffer.readAll();
    *datalist = data.split("\n");

    shareMemory->unlock();
}

void DHCPC_CTRL::show_progressBar()
{
    read_data();
    for (auto l : *datalist) {
        if (l.size() < 2) {
            return;
        }
        bind_info->addEntry(Contact(l));
    }
}
