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
    StopBtn->setEnabled(false);

    //    初始化扩展窗口
    InitDetailPart();
    CtrlLayout->setColumnStretch(0, 0);
    CtrlLayout->setColumnStretch(1, 0);
    CtrlLayout->setColumnStretch(2, 1);

    //网卡布局
    CtrlLayout->addWidget(netboxLabel,0,0);
    CtrlLayout->addWidget(netbox,0,1);
    CtrlLayout->addWidget(client_cnt,1,0);
    CtrlLayout->addWidget(client_cnt_edit,1,1);
    CtrlLayout->addLayout(BtnLayout, 2, 0);
    CtrlLayout->addWidget(DetailBtn, 2, 1);
    CtrlLayout->addWidget(bind_info, 3,2);

    BtnLayout->addWidget(StartBtn);
    BtnLayout->addWidget(StopBtn);
    BtnLayout->addStretch(2);

//    信号
    connect(StartBtn, SIGNAL(clicked()), this, SLOT(StartOperator()));
    connect(StopBtn, SIGNAL(clicked()), this, SLOT(StopOperator()));
    connect(client_cnt_edit, SIGNAL(textChanged(QString)),this,SLOT(upDetailInfo()));

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

void DHCPC_CTRL::showDetailInfo()
{
    upDetailInfo();

    if(table->isHidden()) {
        table->show();
    }
}

void DHCPC_CTRL::upDetailInfo()
{
    model->setRowCount(get_dhcpc_nums());
}

void DHCPC_CTRL::GetCfg(void)
{
    QString ip;
    QString mac;
    QString giaddr;
    qint32 xid = 0x0;
    bool ok;

    need_cfg = false;
    for (int i = 0; i < get_dhcpc_nums(); i++) {
        for (int j = 0; j < 4; j++) {
            QModelIndex index = model->index(i,j);
            QString data = model->data(index).toString();
            switch (j) {
            case 0:
                ip = data;
                break;
            case 1:
                mac = data;
                if (mac.length() != 0) {
                    need_cfg = true;
                }
                break;
            case 2:
                xid = data.toInt(&ok, 16);
                if (ok && xid != 0) {
                    need_cfg = true;
                }
                break;
            case 3:
                giaddr = data;
                if (giaddr.length() != 0) {
                    need_cfg = true;
                }
                break;
            default:
                break;
            }
        }

        Contact c(ip, mac, xid, i);
        c.add_giaddr(giaddr);
        cfg.append(c);
    }
}

void DHCPC_CTRL::write2cfgfile(void)
{
    QMap<QString, QVariant> m_map;
    QMap<QString, QVariant> map;

    QFile file(cfgpathname);

    if(!file.open(QIODevice::ReadWrite)) {
        qDebug() << "File open error";
    } else {
        qDebug() <<"File open succ:" + cfgpathname << endl;
    }

    file.resize(0);

    //    没有权限
    //    unlink(pathname.toLatin1().data());

    for (auto &c : cfg) {
        map.insert("mac", c.mac);
        map.insert("xid", c.xid);
        map.insert("giaddr", c.giaddr);

        m_map.insert(QString::number(c.id), map);
        qDebug() << "##[write2cfgfile]##mac:" << c.mac << "xid:" << c.xid <<" i:" << c.id <<" giaddr:" << c.giaddr << endl;
    }

    QJsonDocument doc=QJsonDocument::fromVariant(QVariant(m_map));
    file.write(doc.toJson());
    file.close();
}

void DHCPC_CTRL::InitDetailPart(void)
{
    DetailBtn =new QPushButton(tr("详细配置"));

    model = new QStandardItemModel(get_dhcpc_nums(), 4, this);
    model->setHeaderData(0,Qt::Horizontal,tr("IP"));
    model->setHeaderData(1,Qt::Horizontal,tr("MAC"));
    model->setHeaderData(2,Qt::Horizontal,tr("XID(0x)"));
    model->setHeaderData(3,Qt::Horizontal,tr("GIADDR"));

    table = new QTableView();
    table->setModel(model);
    table->setWindowTitle(tr("DETAIL CONFIG"));
    QItemSelectionModel *selectionModel = new QItemSelectionModel(model);
    table->setSelectionModel(selectionModel);
    table->hide();

    // 限制输入
    ReadOnlyDelegate* readOnlyDelegate = new ReadOnlyDelegate();
    table->setItemDelegateForColumn(0, readOnlyDelegate);

    InputDelegate *macAddrDelegate = new InputDelegate(InputDelegate_MAC);
    table->setItemDelegateForColumn(1, macAddrDelegate);

    InputDelegate *xidDelegate = new InputDelegate(InputDelegate_XID);
    table->setItemDelegateForColumn(2, xidDelegate);

    InputDelegate *giAddrDelegate = new InputDelegate(InputDelegate_GIADDR);
    table->setItemDelegateForColumn(3, giAddrDelegate);

    // 限制输入 END

    table->resize(QSize(600, 300));

    cfgpathname = QCoreApplication::applicationDirPath().append("/._cfg.json");

    connect(DetailBtn,SIGNAL(clicked()),this,SLOT(showDetailInfo()));
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

    GetCfg();
    write2cfgfile();

    // shm初始化
    shareMemory_init();

    if (update_time == nullptr) {
        update_time = new QTimer(this);
    }
    connect(update_time,SIGNAL(timeout()),this,SLOT(show_progressBar()));

     //删除所有行
    if (bind_info && bind_info->table) {
        bind_info->table->removeRows(0, model->rowCount());
    }


    QString exec;
    if (need_cfg) {
        exec = QCoreApplication::applicationDirPath().append("/dhcp_client.exe ") + netbox->currentText() + " -n " + QString::number(nums) + " -f " + cfgpathname;
    } else {
        exec = QCoreApplication::applicationDirPath().append("/dhcp_client.exe ") + netbox->currentText() + " -n " + QString::number(nums);
    }

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
        RunPy->execute("taskkill", QStringList() << "-f"<<"-im"<<"dhcp_client*");
        RunPy->execute("taskkill", QStringList() << "-f"<<"-im"<<"evb*");
        RunPy->kill();
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
    qDebug() << "client nums:"<< datalist->length() << endl; // needs -1
    for (auto l : *datalist) {
        if (l.size() < 2) {
            return;
        }

        bind_info->addEntry(Contact(l));
    }
}
