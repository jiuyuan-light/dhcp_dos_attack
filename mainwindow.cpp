#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "dhcpc_ctrl.h"
#include "bind_info.h"

#include <QLineEdit>

#include <QCloseEvent>
void MainWindow::closeEvent(QCloseEvent * event)
{
//    switch( QMessageBox::information( this, tr("exit tip"), tr("Do you really want exit?"), tr("Yes"), tr("No"), 0, 1)) {
//    case 0:
//        event->accept();
//        break;
//    case 1:
//    default:
//        event->ignore();
//        break;
//    }

    if (net == nullptr) {
        return;
    }

    if (net->table) {
        net->table->close();
    }

    QFile file(net->cfgpathname);
    file.remove();

    //结束子进程
    if (net->RunPy != nullptr) {
        net->RunPy->execute("taskkill", QStringList() << "-f"<<"-im"<<"dhcp_client*");
        net->RunPy->execute("taskkill", QStringList() << "-f"<<"-im"<<"evb*");
        net->RunPy->kill();
    }

    if(net->shareMemory && net->shareMemory->isAttached()){
        net->shareMemory->detach();
    }
}

MainWindow::MainWindow(QWidget *parent): QMainWindow(parent) , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    setWindowTitle(QObject::tr("DHCPC"));

    QSplitter *splitterMain =new QSplitter(Qt::Vertical, nullptr);
    setCentralWidget(splitterMain);

    net = new DHCPC_CTRL(splitterMain);
}

MainWindow::~MainWindow()
{
    delete ui;

    delete net;
}

