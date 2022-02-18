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

    //结束子进程
    if (net->RunPy != nullptr) {
        net->RunPy->kill();
    }

    if(net->shareMemory && net->shareMemory->isAttached()){
        net->shareMemory->detach();
    }
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    //新建一个水平分割窗对象，作为主布局框
    QSplitter *splitterMain =new QSplitter(Qt::Horizontal, nullptr);
    //设置主布局框即水平分割窗的标题
    splitterMain->setWindowTitle(QObject::tr("DHCPC"));
    splitterMain->setParent(this);

    // 之后要实现为单例模式
    net = new DHCPC_CTRL(splitterMain);
}

MainWindow::~MainWindow()
{
    delete ui;

    delete net;
}

