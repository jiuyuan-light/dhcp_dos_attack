#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

#include <QSplitter>

#include "dhcpc_ctrl.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

protected:
    void closeEvent(QCloseEvent *event);

    QSplitter *splitterMain;
    Bind_Info *bind_info;

private:
    Ui::MainWindow *ui;

private:
    DHCPC_CTRL *net;
};
#endif // MAINWINDOW_H
