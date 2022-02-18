#include "mainwindow.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    QFont font("AR PL KaitiM GB",12);	//设置整个程序采用的字体与字号
    MainWindow w;

    w.show();
    return a.exec();
}
