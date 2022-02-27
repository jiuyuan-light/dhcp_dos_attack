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

#include <QStandardItemModel>
#include <QTableView>
#include <QItemDelegate>
#include <QJsonDocument>
#include <QFile>

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
    QTableView *table;
    QProcess *RunPy;
    QSharedMemory *shareMemory;
    QString cfgpathname;

public slots:
    void StartOperator();
    void StopOperator();
    void show_progressBar();
    void showDetailInfo();
    void upDetailInfo();

private:
    QComboBox *netbox;
    QLabel *netboxLabel;
    QLabel *client_cnt;
    QLineEdit *client_cnt_edit;
    QPushButton *StartBtn;
    QPushButton *StopBtn;
    QHBoxLayout *BtnLayout;
    QGridLayout *CtrlLayout;

    // 扩展窗口
    QPushButton *DetailBtn;
    QStandardItemModel *model;
    QVector<Contact> cfg;
    bool need_cfg;
    void write2cfgfile();



    // 读取数据
    QStringList *datalist;
    QTimer *update_time;

    void InitDetailPart(void);
    void GetCfg(void);

    void GetNetworkCardName(QList<QString> &card);
};

class ReadOnlyDelegate: public QItemDelegate
{

public:
    ReadOnlyDelegate(QWidget *parent = nullptr):QItemDelegate(parent)
    {}

    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option,
const QModelIndex &index) const override //final
    {
        Q_UNUSED(parent)
        Q_UNUSED(option)
        Q_UNUSED(index)
        return nullptr;
    }
};

class  InputDelegate :  public  QItemDelegate
{
    Q_OBJECT
public :
#define InputDelegate_NONE              (0)
#define InputDelegate_MAC               (1)
#define InputDelegate_XID               (2)
#define InputDelegate_GIADDR            (3)
    InputDelegate(int col, QObject *parent = 0): col(col), QItemDelegate(parent) { }
    QWidget *createEditor(QWidget *parent,  const QStyleOptionViewItem &option, const  QModelIndex &index)  const
    {
        if (col == InputDelegate_NONE) {
            return nullptr;
        }

        QLineEdit *editor =  new  QLineEdit(parent);
        QRegExp regExp;

        if (col == InputDelegate_GIADDR) {
            regExp = QRegExp("\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b");
        } else if (col == InputDelegate_MAC) {
            regExp = QRegExp( "[0-9a-fA-F][02468ace](:[0-9a-fA-F]{2}){5}" );
        } else if (col == InputDelegate_XID) {
            regExp = QRegExp( "^0x[0-9a-fA-F]{1,8}" );
        }
        editor->setValidator(new QRegExpValidator(regExp, parent));
        return  editor;
    }
     void  setEditorData(QWidget *editor,  const  QModelIndex &index)  const
    {
        QString text = index.model()->data(index, Qt::EditRole).toString();
        QLineEdit *lineEdit =  static_cast <QLineEdit*>(editor);
        lineEdit->setText(text);
    }
private:
     int col = InputDelegate_NONE;
};


#endif // DHCPCManage_H
