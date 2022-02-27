#ifndef BIND_INFO_H
#define BIND_INFO_H

#include <QWidget>

#include <QLabel>
#include <QLineEdit>
#include <QProgressBar>

#include <QVBoxLayout>
#include <QAbstractTableModel>

#include <QItemSelection>
#include <QTabWidget>
#include <QTimer>
#include <QDebug>

QT_BEGIN_NAMESPACE
class QSortFilterProxyModel;
class QItemSelectionModel;
QT_END_NAMESPACE

class Contact
{
public:
    QString ip;
    QString mac;
    QString giaddr;
    QString serverid;

    qint32 id;
    qint32 xid;

    Contact() {};
    Contact(QString &ip, QString &mac, qint32 xid=0x0, qint32 id=0x0):ip(ip), mac(mac), xid(xid), id(id) {};
    Contact(QString &data);

    void add_giaddr(QString &giaddr) {
        this->giaddr = giaddr;
    }

    bool operator==(const Contact &other) const
    {
        return ip == other.ip && mac == other.mac;
    }

    void show() {
        qDebug() << ip + " " + mac + "" << xid << endl;
    }
};

class TableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    TableModel(QObject *parent = nullptr);
    TableModel(const QVector<Contact> &contacts, QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent) const override;
    int columnCount(const QModelIndex &parent) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    Qt::ItemFlags flags(const QModelIndex &index) const override;
    bool setData(const QModelIndex &index, const QVariant &value, int role = Qt::EditRole) override;
    bool insertRows(int position, int rows, const QModelIndex &index = QModelIndex()) override;
    bool removeRows(int position, int rows, const QModelIndex &index = QModelIndex()) override;
    const QVector<Contact> &getContacts() const;

private:
    QVector<Contact> contacts;
};

class DHCPC_CTRL;
class Bind_Info:public QTabWidget
{
    Q_OBJECT
public:
    Bind_Info(QWidget *parent, QStringList &l);
    ~Bind_Info() {};

    void addEntry(const Contact &);

    TableModel *table;

private:
    QStringList &datalist;

    void setupTabs();
};

#endif // BIND_INFO_H
