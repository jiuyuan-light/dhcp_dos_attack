#include "bind_info.h"

#include <QPushButton>
#include <QDebug>
#include <QtWidgets>

Bind_Info::Bind_Info(QWidget *parent, QStringList &l):QTabWidget(parent),datalist(l),table(new TableModel(this))
{
    setupTabs();
}

void Bind_Info::addEntry(const Contact &data)
{
    if (!table->getContacts().contains({ data })) {
        table->insertRows(0, 1, QModelIndex());
        QModelIndex index = table->index(0, 0, QModelIndex());
        table->setData(index, data.ip, Qt::EditRole);
        index = table->index(0, 1, QModelIndex());
        table->setData(index, data.mac, Qt::EditRole);
    } else {
//        QMessageBox::information(this, tr("Duplicate data"),
//            tr("The data \"%1\" already exists.").arg(data));
        qDebug() << tr("The data (%1) (%2) (%3) already exists.").arg(data.ip, data.mac, data.serverid) << endl;
    }
}


void Bind_Info::setupTabs()
{
    const auto regExp = QRegularExpression(QString("^[1-9].*"),
                                           QRegularExpression::CaseInsensitiveOption);

    auto proxyModel = new QSortFilterProxyModel();
    proxyModel->setSourceModel(table);
    proxyModel->setFilterRegularExpression(regExp);
    proxyModel->setFilterKeyColumn(0);

    QTableView *tableView = new QTableView(this);
    tableView->setModel(proxyModel);
    tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    tableView->horizontalHeader()->setStretchLastSection(true);
    tableView->verticalHeader()->hide();
    tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tableView->setSelectionMode(QAbstractItemView::SingleSelection);
    tableView->setSortingEnabled(true);

    tableView->setColumnWidth(0, 200);
    tableView->setColumnWidth(1, 200);

    addTab(tableView, tr("BIND信息"));
}

TableModel::TableModel(QObject *parent)
    : QAbstractTableModel(parent)
{
}

TableModel::TableModel(const QVector<Contact> &contacts, QObject *parent)
    : QAbstractTableModel(parent),
      contacts(contacts)
{
}

int TableModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : contacts.size();
}

int TableModel::columnCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : 2;
}

QVariant TableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid())
        return QVariant();

    if (index.row() >= contacts.size() || index.row() < 0)
        return QVariant();

    if (role == Qt::DisplayRole) {
        const auto &contact = contacts.at(index.row());

        switch (index.column()) {
            case 0:
                return contact.ip;
            case 1:
                return contact.mac;
            default:
                break;
        }
    }
    return QVariant();
}

QVariant TableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role != Qt::DisplayRole)
        return QVariant();

    if (orientation == Qt::Horizontal) {
        switch (section) {
            case 0:
                return tr("IP");
            case 1:
                return tr("MAC");
            default:
                break;
        }
    }
    return QVariant();
}

bool TableModel::insertRows(int position, int rows, const QModelIndex &index)
{
    Q_UNUSED(index);
    beginInsertRows(QModelIndex(), position, position + rows - 1);
    for (int row = 0; row < rows; ++row) {
        contacts.insert(position, {});
    }

    endInsertRows();
    return true;
}

bool TableModel::removeRows(int position, int rows, const QModelIndex &index)
{
    Q_UNUSED(index);
    beginRemoveRows(QModelIndex(), position, position + rows - 1);

    for (int row = 0; row < rows; ++row)
        contacts.removeAt(position);

    endRemoveRows();
    return true;
}

bool TableModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if (index.isValid() && role == Qt::EditRole) {
        const int row = index.row();
        auto contact = contacts.value(row);

        switch (index.column()) {
            case 0:
                contact.ip = value.toString();
                break;
            case 1:
                contact.mac = value.toString();
                break;
            default:
                return false;
        }
        contacts.replace(row, contact);
        emit dataChanged(index, index, {Qt::DisplayRole, Qt::EditRole});

        return true;
    }

    return false;
}

Qt::ItemFlags TableModel::flags(const QModelIndex &index) const
{
    if (!index.isValid())
        return Qt::ItemIsEnabled;

    return QAbstractTableModel::flags(index) | Qt::ItemIsEditable;
}

const QVector<Contact> &TableModel::getContacts() const
{
    return contacts;
}

Contact::Contact(QString &data)
{
    QStringList itemlist = data.split(",");

    if (itemlist.size() < 3) {
        return;
    }
    ip = itemlist[0];
    mac = itemlist[1];
    serverid = itemlist[2];
}
