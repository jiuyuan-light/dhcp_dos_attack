import sys, typing, threading
from tkinter.messagebox import RETRY
from PyQt6.QtWidgets import QMainWindow, QApplication, QWidget, QHBoxLayout, QFormLayout, QComboBox, QLineEdit, QPushButton, QTableView,\
                            QVBoxLayout, QMessageBox, QProgressBar, QHeaderView, QCheckBox, QTableWidget, QTableWidgetItem, QAbstractButton, QStyleOptionHeader,\
                            QStyle, QStylePainter
from PyQt6.QtCore import QAbstractTableModel, Qt, QModelIndex, QVariant, pyqtSignal, QEvent, QSize
from PyQt6.QtGui import QStandardItem
from dhcp_client_fsm import DhcpcBindsEntryInfo, NetCardInfo, DHCPC_PKT_CFG
from dhcpc_control import DhcpcControlCenter

from dhcpc_gui_sup import DHCPC_PKT_MODEL, DHCPC_PKT_TABLEWIDGET

class UserInputWidget(QWidget):
    userBindGenSignal = pyqtSignal([str,str])
    def __init__(self, parent=None, model=None, progressbar=None):
        super().__init__(parent)
        self.cfgpkt = None
        self.start_new_nums = 1
        self.show_nums = self.start_new_nums
        self.model = model
        self.progressbar = progressbar
        self.userBindGenSignal[str,str].connect(model.add_user)

        self.main_layout = QFormLayout(self)
        self.btn_layout = QHBoxLayout()

        self.dhcpc_num_lineed = QLineEdit()
        self.netcard_cbox = QComboBox()
        # input相关data
        self.netcard_info = NetCardInfo()
        
        netcards = self.NetCardNameList()
        self.netcard_cbox.addItems(netcards)
        self.netcard_cbox.setCurrentIndex(-1)
        
        self.start_btn = QPushButton("开始")
        self.clear_btn = QPushButton("清理")
        self.detailcfg_btn = QPushButton("配置")
        self.detail_chs = QCheckBox("详细模式")

        #DHCPC控制部分
        self.ctrl = DhcpcControlCenter()

        #布局设置
        self.btn_layout.addWidget(self.start_btn)
        self.btn_layout.addWidget(self.clear_btn)

        self.main_layout.addRow(self.detail_chs, self.detailcfg_btn)
        self.main_layout.addRow("网卡:", self.netcard_cbox)
        self.main_layout.addRow("DHCPC数量:", self.dhcpc_num_lineed)
        self.main_layout.addRow(self.btn_layout)

        # 信号槽
        self.start_btn.clicked.connect(self.onClickStartBtn)
        self.clear_btn.clicked.connect(self.onClickClearBtn)
        self.detail_chs.stateChanged.connect(self.onChooseDetailModel)
        self.detailcfg_btn.clicked.connect(self.onClickDetailCfgBtn)

        # 初始状态
        self.clear_btn.setEnabled(False)
        self.detailcfg_btn.setEnabled(False)
        self.dhcpc_num_lineed.setText(str(self.show_nums))

        # 回调设置
        DhcpcControlCenter.set_nty_userbind_gen_cb(self.userbind_entryinfo_gen_cb)
        
    def userbind_entryinfo_gen_cb(self, entryinfo:DhcpcBindsEntryInfo):
        self.userBindGenSignal.emit(entryinfo.ip, entryinfo.mac)
    def NetCardNameList(self):
        return self.netcard_info.NetCardNameList()

    def onChooseDetailModel(self):
        if (self.detail_chs.checkState() == Qt.CheckState.Checked):
            self.detailcfg_btn.setEnabled(True)
        else:
            self.detailcfg_btn.setEnabled(False)

    def get_current_mode(self):
        if (self.detail_chs.checkState() == Qt.CheckState.Checked):
            return 1
        return 0

    def onClickDetailCfgBtn(self):
        self.detail_mode_cfg()
        self.cfgpkt.show()
    def detail_mode_cfg(self):
        if (self.cfgpkt is None):
            self.cfgpkt = DHCPC_PKT_TABLEWIDGET(10, 4)

            self.cfgpkt.setCornerButtonEnabled(False)
            header = QHeaderView(Qt.Orientation.Horizontal)
            header.setDefaultAlignment(Qt.AlignmentFlag.AlignRight)
            header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
            
            self.cfgpkt.setHorizontalHeader(header)
            self.cfgpkt.setHorizontalHeaderLabels(["7", "15", "23", "31"])
            self.cfgpkt.setVerticalHeaderLabels(["" for _ in range(0, self.cfgpkt.rowCount())])
            self.cfgpkt.setItem(0, 4, QTableWidgetItem().setFlags(Qt.ItemFlag.NoItemFlags))
    
            self.cfgpkt.setSpan(1, 0, 1, 4)
            self.cfgpkt.setSpan(2, 0, 1, 2)
            self.cfgpkt.setSpan(2, 2, 1, 2)
            for row in range(3, self.cfgpkt.rowCount()):
                self.cfgpkt.setSpan(row, 0, 1, 4)

            #设置选中行背景色 self.cfgpkt.setStyleSheet("selection-background-color: red")
            # 设置背景色
            self.cfgpkt.setStyleSheet("background: rgb(100, 188, 238)")
            header.setStyleSheet("QHeaderView::section{background: rgb(100, 188, 238)}")
            self.cfgpkt.verticalHeader().setStyleSheet("QHeaderView::section{background: rgb(100, 188, 238)}")
            # self.cfgpkt.setStyleSheet('QTableCornerButton::section{background: rgb(100, 188, 238)}')
            # self.cfgpkt.setStyleSheet('QTableCornerButton::section{background-color:rgba(255,255,255,255)}')

            # 显示行列标题
            # self.cfgpkt.horizontalHeader().setVisible(False)
            self.cfgpkt.verticalHeader().setVisible(False)

            self.cfgpkt.resize(self.cfgpkt.columnWidth(0) * (self.cfgpkt.columnCount() + 1), self.cfgpkt.rowHeight(0) * (self.cfgpkt.rowCount() ))
            self.cfgpkt.other()

    def onClickClearBtn(self):
        self.model.clearALL()
        self.ctrl.clearALL()
        self.clear_btn.setEnabled(False)
        self.start_btn.setEnabled(True)
        self.detail_chs.setEnabled(True)

    def onClickStartBtn(self):
        if (self.input_check() == False):
            return
        self.detail_chs.setEnabled(False)
        self.start_btn.setEnabled(False)
        self.clear_btn.setEnabled(True)
        self.progressbar.setMaximum(self.start_new_nums)
        if (self.get_current_mode() == 1):
            self.detail_mode_cfg()
        self.ctrl.cfg_init(self.netcard_cbox.currentText(), self.start_new_nums, self.get_current_mode(), self.gen_pkt_cfg())
        self.ctrl.async_dhcpc_start()

    def gen_pkt_cfg(self):
        if self.get_current_mode() == 0:
            return None
        pkt_cfg = DHCPC_PKT_CFG(self.cfgpkt.write2dhcpc_cfg())
        return pkt_cfg
        

        # self.pr_thread_info()

    def pr_thread_info(self):
        length = len(threading.enumerate())
        print('### START ### 当前运行的线程数为：%d' % length)
        print(threading.enumerate())
        print('### END ###')

    def user_input_dhcpcnum(self):
        if (self.dhcpc_num_lineed.text()):
            return int(self.dhcpc_num_lineed.text())
        return 0

    def input_check(self) -> bool:
        if (self.netcard_cbox.currentIndex() == -1):
            QMessageBox.information(None, "提示", "必须选择一个网卡")
            return False

        start_new_nums = self.user_input_dhcpcnum()
        if (start_new_nums <= 0 or start_new_nums > 1000):
            QMessageBox.information(None, "提示", "DHCP客户端数量限制为[1, 1000]")
            return False
        if (start_new_nums != 1 and self.get_current_mode() == 1):
            QMessageBox.information(None, "提示", "特殊模式只支持1个客户端")
            return False
        self.start_new_nums = start_new_nums
        self.show_nums = self.start_new_nums
        # if (not self.model.empty()):          # 如果有数据
        # if (self.clear_btn.isEnabled()):        # 如果没有可以按下(有数据)
        #     self.show_nums += start_new_nums
        #     self.dhcpc_num_lineed.setText(str(self.show_nums))
        return True

class DhcpcBindsTableModel(QAbstractTableModel):
    def __init__(self, parent, map, progressbar, *args):
        QAbstractTableModel.__init__(self, parent, *args)
        self.currencyMap = map
        self.progressbar = progressbar
    def rowCount(self, parent:QModelIndex):
        return parent.isValid() if 0 else len(self.currencyMap)

    def columnCount(self, parent:QModelIndex):
        return parent.isValid() if 0 else 2
 
    def data(self, index, role):
        if not index.isValid():
            return QVariant()
        elif (index.row() >= len(self.currencyMap) or index.row() < 0):
            return QVariant()
        elif role != Qt.ItemDataRole.DisplayRole:
            return QVariant()
        
        key = list(self.currencyMap.keys())[index.row()]
        contact = self.currencyMap[key]
        if (index.column() == 0):
            return contact.ip
        elif (index.column() == 1):
            return contact.mac
        return QVariant()
 
    def headerData(self, col, orientation, role):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return "IP"
            elif col == 1:
                return "MAC"
        return None
    def add_user(self, ip, mac):
        if self.currencyMap.get(mac) is not None:
            # QMessageBox.information(self, "Duplicate Name", "XXX")
            return
        self.currencyMap[mac] = DhcpcBindsEntryInfo(ip, mac)
        self.beginInsertRows(QModelIndex(), 0, 0)
        self.endInsertRows()

        self.progressbar.setValue(self.size())
    # def removeEntry(self):
    #     temp = QTableView(currentWidget())
    #     proxy = QSortFilterProxyModel(temp.model())
    #     selectionModel = temp.selectionModel()
    #     indexes = selectionModel.selectedRows()
    #     for index in indexes:
    #         row = proxy.mapToSource(index).row()
    #         table.removeRows(row, 1, QModelIndex())

    #     if (table.rowCount(QModelIndex()) == 0)
    #         insertTab(0, newAddressTab, tr("Address Book"))

    # def removeRows(self, int position, int rows, QModelIndex index):
    #     beginRemoveRows(QModelIndex(), position, position + rows - 1)
    #     endRemoveRows()
    #     return True
    def clearALL(self):
        for i in range(0, len(self.currencyMap)):
            self.beginRemoveRows(QModelIndex(), 0, 0)
            self.endRemoveRows()
        self.currencyMap = {}
        self.progressbar.setValue(self.size())
    def empty(self):
        return False if self.currencyMap else True
        
    def size(self):
        return len(self.currencyMap)
class UserOutputWidget(QWidget):
    def __init__(self, parent=None, progressbar=None):
        super().__init__(parent)

        self.main_layout = QFormLayout(self)

        self.view = QTableView(self)
        self.view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

        # 布局
        self.main_layout.addRow(self.view)
        self.main_layout.addRow("BIND进度:", progressbar)

    def tableview_setmodel(self, model):
        self.view.setModel(model)
        
class DhcpcMainWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.main_layout = QHBoxLayout(self)

        # 进度条
        self.progressbar = QProgressBar(self)
        self.progressbar.setMinimum(0)

        self.model = DhcpcBindsTableModel(None, {}, self.progressbar)

        #输出部分
        self.output_part = UserOutputWidget(self, self.progressbar)
        self.output_part.tableview_setmodel(self.model)

        #输入部分
        self.input_part = UserInputWidget(self, self.model, self.progressbar)

        # 布局
        self.main_layout.addWidget(self.input_part)
        self.main_layout.addWidget(self.output_part)

class DhcpcMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DHCPC")

        self.setCentralWidget(DhcpcMainWidget())
        self.resize(700, 600)
        # self.resize(200, 200)
        self.setMaximumSize(700, 600)
        self.setMinimumSize(700, 600)

    def closeEvent(self, event):
        event.accept()
        sys.exit(0)   # 退出程序

def main():
    a = QApplication(sys.argv)
    win = DhcpcMainWindow()

    win.show()
    sys.exit(a.exec())


if __name__ == "__main__":
    main()