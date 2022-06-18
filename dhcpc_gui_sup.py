from tkinter.messagebox import NO
from PyQt6.QtWidgets import QStyledItemDelegate, QComboBox, QSpinBox, QLineEdit, QTableWidgetItem, QTableWidget, QPushButton, QWidget, QFormLayout, QHBoxLayout, QMessageBox, QDialog
from PyQt6.QtCore import QAbstractTableModel, Qt, pyqtSignal

import re

def get_firstint_fromstr(str):
    if (str):
        l = re.findall("\d+", str)
        if l:
            return int(l[0])
        return None

class DHCPC_OPTION_SET(QDialog):
    add_option_signal = pyqtSignal([int, str, str])
    del_option_signal = pyqtSignal([int])
    def __init__(self, parent=None, conn = None) -> None:
        super().__init__(parent)
        layout = QFormLayout(self)
        btn_layout = QHBoxLayout()

        self.setWindowTitle("OPTION")
        self.setWindowModality(Qt.WindowModality.WindowModal)

        self.option = QSpinBox()
        self.option.setMinimum(1)
        self.option.setMaximum(254)
        self.value_type = QComboBox()
        self.value_type.addItems(["hex", "str"])
        self.value = QLineEdit()

        add_btn = QPushButton("Add")
        del_btn = QPushButton("Del")

        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(del_btn)

        layout.addRow("option:", self.option)
        layout.addRow("value type:", self.value_type)
        layout.addRow("value:", self.value)
        layout.addRow(btn_layout)

        add_btn.clicked.connect(self.onClickAdd)
        del_btn.clicked.connect(self.onClickDel)

        # 信号处理
        self.add_option_signal[int, str, str].connect(conn.add_option)
        self.del_option_signal[int].connect(conn.del_option)
        
    def onClickDel(self):
        op = get_firstint_fromstr(self.option.text())
        if (op is None):
            return
        self.del_option_signal.emit(op)
        # be_del_data = "是否删除数据option({op})?".format(op=op)
        # msg = QMessageBox(QMessageBox.Icon.NoIcon, "提示", be_del_data, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, None)
        # if (msg.exec() == QMessageBox.StandardButton.Yes):
        #     logger.debug("Del")
    def onClickAdd(self):
        op = get_firstint_fromstr(self.option.text())
        if (op is None):
            return
        self.add_option_signal.emit(op, self.get_value_type(), self.value.text())
    def get_value_type(self):
        return self.value_type.currentText()
class DHCPC_PKT_MODEL(QStyledItemDelegate):
    def __init__(self, parent, check, conn) -> None:
        super().__init__(parent)
        self.nondata_ops_check = check
        self.conn = conn
    def createEditor(self, parent, option, index):
        editor = None
        if (index.isValid()):
            # hops
            if (index.row() == 0 and index.column() == 3):
                editor = QSpinBox(parent)
                editor.setMinimum(0)
                editor.setMaximum(255)
            # xid
            elif (index.row() == 1 and index.column() == 0):
                editor = QLineEdit(parent)
                editor.setInputMask("\\0\\xHHHHHHHH;0")
            # secs
            elif (index.row() == 2 and index.column() == 0):
                editor = QSpinBox(parent)
                editor.setMinimum(0)
                editor.setMaximum(2147483647)
            # flags
            elif (index.row() == 2 and index.column() == 2):
                editor = QComboBox(parent)
                editor.addItems(["broadcast", "unicast"])
            # ciaddr
            elif (index.row() == 3 and index.column() == 0):
                editor = QLineEdit(parent)
                editor.setInputMask("000.000.000.000;0")
            # yiaddr
            elif (index.row() == 4 and index.column() == 0):
                editor = QLineEdit(parent)
                editor.setInputMask("000.000.000.000;0")
            # giaddr
            elif (index.row() == 5 and index.column() == 0):
                editor = QLineEdit(parent)
                editor.setInputMask("009.009.009.009;0")
            # chaddr
            elif (index.row() == 6 and index.column() == 0):
                editor = QLineEdit(parent)
                editor.setInputMask("HH:HH:HH:HH:HH:HH")
            # options
            elif (index.row() == 9 and index.column() == 0):
                editor = DHCPC_OPTION_SET(parent, self.conn)
            else:
                if (index.data().find("option") == 0):
                    opint = get_firstint_fromstr(index.data())
                    if (opint == 53):
                        editor = QComboBox(parent)
                        editor.addItems(["discover", "request", "decline", "release", "inform"])
                    elif (self.nondata_ops_check(opint)):                 
                        editor = QLineEdit(parent)

        return editor


    def setEditorData(self, editor, index):
        value = index.data(Qt.ItemDataRole.EditRole)
        # hops
        if (index.row() == 0 and index.column() == 3):
            editor.setValue(int(value.split(":", 1)[1]))
        # secs
        elif (index.row() == 2 and index.column() == 0):
            editor.setValue(int(value.split(":", 1)[1]))
        # flags
        elif (index.row() == 2 and index.column() == 2):
            editor.setCurrentText(value.split(":", 1)[1])
        # xid
        elif (index.row() == 1 and index.column() == 0):
            editor.setText(value.split(":", 1)[1])
        # ciaddr
        elif (index.row() == 3 and index.column() == 0):
            editor.setText(value.split(":", 1)[1])
        # yiaddr
        elif (index.row() == 4 and index.column() == 0):
            editor.setText(value.split(":", 1)[1])
        # giaddr
        elif (index.row() == 5 and index.column() == 0):
            editor.setText(value.split(":", 1)[1])
        # chaddr
        elif (index.row() == 6 and index.column() == 0):
            editor.setText(value.split(":", 1)[1])
        # options
        elif (index.row() == 9 and index.column() == 0):
            pass
        else:
            opint = get_firstint_fromstr(value)
            if (value.find("option") == 0):
                if (opint == 53):
                    editor.setCurrentText(value.split(":", 1)[1])
                elif (len(value.split(":", 1)) > 1):
                    editor.setText(value.split(":", 1)[1])
    def point_check(self, value):
        ipseg_list = value.split('.')
        return '.'.join(['0' if value == '' else value for value in ipseg_list])
    def colon_check(self, value):
        macseg_list = value.split(':')
        return ':'.join(['00' if value == '' else value for value in macseg_list])

    def setModelData(self, editor, model, index):
        # hops
        value = None
        if (index.row() == 0 and index.column() == 3):
            value = "hops:"+ str(editor.value())
        # secs
        elif (index.row() == 2 and index.column() == 0):
            value = "secs:"+ str(editor.value())
        # flags
        elif (index.row() == 2 and index.column() == 2):
            value = "flags:"+ editor.currentText()
        # xid
        elif (index.row() == 1 and index.column() == 0):
            value = "xid:"+ self.point_check(editor.text())
        # ciaddr
        elif (index.row() == 3 and index.column() == 0):
            value = "ciaddr:"+ self.point_check(editor.text())
        # yiaddr
        elif (index.row() == 4 and index.column() == 0):
            value = "yiaddr:"+ self.point_check(editor.text())
        # giaddr
        elif (index.row() == 5 and index.column() == 0):
            value = "giaddr:"+ self.point_check(editor.text())
        # chaddr
        elif (index.row() == 6 and index.column() == 0):
            value = "chaddr:"+ self.colon_check(editor.text())
        # options
        elif (index.row() == 9 and index.column() == 0):
            value = "options:"
        else:
            intop = get_firstint_fromstr(index.data())
            editable = self.nondata_ops_check(intop)
            if (index.data().find("option") == 0):
                if (editable):
                    if (intop == 53):
                        value = index.data().split(":", 1)[0] + ":" + editor.currentText()
                    else:
                        value = index.data().split(":", 1)[0] + ":" + editor.text()
                else:
                    value = "option({op})".format(op = intop)

        model.setData(index, value, Qt.ItemDataRole.EditRole)


    def updateEditorGeometry(self, editor, option, index):
        editor.setGeometry(option.rect)

class DHCPC_PKT_TABLEWIDGET(QTableWidget):
    def __init__(self, row, col, parent=None):
        super().__init__(row, col, parent)
        self.setWindowTitle("DHCP REQUEST PACKET")
        self.zeroip = "0.0.0.0"
        self.req_ops_list = [1, 2, 3, 6, 12, 15, 17, 26, 28, 33, 40, 41, 42, 119, 121, 249, 252]
        self.nondata_ops_list = [255]
    def other(self):
        # op
        op_item = QTableWidgetItem("op:1")
        op_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setItem(0, 0, op_item)
        # htype
        htype_item = QTableWidgetItem("htype:1")
        htype_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setItem(0, 1,htype_item)
        # hlen
        hlen_item = QTableWidgetItem("hlen:6(bytes)")
        hlen_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setItem(0, 2,hlen_item)
        # hops
        hops_item = QTableWidgetItem("hops:0")
        hops_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setItem(0, 3, hops_item)
        # xid
        xid_item = QTableWidgetItem(self.get_xid())
        xid_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        # xid_item.setFlags(Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEditable | Qt.ItemFlag.ItemIsEnabled)
        self.setItem(1, 0, xid_item)
        # secs
        secs_item = QTableWidgetItem("secs:0")
        secs_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setItem(2, 0, secs_item)
        # flags
        flags_item = QTableWidgetItem("flags:broadcast")
        flags_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setItem(2, 2, flags_item)
        # ciaddr
        ciaddr_item = QTableWidgetItem(self.get_ciaddr())
        ciaddr_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setItem(3, 0, ciaddr_item)
        # yiaddr
        yiaddr_item = QTableWidgetItem(self.get_yiaddr())
        yiaddr_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setItem(4, 0, yiaddr_item)
        # giaddr
        giaddr_item = QTableWidgetItem(self.get_giaddr())
        giaddr_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setItem(5, 0, giaddr_item)
        # chaddr
        chaddr_item = QTableWidgetItem(self.get_chaddr())
        chaddr_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setItem(6, 0, chaddr_item)
        # sname
        sname_item = QTableWidgetItem(self.get_sname())
        sname_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setItem(7, 0, sname_item)
        # file
        file_item = QTableWidgetItem(self.get_file())
        file_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setItem(8, 0, file_item)

        # options
        option_title_item = QTableWidgetItem("options:")
        option_title_item.setTextAlignment(Qt.AlignmentFlag.AlignLeft)
        self.setRowHeight(9, 70)
        self.setItem(9, 0, option_title_item)
        # self.setCornerWidget

        # option end
        self.insertRow(self.rowCount())
        row =  self.rowCount() - 1
        self.setSpan(row, 0, 1, 4)
        end_option_item = QTableWidgetItem("option(255)")
        end_option_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setItem(row, 0, end_option_item)

        # dhcp message type
        self.add_req_option_befend(53, "discover", "Dhcp message type")
        self.add_req_option_befend(61, "", "Client identifier")
        self.add_req_option_befend(55, ",".join([str(op) for op in self.req_ops_list]), "Parameter Request List")
        self.add_req_option_befend(57, "576", "Maximum DHCP Message Size")
        self.add_req_option_befend(12, "", "Host Name")
        
        self.setItemDelegate(DHCPC_PKT_MODEL(None, self.nondata_ops_check, self))
    def nondata_ops_check(self, op):
        if (op in self.nondata_ops_list):
            return False
        return True

    # 去重
    def add_option(self, op, type, value):
        editable = self.nondata_ops_check(op)
        if (not editable and len(value) != 0):
            QMessageBox(QMessageBox.Icon.NoIcon, "提示", "该option不可设置value", QMessageBox.StandardButton.Ok, None).exec()
            return
        self.add_req_option_befend(op, value)
    def del_option(self, option):
        for row in range(0, self.rowCount()):
            for col in range(0, self.columnCount()):
                item = self.item(row, col)
                if (item):
                    text = item.text()
                    if (text.find("option(") == 0 and get_firstint_fromstr(text) == option):
                        self.removeRow(row)
                        logger.debug(option, text, row)
                        break


    def add_req_option_befend(self, op, value=None, tips=""):
        self.insertRow(self.rowCount() - 1)
        row =  self.rowCount() - 2
        self.setSpan(row, 0, 1, 4)

        if tips == "":
            separator = ""
        else:
            separator = "-"
        if (value is not None):
            option = "option({op}{separator}{tips}):".format(op = op, tips=tips, separator=separator) + value
        else:
            option = "option({op}{separator}{tips})".format(op = op, tips=tips, separator=separator)

        req_option_item = QTableWidgetItem(option)
        req_option_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setItem(row, 0, req_option_item)
        
    def get_xid(self):
        xid = 12345678
        return "xid:" + "0x" + str(xid)

    def get_ciaddr(self):
        return "ciaddr:" + self.zeroip
    def get_yiaddr(self):
        return "yiaddr:" + self.zeroip
    def get_giaddr(self):
        return "giaddr:" + self.zeroip
    def get_chaddr(self):
        mac = "10:22:33:44:55:66"
        return "chaddr:" + mac
    def get_sname(self):
        return "sname:" + ''
    def get_file(self):
        return "file:" + ''
    def get_option(self, op):
        return "option({op}):".format(op=op) + ''
    def write2dhcpc_cfg(self):
        return DHCPC_PKT_CFG_FROMUI(self)

class DHCPC_PKT_CFG_FROMUI():
    def __init__(self, pkt:DHCPC_PKT_TABLEWIDGET) -> None:
        self.ops = [None] * 256
        for row in range(0, pkt.rowCount()):
            for col in range(0, pkt.columnCount()):
                item = pkt.item(row, col)
                if (item):
                    if (item.text().find(":") != -1):
                        text , value = item.text().split(":", 1)
                    else:
                        text  = item.text()
                    opint = get_firstint_fromstr(text)
                    if (text == "op"):
                        self.op = int(value)
                    elif (text == "htype"):
                        self.htype = int(value)
                    elif (text == "hops"):
                        self.hops = int(value)
                    elif (text == "xid"):
                        self.xid = int(value, 16)
                    elif (text == "secs"):
                        self.secs = int(value)
                    elif (text == "flags"):
                        self.flags = value
                    elif (text == "ciaddr"):
                        self.ciaddr = value
                    elif (text == "yiaddr"):
                        self.yiaddr = value
                    elif (text == "giaddr"):
                        self.giaddr = value
                    elif (text == "chaddr"):
                        self.chaddr = value
                    elif (text == "sname"):
                        self.sname = value
                    elif (text == "file"):
                        self.file = value
                    elif (text.find("option") == 0 and opint):
                        self.ops[opint] = value
                        # logger.debug("BB:", type(opint),opint, value)
                    
    def get_op(self):
        return self.op
    def get_htype(self):
        return self.htype
    def get_hops(self):
        return self.hops
    def get_xid(self):
        return self.xid
    def get_secs(self):
        return self.secs
    def get_flags(self)->str:
        return self.flags
    def get_ciaddr(self)->str:
        return self.ciaddr
    def get_yiaddr(self)->str:
        return self.yiaddr
    def get_giaddr(self)->str:
        return self.giaddr
    def get_chaddr(self)->str:
        return self.chaddr
    def get_sname(self):
        return self.sname
    def get_file(self):
        return self.file
    def get_ops(self):
        return self.ops