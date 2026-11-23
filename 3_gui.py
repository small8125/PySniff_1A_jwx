import sys
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                               QHBoxLayout, QComboBox, QPushButton, QLineEdit, 
                               QTableWidget, QTableWidgetItem, QTreeWidget, 
                               QTreeWidgetItem, QTextEdit, QSplitter)
from PySide6.QtCore import Qt

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("简易网络嗅探器 (NPS) - Day 3")
        self.resize(1000, 700)

        # 1. 创建主控件和主布局
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # 2. 顶部工具栏
        top_layout = QHBoxLayout()
        self.iface_combo = QComboBox()
        self.iface_combo.addItems(["请选择网卡...", "eth0", r"\Device\NPF_{...}"])
        
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("输入过滤规则，例如: tcp, udp, icmp")
        
        self.start_btn = QPushButton("开始抓包")
        self.stop_btn = QPushButton("停止")
        self.stop_btn.setEnabled(False) # 默认不可点

        top_layout.addWidget(self.iface_combo)
        top_layout.addWidget(self.filter_input)
        top_layout.addWidget(self.start_btn)
        top_layout.addWidget(self.stop_btn)
        main_layout.addLayout(top_layout)

        # 3. 中间包列表 (表格)
        self.packet_table = QTableWidget(0, 5)
        self.packet_table.setHorizontalHeaderLabels(["序号", "源 IP", "目的 IP", "协议", "长度"])
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        main_layout.addWidget(self.packet_table)

        # 4. 底部详情区 (用分割器左右分开)
        bottom_splitter = QSplitter(Qt.Horizontal)
        
        # 左侧：树形详情
        self.detail_tree = QTreeWidget()
        self.detail_tree.setHeaderLabel("数据包详情")
        bottom_splitter.addWidget(self.detail_tree)

        # 右侧：十六进制
        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setPlaceholderText("十六进制数据...")
        bottom_splitter.addWidget(self.hex_view)

        # 设置底部区域占整体高度的 40%
        bottom_splitter.setSizes([400, 600]) 
        main_layout.addWidget(bottom_splitter)

        # 绑定按钮事件
        self.start_btn.clicked.connect(self.on_start)
        self.stop_btn.clicked.connect(self.on_stop)
        self.packet_table.itemClicked.connect(self.on_packet_clicked)

    def on_start(self):
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        print("点击了开始抓包 (Day 3 暂未接入真实抓包)")
        
        # 填入假数据测试界面
        self.add_fake_packet("1", "192.168.1.10", "8.8.8.8", "ICMP", "98")
        self.add_fake_packet("2", "192.168.1.10", "114.114.114.114", "UDP", "69")

    def on_stop(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        print("点击了停止抓包")

    def add_fake_packet(self, seq, src, dst, proto, length):
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        self.packet_table.setItem(row, 0, QTableWidgetItem(seq))
        self.packet_table.setItem(row, 1, QTableWidgetItem(src))
        self.packet_table.setItem(row, 2, QTableWidgetItem(dst))
        self.packet_table.setItem(row, 3, QTableWidgetItem(proto))
        self.packet_table.setItem(row, 4, QTableWidgetItem(length))

    def on_packet_clicked(self, item):
        # 当点击表格某一行时，填充底部的假详情
        self.detail_tree.clear()
        
        eth_item = QTreeWidgetItem(self.detail_tree, ["Ethernet II, Src: 00:11:22:33:44:55"])
        ip_item = QTreeWidgetItem(self.detail_tree, ["Internet Protocol Version 4, Src: 192.168.1.10, Dst: 8.8.8.8"])
        QTreeWidgetItem(ip_item, ["Version: 4"])
        QTreeWidgetItem(ip_item, ["Header Length: 20 bytes"])
        
        self.detail_tree.expandAll()
        self.hex_view.setText("45 00 00 54 00 00 40 00 40 01 00 00 c0 a8 01 0a 08 08 08 08\n(假数据)")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())