import sys
import queue
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                               QHBoxLayout, QComboBox, QPushButton, QLineEdit, 
                               QTableWidget, QTableWidgetItem, QTreeWidget, 
                               QTreeWidgetItem, QTextEdit, QSplitter)
from PySide6.QtCore import Qt, QTimer

from scapy.all import conf
conf.use_pcap = True
conf.use_npcap = True
from scapy.all import get_if_list, get_if_addr, IP
from scapy.sendrecv import AsyncSniffer 

from packet_parser import parse_packet

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("简易网络嗅探器 (NPS) - Day 4")
        self.resize(1000, 700)
        
        self.packet_count = 0
        self.sniffer = None
        self.pkt_queue = queue.Queue()

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # 顶部工具栏
        top_layout = QHBoxLayout()
        self.iface_combo = QComboBox()
        # 稍微把下拉框调宽一点，方便显示长名字
        self.iface_combo.setMinimumWidth(350) 
        self.load_interfaces()
        
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("过滤规则: tcp, udp, icmp, 留空抓全部")
        
        self.start_btn = QPushButton("开始抓包")
        self.stop_btn = QPushButton("停止")
        self.stop_btn.setEnabled(False)

        top_layout.addWidget(self.iface_combo)
        top_layout.addWidget(self.filter_input)
        top_layout.addWidget(self.start_btn)
        top_layout.addWidget(self.stop_btn)
        main_layout.addLayout(top_layout)

        # 中间包列表
        self.packet_table = QTableWidget(0, 5)
        self.packet_table.setHorizontalHeaderLabels(["序号", "源 IP", "目的 IP", "协议", "长度"])
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        main_layout.addWidget(self.packet_table)

        # 底部详情区
        bottom_splitter = QSplitter(Qt.Horizontal)
        self.detail_tree = QTreeWidget()
        self.detail_tree.setHeaderLabel("数据包详情")
        bottom_splitter.addWidget(self.detail_tree)

        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        bottom_splitter.addWidget(self.hex_view)
        bottom_splitter.setSizes([400, 600]) 
        main_layout.addWidget(bottom_splitter)

        # 定时器
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.process_queue)
        self.update_timer.start(100)

        # 绑定事件
        self.start_btn.clicked.connect(self.on_start)
        self.stop_btn.clicked.connect(self.on_stop)
        self.packet_table.itemClicked.connect(self.on_packet_clicked)

    def load_interfaces(self):
        self.iface_combo.clear()
        print("\n--- 检测到的网络接口 ---")
        
        try:
            # 尝试使用 Windows 专属的 API 获取友好的网卡名称
            from scapy.arch.windows import get_windows_if_list
            ifaces = get_windows_if_list()
            for iface in ifaces:
                name = iface.get('name', '')
                desc = iface.get('description', 'Unknown Adapter')
                ips = iface.get('ips', [])
                
                # 找 IPv4 地址
                ipv4 = "未分配"
                for ip in ips:
                    if ":" not in ip: # 简单排除 IPv6
                        ipv4 = ip
                        break
                
                # 过滤掉没有 IP 且不是回环的网卡（可保留看个人喜好）
                if ipv4 != "未分配" or "Loopback" in name:
                    display_text = f"{desc} ({ipv4})"
                    # addItem(显示文本, 隐藏数据)
                    self.iface_combo.addItem(display_text, name)
                    print(f"[Windows] {display_text}")
        except ImportError:
            # 跨平台备选方案（比如在 Linux 下）
            interfaces = get_if_list()
            for iface in interfaces:
                ip = get_if_addr(iface)
                if ip != "0.0.0.0":
                    self.iface_combo.addItem(f"{iface} ({ip})", iface)
                    print(f"[Linux] {iface} ({ip})")
                    
        print("------------------------\n")

    def handle_packet(self, pkt):
        if self.sniffer and self.sniffer.running:
            self.pkt_queue.put(pkt)

    def on_start(self):
        # currentData() 取出的就是我们刚才藏在背后的真实 NPF 路径
        iface = self.iface_combo.currentData()
        if not iface:
            return
            
        filter_str = self.filter_input.text().strip()
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.packet_table.setRowCount(0)
        self.packet_count = 0
        
        while not self.pkt_queue.empty():
            self.pkt_queue.get()

        self.sniffer = AsyncSniffer(
            iface=iface, 
            filter=filter_str, 
            prn=self.handle_packet, 
            store=False
        )
        self.sniffer.start()
        print(f"开始抓包: {iface} | 过滤: {filter_str or '无'}")

    def on_stop(self):
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop() 
            self.sniffer = None
            
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        print("已停止抓包")

    def process_queue(self):
        count = 0
        while not self.pkt_queue.empty() and count < 50:
            pkt = self.pkt_queue.get()
            self.process_packet(pkt)
            count += 1

    def process_packet(self, pkt):
        if IP not in pkt:
            return
            
        self.packet_count += 1
        raw_bytes = bytes(pkt)
        parsed = parse_packet(raw_bytes)
        if not parsed:
            return

        ip_info = parsed.get("ipv4", {})
        src = ip_info.get("src", "?")
        dst = ip_info.get("dst", "?")
        length = len(raw_bytes)
        
        proto = "IP"
        if "tcp" in parsed: proto = "TCP"
        elif "udp" in parsed: proto = "UDP"
        elif "icmp" in parsed: proto = "ICMP"
        elif ip_info.get("proto") == 2: proto = "IGMP"

        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        self.packet_table.setItem(row, 0, QTableWidgetItem(str(self.packet_count)))
        self.packet_table.setItem(row, 1, QTableWidgetItem(src))
        self.packet_table.setItem(row, 2, QTableWidgetItem(dst))
        self.packet_table.setItem(row, 3, QTableWidgetItem(proto))
        self.packet_table.setItem(row, 4, QTableWidgetItem(str(length)))
        
        self.packet_table.scrollToBottom()

    def on_packet_clicked(self, item):
        row = item.row()
        seq = self.packet_table.item(row, 0).text()
        src = self.packet_table.item(row, 1).text()
        dst = self.packet_table.item(row, 2).text()
        
        self.detail_tree.clear()
        root = QTreeWidgetItem(self.detail_tree, [f"Packet #{seq}: {src} -> {dst}"])
        root.setExpanded(True)
        self.hex_view.setText("详细数据将在 Day 5 补全...")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())