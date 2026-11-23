import sys
import queue
import time
from datetime import datetime
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                               QHBoxLayout, QComboBox, QPushButton, QLineEdit, 
                               QTableWidget, QTableWidgetItem, QTreeWidget, 
                               QTreeWidgetItem, QTextEdit, QSplitter, QFileDialog, QLabel)
from PySide6.QtCore import Qt, QTimer
from scapy.all import conf, wrpcap

conf.use_pcap = True
conf.use_npcap = True
from scapy.all import get_if_list, get_if_addr, IP
from scapy.sendrecv import AsyncSniffer 

from packet_parser import parse_packet

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("简易网络嗅探器 (NPS) - Day 6 终极版")
        self.resize(1100, 750) # 稍微加宽一点
        
        self.packet_count = 0
        self.sniffer = None
        self.pkt_queue = queue.Queue()
        
        self.all_packets = []   # 存解析数据
        self.raw_pcap_data = [] # 存原始 Scapy 数据包，用于导出

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # 顶部工具栏
        top_layout = QHBoxLayout()
        self.iface_combo = QComboBox()
        self.iface_combo.setMinimumWidth(300) 
        self.load_interfaces()
        
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("过滤规则: tcp, udp, icmp")
        
        self.start_btn = QPushButton("开始抓包")
        self.stop_btn = QPushButton("停止")
        self.stop_btn.setEnabled(False)
        self.export_btn = QPushButton("导出 Pcap")
        self.export_btn.setEnabled(False) # 没数据时不可点

        top_layout.addWidget(self.iface_combo)
        top_layout.addWidget(self.filter_input)
        top_layout.addWidget(self.start_btn)
        top_layout.addWidget(self.stop_btn)
        top_layout.addWidget(self.export_btn)
        main_layout.addLayout(top_layout)

        # 中间包列表 (加了一列时间)
        self.packet_table = QTableWidget(0, 6)
        self.packet_table.setHorizontalHeaderLabels(["序号", "时间", "源 IP", "目的 IP", "协议", "长度"])
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        # 调整列宽
        self.packet_table.setColumnWidth(0, 60)
        self.packet_table.setColumnWidth(1, 120)
        self.packet_table.setColumnWidth(2, 150)
        self.packet_table.setColumnWidth(3, 150)
        self.packet_table.setColumnWidth(4, 80)
        main_layout.addWidget(self.packet_table)

        # 底部详情区
        bottom_splitter = QSplitter(Qt.Horizontal)
        self.detail_tree = QTreeWidget()
        self.detail_tree.setHeaderLabel("数据包详情")
        self.detail_tree.setAlternatingRowColors(True)
        bottom_splitter.addWidget(self.detail_tree)

        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setStyleSheet("font-family: Consolas, Courier New, monospace;")
        bottom_splitter.addWidget(self.hex_view)
        bottom_splitter.setSizes([500, 500]) 
        main_layout.addWidget(bottom_splitter)

        # 底部状态栏
        self.status_label = QLabel("就绪")
        self.statusBar().addWidget(self.status_label)

        # 定时器
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.process_queue)
        self.update_timer.start(100)

        # 绑定事件
        self.start_btn.clicked.connect(self.on_start)
        self.stop_btn.clicked.connect(self.on_stop)
        self.export_btn.clicked.connect(self.on_export)
        self.packet_table.itemClicked.connect(self.on_packet_clicked)

    def load_interfaces(self):
        self.iface_combo.clear()
        try:
            from scapy.arch.windows import get_windows_if_list
            ifaces = get_windows_if_list()
            for iface in ifaces:
                name = iface.get('name', '')
                desc = iface.get('description', 'Unknown Adapter')
                ips = iface.get('ips', [])
                ipv4 = "未分配"
                for ip in ips:
                    if ":" not in ip:
                        ipv4 = ip
                        break
                if ipv4 != "未分配" or "Loopback" in name:
                    display_text = f"{desc} ({ipv4})"
                    self.iface_combo.addItem(display_text, name)
        except ImportError:
            pass

    def handle_packet(self, pkt):
        if self.sniffer and self.sniffer.running:
            self.pkt_queue.put(pkt)

    def on_start(self):
        iface = self.iface_combo.currentData()
        if not iface: return
        filter_str = self.filter_input.text().strip()
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.export_btn.setEnabled(False)
        self.packet_table.setRowCount(0)
        self.packet_count = 0
        self.all_packets.clear()
        self.raw_pcap_data.clear()
        self.status_label.setText("正在抓包...")

        while not self.pkt_queue.empty():
            self.pkt_queue.get()

        self.sniffer = AsyncSniffer(iface=iface, filter=filter_str, prn=self.handle_packet, store=False)
        self.sniffer.start()

    def on_stop(self):
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop() 
            self.sniffer = None
        
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        if self.packet_count > 0:
            self.export_btn.setEnabled(True)
            self.status_label.setText(f"抓包已停止，共捕获 {self.packet_count} 个数据包。")

    def on_export(self):
        if not self.raw_pcap_data:
            return
        
        file_path, _ = QFileDialog.getSaveFileName(self, "保存 Pcap 文件", "capture.pcap", "Pcap Files (*.pcap)")
        if file_path:
            wrpcap(file_path, self.raw_pcap_data)
            self.status_label.setText(f"成功导出至: {file_path}")

    def process_queue(self):
        count = 0
        while not self.pkt_queue.empty() and count < 50:
            pkt = self.pkt_queue.get()
            self.process_packet(pkt)
            count += 1

    def process_packet(self, pkt):
        if IP not in pkt: return
            
        self.packet_count += 1
        raw_bytes = bytes(pkt)
        parsed = parse_packet(raw_bytes)
        if not parsed: return

        self.all_packets.append({"raw": raw_bytes, "parsed": parsed})
        self.raw_pcap_data.append(pkt) # 存入原始包用于导出

        ip_info = parsed.get("ipv4", {})
        src = ip_info.get("src", "?")
        dst = ip_info.get("dst", "?")
        length = len(raw_bytes)
        
        proto = "IP"
        if "tcp" in parsed: proto = "TCP"
        elif "udp" in parsed: proto = "UDP"
        elif "icmp" in parsed: proto = "ICMP"

        # 获取当前时间戳
        now_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        self.packet_table.setItem(row, 0, QTableWidgetItem(str(self.packet_count)))
        self.packet_table.setItem(row, 1, QTableWidgetItem(now_str))
        self.packet_table.setItem(row, 2, QTableWidgetItem(src))
        self.packet_table.setItem(row, 3, QTableWidgetItem(dst))
        self.packet_table.setItem(row, 4, QTableWidgetItem(proto))
        self.packet_table.setItem(row, 5, QTableWidgetItem(str(length)))
        
        self.packet_table.scrollToBottom()

    def on_packet_clicked(self, item):
        row = item.row()
        if row >= len(self.all_packets): return
            
        pkt_data = self.all_packets[row]
        raw = pkt_data["raw"]
        parsed = pkt_data["parsed"]

        self.detail_tree.clear()
        
        # 树形展示部分（和 Day 5 相同，略作精简）
        frame_item = QTreeWidgetItem(self.detail_tree, [f"Frame {row+1}: {len(raw)} bytes on wire"])
        
        if "ethernet" in parsed:
            eth = parsed["ethernet"]
            eth_item = QTreeWidgetItem(self.detail_tree, [f"Ethernet II, Src: {eth['src_mac']}, Dst: {eth['dst_mac']}"])
            QTreeWidgetItem(eth_item, [f"Type: 0x{eth['ethertype']:04x}"])
            eth_item.setExpanded(True)
        
        if "ipv4" in parsed:
            ip = parsed["ipv4"]
            ip_item = QTreeWidgetItem(self.detail_tree, [f"Internet Protocol Version 4, Src: {ip['src']}, Dst: {ip['dst']}"])
            QTreeWidgetItem(ip_item, [f"Version: {ip['version']}"])
            QTreeWidgetItem(ip_item, [f"Header Length: {ip['ihl']} bytes"])
            QTreeWidgetItem(ip_item, [f"Time to Live: {ip['ttl']}"])
            ip_item.setExpanded(True)

        if "tcp" in parsed:
            tcp = parsed["tcp"]
            tcp_item = QTreeWidgetItem(self.detail_tree, [f"TCP, Src Port: {tcp['sport']}, Dst Port: {tcp['dport']}"])
            QTreeWidgetItem(tcp_item, [f"Flags: 0x{tcp['flags']:03x}"])
            tcp_item.setExpanded(True)
        elif "udp" in parsed:
            udp = parsed["udp"]
            udp_item = QTreeWidgetItem(self.detail_tree, [f"UDP, Src Port: {udp['sport']}, Dst Port: {udp['dport']}"])
            udp_item.setExpanded(True)
        elif "icmp" in parsed:
            icmp = parsed["icmp"]
            icmp_item = QTreeWidgetItem(self.detail_tree, [f"ICMP, Type: {icmp['type']}, Code: {icmp['code']}"])
            icmp_item.setExpanded(True)

        self.hex_view.setText(self.format_hex_dump(raw))

    def format_hex_dump(self, data, width=16):
        lines = []
        for i in range(0, len(data), width):
            chunk = data[i:i+width]
            offset = f"{i:04x}"
            hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{offset}  {hex_part}  {ascii_part}")
        return "\n".join(lines)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())