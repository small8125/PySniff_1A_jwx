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
        self.setWindowTitle("简易网络嗅探器 (NPS) - Day 5")
        self.resize(1000, 700)
        
        self.packet_count = 0
        self.sniffer = None
        self.pkt_queue = queue.Queue()
        
        # 用来保存所有抓到的包的数据，方便点击时查询
        self.all_packets = [] 

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # 顶部工具栏
        top_layout = QHBoxLayout()
        self.iface_combo = QComboBox()
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
        self.detail_tree.setAlternatingRowColors(True)
        bottom_splitter.addWidget(self.detail_tree)

        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        # 使用等宽字体，保证十六进制对齐
        self.hex_view.setStyleSheet("font-family: Consolas, Courier New, monospace;")
        bottom_splitter.addWidget(self.hex_view)
        bottom_splitter.setSizes([500, 500]) 
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
            interfaces = get_if_list()
            for iface in interfaces:
                ip = get_if_addr(iface)
                if ip != "0.0.0.0":
                    self.iface_combo.addItem(f"{iface} ({ip})", iface)

    def handle_packet(self, pkt):
        if self.sniffer and self.sniffer.running:
            self.pkt_queue.put(pkt)

    def on_start(self):
        iface = self.iface_combo.currentData()
        if not iface: return
        filter_str = self.filter_input.text().strip()
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.packet_table.setRowCount(0)
        self.packet_count = 0
        self.all_packets.clear()

        while not self.pkt_queue.empty():
            self.pkt_queue.get()

        self.sniffer = AsyncSniffer(iface=iface, filter=filter_str, prn=self.handle_packet, store=False)
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
        if IP not in pkt: return
            
        self.packet_count += 1
        raw_bytes = bytes(pkt)
        parsed = parse_packet(raw_bytes)
        if not parsed: return

        # 将解析结果和原始字节存起来，供点击时使用
        self.all_packets.append({
            "raw": raw_bytes,
            "parsed": parsed
        })

        ip_info = parsed.get("ipv4", {})
        src = ip_info.get("src", "?")
        dst = ip_info.get("dst", "?")
        length = len(raw_bytes)
        
        proto = "IP"
        if "tcp" in parsed: proto = "TCP"
        elif "udp" in parsed: proto = "UDP"
        elif "icmp" in parsed: proto = "ICMP"

        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        self.packet_table.setItem(row, 0, QTableWidgetItem(str(self.packet_count)))
        self.packet_table.setItem(row, 1, QTableWidgetItem(src))
        self.packet_table.setItem(row, 2, QTableWidgetItem(dst))
        self.packet_table.setItem(row, 3, QTableWidgetItem(proto))
        self.packet_table.setItem(row, 4, QTableWidgetItem(str(length)))
        
        self.packet_table.scrollToBottom()

    def on_packet_clicked(self, item):
        # 获取点击的行号
        row = item.row()
        if row >= len(self.all_packets): return
            
        pkt_data = self.all_packets[row]
        raw = pkt_data["raw"]
        parsed = pkt_data["parsed"]

        # 1. 更新树形详情
        self.detail_tree.clear()
        
        # Frame 层
        frame_item = QTreeWidgetItem(self.detail_tree, [f"Frame {row+1}: {len(raw)} bytes on wire"])
        
        # Ethernet 层（如果有）
        if "ethernet" in parsed:
            eth = parsed["ethernet"]
            eth_item = QTreeWidgetItem(self.detail_tree, [f"Ethernet II, Src: {eth['src_mac']}, Dst: {eth['dst_mac']}"])
            QTreeWidgetItem(eth_item, [f"Type: 0x{eth['ethertype']:04x}"])
            eth_item.setExpanded(True)
        
        # IPv4 层
        if "ipv4" in parsed:
            ip = parsed["ipv4"]
            ip_item = QTreeWidgetItem(self.detail_tree, [f"Internet Protocol Version 4, Src: {ip['src']}, Dst: {ip['dst']}"])
            QTreeWidgetItem(ip_item, [f"Version: {ip['version']}"])
            QTreeWidgetItem(ip_item, [f"Header Length: {ip['ihl']} bytes"])
            QTreeWidgetItem(ip_item, [f"Time to Live: {ip['ttl']}"])
            QTreeWidgetItem(ip_item, [f"Protocol: {ip['proto']}"])
            ip_item.setExpanded(True)

        # TCP 层
        if "tcp" in parsed:
            tcp = parsed["tcp"]
            tcp_item = QTreeWidgetItem(self.detail_tree, [f"Transmission Control Protocol, Src Port: {tcp['sport']}, Dst Port: {tcp['dport']}"])
            QTreeWidgetItem(tcp_item, [f"Sequence Number: {tcp['seq']}"])
            QTreeWidgetItem(tcp_item, [f"Acknowledgment Number: {tcp['ack']}"])
            QTreeWidgetItem(tcp_item, [f"Flags: 0x{tcp['flags']:03x}"])
            QTreeWidgetItem(tcp_item, [f"Window: {tcp['window']}"])
            tcp_item.setExpanded(True)

        # UDP 层
        if "udp" in parsed:
            udp = parsed["udp"]
            udp_item = QTreeWidgetItem(self.detail_tree, [f"User Datagram Protocol, Src Port: {udp['sport']}, Dst Port: {udp['dport']}"])
            QTreeWidgetItem(udp_item, [f"Length: {udp['length']}"])
            udp_item.setExpanded(True)

        # ICMP 层
        if "icmp" in parsed:
            icmp = parsed["icmp"]
            icmp_item = QTreeWidgetItem(self.detail_tree, [f"Internet Control Message Protocol, Type: {icmp['type']}, Code: {icmp['code']}"])
            icmp_item.setExpanded(True)

        # 2. 更新十六进制视图
        self.hex_view.setText(self.format_hex_dump(raw))

    def format_hex_dump(self, data, width=16):
        """将 bytes 格式化成 Wireshark 风格的十六进制 + ASCII 样式"""
        lines = []
        for i in range(0, len(data), width):
            chunk = data[i:i+width]
            # 偏移量 (如 0000, 0010)
            offset = f"{i:04x}"
            # 十六进制部分 (如 45 00 00 3c)
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            # 补齐空格，保证后面的 ASCII 对齐
            hex_part = hex_part.ljust(width * 3 - 1)
            # ASCII 部分 (遇到不可打印字符显示为 .)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{offset}  {hex_part}  {ascii_part}")
        return "\n".join(lines)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())