# -*- coding: utf-8 -*-
"""
实验 1A：带 GUI 的网络嗅探器 (NPS/NPA)
主程序文件 (main.py)

整体架构：
- UI 界面层：PySide6 (Qt for Python)
- 网络抓包底层：Scapy + Npcap 驱动 (Windows)
- 并发模型：生产者-消费者模型 (抓包线程 -> Queue队列 -> QTimer主线程)
- 添加功能：实时流量波形图、协议树高亮联动、TCP流追踪、Pcap导出
"""

import sys
import queue
import time
from datetime import datetime
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                               QHBoxLayout, QComboBox, QPushButton, QLineEdit, 
                               QTableWidget, QTableWidgetItem, QTreeWidget, 
                               QTreeWidgetItem, QTextEdit, QSplitter, QFileDialog, 
                               QLabel, QMessageBox, QMenu, QDialog, QStyledItemDelegate, QStyle)
from PySide6.QtCore import Qt, QTimer, QThread, Signal, QPointF
from PySide6.QtGui import QTextCursor, QTextCharFormat, QAction, QColor, QBrush, QPainter, QPen, QPolygonF
from scapy.all import conf, wrpcap

# 强制 Scapy 在 Windows 环境下使用 Npcap 驱动
# 注意：必须确保安装 Npcap 时勾选了 "WinPcap API-compatible Mode"
conf.use_pcap = True
conf.use_npcap = True
from scapy.all import get_if_list, IP, TCP, ARP
from scapy.sendrecv import AsyncSniffer 

# 导入自定义的底层二进制协议解析模块
from packet_parser import parse_packet


# ==============================================================================
# 模块 1：UI绘制实时流量波形图
# 作用：重写 QComboBox 的渲染方式，在网卡名字右侧画折线图
# ==============================================================================
class TrafficDelegate(QStyledItemDelegate):
    def __init__(self, parent=None):
        super().__init__(parent)
        # 记录每个网卡的流量历史数据 (以 NPF 路径为键)
        self.traffic_history = {} 
        self.max_points = 30 # 波形图最多显示 30 个采样点

    def paint(self, painter, option, index):
        painter.save()
        # 1. 绘制背景（处理选中和未选中状态）
        if option.state & QStyle.State_Selected:
            painter.fillRect(option.rect, QColor("#E0E0E0"))
        else:
            painter.fillRect(option.rect, QColor("#FFFFFF"))

        # 2. 绘制文字（网卡描述与 IP）
        text = index.data(Qt.DisplayRole)
        painter.setPen(QColor("#333333"))
        # 右侧留出 120px 空间给波形图
        text_rect = option.rect.adjusted(8, 0, -120, 0)
        painter.drawText(text_rect, Qt.AlignVCenter | Qt.AlignLeft, text)

        # 3. 绘制流量波形折线图
        iface_data = index.data(Qt.UserRole)
        if iface_data:
            npf_path = iface_data.get("npf_path", "")
            if npf_path in self.traffic_history:
                history = self.traffic_history[npf_path]
                # 只有当历史数据大于 1 且存在非零值时，才绘制波形
                if len(history) > 1 and max(history) > 0:
                    graph_rect = option.rect.adjusted(option.rect.width() - 120, 6, -10, -6)
                    max_speed = max(history) if max(history) > 0 else 1
                    
                    polygon = QPolygonF()
                    step = graph_rect.width() / (self.max_points - 1)
                    
                    # 坐标映射：将流量值归一化为 Y 轴像素坐标
                    for i, speed in enumerate(history[-self.max_points:]):
                        norm_speed = speed / max_speed
                        # Y轴反转（像素坐标是从上往下递增的）
                        y = graph_rect.bottom() - (norm_speed * graph_rect.height())
                        x = graph_rect.left() + i * step
                        polygon.append(QPointF(x, y))
                        
                    # 开启抗锯齿绘制折线
                    painter.setRenderHint(QPainter.Antialiasing)
                    pen = QPen(QColor("#4A90E2"))
                    pen.setWidth(2)
                    painter.setPen(pen)
                    painter.drawPolyline(polygon)
                    
        painter.restore()

    def sizeHint(self, option, index):
        # 增加下拉框项的高度，以便给波形图留出垂直空间
        size = super().sizeHint(option, index)
        size.setHeight(35)
        return size


# ==============================================================================
# 模块 2：后台全局监控线程 —— 模仿Wireshark启动界面波形图
# 作用：在未点击“开始抓包”时，后台对系统所有网卡进行轻量级监听，统计流量
# ==============================================================================
class BackgroundMonitor(QThread):
    traffic_updated = Signal(dict) # 信号：传递流量统计数据字典
    
    def __init__(self, ifaces_npf):
        super().__init__()
        self.ifaces_npf = ifaces_npf
        self.running = True
        self.stats = {npf: 0 for npf in ifaces_npf}
        self.sniffers = []
        
    def run(self):
        # 为系统上的每一块网卡都启动一个极轻量的嗅探器
        for npf in self.ifaces_npf:
            try:
                sniffer = AsyncSniffer(
                    iface=npf, 
                    prn=lambda pkt, n=npf: self._count_pkt(n, pkt), 
                    store=False, # 只统计不保存，降低内存开销
                    filter="ip"  # 只抓 IP 包，过滤掉底层 ARP 广播等，降低 CPU 负载
                )
                sniffer.start()
                self.sniffers.append(sniffer)
            except Exception:
                pass 

        # 每 500ms 汇报一次流量数据
        while self.running:
            time.sleep(0.5) 
            if self.running:
                self.traffic_updated.emit(self.stats.copy())
                # 清零，以便统计下一个时间窗口的增量
                for k in self.stats.keys():
                    self.stats[k] = 0 
                
    def _count_pkt(self, npf, pkt):
        """回调函数：累加接收到的字节数"""
        if self.running:
            self.stats[npf] += len(pkt)

    def stop(self):
        """安全停止所有后台嗅探器"""
        self.running = False
        for s in self.sniffers:
            if s.running:
                try: s.stop()
                except: pass


# --- 颜色定义 (用于表格行背景色) ---
COLOR_TCP = QColor("#FDE2E4")   # 淡粉色
COLOR_UDP = QColor("#E2F0F9")   # 淡蓝色
COLOR_ICMP = QColor("#FFF8E1")  # 淡黄色
COLOR_OTHER = QColor("#F2F2F2") # 浅灰色


# ==============================================================================
# 模块 3：TCP 流追踪弹窗
# 作用：将同一会话（五元组相同）的包按时间顺序展示，呈现连接建立、传输和关闭过程
# ==============================================================================
class FlowWindow(QDialog):
    def __init__(self, flow_id, packets_info, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"TCP 流追踪 - {flow_id[0][0]}:{flow_id[0][1]} <-> {flow_id[1][0]}:{flow_id[1][1]}")
        self.resize(900, 500)
        layout = QVBoxLayout(self)
        self.text_view = QTextEdit()
        self.text_view.setReadOnly(True)
        self.text_view.setStyleSheet("font-family: Consolas, Courier New, monospace; font-size: 13px;")
        self.text_view.setLineWrapMode(QTextEdit.NoWrap) # 禁用自动换行
        layout.addWidget(self.text_view)
        self.text_view.setText(self.generate_flow_text(packets_info))
        
    def generate_flow_text(self, packets_info):
        """核心逻辑：解析 TCP Flags，格式化输出流数据"""
        lines = []
        lines.append("=" * 110)
        lines.append(f"TCP 流追踪 (共 {len(packets_info)} 个数据包)")
        lines.append("=" * 110 + "\n")
        
        for info in packets_info:
            idx = info["row_idx"]
            pkt = info["parsed"]
            tcp = pkt["tcp"]
            ip = pkt["ipv4"]
            
            # 位运算解析 TCP 标志位 (Flag 掩码)
            flags_str = []
            f = tcp["flags"]
            if f & 0x002: flags_str.append("SYN") # 建立连接
            if f & 0x010: flags_str.append("ACK") # 确认
            if f & 0x001: flags_str.append("FIN") # 断开连接
            if f & 0x004: flags_str.append("RST") # 重置
            if f & 0x008: flags_str.append("PSH") # 推送数据
            flags_text = ", ".join(flags_str) if flags_str else "None"
            
            # 判断数据包方向（基于源端口）
            arrow = "->" if info["src_port"] == tcp["sport"] else "<-"
            
            # 应用层载荷长度
            payload_len = len(tcp.get("payload", b""))
            
            line = (f"[Packet #{idx+1:3d}] {ip['src']:15}:{tcp['sport']:<5} {arrow} "
                    f"{ip['dst']:15}:{tcp['dport']:<5} | Flags: [{flags_text:<12}] | "
                    f"Seq: {tcp['seq']:<10} Ack: {tcp['ack']:<10} Len: {payload_len}")
            lines.append(line)
        return "\n".join(lines)


# ==============================================================================
# 模块 4：主窗口 (业务逻辑与界面控制)
# ==============================================================================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PySniff_1A_jwx")
        self.resize(1100, 750)
        
        # --- 核心状态变量 ---
        self.packet_count = 0
        self.sniffer = None # 前台抓包嗅探器
        self.pkt_queue = queue.Queue() # 线程安全队列，用于跨线程传递数据包
        self.all_packets = [] # 保存所有解析后的包字典
        self.raw_pcap_data = [] # 保存 Scapy 原始对象，用于导出 pcap
        self.tcp_flows = {} # 保存 TCP 流字典 { flow_id: [包列表] }

        # --- UI 布局初始化 ---
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # 1. 顶部工具栏
        top_layout = QHBoxLayout()
        self.iface_combo = QComboBox()
        self.iface_combo.setMinimumWidth(450) 
        self.combo_delegate = TrafficDelegate()
        self.iface_combo.setItemDelegate(self.combo_delegate)
        
        # 加载网卡并获取所有的 NPF 路径
        self.ifaces_npf = self.load_interfaces()
        
        # 启动后台全局监听，实现“一打开软件就显示波形”
        if self.ifaces_npf:
            self.bg_monitor = BackgroundMonitor(self.ifaces_npf)
            self.bg_monitor.traffic_updated.connect(self.update_traffic_graph)
            self.bg_monitor.start()
        
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("过滤规则，留空抓全部 (支持 tcp, udp, port 80 等)")
        self.help_btn = QPushButton("帮助")
        self.start_btn = QPushButton("开始抓包")
        self.stop_btn = QPushButton("停止")
        self.stop_btn.setEnabled(False)
        self.export_btn = QPushButton("导出 Pcap")
        self.export_btn.setEnabled(False)

        top_layout.addWidget(self.iface_combo)
        top_layout.addWidget(self.filter_input)
        top_layout.addWidget(self.help_btn)
        top_layout.addWidget(self.start_btn)
        top_layout.addWidget(self.stop_btn)
        top_layout.addWidget(self.export_btn)
        main_layout.addLayout(top_layout)

        # 2. 中间数据包列表 (表格)
        self.main_splitter = QSplitter(Qt.Vertical)

        # 2. 中间数据包列表 (表格)
        self.packet_table = QTableWidget(0, 6)
        self.packet_table.setHorizontalHeaderLabels(["序号", "时间", "源 IP", "目的 IP", "协议", "长度"])
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        self.packet_table.setColumnWidth(0, 60)
        self.packet_table.setColumnWidth(1, 120)
        self.packet_table.setAlternatingRowColors(False) 
        self.packet_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.packet_table.customContextMenuRequested.connect(self.show_context_menu)
        
        # 将表格加入垂直分割器
        self.main_splitter.addWidget(self.packet_table)

        # 3. 底部详情区 (树形图 + Hex 视图)
        self.bottom_splitter = QSplitter(Qt.Horizontal)
        
        self.detail_tree = QTreeWidget()
        self.detail_tree.setHeaderLabel("数据包详情")
        self.detail_tree.setAlternatingRowColors(True)
        self.bottom_splitter.addWidget(self.detail_tree)

        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setStyleSheet("font-family: Consolas, Courier New, monospace; font-size: 14px;")
        self.hex_view.setLineWrapMode(QTextEdit.NoWrap) 
        self.bottom_splitter.addWidget(self.hex_view)
        self.bottom_splitter.setSizes([500, 500]) 
        
        # 将底部的水平分割器，加入到主垂直分割器中
        self.main_splitter.addWidget(self.bottom_splitter)
        
        # 设置初始比例：上面表格占 60%，下面详情占 40%
        self.main_splitter.setSizes([400, 250]) 

        # 最后把主分割器加到主布局里
        main_layout.addWidget(self.main_splitter)

        self.status_label = QLabel("就绪 (提示: 在列表中右键点击 TCP 包可追踪流)")
        self.statusBar().addWidget(self.status_label)

        # --- 信号槽绑定 ---
        self.update_timer = QTimer()
        # 核心机制：每 100ms 从队列取一次数据刷新 UI，防止主线程阻塞卡死
        self.update_timer.timeout.connect(self.process_queue)
        self.update_timer.start(100)

        self.help_btn.clicked.connect(self.on_help)
        self.start_btn.clicked.connect(self.on_start)
        self.stop_btn.clicked.connect(self.on_stop)
        self.export_btn.clicked.connect(self.on_export)
        self.packet_table.itemClicked.connect(self.on_packet_clicked)
        self.detail_tree.itemClicked.connect(self.on_tree_item_clicked)

    def update_traffic_graph(self, speeds):
        """接收后台监控线程的数据，更新下拉框波形"""
        for npf_path, speed in speeds.items():
            if npf_path not in self.combo_delegate.traffic_history:
                self.combo_delegate.traffic_history[npf_path] = []
            
            # 过滤极微小的网络噪点
            if speed < 100: speed = 0
            self.combo_delegate.traffic_history[npf_path].append(speed)
            
            # 维持历史数据长度不超过 30 个点
            if len(self.combo_delegate.traffic_history[npf_path]) > self.combo_delegate.max_points:
                self.combo_delegate.traffic_history[npf_path].pop(0)
                
        # 触发 UI 重绘
        self.iface_combo.view().update()

    def load_interfaces(self):
        """获取系统网卡列表，进行清洗和智能排序"""
        self.iface_combo.clear()
        ifaces_list = []
        npf_paths = []
        
        try:
            from scapy.arch.windows import get_windows_if_list
            ifaces = get_windows_if_list()
            
            for iface in ifaces:
                npf_path = iface.get('name', '')
                desc = iface.get('description', 'Unknown Adapter')
                ips = iface.get('ips', [])
                
                # 提取 IPv4 地址
                ipv4 = "未分配"
                for ip in ips:
                    if ":" not in ip:
                        ipv4 = ip
                        break

                # 清理冗余的驱动后缀字符，使 UI 更清爽
                clean_desc = desc.replace("(NPCAP)", "").replace("Npcap Packet Driver", "").replace("Npcap", "").strip()
                if clean_desc.endswith("()"): clean_desc = clean_desc[:-2]

                ifaces_list.append({
                    "npf_path": npf_path,
                    "desc": clean_desc,
                    "ipv4": ipv4
                })
                npf_paths.append(npf_path)

            # 【智能排序】：真实 IP 的网卡优先，其次是 169.254 临时地址，最后是未分配 IP 的网卡
            def sort_key(item):
                ip = item["ipv4"]
                if ip != "未分配" and not ip.startswith("169.254."):
                    priority = 0
                elif ip.startswith("169.254."):
                    priority = 1
                else:
                    priority = 2
                return (priority, ip)
            
            ifaces_list.sort(key=sort_key)

            # 添加到下拉框
            for item in ifaces_list:
                display_text = f"{item['desc']} ({item['ipv4']})"
                item_data = {"npf_path": item["npf_path"]}
                self.iface_combo.addItem(display_text, item_data)

        except ImportError:
            pass
            
        return npf_paths

    def on_start(self):
        """启动抓包 (包含过滤器语法预检验)"""
        item_data = self.iface_combo.currentData()
        if not item_data: return
        iface = item_data["npf_path"]
        
        filter_str = self.filter_input.text().strip()
        
        # 应用层协议映射：将 HTTP 等应用层协议转化为底层的 BPF 端口过滤
        if filter_str.lower() == "http": filter_str = "tcp port 80"
        elif filter_str.lower() == "https": filter_str = "tcp port 443"
        elif filter_str.lower() == "dns": filter_str = "udp port 53"

        # 【防御性编程】：先尝试让底层 C 驱动编译一次过滤器，如果不合法则弹窗拦截
        if filter_str:
            try:
                test_listen = conf.L2listen(iface=iface, filter=filter_str)
                test_listen.close()
            except Exception as e:
                QMessageBox.critical(self, "过滤规则错误", f"语法无效：\n{e}")
                return

        # 状态重置
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.export_btn.setEnabled(False)
        self.packet_table.setRowCount(0)
        self.packet_count = 0
        self.all_packets.clear()
        self.raw_pcap_data.clear()
        self.tcp_flows.clear() 
        self.status_label.setText("正在抓包...")

        # 清空队列残留
        while not self.pkt_queue.empty(): self.pkt_queue.get()

        try:
            # 启动异步嗅探器（生产者）
            self.sniffer = AsyncSniffer(iface=iface, filter=filter_str, prn=self.handle_packet, store=False)
            self.sniffer.start()
        except Exception as e:
            QMessageBox.critical(self, "启动失败", f"发生未知错误：\n{e}")
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)

    def handle_packet(self, pkt):
        """生产者逻辑：由后台抓包线程调用，仅将包放入队列"""
        if self.sniffer and self.sniffer.running:
            self.pkt_queue.put(pkt)

    def on_stop(self):
        """停止抓包"""
        if self.sniffer and self.sniffer.running:
            try: self.sniffer.stop() 
            except: pass
            self.sniffer = None
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        if self.packet_count > 0:
            self.export_btn.setEnabled(True)
            self.status_label.setText(f"抓包已停止，共 {self.packet_count} 个包")
        else:
            self.status_label.setText("已停止")

    def on_export(self):
        """导出 Pcap 文件供 Wireshark 分析"""
        if not self.raw_pcap_data: return
        file_path, _ = QFileDialog.getSaveFileName(self, "保存 Pcap 文件", "capture.pcap", "Pcap Files (*.pcap)")
        if file_path:
            wrpcap(file_path, self.raw_pcap_data)
            self.status_label.setText(f"导出至: {file_path}")

    def process_queue(self):
        """消费者逻辑：在主线程定时消费队列数据，每次最多处理 50 个包"""
        count = 0
        while not self.pkt_queue.empty() and count < 50:
            pkt = self.pkt_queue.get()
            self.process_packet(pkt)
            count += 1

    def process_packet(self, pkt):
        """核心业务处理：解析包、更新表格、构建 TCP Flow"""
        if not (IP in pkt or ARP in pkt): return
        
        self.packet_count += 1
        raw_bytes = bytes(pkt)
        
        # 调用独立的协议解析模块
        parsed = parse_packet(raw_bytes)
        if not parsed: return

        # 缓存数据
        row_idx = len(self.all_packets)
        pkt_data = {"raw": raw_bytes, "parsed": parsed}
        self.all_packets.append(pkt_data)
        self.raw_pcap_data.append(pkt)

        # 提取关键字段用于表格展示
        ip_info = parsed.get("ipv4", {})
        src = ip_info.get("src", "?")
        dst = ip_info.get("dst", "?")
        length = len(raw_bytes)
        
        # 根据协议分配背景色
        proto = "IP"
        bg_color = COLOR_OTHER  
        
        if "arp" in parsed:
            arp_info = parsed["arp"]
            src = arp_info.get("src_ip", "?")
            dst = arp_info.get("dst_ip", "?")
            proto = "ARP"
            bg_color = QColor("#E8F8F5") 
        elif "tcp" in parsed: 
            proto = "TCP"
            bg_color = COLOR_TCP
        elif "udp" in parsed: 
            proto = "UDP"
            bg_color = COLOR_UDP
        elif "icmp" in parsed: 
            proto = "ICMP"
            bg_color = COLOR_ICMP
        elif ip_info.get("proto") == 2:
            proto = "IGMP"  
            bg_color = QColor("#EAEAEA") 

        # 【加分项：构建 TCP 流追踪】
        # 利用五元组（源IP、目的IP、源端口、目的端口、协议）进行双向哈希
        if proto == "TCP":
            tcp = parsed["tcp"]
            sport, dport = tcp["sport"], tcp["dport"]
            # 保证 A->B 和 B->A 的 Hash 值相同
            endpoint1 = (src, sport)
            endpoint2 = (dst, dport)
            if endpoint1 > endpoint2:
                endpoint1, endpoint2 = endpoint2, endpoint1
            flow_id = (endpoint1, endpoint2)
            
            if flow_id not in self.tcp_flows:
                self.tcp_flows[flow_id] = []
            self.tcp_flows[flow_id].append({
                "row_idx": row_idx,
                "parsed": parsed,
                "raw": raw_bytes,
                "src_port": sport 
            })

        # 更新表格 UI
        now_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        
        def make_item(text):
            item = QTableWidgetItem(text)
            item.setBackground(QBrush(bg_color))
            return item

        self.packet_table.setItem(row, 0, make_item(str(self.packet_count)))
        self.packet_table.setItem(row, 1, make_item(now_str))
        self.packet_table.setItem(row, 2, make_item(src))
        self.packet_table.setItem(row, 3, make_item(dst))
        self.packet_table.setItem(row, 4, make_item(proto))
        self.packet_table.setItem(row, 5, make_item(str(length)))
        self.packet_table.scrollToBottom()

    def show_context_menu(self, pos):
        """右键菜单：仅对 TCP 包提供流追踪功能"""
        item = self.packet_table.itemAt(pos)
        if not item: return
        row = item.row()
        proto = self.packet_table.item(row, 4).text()
        if proto != "TCP": return

        menu = QMenu(self)
        trace_action = QAction("追踪此 TCP 流", self)
        trace_action.triggered.connect(lambda: self.trace_tcp_flow(row))
        menu.addAction(trace_action)
        menu.exec(self.packet_table.viewport().mapToGlobal(pos))

    def trace_tcp_flow(self, row_idx):
        """根据点击的行，提取对应的 Flow ID，弹出追踪窗口"""
        pkt_data = self.all_packets[row_idx]
        ip_info = pkt_data["parsed"]["ipv4"]
        tcp_info = pkt_data["parsed"]["tcp"]
        
        endpoint1 = (ip_info["src"], tcp_info["sport"])
        endpoint2 = (ip_info["dst"], tcp_info["dport"])
        if endpoint1 > endpoint2:
            endpoint1, endpoint2 = endpoint2, endpoint1
        flow_id = (endpoint1, endpoint2)
        
        if flow_id in self.tcp_flows:
            flow_packs = self.tcp_flows[flow_id]
            dialog = FlowWindow(flow_id, flow_packs, self)
            dialog.exec()

    def on_packet_clicked(self, item):
        """点击表格某行：构建左下角的树形协议详情"""
        row = item.row()
        if row >= len(self.all_packets): return
        pkt_data = self.all_packets[row]
        raw = pkt_data["raw"]
        parsed = pkt_data["parsed"]

        self.detail_tree.clear()
        
        # 辅助函数：将 Offset 和 Length 存入 UserRole，为高亮联动做准备
        def add_node(parent, text, offset=None, length=None):
            node = QTreeWidgetItem(parent, [text])
            if offset is not None and length is not None:
                node.setData(0, Qt.UserRole, (offset, length))
            return node

        add_node(self.detail_tree, f"Frame {row+1}: {len(raw)} bytes on wire", 0, len(raw))
        
        # 逐层解析展示
        if "ethernet" in parsed:
            eth = parsed["ethernet"]
            eth_item = add_node(self.detail_tree, "Ethernet II")
            add_node(eth_item, f"Src MAC: {eth['src_mac']}", eth['src_mac_offset'], eth['src_mac_len'])
            add_node(eth_item, f"Dst MAC: {eth['dst_mac']}", eth['dst_mac_offset'], eth['dst_mac_len'])
            add_node(eth_item, f"Type: 0x{eth['ethertype']:04x}", eth['ethertype_offset'], eth['ethertype_len'])
            eth_item.setExpanded(True)

                # 渲染 ARP 树形节点
        if "arp" in parsed:
            arp = parsed["arp"]
            op_text = "Request (1)" if arp["opcode"] == 1 else "Reply (2)"
            arp_item = add_node(self.detail_tree, f"Address Resolution Protocol ({op_text})")
            add_node(arp_item, f"Hardware Type: {arp['htype']}", arp['htype_offset'], arp['htype_len'])
            add_node(arp_item, f"Protocol Type: 0x{arp['ptype']:04x}", arp['ptype_offset'], arp['ptype_len'])
            add_node(arp_item, f"Opcode: {arp['opcode']}", arp['opcode_offset'], arp['opcode_len'])
            add_node(arp_item, f"Sender MAC: {arp['src_mac']}", arp['src_mac_offset'], arp['src_mac_len'])
            add_node(arp_item, f"Sender IP: {arp['src_ip']}", arp['src_ip_offset'], arp['src_ip_len'])
            add_node(arp_item, f"Target MAC: {arp['dst_mac']}", arp['dst_mac_offset'], arp['dst_mac_len'])
            add_node(arp_item, f"Target IP: {arp['dst_ip']}", arp['dst_ip_offset'], arp['dst_ip_len'])
            arp_item.setExpanded(True)
        
        if "ipv4" in parsed:
            ip = parsed["ipv4"]
            ip_item = add_node(self.detail_tree, f"Internet Protocol Version 4, Src: {ip['src']}, Dst: {ip['dst']}")
            add_node(ip_item, f"Version: {ip['version']}", ip['version_offset'], ip['version_len'])
            add_node(ip_item, f"Header Length: {ip['ihl']} bytes", ip['ihl_offset'], ip['ihl_len'])
            add_node(ip_item, f"Total Length: {ip['total_len']}", ip['total_len_offset'], ip['total_len_len'])
            add_node(ip_item, f"Time to Live: {ip['ttl']}", ip['ttl_offset'], ip['ttl_len'])
            add_node(ip_item, f"Protocol: {ip['proto']}", ip['proto_offset'], ip['proto_len'])
            add_node(ip_item, f"Source Address: {ip['src']}", ip['src_offset'], ip['src_len'])
            add_node(ip_item, f"Destination Address: {ip['dst']}", ip['dst_offset'], ip['dst_len'])
            ip_item.setExpanded(True)

        if "tcp" in parsed:
            tcp = parsed["tcp"]
            tcp_item = add_node(self.detail_tree, "Transmission Control Protocol")
            add_node(tcp_item, f"Source Port: {tcp['sport']}", tcp['sport_offset'], tcp['sport_len'])
            add_node(tcp_item, f"Destination Port: {tcp['dport']}", tcp['dport_offset'], tcp['dport_len'])
            add_node(tcp_item, f"Sequence Number: {tcp['seq']}", tcp['seq_offset'], tcp['seq_len'])
            add_node(tcp_item, f"Acknowledgment Number: {tcp['ack']}", tcp['ack_offset'], tcp['ack_len'])
            add_node(tcp_item, f"Window Size: {tcp['window']}", tcp['window_offset'], tcp['window_len'])
            
            # 计算应用层 Data 数据的绝对偏移量并展示
            if len(tcp.get("payload", b"")) > 0:
                payload_offset = tcp['sport_offset'] + tcp['data_offset']
                add_node(tcp_item, f"Data ({len(tcp['payload'])} bytes)", payload_offset, len(tcp['payload']))
                
            tcp_item.setExpanded(True)
            
        elif "udp" in parsed:
            udp = parsed["udp"]
            udp_item = add_node(self.detail_tree, "User Datagram Protocol")
            add_node(udp_item, f"Source Port: {udp['sport']}", udp['sport_offset'], udp['sport_len'])
            add_node(udp_item, f"Destination Port: {udp['dport']}", udp['dport_offset'], udp['dport_len'])
            add_node(udp_item, f"Length: {udp['length']}", udp['length_offset'], udp['length_len'])
            
            if len(udp.get("payload", b"")) > 0:
                payload_offset = udp['sport_offset'] + 8
                add_node(udp_item, f"Data ({len(udp['payload'])} bytes)", payload_offset, len(udp['payload']))
                
            udp_item.setExpanded(True)
            
        elif "icmp" in parsed:
            icmp = parsed["icmp"]
            icmp_item = add_node(self.detail_tree, "Internet Control Message Protocol")
            add_node(icmp_item, f"Type: {icmp['type']}", icmp['type_offset'], icmp['type_len'])
            add_node(icmp_item, f"Code: {icmp['code']}", icmp['code_offset'], icmp['code_len'])
            icmp_item.setExpanded(True)

        # 渲染右侧十六进制
        self.hex_view.setText(self.format_hex_dump(raw))

    def on_tree_item_clicked(self, item, column):
        """
        【核心难点：Hex 视图的跨行精准高亮联动】
        当点击左侧树节点时，根据绑定的 Offset 和 Length 计算字符坐标并上色。
        """
        data = item.data(0, Qt.UserRole)
        if not data: return
        offset, length = data

        # 1. 先清除上一次的高亮背景
        cursor = QTextCursor(self.hex_view.document())
        cursor.select(QTextCursor.Document)
        default_fmt = QTextCharFormat()
        default_fmt.setBackground(QBrush(Qt.transparent))
        default_fmt.setForeground(QBrush(Qt.black))
        cursor.setCharFormat(default_fmt)

        # 2. 计算该字段在 Hex 矩阵中的起始/结束行列 (每行 16 字节)
        start_row = offset // 16
        start_col = offset % 16
        end_offset = offset + length - 1
        end_row = end_offset // 16
        end_col = end_offset % 16
        
        # 每一行的字符总长度 = 4(偏移) + 2(空格) + 16*3-1(Hex+空格) + 2(空格) + 16(ASCII) + 1(换行) = 72
        LINE_LEN = 72 
        
        # 设置高亮样式 (Wireshark 蓝)
        highlight_fmt = QTextCharFormat()
        highlight_fmt.setBackground(QBrush(QColor("#0078D7")))
        highlight_fmt.setForeground(QBrush(Qt.white))

        # 3. 逐行进行颜色渲染 (解决跨行选中把换行符也框进去的 Bug)
        for row_idx in range(start_row, end_row + 1):
            # 第一行从实际列开始，其余行从 0 列开始
            r_start_col = start_col if row_idx == start_row else 0
            # 最后一行在实际列结束，其余行在 15 列结束
            r_end_col = end_col if row_idx == end_row else 15
            
            # 计算字符的绝对索引
            hex_start = row_idx * LINE_LEN + 6 + r_start_col * 3
            hex_end = row_idx * LINE_LEN + 6 + r_end_col * 3 + 2
            
            cursor.setPosition(hex_start)
            cursor.setPosition(hex_end, QTextCursor.KeepAnchor)
            cursor.mergeCharFormat(highlight_fmt)
            
        self.hex_view.setTextCursor(cursor)

    def format_hex_dump(self, data, width=16):
        """将原始 bytes 格式化为 Wireshark 风格的 Hex Dump (偏移 + 16进制 + ASCII)"""
        lines = []
        for i in range(0, len(data), width):
            chunk = data[i:i+width]
            offset = f"{i:04x}"
            # 不足 16 字节补齐空格，确保右侧 ASCII 对齐
            hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
            # 32~126 是可打印 ASCII 字符，其余转为点号
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{offset}  {hex_part}  {ascii_part}")
        return "\n".join(lines)

    def on_help(self):
        """帮助文档：提示 BPF 语法规则"""
        help_text = """
        <h2 style="color: #2c3e50;">过滤规则帮助说明</h2>
        <p>支持标准的 <b>BPF (Berkeley Packet Filter)</b> 语法，所有规则不区分大小写。</p>
        
        <h3 style="color: #2980b9;">1. 基础协议过滤</h3>
        <ul>
            <li><code>tcp</code> / <code>udp</code> / <code>icmp</code> / <code>arp</code></li>
            <li><code>ip</code> / <code>ip6</code> : IPv4 / IPv6 数据包</li>
            <li><code>http</code> / <code>https</code> : 自动转换为 <code>tcp port 80</code> / <code>443</code></li>
        </ul>
        
        <h3 style="color: #2980b9;">2. IP 与端口过滤</h3>
        <ul>
            <li><code>host 192.168.1.1</code> : 过滤与该 IP 相关的所有包</li>
            <li><code>port 80</code> : 过滤源或目的端口为 80 的包</li>
        </ul>
        
        <h3 style="color: #2980b9;">3. 逻辑组合运算</h3>
        <ul>
            <li>与: <code>tcp and port 80</code></li>
            <li>或: <code>udp or icmp</code></li>
            <li>非: <code>not arp</code></li>
        </ul>
        """
        QMessageBox.information(self, "过滤规则说明", help_text)


    def closeEvent(self, event):
        """安全退出：清理后台线程与资源"""
        if hasattr(self, 'bg_monitor'):
            self.bg_monitor.stop()
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())