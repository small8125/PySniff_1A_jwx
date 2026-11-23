# -*- coding: utf-8 -*-
"""
实验 1A：底层网络协议二进制解析模块 (packet_parser.py)

本模块处理原始字节流 (bytes)。
利用 Python 自带的模块和位运算，按照OSI七层模型进行逐层解析
解析结果以字典形式返回，并记录了每个字段在整个数据包中的绝对偏移量级长度
"""

import struct

def mac_str(raw6):
    """
    工具函数：将 6 字节的 bytes 转换为标准的 MAC 地址字符串格式 (如 "00:11:22:33:44:55")
    """
    return ":".join(f"{b:02x}" for b in raw6)

def ipv4_str(raw4):
    """
    工具函数：将 4 字节的 bytes 转换为标准的 IPv4 点分十进制格式 (如 "192.168.1.1")
    """
    return ".".join(str(b) for b in raw4)


def parse_ethernet(data, base_offset=0):
    """
    解析以太网帧头
    支持标准帧，以及带有 802.1Q VLAN Tag 的特殊帧。
    """
    if len(data) < 14: return None
    
    dst, src, eth_type = struct.unpack("!6s6sH", data[:14])
    
    result = {
        "dst_mac": mac_str(dst), "dst_mac_offset": base_offset, "dst_mac_len": 6,
        "src_mac": mac_str(src), "src_mac_offset": base_offset + 6, "src_mac_len": 6,
        "ethertype": eth_type, "ethertype_offset": base_offset + 12, "ethertype_len": 2,
        "payload": data[14:],
    }

   
    # 0x8100 表示存在 VLAN 标签
    # 前 2 字节是 VLAN 优先级和 ID (TCI)，后 2 字节才是真正的上层协议类型。
    # ========================================================
    if eth_type in (0x8100, 0x88A8):  # 0x8100: 802.1Q, 0x88A8: 802.1ad (QinQ)
        if len(data) < 18: return result
        
        # 解析 4 字节的 VLAN 信息
        vlan_tci, inner_eth_type = struct.unpack("!HH", data[14:18])
        
        # 记录 VLAN 信息（方便在 UI 里展示）
        result["vlan_tci"] = vlan_tci
        result["vlan_tci_offset"] = base_offset + 14
        result["vlan_tci_len"] = 2
        
        # 更新为真正的以太网类型 (比如 0x0800 代表 IPv4)
        result["ethertype"] = inner_eth_type
        result["ethertype_offset"] = base_offset + 16
        result["ethertype_len"] = 2
        
        # 跳过 14 字节基础头 + 4 字节 VLAN 头，将真正的 IP 数据包传给上层
        result["payload"] = data[18:] 

    return result

def parse_ipv4(data, base_offset=0):
    """
    【L3 网络层】解析 IPv4 报文头
    基本长度：20 字节（不含选项）
    """
    if len(data) < 20: return None
    
    # 第 1 个字节包含了版本号和头部长度
    ver_ihl = data[0]
    
    #得到版本号
    version = ver_ihl >> 4
    
    # IHL 的单位是 "4字节"
    ihl = (ver_ihl & 0x0F) * 4
    
    if version != 4 or ihl < 20 or len(data) < ihl: return None

    # 解析其他字段：总长度、TTL、上层协议号
    total_len = struct.unpack("!H", data[2:4])[0]  # 第 3~4 字节
    ttl = data[8]       # 第 9 字节
    proto = data[9]     # 第 10 字节 (1=ICMP, 6=TCP, 17=UDP)
    
    src = ipv4_str(data[12:16]) # 第 13~16 字节：源 IP
    dst = ipv4_str(data[16:20]) # 第 17~20 字节：目的 IP

    return {
        "version": version, "version_offset": base_offset, "version_len": 1,
        "ihl": ihl, "ihl_offset": base_offset, "ihl_len": 1,
        "total_len": total_len, "total_len_offset": base_offset + 2, "total_len_len": 2,
        "ttl": ttl, "ttl_offset": base_offset + 8, "ttl_len": 1,
        "proto": proto, "proto_offset": base_offset + 9, "proto_len": 1,
        "src": src, "src_offset": base_offset + 12, "src_len": 4,
        "dst": dst, "dst_offset": base_offset + 16, "dst_len": 4,
        # 剥离 IP 头（根据 IHL 动态计算），剩下的载荷交给传输层
        "payload": data[ihl:], "header_len": ihl,
    }


def parse_tcp(data, base_offset=0):
    """
    传输层  TCP 报文头
    基本长度：20 字节
    """
    if len(data) < 20: return None
    
    # "!HHIIHH" (全部为大端序)
    # H(2B): 源端口, 目的端口 | I(4B): 序列号, 确认号 | H(2B): 偏移+标志, 窗口大小
    sport, dport, seq, ack, offset_flags, window = struct.unpack("!HHIIHH", data[:16])
    
    # TCP 数据偏移量与标志位
    # offset_flags 是 2 字节 。
    # 高 4 位代表 "数据偏移量" ，表示 TCP 头总长度。
    data_offset = (offset_flags >> 12) * 4
    
    # 低 9 位代表控制标志位 (SYN, ACK, FIN 等)。
    # 0x01FF 的二进制是 1 1111 1111，按位与即可取出这 9 个标志位。
    flags = offset_flags & 0x01FF
    
    return {
        "sport": sport, "sport_offset": base_offset, "sport_len": 2,
        "dport": dport, "dport_offset": base_offset + 2, "dport_len": 2,
        "seq": seq, "seq_offset": base_offset + 4, "seq_len": 4,
        "ack": ack, "ack_offset": base_offset + 8, "ack_len": 4,
        "flags": flags, "flags_offset": base_offset + 12, "flags_len": 1,
        "window": window, "window_offset": base_offset + 14, "window_len": 2,
        "data_offset": data_offset, 
        # 剥离 TCP 头，剩下的就是应用层数据 (Data / Payload)
        "payload": data[data_offset:],
    }


def parse_udp(data, base_offset=0):
    """
    【L4 传输层】解析 UDP 报文头
    固定长度：8 字节
    """
    if len(data) < 8: return None
    # "!HHHH"：源端口(2)、目的端口(2)、长度(2)、校验和(2)
    sport, dport, length, checksum = struct.unpack("!HHHH", data[:8])
    return {
        "sport": sport, "sport_offset": base_offset, "sport_len": 2,
        "dport": dport, "dport_offset": base_offset + 2, "dport_len": 2,
        "length": length, "length_offset": base_offset + 4, "length_len": 2,
        "checksum": checksum, "checksum_offset": base_offset + 6, "checksum_len": 2,
        "payload": data[8:],
    }


def parse_icmp(data, base_offset=0):
    """
    【L4 传输层】解析 ICMP 报文头 (常用于 Ping 命令)
    基本长度：4 字节
    """
    if len(data) < 4: return None
    # "!BBH"：类型(1)、代码(1)、校验和(2)
    icmp_type, code, checksum = struct.unpack("!BBH", data[:4])
    return {
        "type": icmp_type, "type_offset": base_offset, "type_len": 1,
        "code": code, "code_offset": base_offset + 1, "code_len": 1,
        "checksum": checksum, "checksum_offset": base_offset + 2, "checksum_len": 2,
        "payload": data[4:],
    }

def parse_arp(data, base_offset=0):
    """
    【L2.5 地址解析协议】解析 ARP 报文
    固定长度：28 字节
    """
    if len(data) < 28: return None
    
    # "!HHBBH6s4s6s4s"
    # 2B硬件类型, 2B协议类型, 1B硬件长度, 1B协议长度, 2B操作码
    # 6B发送方MAC, 4B发送方IP, 6B目标MAC, 4B目标IP
    htype, ptype, hlen, plen, opcode, src_mac, src_ip, dst_mac, dst_ip = struct.unpack("!HHBBH6s4s6s4s", data[:28])
    
    return {
        "htype": htype, "htype_offset": base_offset, "htype_len": 2,
        "ptype": ptype, "ptype_offset": base_offset + 2, "ptype_len": 2,
        "hlen": hlen, "hlen_offset": base_offset + 4, "hlen_len": 1,
        "plen": plen, "plen_offset": base_offset + 5, "plen_len": 1,
        "opcode": opcode, "opcode_offset": base_offset + 6, "opcode_len": 2,
        "src_mac": mac_str(src_mac), "src_mac_offset": base_offset + 8, "src_mac_len": 6,
        "src_ip": ipv4_str(src_ip), "src_ip_offset": base_offset + 14, "src_ip_len": 4,
        "dst_mac": mac_str(dst_mac), "dst_mac_offset": base_offset + 18, "dst_mac_len": 6,
        "dst_ip": ipv4_str(dst_ip), "dst_ip_offset": base_offset + 24, "dst_ip_len": 4,
    }

def parse_packet(raw):
    """
    【总控入口】逐层解包
    负责处理特殊网卡的包头差异，并调度底层的各个解析函数。
    """
    result = {}
    ip_data = None
    ip_base_offset = 0

    # ========================================================
    # 在 Windows 下抓取本地回环 (Loopback, 127.0.0.1) 流量时，Npcap 驱动会在原始 IP 包
    # 前面强行加上 4 个字节的假以太网头（通常为 02 00 00 00）。
    # 必须识别出它并跳过这 4 个字节，否则后面的 IP 解析全错位。
    # ========================================================
    if len(raw) >= 4 and raw[0:4] == b'\x02\x00\x00\x00':
        ip_data = raw[4:]
        ip_base_offset = 4
        
    # 如果发现是没有以太网头的纯 IP 包 (第一个字节高 4 位是 4)
    elif len(raw) >= 20 and (raw[0] >> 4) == 4:
        ip_data = raw
        ip_base_offset = 0
        
    # 正常的物理网卡捕获到的标准以太网帧
    elif len(raw) >= 14:
        eth = parse_ethernet(raw, 0)
        if eth:
            result["ethernet"] = eth
            # ARP 协议
            if eth["ethertype"] == 0x0806:
                arp = parse_arp(eth["payload"], 14)
                if arp: result["arp"] = arp
                return result
            # 如果不是 IPv4 协议，就不继续往下解了
            elif eth["ethertype"] != 0x0800:
                return result
            ip_data = eth["payload"]
            ip_base_offset = 14
        else:
            return result
    else:
        return result

    # 开始逐层深入
    if ip_data:
        ip = parse_ipv4(ip_data, ip_base_offset)
        if not ip: return result
        result["ipv4"] = ip

        # 计算传输层数据的起始绝对位置
        trans_data = ip["payload"]
        trans_base_offset = ip_base_offset + ip["header_len"]

        # 根据 IP 头里的 Protocol 字段 (1=ICMP, 6=TCP, 17=UDP) 分发给对应的解析器
        if ip["proto"] == 6:
            tcp = parse_tcp(trans_data, trans_base_offset)
            if tcp: result["tcp"] = tcp
        elif ip["proto"] == 17:
            udp = parse_udp(trans_data, trans_base_offset)
            if udp: result["udp"] = udp
        elif ip["proto"] == 1:
            icmp = parse_icmp(trans_data, trans_base_offset)
            if icmp: result["icmp"] = icmp

    return result


def summarize(result):
    """
    控制台调试用：将解析结果提取为单行摘要字符串
    """
    if not result: return "parse failed"
    ip = result.get("ipv4")
    if not ip: return "Non-IPv4"
    
    base = f"{ip['src']} -> {ip['dst']}"
    if "tcp" in result: 
        return f"{base} | TCP {result['tcp']['sport']}->{result['tcp']['dport']}"
    if "udp" in result: 
        return f"{base} | UDP {result['udp']['sport']}->{result['udp']['dport']}"
    if "icmp" in result: 
        return f"{base} | ICMP type={result['icmp']['type']}"
    return base