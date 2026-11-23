# =========================================================
# 强制 Scapy 使用 Npcap 后端
# =========================================================
from scapy.all import conf
conf.use_pcap = True
conf.use_npcap = True

from scapy.all import sniff, IP
# 注意这里改成 packet_parser
from packet_parser import parse_packet, summarize

def handle(pkt):
    if IP not in pkt:
        return
    raw = bytes(pkt)
    result = parse_packet(raw)
    print(summarize(result))

if __name__ == "__main__":
    # 填入对应 10.207.60.246 的 NPF 路径
    iface_path = r"\Device\NPF_{6832C14C-A3F7-4006-A7E6-6C235AC9A90C}"
    
    print(f"[*] sniffing 10 packets on {iface_path} ...")
    print("[*] 请另开一个窗口 ping baidu.com 产生流量...")
    
    sniff(iface=iface_path, prn=handle, count=10, store=False)
    
    print("[*] done")