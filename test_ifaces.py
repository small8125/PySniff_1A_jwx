from scapy.all import get_if_list, get_if_addr
for i in get_if_list():
    print(f"{i} | {get_if_addr(i)}")