from scapy.all import sniff, ARP, IP, Ether, wrpcap, srp
from colorama import Fore

#Get deatails about the src and the dst (IP address or MAC)
def packet_deatails(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        return ip_layer.src, ip_layer.dst
    if packet.haslayer(Ether):
        ether_layer = packet.getlayer(Ether)
        return ether_layer.src, ether_layer.dst
    return None,None

#Get Mac address of the ip adress
def get_mac(ip_address):
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address)
    reply, _ = srp(arp_request,timeout=3,verbose=0)
    if reply:
        return reply[0][1].src
    return None

#Filter the packets by address that is given with the packet
#Function for every packet that is captured
def packet_handle(packet,ip_address):
    SRC,DST = packet_deatails(packet)
    if ip_address == SRC or ip_address == DST:
        print(Fore.GREEN+packet.summary())
    elif get_mac(ip_address) == SRC or get_mac(ip_address) == DST:
        print(Fore.BLUE+packet.summary())

#Function to input ip adress to sniff and start the packet_handler function        
def packet_handle_booter(packet):
    ip_address = "192.168.1.22"
    packet_handle(packet,ip_address)
   
#start sniffing packets until KeyboardInterrupt 
try:
    packets = sniff(prn=packet_handle_booter)
except KeyboardInterrupt:
    print("sniffing complete")
    
#Save the packets that are captured    
wrpcap('attack1.pcap',packets)