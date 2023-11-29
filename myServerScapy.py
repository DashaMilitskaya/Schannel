from scapy.all import *


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

def serverRetransimitUdpPacket(packet):
    if packet.haslayer(Ether):
        if(packet[Ether].src != userMAC):
            return
        if(packet[Ether].src == Ether().src):
            return
    
    if packet.haslayer(UDP): 
        if packet.haslayer(Raw):
            user_packet = packet[Raw].load
            try:
                scapy_user_packet = Ether(user_packet)
            except struct.error:
                return
            else:
                #scapy_user_packet.show()
                sendPacketByServer(scapy_user_packet)
            
                       
def serverRetransmitToUser(packet):
    if packet.haslayer(Ether):
        if(packet[Ether].src == userMAC):
            return
        if(packet[Ether].src == Ether().src):
            return
    retransmitToUser(packet)    

def serverRetransmit(packet):
    serverRetransimitUdpPacket(packet)
    serverRetransmitToUser(packet)
 
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
print(Ether().src)

while(userIP == 0):
    sniff(prn=getUserMacAndIp, count=10)
    print(userIP)
    print(userMAC)


sniff(prn=serverRetransmit)
