#include "precomp.h"
#include "frameStructs.h"

BOOLEAN SniffedPacket(PUCHAR frame, ULONG frameSize) {
    if (frameSize < sizeof(ETHERNET_HEADER)) 
        return FALSE;
    PETHERNET_FRAME etherFrame = (PETHERNET_FRAME)frame;
    if (!MmIsAddressValid(frame)) return FALSE;
    /*DbgPrint("packet %02X-%02X-%02X-%02X-%02X-%02X -> %02X-%02X-%02X-%02X-%02X-%02X  size: %u\n",
        etherFrame->header.srcMacAddr[0], etherFrame->header.srcMacAddr[1],
        etherFrame->header.srcMacAddr[2], etherFrame->header.srcMacAddr[3],
        etherFrame->header.srcMacAddr[2], etherFrame->header.srcMacAddr[5],
        etherFrame->header.dstMacAddr[0], etherFrame->header.dstMacAddr[1],
        etherFrame->header.dstMacAddr[2], etherFrame->header.dstMacAddr[3],
        etherFrame->header.dstMacAddr[4], etherFrame->header.dstMacAddr[5],
        frameSize);*/

    switch (HTONS(etherFrame->header.type)) {
    case ETHERNET_PROTOCOL_IP:
    {   
        if (frameSize < sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER)) 
            break;
        IPV4_PACKET* ip = (IPV4_PACKET*)&etherFrame->body;
        if (!MmIsAddressValid(ip)) break;
        /*DbgPrint("ip %d.%d.%d.%d -> %d.%d.%d.%d\n",
            ip->header.srcAddressOctet[0], ip->header.srcAddressOctet[1],
            ip->header.srcAddressOctet[2], ip->header.srcAddressOctet[3],
            ip->header.dstAddressOctet[0], ip->header.dstAddressOctet[1],
            ip->header.dstAddressOctet[2], ip->header.dstAddressOctet[3]);*/
        if (ip->header.protocol == IP_PROTOCOL_TCP) {
            unsigned int dataSize;
           // unsigned char* data;
            if (frameSize < sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER)+sizeof(TCP_HEADER))
                break;
            TCP_HEADER* tcp = (TCP_HEADER*)((PUCHAR)ip + (4 * (ULONG_PTR)ip->header.headerLength));
            if (!MmIsAddressValid(tcp)) break;
            //DbgPrint("%d %d %d\n", HTONS(ip->header.totalLength), 4 * ip->header.headerLength, TCP_DATA_OFFSET(tcp));
            dataSize = (HTONS(ip->header.totalLength) - 4 * ip->header.headerLength - TCP_DATA_OFFSET(tcp));
            dataSize = min(dataSize, 100);
            //data = (unsigned char*)tcp + (ULONG_PTR)TCP_DATA_OFFSET(tcp);
            //DbgPrint("tcp %d -> %d\n", HTONS(tcp->srcPort), HTONS(tcp->dstPort));
        }
        break;
    }
    case ETHERNET_PROTOCOL_ARP:
    {
        if (frameSize < sizeof(ETHERNET_HEADER) + sizeof(ARP_ETHER_HEADER))
            break;
        PARP_ETHER_HEADER arpFrame = (PARP_ETHER_HEADER)&etherFrame->body;
        if (!MmIsAddressValid(arpFrame)) break;
        //DbgBreakPoint();
        if (arpFrame->header.oper == HTONS(1)) {
            DbgPrint("arp request %d.%d.%d.%d",
                arpFrame->tpa[0], arpFrame->tpa[1], arpFrame->tpa[2], arpFrame->tpa[3]);
        }
        else {
            DbgPrint("arp answer %d.%d.%d.%d",
              
                arpFrame->spa[0], arpFrame->spa[1], arpFrame->spa[2], arpFrame->spa[3]);
            
            if (glIsConfigSet) {

           
            
            if ((arpFrame->spa[0] == glGatewayIP[0]) && (arpFrame->spa[1] == glGatewayIP[1]) && (arpFrame->spa[2] == glGatewayIP[2]) && ((arpFrame->spa[3] == glGatewayIP[3]))) {
                BOOLEAN                     bFalse = FALSE;
                FILTER_ACQUIRE_LOCK(&glMacMutex, bFalse);
                memcpy(glServerMac, arpFrame->sha, 6);
                FILTER_RELEASE_LOCK(&glMacMutex, bFalse);
                

               
            } 
            }
            
        }
        return TRUE;
    }
    }

    return FALSE;
}

BOOLEAN IsPassSendPacket(PUCHAR frame, ULONG frameSize) {
    DbgPrint("IsPassSendPacket");
    if (frameSize < sizeof(ETHERNET_HEADER))
        return FALSE;
    PETHERNET_FRAME etherFrame = (PETHERNET_FRAME)frame;
    if (!MmIsAddressValid(frame)) return FALSE;
    DbgPrint("packet %02X-%02X-%02X-%02X-%02X-%02X -> %02X-%02X-%02X-%02X-%02X-%02X  size: %u\n",
        etherFrame->header.srcMacAddr[0], etherFrame->header.srcMacAddr[1],
        etherFrame->header.srcMacAddr[2], etherFrame->header.srcMacAddr[3],
        etherFrame->header.srcMacAddr[2], etherFrame->header.srcMacAddr[5],
        etherFrame->header.dstMacAddr[0], etherFrame->header.dstMacAddr[1],
        etherFrame->header.dstMacAddr[2], etherFrame->header.dstMacAddr[3],
        etherFrame->header.dstMacAddr[4], etherFrame->header.dstMacAddr[5],
        frameSize);

    switch (HTONS(etherFrame->header.type)) {
    case ETHERNET_PROTOCOL_IP:
    {
        if (frameSize < sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER))
            break;
        IPV4_PACKET* ip = (IPV4_PACKET*)&etherFrame->body;
        if (!MmIsAddressValid(ip)) break;
        /*DbgPrint("ip %d.%d.%d.%d -> %d.%d.%d.%d\n",
            ip->header.srcAddressOctet[0], ip->header.srcAddressOctet[1],
            ip->header.srcAddressOctet[2], ip->header.srcAddressOctet[3],
            ip->header.dstAddressOctet[0], ip->header.dstAddressOctet[1],
            ip->header.dstAddressOctet[2], ip->header.dstAddressOctet[3]);*/
        if (ip->header.protocol == IP_PROTOCOL_TCP) {
            unsigned int dataSize;
            // unsigned char* data;
            if (frameSize < sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER) + sizeof(TCP_HEADER))
                break;
            TCP_HEADER* tcp = (TCP_HEADER*)((PUCHAR)ip + (4 * (ULONG_PTR)ip->header.headerLength));
            if (!MmIsAddressValid(tcp)) break;
            //DbgPrint("%d %d %d\n", HTONS(ip->header.totalLength), 4 * ip->header.headerLength, TCP_DATA_OFFSET(tcp));
            dataSize = (HTONS(ip->header.totalLength) - 4 * ip->header.headerLength - TCP_DATA_OFFSET(tcp));
            dataSize = min(dataSize, 100);
            //data = (unsigned char*)tcp + (ULONG_PTR)TCP_DATA_OFFSET(tcp);
            //DbgPrint("tcp %d -> %d\n", HTONS(tcp->srcPort), HTONS(tcp->dstPort));
        }
        break;
    }

    case ETHERNET_PROTOCOL_ARP:
    {
        DbgPrint("To ARP send");
        return TRUE;
        
       
    }
    }

    return FALSE;


}

BOOLEAN IsEqualIP(PUCHAR IP_a, PUCHAR IP_b) {
    if ((IP_a[0] == IP_b[0]) && (IP_a[1] == IP_b[1]) && (IP_a[2] == IP_b[2]) && (IP_a[3] == IP_b[3])) {
        return TRUE;
    }
    return FALSE;
}