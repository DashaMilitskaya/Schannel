
#include "arp.h"




void GetIpBitsFromString(const char* IP, void* ip_bit) {
   
    unsigned long ip_bits_4;

    struct sockaddr_in antelope;

    
    inet_pton(AF_INET,  IP, &(antelope.sin_addr));

    ip_bits_4 = antelope.sin_addr.s_addr;

    memcpy(ip_bit, &ip_bits_4, sizeof(unsigned long));


}


PIP_ADAPTER_INFO GetAdapterById(DWORD id) {
    PIP_ADAPTER_INFO AdapterInfo;
    DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);

    AdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));


    // Make an initial call to GetAdaptersInfo to get the necessary size into the dwBufLen variable
    if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(AdapterInfo);
        AdapterInfo = (IP_ADAPTER_INFO*)malloc(dwBufLen);

    }

    if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
        // Contains pointer to current adapter info
        PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
        do {
            if (pAdapterInfo->Index = id) {
                printf("set adapter ... \n");
                PIP_ADAPTER_INFO info = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
                if (info == 0) break;
                memcpy(info, pAdapterInfo, sizeof(IP_ADAPTER_INFO));
                free(AdapterInfo);
                return info;
            }
            pAdapterInfo = pAdapterInfo->Next;
        } while (pAdapterInfo);
    }
    free(AdapterInfo);
    return NULL; 
}


void ListAdapters() {
    
    PIP_ADAPTER_INFO AdapterInfo;
    DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);

    AdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));


    // Make an initial call to GetAdaptersInfo to get the necessary size into the dwBufLen variable
    if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(AdapterInfo);
        AdapterInfo = (IP_ADAPTER_INFO*)malloc(dwBufLen);

    }

    if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
        // Contains pointer to current adapter info
        PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
        do {
           
            printf("Index: %d, Adapter name: %s", pAdapterInfo->Index, pAdapterInfo->AdapterName);

            printf("Ip Address: %s, Get %s, mac: ", pAdapterInfo->IpAddressList.IpAddress.String, 
                                                      pAdapterInfo->GatewayList.IpAddress.String);
            printf("%02X:%02X:%02X:%02X:%02X:%02X",
                pAdapterInfo->Address[0], pAdapterInfo->Address[1],
                pAdapterInfo->Address[2], pAdapterInfo->Address[3],
                pAdapterInfo->Address[4], pAdapterInfo->Address[5]);

            printf("\n");
            pAdapterInfo = pAdapterInfo->Next;
        } while (pAdapterInfo);
    }
    free(AdapterInfo);
    return; 
}




std::pair<void*, void*> Adapter_MAC_IP_bits(PIP_ADAPTER_INFO pAdapterInfo) {
    
    char* ip_addr = (char*)malloc(4);
    char* mac_bit = (char*)malloc(6);
    if (ip_addr && mac_bit) {
        memcpy(mac_bit, pAdapterInfo->Address, 6);
        GetIpBitsFromString(pAdapterInfo->IpAddressList.IpAddress.String, ip_addr);
  // GetIpBitsFromString(pAdapterInfo->GatewayList.IpAddress.String, ip_addr);
   }
   
   return std::make_pair(mac_bit, ip_addr); // caller must free.
}

/*TO_DO htons()*/

void FillArpRequest(PARP_PACKET buf, void* targetIP, void* senderMac, void* senderIP) {

    buf->preambule[0] = 0x18;
    buf->preambule[1] = 0xe1;
    memset(buf->preambule + 2, 0x00, 6);

	memset(buf->ethernet_head.dstMacAddr, 0xff, 6);
    memcpy(buf->ethernet_head.srcMacAddr, senderMac, 6);
    buf->ethernet_head.type = ETHERNET_PROTOCOL_ARP;

    buf->arp.header.htype = 0x0100;
    buf->arp.header.ptype = 0x0008;
    buf->arp.header.hlen = 0x06;
    buf->arp.header.plen = 0x04;
    buf->arp.header.oper = 0x0100; //request

    memcpy(buf->arp.sha, senderMac, 6);
    memcpy(buf->arp.spa, senderIP, 4);
    memset(buf->arp.tha, 0x00, 6);
    memcpy(buf->arp.tpa, targetIP, 4);
	
	
}

void FillArpRepli(PARP_PACKET buf, void* targetIP, void* targetMAC, void* senderMac, void* senderIP) {
    buf->preambule[0] = 0x18;
    buf->preambule[1] = 0xe1;
    memset(buf->preambule + 2, 0x00, 6);

    memcpy(buf->ethernet_head.dstMacAddr, targetMAC, 6);
    memcpy(buf->ethernet_head.srcMacAddr, senderMac, 6);
    buf->ethernet_head.type = ETHERNET_PROTOCOL_ARP;

    buf->arp.header.htype = 0x0100;
    buf->arp.header.ptype = 0x0008;
    buf->arp.header.hlen = 0x06;
    buf->arp.header.plen = 0x04;
    buf->arp.header.oper = 0x0200; //reply

    memcpy(buf->arp.sha, senderMac, 6);
    memcpy(buf->arp.spa, senderIP, 4);
    memcpy(buf->arp.tha, targetMAC, 6);
    memcpy(buf->arp.tpa, targetIP, 4);
}


