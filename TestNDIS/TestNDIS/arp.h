#pragma once


#include <Ws2tcpip.h>
#include <string>
#include <Iphlpapi.h>
#include <Assert.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment (lib,"Ws2_32.lib")
#include "frameStructs.h"

#define ETHERNET_PROTOCOL_ARP   0x0608


#pragma pack(1)
typedef struct _ARP_PACKET
{
	BYTE preambule[8];
	ETHERNET_HEADER ethernet_head;
	ARP_ETHER_HEADER arp;

}ARP_PACKET, *PARP_PACKET;
#pragma pack()

void GetIpBitsFromString(const char* IP, void* ip_bit);
std::pair<void*, void*> Adapter_MAC_IP_bits(PIP_ADAPTER_INFO pAdapterInfo);
void FillArpRequest(PARP_PACKET buf, void* targetIP, void* senderMac, void* senderIP);
void FillArpRepli(PARP_PACKET buf, void* targetIP, void* targetMAC, void* senderMac, void* senderIP);
void ListAdapters();
PIP_ADAPTER_INFO GetAdapterById(DWORD id);
