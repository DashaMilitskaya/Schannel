#pragma once
#include "frameStructs.h"


typedef unsigned char BYTE;
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;

#pragma pack(1)
typedef struct _UDP_HEADER {
	unsigned short int srcPort;
	unsigned short int dstPort;
	unsigned short int Length;
	unsigned short int CheckSum;

}UDP_HEADER, * PUDP_HEADER;
#pragma pack()

#pragma pack(1)
typedef struct _UDP_PACKET {

	//BYTE preambule[8];
	ETHERNET_HEADER ethernet_head;
	IPV4_HEADER ipv4_header;
	UDP_HEADER udp_header;
	unsigned char body[1];
}UDP_PACKET, * PUDP_PACKET;
#pragma pack()

uint16_t udp_checksum(PUDP_HEADER p_udp_header, size_t len, void* src_addr, void* dest_addr);
void FillUdpPacket(PUDP_PACKET packet, void* srcMAC, void* srcIP, void* dstMAC, void* dstIP, void* body, unsigned short int bodyLength);