
#include "udp.h"
static unsigned short compute_checksum(unsigned short* addr, unsigned int count) {
		/* Compute Internet Checksum for "count" bytes
		 * beginning at location "addr".
		 */
		register long sum = 0;

		while (count > 1) {
			/* This is the inner loop */
			sum += *(unsigned short*)addr++;
			count -= 2;
		}

		/*  Add left-over byte, if any */
		if (count > 0)
			sum += *(unsigned char*)addr;

		/*  Fold 32-bit sum to 16 bits */
		while (sum >> 16)
			sum = (sum & 0xffff) + (sum >> 16);

		unsigned short checksum = ~sum;
		return checksum;
}


uint16_t udp_checksum(PUDP_HEADER p_udp_header, size_t len, void* src_addr, void* dest_addr){
	const uint16_t* buf = (const uint16_t*)p_udp_header;
	uint16_t* ip_src = (uint16_t*)src_addr, * ip_dst = (uint16_t*)dest_addr;
	uint32_t sum;
	size_t length = len;

	// Calculate the sum
	sum = 0;
	while (len > 1)
	{
		sum += *buf++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	if (len & 1)
		// Add the padding if the packet lenght is odd
		sum += *((uint8_t*)buf);

	// Add the pseudo-header
	sum += *(ip_src++);
	sum += *ip_src;

	sum += *(ip_dst++);
	sum += *ip_dst;

	sum += htons(IPPROTO_UDP);
	sum += htons(length);

	// Add the carries
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// Return the one's complement of sum
	return (uint16_t)~sum;
}
void FillUdpPacket(PUDP_PACKET packet, void* srcMAC, void* srcIP, void* dstMAC, void* dstIP, void* body, unsigned short int bodyLength) {
	/*Ethernet*/
	memcpy(packet->ethernet_head.dstMacAddr, dstMAC, MAC_SIZE);
	memcpy(packet->ethernet_head.srcMacAddr, srcMAC, MAC_SIZE);
	packet->ethernet_head.type = htons(0x0800);

	/*IPv4*/
	packet->ipv4_header.headerLength = 5;
	packet->ipv4_header.version = 4;
	packet->ipv4_header.tos = 0x00;

	
	
	packet->ipv4_header.totalLength = htons(20 + 8 + bodyLength);
	packet->ipv4_header.id = htons(0xbfe4);
	packet->ipv4_header.offset = 0x0000;
	packet->ipv4_header.ttl = 0x80;
	packet->ipv4_header.protocol = 0x11;
	packet->ipv4_header.checksum = htons(0x0000);
	
	memcpy(packet->ipv4_header.srcAddressOctet, srcIP, IPv4_SIZE);
	memcpy(packet->ipv4_header.dstAddressOctet, dstIP, IPv4_SIZE);
	packet->ipv4_header.checksum = compute_checksum((USHORT*)&packet->ipv4_header, 20);
	/*UDP*/

	packet->udp_header.srcPort = htons(65230); //3478
	packet->udp_header.dstPort = htons(49152); //8888
	packet->udp_header.Length = htons(8 + bodyLength);
	packet->udp_header.CheckSum = htons(0x0000);
	
	/*data*/
	memcpy(packet->body, body, bodyLength);
	
	/*UDP checksum*/
	packet->udp_header.CheckSum = udp_checksum(&packet->udp_header, 8 + bodyLength, srcIP, dstIP);

	

}