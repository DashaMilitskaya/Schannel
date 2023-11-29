#pragma once
#include <Windows.h>



//*************************************************************


#define ETHERNET_PROTOCOL_IP    0x0800


typedef UCHAR MAC_ADDRESS[6];

#pragma pack(1)
typedef struct _ETHERNET_HEADER {

    MAC_ADDRESS dstMacAddr;
    MAC_ADDRESS srcMacAddr;
    USHORT type;

} ETHERNET_HEADER, * PETHERNET_HEADER;
#pragma pack(1)
typedef struct _ETHERNET_FRAME {

    ETHERNET_HEADER header;
    char body[1];

} ETHERNET_FRAME, * PETHERNET_FRAME;

#define MAX_ETHERNET_PACKET_SIZE   1500
#define MAC_SIZE 6
#define IPv4_SIZE 4

#pragma pack(1)
typedef struct _ARP_HEADER {

    unsigned short int htype;       /* Код канального протокола */
    unsigned short int ptype;       /* Код сетевого протокола */
    unsigned char hlen;             /* Длина физического адреса в байтах */
    unsigned char plen;             /* Длина логического адреса в байтах */
    unsigned short int oper;        /* Код операции */

} ARP_HEADER, * PARP_HEADER;
#pragma pack()



#pragma pack(1)
typedef struct _ARP_ETHER_HEADER {

    ARP_HEADER header;
    unsigned char sha[6];
    unsigned char spa[4];
    unsigned char tha[6];
    unsigned char tpa[4];

} ARP_ETHER_HEADER, * PARP_ETHER_HEADER;
#pragma pack()



#define IP_PROTOCOL_ICMP    1
#define IP_PROTOCOL_IGMP    2
#define IP_PROTOCOL_IPV4    4
#define IP_PROTOCOL_TCP     6
#define IP_PROTOCOL_EGP     8
#define IP_PROTOCOL_IGP     9
#define IP_PROTOCOL_UDP     17


#pragma pack(1)
typedef struct _IPV4_HEADER {

    unsigned char headerLength : 4;
    unsigned char version : 4;
    unsigned char tos;
    unsigned short int totalLength;
    unsigned short int id;
    unsigned short int offset;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short int checksum;
    union {
        unsigned int srcAddress;
        unsigned char srcAddressOctet[4];
    };
    union {
        unsigned int dstAddress;
        unsigned char dstAddressOctet[4];
    };
} IPV4_HEADER;
#pragma pack()


#pragma pack(1)
typedef struct _IPV4_PACKET {

    IPV4_HEADER header;
    unsigned char body[1];

} IPV4_PACKET;
#pragma pack()



#pragma pack(1)
typedef struct _TCP_HEADER {
    unsigned short srcPort;
    unsigned short dstPort;
    unsigned int   sequenceNumber;
    unsigned int   ackNumber;
    unsigned char  dataOffset;
#define TCP_DATA_OFFSET(th)  (4 * (((th)->dataOffset & 0xf0) >> 4))
    union {
        unsigned char   flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECNECHO  0x40    /* ECN Echo */
#define TH_CWR      0x80    /* ECN Cwnd Reduced */
        struct {
            unsigned char fin : 1;
            unsigned char syn : 1;
            unsigned char rst : 1;
            unsigned char psh : 1;
            unsigned char ack : 1;
            unsigned char urg : 1;
            unsigned char ecn : 1;
            unsigned char cwr : 1;
        };
    };

    unsigned short windowSize;
    unsigned short checksum;
    unsigned short urgpointer;
} TCP_HEADER;
#pragma pack()

#pragma pack(1)
typedef struct _TCP_PACKET {

    TCP_HEADER header;
    unsigned char body[1];

} TCP_PACKET;
#pragma pack()


//*************************************************************


#define INETADDR(a, b, c, d)    (a + (b << 8) + (c << 16) + (d << 24))
#define HTONL(a)    (((a&0xFF)<<24) + ((a&0xFF00)<<8) + ((a&0xFF0000)>>8) + ((a&0xFF000000)>>24)
#define HTONS(a)    (((a&0xFF)<<8) + ((a&0xFF00)>>8))


VOID SniffedPacket(PUCHAR frame, ULONG frameSize);