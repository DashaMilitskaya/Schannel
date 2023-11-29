

#include "ServerUDPReceive.h"
#include "precomp.h"
VOID* TransmitFromMdlToPayload(
    PMDL PacketMdl,
    ULONG PacketSize,
    ULONG_PTR DataOffset) {

    PUCHAR packet = (PUCHAR)ExAllocatePool(NonPagedPoolNx, PacketSize);
    PMDL mdlList = PacketMdl;
    if (packet == 0)
        return NULL;

    ULONG count = 0;
    ULONG size = PacketSize;
    while (mdlList && size) {

        __try {

            MmProbeAndLockPages(PacketMdl, KernelMode, IoReadAccess);

            PUCHAR PacketData = (UCHAR*)MmGetSystemAddressForMdlSafe(mdlList, NormalPagePriority);

            if (!MmIsAddressValid(PacketData)) {
                ExFreePool(packet);
                return NULL;
            }

            if (count == 0) {
                PacketData += DataOffset;
                memcpy(packet, PacketData, MmGetMdlByteCount(mdlList) - DataOffset);
                size = size - (MmGetMdlByteCount(mdlList) - (ULONG)DataOffset);
            }
            else {
                if (size <= MmGetMdlByteCount(mdlList)) {
                    memcpy(packet + (PacketSize - size), PacketData, size);
                    size = 0;
                    break;
                }
                else {
                    memcpy(packet + (PacketSize - size), PacketData, MmGetMdlByteCount(mdlList));
                    size = size - MmGetMdlByteCount(mdlList);
                }


            }

            mdlList = mdlList->Next;
            count++;


        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            ExFreePool(packet);
            return NULL;
        }
        MmUnlockPages(PacketMdl);
    }
    
   
    return packet;

}

PVOID GetDataBuffer(PUDP_PACKET packet, ULONG PacketSize, PULONG dataLength) {
    
    USHORT lenght = htons(packet->udp_header.Length);
    lenght = lenght - sizeof(UDP_HEADER);
    if (lenght > PacketSize - sizeof(UDP_PACKET) + 1) 
        return NULL;
    PVOID data = (PUCHAR)ExAllocatePool(NonPagedPoolNx, lenght);
    if (data == NULL) return NULL;
    RtlCopyMemory(data, &packet->body, lenght);
    *dataLength = lenght;
    cryptInterfaceDecode(data, lenght, "pacman", 6);
    return data;

}


PVOID GetDataUdpFromServer(
    PMDL PacketMdl,
    ULONG PacketSize,
    ULONG_PTR DataOffset,
    PULONG dataLength) {


    if (PacketSize < sizeof(UDP_PACKET)) return NULL;

    PUDP_PACKET packet = TransmitFromMdlToPayload(PacketMdl, PacketSize, DataOffset);
    if (packet == NULL) return NULL;
    
    if (
        (HTONS(packet->ethernet_head.type) != ETHERNET_PROTOCOL_IP) ||
        (IsEqualIP(glServerIP, (PUCHAR)(&packet->ipv4_header.srcAddress))==FALSE) ||
        ((packet->ipv4_header.protocol) != IP_PROTOCOL_UDP)
        )
    { 
        
        ExFreePool(packet);
        return NULL;
    
    }
   
   

    PVOID data = GetDataBuffer(packet, PacketSize, dataLength);
    ExFreePool(packet);
    return data;
    

}