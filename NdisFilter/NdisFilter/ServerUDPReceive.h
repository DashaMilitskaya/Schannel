#pragma once
#include "udp.h"
#include "crypt.h"

extern PUCHAR glServerIP;

PVOID GetDataUdpFromServer(
    PMDL PacketMdl,
    ULONG PacketSize,
    ULONG_PTR DataOffset,
    PULONG dataLength);