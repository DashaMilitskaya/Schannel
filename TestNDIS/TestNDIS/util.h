#pragma once
#include "io_controller.h"
#include "filteruser.h"


#define DEVICE_NAME L"\\\\.\\NdisFilter"


HANDLE ConnectDevice();
void SendPacket(PVOID packet, ULONG length, HANDLE hdevice);
void SendVPNConfig(HANDLE hdevice, void* netServerIp, void* srcIp, void* srcMAC, void* gatewayIP);
PVOID GetServerMAC(HANDLE hdevice);