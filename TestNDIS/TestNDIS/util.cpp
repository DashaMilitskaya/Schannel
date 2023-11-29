
#include "util.h"

HANDLE ConnectDevice() {
	const TCHAR* G_DevicePath = DEVICE_NAME;
	HANDLE hdevice = CreateFile(
		G_DevicePath,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);

	if (hdevice == INVALID_HANDLE_VALUE) {
		GetLastError();
		return 0;
	}

	return hdevice;
}

void SendPacket(PVOID packet, ULONG length, HANDLE hdevice) {
	
	PVOID buf = (PVOID)malloc(length);
	memcpy(buf, packet, length);
	SV_SendDriverInfo(hdevice, buf, length, IOCTL_FILTER_SEND_ETHERNET_FRAME);
	free(buf);
}

void SendVPNConfig(HANDLE hdevice, void* netServerIp, void* srcIp, void* srcMAC, void* gatewayIP) {

	DWORD size = 4 + 4 + 6 + 4;
	PUCHAR SetConfig = (PUCHAR)malloc(size);
	if (SetConfig) {
		memcpy(SetConfig, netServerIp, 4);
		memcpy(SetConfig + 4, srcIp, 4);
		memcpy(SetConfig + 8, srcMAC, 6);
		memcpy(SetConfig + 14, gatewayIP, 4);
		SV_SendDriverInfo(hdevice, SetConfig, size, IOCTL_FILTER_SET_VPN_CONFIG);
		free(SetConfig);
	}

}


PVOID GetServerMAC(HANDLE hdevice) {

	PVOID arp = (PVOID)malloc(6);

	DWORD rlen = SV_GetDriverInfo(hdevice, arp, 6, IOCTL_FILTER_GET_SERVER_ARP);
	if (rlen == 6) return arp;
	return nullptr;

}