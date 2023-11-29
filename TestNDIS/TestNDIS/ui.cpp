#include "ui.h"


int Reconnect(PIP_ADAPTER_INFO AdapterInfo, std::string& serverIp) {

	if (AdapterInfo == NULL) {
		std::cout << "Adapter Info not found. Use adapter command to set it.\n";
		return 0;
	} 

	HANDLE hdevice = ConnectDevice();

	if (hdevice == NULL) {
		std::cout << "ERR: cannot open device\n";
		return 0;
	}

	PARP_PACKET arp_request = (PARP_PACKET)malloc(sizeof(ARP_PACKET));
	void* SERVER_IP_BITS = malloc(4);
	if (SERVER_IP_BITS == 0)
		return 0;
	void* GATEWAY_IP_BITS = malloc(4);
	if (GATEWAY_IP_BITS == 0) {
		free(SERVER_IP_BITS);
		return 0;
	}
	std::pair<void*, void*>mac_ip = Adapter_MAC_IP_bits(AdapterInfo);
	

	/*
	Renew Driver Config
	*/
	GetIpBitsFromString(AdapterInfo->GatewayList.IpAddress.String, GATEWAY_IP_BITS); //real server
	GetIpBitsFromString(serverIp.c_str(), SERVER_IP_BITS); //real server
	SendVPNConfig(hdevice, SERVER_IP_BITS, mac_ip.second, mac_ip.first, GATEWAY_IP_BITS);


	/*	
	Gateway MAC
	*/
	
	FillArpRequest(arp_request, GATEWAY_IP_BITS, mac_ip.first, mac_ip.second);
	SendPacket(arp_request, sizeof(ARP_PACKET), hdevice);
	Sleep(1000);
	PUCHAR GatewayMAC = (PUCHAR)GetServerMAC(hdevice);
	printf(" Gateway MAC: %02X-%02X-%02X-%02X-%02X-%02X \n", GatewayMAC[0], GatewayMAC[1], GatewayMAC[2],
		GatewayMAC[3], GatewayMAC[4], GatewayMAC[5]);


	/*
	Evil Message to connect client
	*/
	int body_len = 5;
	unsigned short int packet_size = sizeof(UDP_PACKET) + body_len - 1;
	PUDP_PACKET packet = (PUDP_PACKET)malloc(packet_size);
	void* body = malloc(5);
	memcpy(body, "evil\n", 5);
	FillUdpPacket(packet, mac_ip.first, mac_ip.second, GatewayMAC, SERVER_IP_BITS, body, body_len);
	SendPacket(packet, packet_size, hdevice);
	Sleep(1000);
	

	free(SERVER_IP_BITS);
	free(GATEWAY_IP_BITS);
	free(mac_ip.first);
	free(mac_ip.second);
	free(GatewayMAC);
	return 0;
}


int UI_Processing() {
	HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(console, FOREGROUND_INTENSITY | FOREGROUND_RED);
	PIP_ADAPTER_INFO AdapterInfo = NULL;
	std::string serverIP("10.0.0.2");
	printf("*********************>\n\n\n UDP trafick retransmitter \n\n\n <********************* \n\n\n");


	std::string inputCommand;
	
	while (1) {
		SetConsoleTextAttribute(console, FOREGROUND_INTENSITY | FOREGROUND_GREEN);
		printf("config>");
		SetConsoleTextAttribute(console, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
		std::cin >> inputCommand;
		if (inputCommand._Equal("list"))
			ListAdapters();

		if (inputCommand._Equal("reconnect"))
			Reconnect(AdapterInfo, serverIP);
		
		if (inputCommand._Equal("adapter")) {
			DWORD id;
			SetConsoleTextAttribute(console, FOREGROUND_INTENSITY | FOREGROUND_RED);
			printf("     @adapter Id>");
			SetConsoleTextAttribute(console, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
			std::cin >> id;
			AdapterInfo = GetAdapterById(id);
		}

		if (inputCommand._Equal("server")) {
			SetConsoleTextAttribute(console, FOREGROUND_INTENSITY | FOREGROUND_RED);
			printf("     @server IP>");
			SetConsoleTextAttribute(console, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
			std::cin >> serverIP;
		}

		if (inputCommand._Equal("exit")) {
			break;
		}

		printf("\n");
	}
		


	free(AdapterInfo);
	return 0;

}