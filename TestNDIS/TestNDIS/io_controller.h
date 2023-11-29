#pragma once
#include <Windows.h>
#include <stdlib.h>
#include <SetupAPI.h>
#include <initguid.h>
#include <memory>
#include <vector>
#include <iostream>
#include <iomanip>
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "odbc32.lib")
#pragma comment(lib, "odbccp32.lib")
#include <initguid.h>


DEFINE_GUID(GUID_DEVINTERFACE_SystemTest,
	0x30809efd, 0x6125, 0x42dc, 0x85, 0xbc, 0x63, 0x1e, 0x61, 0x4a, 0x60, 0x0d);

BOOL
SV_GetDriverInfo(
	_In_ HANDLE hDevice,
	_In_ DWORD dwIoControlCode,
	_In_reads_bytes_opt_(nInBufferSize) LPVOID lpInBuffer,
	_In_ DWORD nInBufferSize,
	_Out_writes_bytes_to_opt_(nOutBufferSize, *lpBytesReturned) LPVOID lpOutBuffer,
	_In_ DWORD nOutBufferSize,
	_Out_opt_ LPDWORD lpBytesReturned
); 

//std::pair<DWORD, PDWORD64> IoGetBufferData(HANDLE hdevice, PDWORD64 InputBuffer, DWORD InputBuffersize, DWORD IoCtlCod, size_t StructSize);
void SV_SendDriverInfo(HANDLE hdevice, PVOID InputBuffer, DWORD InputBufferSize, DWORD IoCtlCod);
DWORD SV_GetDriverInfo(HANDLE hdevice, PVOID OutputBuffer, DWORD OutputBufferSize, DWORD IoCtlCod);