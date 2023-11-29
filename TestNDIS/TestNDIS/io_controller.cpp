#include "io_controller.h"

BOOL
SV_GetDriverInfo(
	_In_ HANDLE hDevice,
	_In_ DWORD dwIoControlCode,
	_In_reads_bytes_opt_(nInBufferSize) LPVOID lpInBuffer,
	_In_ DWORD nInBufferSize,
	_Out_writes_bytes_to_opt_(nOutBufferSize, *lpBytesReturned) LPVOID lpOutBuffer,
	_In_ DWORD nOutBufferSize,
	_Out_opt_ LPDWORD lpBytesReturned
)
{
	if (!DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, nullptr))
	{
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			DWORD ttt = 0;;
			DWORD Num;
			DWORD tempreturns = 0;
			if (DeviceIoControl(hDevice, dwIoControlCode, &ttt, sizeof(DWORD), &Num, sizeof(DWORD), &tempreturns, nullptr))
			{
				if (Num)
				{
					SetLastError(ERROR_INSUFFICIENT_BUFFER);
					*lpBytesReturned = Num;
				}
			}
			else
				SetLastError(ERROR_INVALID_PARAMETER);
			return FALSE;
		}
		else
			return FALSE;
	}
	return TRUE;
}
/*
std::pair<DWORD, PVOID> IoGetBufferData(HANDLE hdevice, PDWORD64 InputBuffer, DWORD InputBuffersize, DWORD IoCtlCod, size_t StructSize) {


	DWORD buffersize = 0;
	PVOID OutBuffer = nullptr;
	DWORD OutBuffersize = 0;
	


	while (!SV_GetDriverInfo(hdevice, IoCtlCod, &InputBuffer, sizeof(PVOID), OutBuffer, OutBuffersize, &buffersize)) {
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			if (OutBuffer)
			{
				HeapFree(GetProcessHeap(), 0, OutBuffer);
				OutBuffer = nullptr;
			}
			OutBuffer = (PVOID)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buffersize);
			OutBuffersize = buffersize;
		}
		else
		{
			return std::make_pair((DWORD)NULL,(PDWORD64)NULL);
		}
	}

	return std::make_pair(OutBuffersize, OutBuffer);

}*/

void SV_SendDriverInfo(HANDLE hdevice, PVOID InputBuffer, DWORD InputBufferSize, DWORD IoCtlCod) {


	DeviceIoControl(hdevice, IoCtlCod, InputBuffer, InputBufferSize, nullptr, NULL, nullptr, nullptr);
	
	
	return;

}

DWORD SV_GetDriverInfo(HANDLE hdevice, PVOID OutputBuffer, DWORD OutputBufferSize, DWORD IoCtlCod) {
	DWORD BytesReturned;
	DeviceIoControl(hdevice, IoCtlCod, nullptr, NULL, OutputBuffer, OutputBufferSize, &BytesReturned, nullptr);
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
		return 0;
	}
	printf("/n %d /n", BytesReturned);
	return BytesReturned;

}