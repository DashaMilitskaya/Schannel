#include "crypt.h"
#include "precomp.h"

void blockEncode(PUCHAR buffer, ULONG len, PUCHAR key) {
	for (ULONG i = 0; i < len; i++) {
		buffer[i] = buffer[i] ^ key[i];
	}
}

void cryptGammir(void* buffer, ULONG dataLen, PUCHAR key, ULONG keyLen) {
	ULONG crLen = dataLen;
	PUCHAR crPtr = buffer;
	while (crLen) {
		if (crLen < keyLen) { 
			blockEncode(crPtr, crLen, key);
			crLen = 0;
		}
		else
		{
			blockEncode(crPtr, keyLen, key);
			crLen -= keyLen;
			crPtr = crPtr + keyLen;
		}

	}
	

}

void cryptInterfaceEncode(void* buffer, ULONG dataLen, void* key, ULONG keyLen) {
	if(keyLen)
		cryptGammir( buffer,  dataLen,  key,  keyLen);
}

void cryptInterfaceDecode(void* buffer, ULONG dataLen, void* key, ULONG keyLen) {
	if (keyLen)
		cryptGammir(buffer, dataLen, key, keyLen);

}