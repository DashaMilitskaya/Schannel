#pragma once
#include "crypt.h"

void cryptInterfaceEncode(void* buffer, ULONG dataLen, void* key, ULONG keyLen);
void cryptInterfaceDecode(void* buffer, ULONG dataLen, void* key, ULONG keyLen);

