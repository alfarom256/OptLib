#pragma once
#include "aes.hpp"
#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <wincrypt.h>
#include <bcrypt.h>

//#define CBC 1
#define CBC 1
#define AES256 1

namespace OptCrypto {
	uint8_t* AESCBCDecrypt(uint8_t* buf, uint8_t* key, uint8_t* iv, int shellcodeLen);
	uint8_t* AESECBDecrypt(uint8_t* buf, uint8_t* key);
	bool GetSHA256Hash(char* buffer, DWORD dwBufferSize, BYTE* byteFinalHash, DWORD* dwFinalHashSize);
}