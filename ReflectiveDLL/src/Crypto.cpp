#include "Crypto.h"

uint8_t* OptCrypto::AESCBCDecrypt(uint8_t* buf, uint8_t* key, uint8_t* iv, int shellcodeLen)
{
	struct AES_ctx ctx;
	AES_init_ctx(&ctx, key);
	AES_ctx_set_iv(&ctx, iv);
	AES_CBC_decrypt_buffer(&ctx, buf, shellcodeLen);
	return buf;
}
uint8_t* OptCrypto::AESECBDecrypt(uint8_t* buf, uint8_t* key)
{
	struct AES_ctx ctx;
	AES_init_ctx(&ctx, key);
	AES_ECB_decrypt(&ctx, buf);
	return buf;
}

//  Compute the SHA256 checksum for input buffer
//
bool OptCrypto::GetSHA256Hash(char* buffer,             //input buffer
	DWORD dwBufferSize,       //input buffer size
	BYTE* byteFinalHash,      //ouput hash buffer
	DWORD* dwFinalHashSize    //input/output final buffer size
)
{
	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	//BYTE *byteHash;
	DWORD cbHashSize = 0;
	DWORD dwCount = sizeof(DWORD);

	// Get handle to the crypto provider
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		printf("\nCryptAcquireContext failed, Error=0x%.8x", GetLastError());
		return FALSE;
	}

	//Specify the Hash Algorithm here
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
	{
		printf("\nCryptCreateHash failed,  Error=%d", GetLastError());
		goto EndHash;
	}

	//Create the hash with input buffer
	if (!CryptHashData(hHash, (const BYTE*)buffer, dwBufferSize, 0))
	{
		printf("\nCryptHashData failed,  Error=0x%.8x", GetLastError());
		goto EndHash;
	}

	//Get the final hash size
	if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)& cbHashSize, &dwCount, 0))
	{
		printf("\nCryptGetHashParam failed, Error=0x%.8x", GetLastError());
		goto EndHash;
	}

	//check if the output buffer is enough to copy the hash data
	if (*dwFinalHashSize < cbHashSize)
	{
		printf("\nOutput buffer (%d) is not sufficient, Required Size = %d",
			*dwFinalHashSize, cbHashSize);
		goto EndHash;
	}

	//Now get the computed hash 
	if (CryptGetHashParam(hHash, HP_HASHVAL, byteFinalHash, dwFinalHashSize, 0))
	{
		bResult = TRUE;
	}
	for (int i = 0; i < *dwFinalHashSize; i++) {
		printf("%02x", (unsigned char)byteFinalHash[i]);
	}
	printf("\n");
EndHash:

	if (hHash)
		CryptDestroyHash(hHash);

	if (hProv)
		CryptReleaseContext(hProv, 0);

	return bResult;
}