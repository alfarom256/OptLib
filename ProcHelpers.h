#pragma once
#include "includes.h"
#include <map>
struct PH_THREAD_INFO
{
	HANDLE ImpersonationToken, PrimaryToken;
	DWORD GLE;
	DWORD ThreadCreateFlags; // CREATE_SUSPENDED, etc.
	DWORD pagePermissions;
	int StackSpace = 0x00001000;
	HANDLE threadHandle;
};

struct ProcExecute {
	unsigned int pid;
	unsigned int GLE;
	std::string Command;
	DWORD token_flags; // TOKEN_DUPLICATE | TOKEN_....
	HANDLE proc_token;
	HANDLE fiber_handle;
};


namespace ProcHelper
{
	HANDLE SpawnThreadShellcode(unsigned char* buf, int bufLen, PH_THREAD_INFO *pt);
	HANDLE SpawnProcessShellcode(unsigned char* buf, int bufLen, PH_THREAD_INFO *pt);
	HANDLE CreateFiberShellcode(unsigned char* buf, int bufLen, PH_THREAD_INFO *pt);
	HANDLE RunFiberShellcode(HANDLE hFiber, PH_THREAD_INFO *pt);
	HANDLE CreateFiberStartRoutine(LPFIBER_START_ROUTINE lpt, PH_THREAD_INFO* pt);
	DWORD Win32SetRvaToDwordOffset(IMAGE_NT_HEADERS32* m_pNtHeader, DWORD m_dwRVA, PIMAGE_SECTION_HEADER m_pSectionHeader);
	std::map<std::string, LPVOID> ImportListPopulate(LPVOID imageBase);
	ProcExecute CreateNewProcExec(unsigned int pid, std::string command, DWORD token_flags);
	BOOL EnableDebugPriv();
	ProcExecute CreateThreadWithToken(ProcExecute pe, unsigned char buf[], int bufLen);
	HANDLE PESetTokenFromPID(ProcExecute& pe);
}

BOOL SetPrivilege(HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege);
