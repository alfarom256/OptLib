#include "MemInfo.h"
#pragma comment(lib, "kernel32.lib")


// Don't thread this.
// If it fails, and the thread exits, you won't be able to call GetLastError
// Up to you if you care /shrug

std::vector<MemInfoModule> MemInfo::GetAllModules(int PID)
{
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	LPVOID imageBase;

	// If PID is zero, we're calling this on ourself
	bool self = !PID;

	// and we need to get the current process ID;
	if (self) PID = GetCurrentProcessId();

	std::vector<MemInfoModule> retVal;
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, PID);
	if (hProcess == NULL){
		// GetLastError goes here... need to do error handling better
		return std::vector<MemInfoModule>(0);
	}
	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		MODULEINFO lpm;
		GetModuleInformation(hProcess, hMods[0], &lpm, sizeof(lpm));
		imageBase = lpm.EntryPoint;
		for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			MemInfoModule m;
			m.hMod = hMods[i];
			TCHAR szModName[MAX_PATH];
			if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
				sizeof(szModName) / sizeof(TCHAR)))
			{
				MODULEINFO lpm;
				GetModuleInformation(hProcess, hMods[i], &lpm, sizeof(lpm));
				m.modName = (char*)szModName;
				m.baseAddr = lpm.lpBaseOfDll;
				retVal.push_back(m);
				// Print the module name and handle value.
#ifdef DEBUG
				std::wcout << "Found Loaded Module: " << szModName << std::endl;
				printf("Found Loaded Module Relative Address: %p\n", m.baseAddr);
#endif // DEBUG				
			}

		}
	}
	return retVal;
}



std::vector<MemInfoModule> MemInfo::CurrentLoadedModules()
{
	return GetAllModules(0);
}

bool MemInfo::RemoveLoadedModule(HANDLE hTread, HMODULE hMod)
{
	return false;
}
bool MemInfo::RemoveLoadedModule(HMODULE hMod)
{
	bool res = FreeLibrary(hMod);
#ifdef DEBUG
	std::cout << "FreeLibrary " << (res ? "Succeeded " : "Failed ") << std::endl;
#endif // DEBUG
	return res;
}