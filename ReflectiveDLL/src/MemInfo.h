#ifndef MEMINFO_H
#define MEMINFO_H
#include <Windows.h>
#include <Psapi.h>
#include <iostream>
#include <vector>
#include <map>
#include <tchar.h>
#include "includes.h"


struct MemInfoModule {
	HMODULE hMod;
	std::string modName;
	LPVOID baseAddr;
	LPVOID fullAddr;
};


namespace MemInfo
{
	// List all loaded DLLs in a process
	std::vector<MemInfoModule> GetAllModules(int PID);
	std::vector<MemInfoModule> CurrentLoadedModules();
	bool RemoveLoadedModule(HANDLE hProc, HMODULE hMod);
	bool RemoveLoadedModule(HMODULE hMod);
	//std::vector<HMODULE> curModules;
};
#endif