#include "includes.h"
#include <LM.h>
#include <sddl.h>
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma once
#define DEBUG
#ifdef DEBUG
#include <iostream>
#include <stdio.h>
#endif // DEBUG




class OptPrivs
{
public:
	OptPrivs();
	~OptPrivs();
	LPSTR SID;
	TCHAR* Username;
	LPSTR Domain;
	bool isSystem, isAdmin, isLocalAdminGroup, isAdminGroup = false;

private:
	HANDLE currentThreadHandle;
	HANDLE currentThreadToken;
	int PID;

	LPSTR getCurrentSID();
	TCHAR* getCurrentUserName();
	void getCurrentProcInfo();
	bool IsSystem();
	bool IsAdmin();
	bool IsAdminGroup();
};
