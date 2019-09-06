#pragma once
#include "MemInfo.h"

bool hasEnding(std::string const& fullString, std::string const& ending);

namespace Cylance {
	bool FreeLibraryCylance();
	void RemoveCylanceHook(const char* dll, const char* apiName, char code);
}
