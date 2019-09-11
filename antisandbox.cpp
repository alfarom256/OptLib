#include "antisandbox.h"
#include <Lm.h>
#pragma comment(lib, "Netapi32.lib")

#define UNAME_MAX 257

int mutate(std::time_t *time)
{
	return 0;
}

bool AntiSandbox::isDomainJoined(SandboxInformation *si)
{
	// the buffer is allocated by the system
	LPWSTR	lpNameBuffer;

	NET_API_STATUS nas;
	NETSETUP_JOIN_STATUS BufferType;

	// get info
	nas = NetGetJoinInformation(NULL, &lpNameBuffer, &BufferType);

	if (nas != NERR_Success)
	{
		// op failed :(
		si->GLE = GetLastError();
		return false;
	}

	switch (BufferType)
	{
	case NetSetupWorkgroupName:
		si->Workgroup = lpNameBuffer;
		break;

	case NetSetupDomainName:
		si->Domain = lpNameBuffer;
		break;
	}
	// clean up
	bool res = lstrlenW(lpNameBuffer);
	NetApiBufferFree(lpNameBuffer);
	return res;

}