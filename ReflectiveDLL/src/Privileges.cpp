#include "Privileges.h"

OptPrivs::OptPrivs()
{
	getCurrentProcInfo();
	getCurrentUserName();
	getCurrentSID();
	IsAdmin();
	if (this->isAdmin) {
		IsAdminGroup();
		IsSystem();
	}
}

OptPrivs::~OptPrivs()
{
	CloseHandle(this->currentThreadHandle);
	CloseHandle(this->currentThreadToken);
}

LPSTR OptPrivs::getCurrentSID()
{
	TOKEN_OWNER t;
	DWORD tokenInfoLen = sizeof(TOKEN_OWNER);
	DWORD totalLen;
	ZeroMemory(&t, sizeof(TOKEN_OWNER));
	// get the size of the struct
	GetTokenInformation(this->currentThreadToken, TokenOwner, NULL, 0, &totalLen);

	PTOKEN_OWNER po = (PTOKEN_OWNER)LocalAlloc(LPTR, totalLen);

	bool res = GetTokenInformation(
		this->currentThreadToken,
		TokenOwner,
		po,
		totalLen,
		&totalLen
	);
#ifdef DEBUG
	if (!res) {
		std::cout << "GetTokenInformation failed, GLE: " << GetLastError() << std::endl;
		exit(0);
	}

	std::cout << "Wrote " << totalLen << "bytes to structure" << std::endl;
	std::cout << po->Owner << std::endl;
#endif // DEBUG
	char nameUser[256] = { 0 };
	char domainName[256] = { 0 };
	DWORD nameUserLen = 256;
	DWORD domainNameLen = 256;
	SID_NAME_USE snu;
	
	LPWSTR StringSid;
	if (!ConvertSidToStringSid(po->Owner, &StringSid)) {
		this->SID = (LPSTR)"0";
	}
	else {
		this->SID = (LPSTR)StringSid;
	}


	if (!LookupAccountSidA(NULL, po->Owner, nameUser, &nameUserLen, domainName, &domainNameLen, &snu))
	{
#ifdef DEBUG
		std::cout << "LookupAccountSidA Failed, GLE: " << GetLastError() << std::endl;
#endif // DEBUG

	}
	this->Domain = domainName;
	return (LPSTR)StringSid;
}


TCHAR* OptPrivs::getCurrentUserName()
{
	this->Username = (TCHAR*) calloc(UNLEN + 1, sizeof(TCHAR));
	DWORD usernameLen = UNLEN + 1;
	GetUserName(this->Username, &usernameLen);
	return this->Username;
}

void OptPrivs::getCurrentProcInfo()
{
	this->PID = GetCurrentProcessId();
	this->currentThreadHandle = GetCurrentProcess();
	if (!OpenProcessToken(this->currentThreadHandle, TOKEN_QUERY, &this->currentThreadToken)) {
		this->currentThreadHandle = (HANDLE)0xDEADBEEF;
#ifdef DEBUG
		std::cout << "OpenProcessToken failed on self, GLE: " << GetLastError() << std::endl;
		exit(0);
#endif // DEBUG

	}
#ifdef DEBUG
	std::cout << "Current PID: " << this->PID << std::endl;
	printf("Current Thread Token: %x\n", this->currentThreadToken);
	printf("Current Thread Handle: %x\n", this->currentThreadHandle);
#endif // DEBUG

}

bool OptPrivs::IsSystem()
{
	const char* uname = (char*)this->Username;
	this->isSystem = !strncmp(uname, "SYSTEM", 6) || !strncmp(this->SID, "S-1-5-18", 9);

#ifdef DEBUG
	std::cout << "Is System? " << this->isSystem << std::endl;
#endif // DEBUG
	return this->isSystem;
}

bool OptPrivs::IsAdmin()
{
	BOOL isMember;
	PSID administratorsGroup = NULL;
	SID_IDENTIFIER_AUTHORITY SIDAuthNT =
		SECURITY_NT_AUTHORITY;

	if (!AllocateAndInitializeSid(&SIDAuthNT, 2,
		SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&administratorsGroup))
	{
		this->isAdmin = false;
	}

	if (!CheckTokenMembership(nullptr, administratorsGroup, &isMember))
	{
		this->isAdmin = false;
	}
	this->isAdmin = isMember;
#ifdef DEBUG
	std::cout << "Is Admin? " << this->isAdmin << std::endl;
#endif


	return isMember;
}

bool OptPrivs::IsAdminGroup()
{
	// get the current user info
	LPUSER_INFO_0 pBuf;
	LPUSER_INFO_1 pBuf1 = NULL;
	NET_API_STATUS nStatus;


	nStatus = NetUserGetInfo(NULL, (LPCWSTR)this->Username, 1, (LPBYTE*)& pBuf);
	if (nStatus == NERR_Success) {
		pBuf1 = (LPUSER_INFO_1)pBuf;

		this->isAdminGroup = pBuf1->usri1_priv == USER_PRIV_ADMIN;
	}
#ifdef DEBUG
	std::cout << "Is Admin Group? " << this->isAdminGroup << std::endl;
#endif // DEBUG	
	return this->isAdminGroup;
}
