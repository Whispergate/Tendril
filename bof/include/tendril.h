/*
 * tendril.h - Shared definitions for Tendril BOF modules
 */
#ifndef TENDRIL_H
#define TENDRIL_H

#include <windows.h>
#include "beacon.h"
#include "beacon_gate.h"

/* DFR declarations for Win32 APIs used across modules */
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegOpenKeyExW(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegCreateKeyExW(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegSetValueExW(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegDeleteValueW(HKEY, LPCWSTR);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegDeleteKeyExW(HKEY, LPCWSTR, REGSAM, DWORD);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegQueryValueExW(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegEnumKeyExW(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME);

DECLSPEC_IMPORT int WINAPI KERNEL32$lstrlenW(LPCWSTR);
DECLSPEC_IMPORT LPWSTR WINAPI KERNEL32$lstrcpyW(LPWSTR, LPCWSTR);
DECLSPEC_IMPORT LPWSTR WINAPI KERNEL32$lstrcatW(LPWSTR, LPCWSTR);
DECLSPEC_IMPORT void* WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);

/* Helper macros */
#define HEAP_ALLOC(sz) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (sz))
#define HEAP_FREE(p)   KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, (p))

/* Set a REG_SZ value (wchar) */
static inline LSTATUS tendril_reg_set_sz(HKEY root, LPCWSTR subkey, LPCWSTR valueName, LPCWSTR data)
{
    HKEY hKey = NULL;
    DWORD disp;
    LSTATUS status = ADVAPI32$RegCreateKeyExW(root, subkey, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_WOW64_64KEY, NULL, &hKey, &disp);
    if (status != ERROR_SUCCESS) return status;

    DWORD cbData = (KERNEL32$lstrlenW(data) + 1) * sizeof(WCHAR);
    status = ADVAPI32$RegSetValueExW(hKey, valueName, 0, REG_SZ, (const BYTE*)data, cbData);
    ADVAPI32$RegCloseKey(hKey);
    return status;
}

/* Set a REG_DWORD value */
static inline LSTATUS tendril_reg_set_dword(HKEY root, LPCWSTR subkey, LPCWSTR valueName, DWORD data)
{
    HKEY hKey = NULL;
    DWORD disp;
    LSTATUS status = ADVAPI32$RegCreateKeyExW(root, subkey, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_WOW64_64KEY, NULL, &hKey, &disp);
    if (status != ERROR_SUCCESS) return status;

    status = ADVAPI32$RegSetValueExW(hKey, valueName, 0, REG_DWORD, (const BYTE*)&data, sizeof(DWORD));
    ADVAPI32$RegCloseKey(hKey);
    return status;
}

/* Delete a registry value */
static inline LSTATUS tendril_reg_delete_value(HKEY root, LPCWSTR subkey, LPCWSTR valueName)
{
    HKEY hKey = NULL;
    LSTATUS status = ADVAPI32$RegOpenKeyExW(root, subkey, 0, KEY_WRITE | KEY_WOW64_64KEY, &hKey);
    if (status != ERROR_SUCCESS) return status;

    status = ADVAPI32$RegDeleteValueW(hKey, valueName);
    ADVAPI32$RegCloseKey(hKey);
    return status;
}

#endif /* TENDRIL_H */
