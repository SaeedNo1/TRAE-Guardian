#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "daemon_core.h"

int main(void) {
    DaemonState* s = (DaemonState*)calloc(1, sizeof(DaemonState));
    if (!s) return 1;
    s->checkInterval = 500;
    s->reloadInterval = 30000;

    DaemonLoadSettings(s);
    DaemonLoadAll(s);

    wprintf(L"Test snapshot: calling DaemonTick 3 times to establish baseline...\n");
    for (int i = 0; i < 3; i++) {
        DaemonTick(s);
        Sleep(500);
    }

    wprintf(L"Now modify protected registry...\n");
    HKEY hKey;
    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey);
    if (rc != ERROR_SUCCESS) {
        wprintf(L"RegOpenKeyExW failed rc=%ld\n", rc);
        free(s);
        return 1;
    }
    const wchar_t* val = L"C:\\Windows\\System32\\notepad.exe";
    rc = RegSetValueExW(hKey, L"CalcStartTest", 0, REG_SZ, (const BYTE*)val, (DWORD)((wcslen(val)+1)*sizeof(wchar_t)));
    if (rc != ERROR_SUCCESS) {
        wprintf(L"RegSetValueExW failed rc=%ld\n", rc);
        RegCloseKey(hKey);
        free(s);
        return 1;
    }
    RegCloseKey(hKey);
    wprintf(L"Registry value written successfully.\n");

    wprintf(L"Sleeping 1s then checking...\n");
    Sleep(1000);
    for (int i = 0; i < 5; i++) {
        DaemonTick(s);
        Sleep(500);
    }

    wprintf(L"Test done. Check bin\\data\\daemon.log\n");
    free(s);
    return 0;
}
