#include <windows.h>
#include <stdio.h>

int main(void) {
    printf("ETW registry test: modifying protected system registry key...\n");
    HKEY hKey;
    LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hKey);
    if (r != ERROR_SUCCESS) {
        printf("RegOpenKeyEx failed: %ld\n", r);
        return 1;
    }
    const wchar_t* val = L"C:\\Windows\\System32\\notepad.exe";
    r = RegSetValueExW(hKey, L"GuardianTestETW", 0, REG_SZ,
                       (const BYTE*)val, (DWORD)((wcslen(val) + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);
    if (r != ERROR_SUCCESS) {
        printf("RegSetValueEx failed: %ld\n", r);
        return 1;
    }
    printf("Registry modified. PID=%lu. Sleeping 5s...\n", GetCurrentProcessId());
    Sleep(5000);
    return 0;
}
