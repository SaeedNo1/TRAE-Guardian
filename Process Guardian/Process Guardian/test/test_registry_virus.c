#include <windows.h>
#include <stdio.h>

void WriteToRunKey() {
    HKEY hKey;
    LSTATUS status = RegOpenKeyExW(HKEY_CURRENT_USER, 
                                    L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                                    0, KEY_WRITE, &hKey);
    if (status == ERROR_SUCCESS) {
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);
        status = RegSetValueExW(hKey, L"MaliciousStartup", 0, REG_SZ, 
                                (const BYTE*)path, (wcslen(path) + 1) * 2);
        RegCloseKey(hKey);
        if (status == ERROR_SUCCESS) {
            wprintf(L"[TEST] SUCCESS: Written to HKCU\\Run key\n");
        } else {
            wprintf(L"[TEST] FAILED: Write to Run key failed, error: %lu\n", GetLastError());
        }
    } else {
        wprintf(L"[TEST] FAILED: Open Run key failed, error: %lu\n", GetLastError());
    }
}

void WriteToSystemRegistry() {
    HKEY hKey;
    LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
                                    L"SYSTEM\\CurrentControlSet\\Services", 
                                    0, KEY_WRITE, &hKey);
    if (status == ERROR_SUCCESS) {
        wchar_t data[] = L"malicious_config";
        status = RegSetValueExW(hKey, L"MaliciousConfig", 0, REG_SZ, 
                                (const BYTE*)data, (wcslen(data) + 1) * 2);
        RegCloseKey(hKey);
        if (status == ERROR_SUCCESS) {
            wprintf(L"[TEST] SUCCESS: Written to HKLM\\SYSTEM\\Services\n");
        } else {
            wprintf(L"[TEST] FAILED: Write to SYSTEM registry failed, error: %lu\n", GetLastError());
        }
    } else {
        wprintf(L"[TEST] FAILED: Open SYSTEM key failed, error: %lu\n", GetLastError());
    }
}

void WriteToRunOnce() {
    HKEY hKey;
    LSTATUS status = RegOpenKeyExW(HKEY_CURRENT_USER, 
                                    L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 
                                    0, KEY_WRITE, &hKey);
    if (status == ERROR_SUCCESS) {
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);
        status = RegSetValueExW(hKey, L"MaliciousRunOnce", 0, REG_SZ, 
                                (const BYTE*)path, (wcslen(path) + 1) * 2);
        RegCloseKey(hKey);
        if (status == ERROR_SUCCESS) {
            wprintf(L"[TEST] SUCCESS: Written to HKCU\\RunOnce key\n");
        } else {
            wprintf(L"[TEST] FAILED: Write to RunOnce failed, error: %lu\n", GetLastError());
        }
    } else {
        wprintf(L"[TEST] FAILED: Open RunOnce key failed, error: %lu\n", GetLastError());
    }
}

int wmain(int argc, wchar_t* argv[]) {
    wprintf(L"=== Registry Virus Test ===\n");
    wprintf(L"PID: %lu\n\n", GetCurrentProcessId());

    WriteToRunKey();
    WriteToRunOnce();
    WriteToSystemRegistry();

    wprintf(L"\n=== Registry modifications complete ===\n");
    wprintf(L"Waiting for termination...\n");

    while (1) {
        Sleep(1000);
    }

    return 0;
}