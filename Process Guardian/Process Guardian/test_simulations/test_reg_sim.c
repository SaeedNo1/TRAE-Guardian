#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
    printf("[TEST] Registry Tampering Simulation\n");
    
    HKEY hKey;
    LONG result;
    
    result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey);
    if (result == ERROR_SUCCESS) {
        const wchar_t* malwarePath = L"C:\\Windows\\malware.exe";
        result = RegSetValueExW(hKey, L"MalwareService", 0, REG_SZ, (BYTE*)malwarePath, (wcslen(malwarePath) + 1) * sizeof(wchar_t));
        if (result == ERROR_SUCCESS) {
            printf("[OK] Created startup registry entry\n");
        } else {
            printf("[FAIL] RegSetValueEx failed: %lu\n", result);
        }
        RegCloseKey(hKey);
    } else {
        printf("[FAIL] RegOpenKeyEx failed: %lu\n", result);
    }
    
    result = RegOpenKeyExW(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey);
    if (result == ERROR_SUCCESS) {
        const wchar_t* malwarePath = L"C:\\Windows\\malware.exe";
        result = RegSetValueExW(hKey, L"MalwareService", 0, REG_SZ, (BYTE*)malwarePath, (wcslen(malwarePath) + 1) * sizeof(wchar_t));
        if (result == ERROR_SUCCESS) {
            printf("[OK] Created user startup registry entry\n");
        } else {
            printf("[FAIL] RegSetValueEx (HKCU) failed: %lu\n", result);
        }
        RegCloseKey(hKey);
    } else {
        printf("[FAIL] RegOpenKeyEx (HKCU) failed: %lu\n", result);
    }
    
    printf("[TEST] Registry tampering simulation completed - should be detected!\n");
    Sleep(5000);
    return 0;
}