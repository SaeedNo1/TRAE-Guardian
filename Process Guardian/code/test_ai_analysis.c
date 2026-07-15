#include <windows.h>
#include <stdio.h>

int main() {
    const wchar_t* runKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    const wchar_t* valueName = L"TestAIProcess";
    const wchar_t* valueData = L"C:\\test\\malicious.exe";
    
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, runKey, 0, KEY_WRITE, &hKey);
    
    if (result == ERROR_SUCCESS) {
        printf("Opened Run key successfully\n");
        
        result = RegSetValueExW(hKey, valueName, 0, REG_SZ, 
                                (const BYTE*)valueData, 
                                (wcslen(valueData) + 1) * sizeof(wchar_t));
        
        if (result == ERROR_SUCCESS) {
            printf("Wrote to Run key: %ls\n", valueData);
        } else {
            printf("Failed to write to Run key, error=%lu\n", result);
        }
        
        Sleep(5000);
        
        RegDeleteValueW(hKey, valueName);
        printf("Cleaned up test value\n");
        
        RegCloseKey(hKey);
    } else {
        printf("Failed to open Run key, error=%lu\n", result);
    }
    
    Sleep(3000);
    return 0;
}
