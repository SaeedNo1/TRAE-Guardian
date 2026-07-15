#include <windows.h>
#include <stdio.h>

int main() {
    const char* popup = "ShellExecute";
    const char* winExec = "WinExec";
    const char* runKey = "Run\\";
    const char* runOnce = "RunOnce\\";
    const char* browser = "SetDefaultBrowser";
    const char* homePage = "SetStartPage";
    
    printf("Test rogue software - popup + homepage hijack\n");
    
    HKEY hKey;
    LONG result = RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                                0, KEY_WRITE, &hKey);
    if (result == ERROR_SUCCESS) {
        printf("Opened Run key\n");
        RegCloseKey(hKey);
    }
    
    Sleep(3000);
    return 0;
}