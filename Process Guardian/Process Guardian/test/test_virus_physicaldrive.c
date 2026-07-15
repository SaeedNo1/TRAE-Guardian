#include <windows.h>
#include <stdio.h>

int main() {
    const char* physicalDrive = "\\\\.\\PhysicalDrive0";
    const char* bsodApi = "NtRaiseHardError";
    const char* shutdownApi = "NtShutdownSystem";
    
    printf("Test virus - PhysicalDrive + BSOD\n");
    printf("Contains: %s\n", physicalDrive);
    printf("Contains: %s\n", bsodApi);
    
    HANDLE h = CreateFileA(physicalDrive, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
                          NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("Open PhysicalDrive failed (expected)\n");
        printf("Error: %lu\n", GetLastError());
    } else {
        printf("SUCCESS: PhysicalDrive0 opened successfully!\n");
        printf("Keeping handle open for 30 seconds...\n");
        Sleep(30000);
        CloseHandle(h);
    }
    
    return 0;
}