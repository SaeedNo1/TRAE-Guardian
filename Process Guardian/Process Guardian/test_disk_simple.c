#include <windows.h>
#include <stdio.h>

int main() {
    printf("=== Disk Handle Test ===\n");
    printf("PID: %lu\n", GetCurrentProcessId());
    printf("Opening disk handle...\n");
    
    HANDLE hDisk = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
                          NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk == INVALID_HANDLE_VALUE) {
        printf("PhysicalDrive0 failed, error=%lu\n", GetLastError());
        printf("Trying \\\\.\\C: ...\n");
        hDisk = CreateFileA("\\\\.\\C:", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
                          NULL, OPEN_EXISTING, 0, NULL);
    }
    
    if (hDisk != INVALID_HANDLE_VALUE) {
        printf("SUCCESS: Disk handle opened!\n");
        printf("Keeping handle open for 30 seconds...\n");
        Sleep(30000);
        CloseHandle(hDisk);
    } else {
        printf("FAILED: All disk handle attempts failed\n");
        printf("Sleeping 30 seconds...\n");
        Sleep(30000);
    }
    
    return 0;
}