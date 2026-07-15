#include <windows.h>
#include <stdio.h>

int main() {
    printf("Testing disk handle access for watchdog group termination...\n");
    printf("PID: %lu\n", GetCurrentProcessId());
    
    HANDLE h = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
                          NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("PhysicalDrive0 failed, trying C: volume...\n");
        h = CreateFileA("\\\\.\\C:", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
                      NULL, OPEN_EXISTING, 0, NULL);
    }
    
    if (h != INVALID_HANDLE_VALUE) {
        printf("SUCCESS: Disk handle opened!\n");
        printf("Keeping handle open for 30 seconds...\n");
        Sleep(30000);
        CloseHandle(h);
    } else {
        printf("FAILED: Could not open disk handle, error=%lu\n", GetLastError());
        printf("Sleeping 30 seconds...\n");
        Sleep(30000);
    }
    
    return 0;
}