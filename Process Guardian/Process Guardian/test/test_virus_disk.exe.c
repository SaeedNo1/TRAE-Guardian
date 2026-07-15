#include <windows.h>
#include <stdio.h>
#include <string.h>

int main() {
    printf("=== Virus Disk Access Test ===\n");
    printf("Testing PhysicalDrive access detection\n\n");
    
    const char* physicalDrive = "\\\\.\\PhysicalDrive0";
    printf("Attempting to open %s...\n", physicalDrive);
    
    HANDLE h = CreateFileA(physicalDrive, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
                          NULL, OPEN_EXISTING, 0, NULL);
    
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        printf("Open PhysicalDrive failed (error %lu)\n", err);
        if (err == ERROR_ACCESS_DENIED) {
            printf("Note: Access denied - this is expected on most systems.\n");
            printf("Trying with GENERIC_READ | FILE_SHARE_READ only...\n");
            h = CreateFileA(physicalDrive, GENERIC_READ, FILE_SHARE_READ, 
                          NULL, OPEN_EXISTING, 0, NULL);
            if (h == INVALID_HANDLE_VALUE) {
                err = GetLastError();
                printf("Still failed (error %lu)\n", err);
                printf("Testing with Harddisk volume path...\n");
                
                const char* harddiskPath = "\\\\.\\Harddisk0\\DR0";
                h = CreateFileA(harddiskPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
                              NULL, OPEN_EXISTING, 0, NULL);
                if (h == INVALID_HANDLE_VALUE) {
                    err = GetLastError();
                    printf("Harddisk path also failed (error %lu)\n", err);
                    printf("\nPress Enter to exit...\n");
                    getchar();
                    return 1;
                }
            }
        } else {
            printf("\nPress Enter to exit...\n");
            getchar();
            return 1;
        }
    }
    
    printf("SUCCESS: Disk handle opened!\n");
    printf("Keeping handle open for 30 seconds...\n");
    printf("During this time, the daemon should detect and terminate this process.\n");
    printf("Press Ctrl+C to exit early...\n\n");
    
    for (int i = 0; i < 30; i++) {
        printf("Second %d/30 - Handle still open\n", i + 1);
        Sleep(1000);
    }
    
    CloseHandle(h);
    printf("\nHandle closed normally.\n");
    return 0;
}