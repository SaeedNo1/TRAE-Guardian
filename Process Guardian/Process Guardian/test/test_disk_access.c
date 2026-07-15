#include <windows.h>
#include <stdio.h>

int main() {
    printf("Opening PhysicalDrive0...\n");
    
    HANDLE h = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ, 
                           FILE_SHARE_READ | FILE_SHARE_WRITE, 
                           NULL, OPEN_EXISTING, 0, NULL);
    
    if (h == INVALID_HANDLE_VALUE) {
        printf("Open PhysicalDrive0 failed (expected on restricted systems)\n");
        printf("Error: %lu\n", GetLastError());
        printf("Trying HarddiskVolume...\n");
        
        h = CreateFileA("\\\\.\\HarddiskVolume1", GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL, OPEN_EXISTING, 0, NULL);
        
        if (h == INVALID_HANDLE_VALUE) {
            printf("Open HarddiskVolume1 failed\n");
            printf("Error: %lu\n", GetLastError());
            return 1;
        }
    }
    
    printf("SUCCESS: Opened disk handle!\n");
    printf("Keeping handle open for 30 seconds...\n");
    
    for (int i = 0; i < 30; i++) {
        printf(".");
        fflush(stdout);
        Sleep(1000);
    }
    
    printf("\nClosing handle...\n");
    CloseHandle(h);
    
    return 0;
}