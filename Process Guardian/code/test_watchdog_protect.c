#include <windows.h>
#include <stdio.h>
#include <string.h>

#define WATCHDOG_COUNT 3

HANDLE watchdogPids[WATCHDOG_COUNT] = {0};
int watchdogCount = 0;
CRITICAL_SECTION cs;

BOOL IsProcessRunning(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h) {
        DWORD exitCode;
        GetExitCodeProcess(h, &exitCode);
        CloseHandle(h);
        return exitCode == STILL_ACTIVE;
    }
    return FALSE;
}

DWORD WINAPI WatchdogThread(LPVOID param) {
    int index = *(int*)param;
    DWORD myPid = GetCurrentProcessId();
    printf("Watchdog %d thread running (PID: %lu)\n", index, myPid);
    
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    
    while (1) {
        for (int i = 0; i < WATCHDOG_COUNT; i++) {
            if (i == index) continue;
            
            EnterCriticalSection(&cs);
            DWORD targetPid = (DWORD)(INT_PTR)watchdogPids[i];
            LeaveCriticalSection(&cs);
            
            if (targetPid != 0 && !IsProcessRunning(targetPid)) {
                printf("Watchdog %d: Process %lu is dead, restarting...\n", index, targetPid);
                
                STARTUPINFOA si = {0};
                si.cb = sizeof(si);
                PROCESS_INFORMATION pi = {0};
                
                if (CreateProcessA(path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
                    printf("Watchdog %d: Restarted process, new PID: %lu\n", index, pi.dwProcessId);
                    EnterCriticalSection(&cs);
                    watchdogPids[i] = (HANDLE)(INT_PTR)pi.dwProcessId;
                    LeaveCriticalSection(&cs);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                } else {
                    printf("Watchdog %d: Failed to restart process, error=%lu\n", index, GetLastError());
                }
            }
        }
        Sleep(500);
    }
    return 0;
}

int main() {
    InitializeCriticalSection(&cs);
    
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    char* filename = strrchr(path, '\\');
    if (filename) filename++;
    else filename = path;
    
    printf("=== Watchdog Protection Test ===\n");
    printf("Executable: %s\n", filename);
    printf("PID: %lu\n", GetCurrentProcessId());
    
    if (strstr(filename, "watchdog_")) {
        int index = -1;
        char* idxStr = strstr(filename, "_");
        if (idxStr) {
            index = atoi(idxStr + 1);
        }
        
        if (index >= 0 && index < WATCHDOG_COUNT) {
            printf("Running as watchdog %d\n", index);
            
            HANDLE hThread = CreateThread(NULL, 0, WatchdogThread, &index, 0, NULL);
            if (hThread) {
                printf("Watchdog %d: Started monitoring thread\n", index);
            }
            
            printf("Watchdog %d: Sleeping and protecting...\n", index);
            while (1) {
                Sleep(1000);
            }
            return 0;
        }
    }
    
    printf("Creating watchdog processes...\n");
    
    for (int i = 0; i < WATCHDOG_COUNT; i++) {
        char cmdline[MAX_PATH];
        snprintf(cmdline, sizeof(cmdline), "%s_w%d", path, i);
        
        STARTUPINFOA si = {0};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi = {0};
        
        if (CreateProcessA(path, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            printf("Created watchdog %d with PID: %lu\n", i, pi.dwProcessId);
            watchdogPids[i] = (HANDLE)(INT_PTR)pi.dwProcessId;
            watchdogCount++;
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            printf("Failed to create watchdog %d, error=%lu\n", i, GetLastError());
        }
    }
    
    Sleep(2000);
    
    printf("\n=== Performing malicious actions ===\n");
    printf("Opening PhysicalDrive0...\n");
    
    HANDLE hDisk = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
                              NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk == INVALID_HANDLE_VALUE) {
        printf("PhysicalDrive0 failed, trying C: volume...\n");
        hDisk = CreateFileA("\\\\.\\C:", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
                          NULL, OPEN_EXISTING, 0, NULL);
    }
    
    if (hDisk != INVALID_HANDLE_VALUE) {
        printf("SUCCESS: Disk handle opened!\n");
        printf("Keeping handle open for 30 seconds...\n");
    } else {
        printf("FAILED: Could not open disk handle, error=%lu\n", GetLastError());
    }
    
    Sleep(30000);
    
    if (hDisk != INVALID_HANDLE_VALUE) {
        CloseHandle(hDisk);
    }
    
    DeleteCriticalSection(&cs);
    return 0;
}