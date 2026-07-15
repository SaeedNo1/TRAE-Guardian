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
    
    printf("All watchdogs running, press any key to exit...\n");
    getchar();
    
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
    printf("Watchdog test - simulating multiple processes protecting each other\n");
    printf("This test creates 3 processes that watch each other\n");
    printf("If one dies, another will restart it immediately\n");
    printf("\nPress any key to start...\n");
    getchar();
    
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
    
    printf("\nAll 3 watchdogs started. They will protect each other.\n");
    printf("Press any key to stop the test...\n");
    getchar();
    
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