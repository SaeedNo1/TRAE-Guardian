#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <process.h>

#define WATCHDOG_COUNT 3

HANDLE g_hDisk = NULL;
HANDLE g_hWatchdogThreads[WATCHDOG_COUNT] = {NULL};
DWORD g_watchdogPIDs[WATCHDOG_COUNT] = {0};
volatile BOOL g_running = TRUE;

void OpenPhysicalDrive() {
    wchar_t drivePath[64];
    for (int i = 0; i < 5; i++) {
        swprintf(drivePath, 64, L"\\\\.\\PhysicalDrive%d", i);
        g_hDisk = CreateFileW(drivePath, GENERIC_READ | GENERIC_WRITE, 
                              FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, 
                              OPEN_EXISTING, 0, NULL);
        if (g_hDisk != INVALID_HANDLE_VALUE) {
            wprintf(L"[WATCHDOG] SUCCESS: Opened PhysicalDrive%d, handle=%p\n", i, g_hDisk);
            return;
        }
    }
    wprintf(L"[WATCHDOG] FAILED: Could not open any PhysicalDrive\n");
}

void WriteToRunKey() {
    HKEY hKey;
    LSTATUS status = RegOpenKeyExW(HKEY_CURRENT_USER, 
                                    L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                                    0, KEY_WRITE, &hKey);
    if (status == ERROR_SUCCESS) {
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);
        status = RegSetValueExW(hKey, L"MaliciousService", 0, REG_SZ, 
                                (const BYTE*)path, (wcslen(path) + 1) * 2);
        RegCloseKey(hKey);
        if (status == ERROR_SUCCESS) {
            wprintf(L"[WATCHDOG] SUCCESS: Written to Run key\n");
        }
    }
}

void WriteToSystemRegistry() {
    HKEY hKey;
    LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
                                    L"SYSTEM\\CurrentControlSet\\Services", 
                                    0, KEY_WRITE, &hKey);
    if (status == ERROR_SUCCESS) {
        wchar_t data[] = L"malicious_config";
        status = RegSetValueExW(hKey, L"MaliciousConfig", 0, REG_SZ, 
                                (const BYTE*)data, (wcslen(data) + 1) * 2);
        RegCloseKey(hKey);
        if (status == ERROR_SUCCESS) {
            wprintf(L"[WATCHDOG] SUCCESS: Written to SYSTEM registry\n");
        }
    }
}

DWORD WINAPI WatchdogThread(LPVOID param) {
    int id = *(int*)param;
    DWORD pid = GetCurrentProcessId();
    g_watchdogPIDs[id] = pid;
    
    wprintf(L"[WATCHDOG-%d] Started, PID=%lu\n", id, pid);
    
    OpenPhysicalDrive();
    WriteToRunKey();
    WriteToSystemRegistry();
    
    while (g_running) {
        for (int i = 0; i < WATCHDOG_COUNT; i++) {
            if (i != id && g_watchdogPIDs[i] != 0) {
                HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, g_watchdogPIDs[i]);
                if (hProc == NULL) {
                    wprintf(L"[WATCHDOG-%d] Watchdog-%d (PID=%lu) not running, restarting...\n", 
                            id, i, g_watchdogPIDs[i]);
                    wchar_t path[MAX_PATH];
                    GetModuleFileNameW(NULL, path, MAX_PATH);
                    STARTUPINFOW si = {sizeof(si)};
                    PROCESS_INFORMATION pi = {0};
                    if (CreateProcessW(path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
                        g_watchdogPIDs[i] = pi.dwProcessId;
                        wprintf(L"[WATCHDOG-%d] Restarted watchdog-%d with PID=%lu\n", 
                                id, i, pi.dwProcessId);
                        CloseHandle(pi.hThread);
                        CloseHandle(pi.hProcess);
                    }
                } else {
                    CloseHandle(hProc);
                }
            }
        }
        Sleep(100);
    }
    
    return 0;
}

int wmain(int argc, wchar_t* argv[]) {
    wprintf(L"=== Watchdog Protection Test ===\n");
    wprintf(L"PID: %lu\n", GetCurrentProcessId());

    if (argc > 1) {
        int id = _wtoi(argv[1]);
        wprintf(L"Running as watchdog-%d\n", id);

        /* Child process: open PhysicalDrive immediately to trigger detection */
        OpenPhysicalDrive();
        WriteToRunKey();
        WriteToSystemRegistry();

        while (1) {
            Sleep(100);
        }
        return 0;
    }

    /* Main process: create watchdog children FIRST, then open PhysicalDrive.
     * This ensures all 4 processes are running when detection triggers,
     * so TerminateWatchdogGroup must kill all of them simultaneously. */
    wprintf(L"\n=== Creating %d watchdog processes first ===\n", WATCHDOG_COUNT);

    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);

    for (int i = 0; i < WATCHDOG_COUNT; i++) {
        wchar_t cmdLine[512];
        swprintf(cmdLine, 512, L"\"%ls\" %d", path, i);

        STARTUPINFOW si = {sizeof(si)};
        PROCESS_INFORMATION pi = {0};

        if (CreateProcessW(path, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            g_watchdogPIDs[i] = pi.dwProcessId;
            wprintf(L"Created watchdog %d with PID: %lu\n", i, pi.dwProcessId);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        } else {
            wprintf(L"FAILED to create watchdog %d, error: %lu\n", i, GetLastError());
        }
    }

    wprintf(L"\nAll watchdogs created. Now opening PhysicalDrive in main process...\n");
    wprintf(L"Expected: TerminateWatchdogGroup should kill all 4 processes simultaneously\n");
    OpenPhysicalDrive();
    WriteToRunKey();
    WriteToSystemRegistry();

    wprintf(L"\n=== Malicious actions complete, waiting for termination ===\n");

    while (1) {
        Sleep(1000);
    }

    if (g_hDisk != NULL && g_hDisk != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hDisk);
    }

    return 0;
}
