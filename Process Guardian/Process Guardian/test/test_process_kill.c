#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>

static void ListProcesses() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
        return;
    }
    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(hSnap, &pe)) {
        printf("Process32FirstW failed: %lu\n", GetLastError());
        CloseHandle(hSnap);
        return;
    }
    printf("PID\tName\n");
    printf("========================\n");
    do {
        if (pe.th32ProcessID != 0 && pe.th32ProcessID != 4) {
            printf("%lu\t%ls\n", pe.th32ProcessID, pe.szExeFile);
        }
    } while (Process32NextW(hSnap, &pe));
    CloseHandle(hSnap);
}

static void WaitAndBeKilled() {
    printf("\n[Test Mode] Waiting to be killed...\n");
    printf("Use another process to terminate this test program.\n");
    printf("PID: %lu\n", GetCurrentProcessId());
    printf("Press Ctrl+C to exit.\n");
    while (1) {
        Sleep(1000);
    }
}

int main(int argc, char** argv) {
    printf("=== Process Kill Test Tool ===\n");
    printf("This is a UNSIGNED test program for testing AI process termination detection.\n\n");

    if (argc == 1) {
        printf("Usage:\n");
        printf("  test_process_kill.exe list          - List all processes\n");
        printf("  test_process_kill.exe kill <pid>    - Kill a process by PID\n");
        printf("  test_process_kill.exe wait          - Wait to be killed (test target)\n");
        printf("  test_process_kill.exe killbyname <name> - Kill by process name\n");
        return 0;
    }

    if (_stricmp(argv[1], "list") == 0) {
        ListProcesses();
        return 0;
    }

    if (_stricmp(argv[1], "wait") == 0) {
        WaitAndBeKilled();
        return 0;
    }

    if (_stricmp(argv[1], "kill") == 0 && argc >= 3) {
        DWORD pid = (DWORD)atoi(argv[2]);
        printf("Attempting to terminate process PID=%lu...\n", pid);
        HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (!hProc) {
            printf("OpenProcess failed: %lu\n", GetLastError());
            return 1;
        }
        BOOL ok = TerminateProcess(hProc, 1);
        CloseHandle(hProc);
        if (!ok) {
            printf("TerminateProcess failed: %lu\n", GetLastError());
            return 1;
        }
        printf("SUCCESS: Terminated process PID=%lu\n", pid);
        printf("\nNote: This is an UNSIGNED test program. ");
        printf("If the target was a system/background process, ");
        printf("the daemon should detect this and send to AI for evaluation.\n");
        return 0;
    }

    if (_stricmp(argv[1], "killbyname") == 0 && argc >= 3) {
        wchar_t targetName[256];
        mbstowcs(targetName, argv[2], 256);
        
        printf("Searching for process: %s\n", argv[2]);
        
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) {
            printf("CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
            return 1;
        }
        
        PROCESSENTRY32W pe = {0};
        pe.dwSize = sizeof(pe);
        BOOL found = FALSE;
        
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, targetName) == 0) {
                    printf("Found process: %ls (PID=%lu)\n", pe.szExeFile, pe.th32ProcessID);
                    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if (hProc) {
                        TerminateProcess(hProc, 1);
                        CloseHandle(hProc);
                        printf("SUCCESS: Terminated %ls (PID=%lu)\n", pe.szExeFile, pe.th32ProcessID);
                        found = TRUE;
                    } else {
                        printf("Failed to open process %lu: %lu\n", pe.th32ProcessID, GetLastError());
                    }
                }
            } while (Process32NextW(hSnap, &pe));
        }
        
        CloseHandle(hSnap);
        
        if (!found) {
            printf("Process not found: %s\n", argv[2]);
            return 1;
        }
        
        printf("\nNote: This is an UNSIGNED test program. ");
        printf("If the target was a system/background process, ");
        printf("the daemon should detect this and send to AI for evaluation.\n");
        return 0;
    }

    printf("Invalid command. Use 'list', 'kill <pid>', 'killbyname <name>', or 'wait'.\n");
    return 1;
}