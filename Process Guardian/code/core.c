#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "core.h"

BOOL KillProcessById(DWORD pid, BOOL killTree) {
    if (pid == 0 || pid == 4) return FALSE;
    
    if (killTree) {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = {0};
            pe.dwSize = sizeof(PROCESSENTRY32W);
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    if (pe.th32ParentProcessID == pid) {
                        KillProcessById(pe.th32ProcessID, TRUE);
                    }
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
    }
    
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
        AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, 0);
        CloseHandle(hToken);
    }
    
    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProc) return FALSE;
    BOOL result = TerminateProcess(hProc, 1);
    CloseHandle(hProc);
    return result;
}

DWORD GetProcessIdByName(const wchar_t* name) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(PROCESSENTRY32W);
    DWORD pid = 0;
    
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    
    CloseHandle(hSnap);
    return pid;
}

BOOL KillProcessByName(const wchar_t* name, BOOL killTree) {
    DWORD pid = GetProcessIdByName(name);
    if (pid == 0) return FALSE;
    return KillProcessById(pid, killTree);
}

void EnumerateProcesses(ProcessEntry* entries, int* count) {
    *count = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    
    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(PROCESSENTRY32W);
    
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (*count < MAX_PROCESSES) {
                wcsncpy(entries[*count].name, pe.szExeFile, MAX_PATH_W - 1);
                entries[*count].name[MAX_PATH_W - 1] = L'\0';
                entries[*count].pid = pe.th32ProcessID;
                entries[*count].isTree = FALSE;
                entries[*count].isRepeated = FALSE;
                (*count)++;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    
    CloseHandle(hSnap);
}