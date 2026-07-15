#define UNICODE
#define _UNICODE

#include "response_center.h"
#include "daemon_core.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <aclapi.h>
#include <wchar.h>
#include <windows.h>
#include <tlhelp32.h>

#pragma comment(lib, "advapi32.lib")

void DeleteVirusCopies(const wchar_t* originalPath) {
    if (!originalPath || !originalPath[0]) return;
    
    wchar_t fileName[MAX_PATH] = {0};
    wchar_t* lastSlash = wcsrchr(originalPath, L'\\');
    if (lastSlash) {
        wcscpy(fileName, lastSlash + 1);
    } else {
        wcscpy(fileName, originalPath);
    }
    
    if (IsSelfProcessName(fileName)) {
        DaemonLog(L"[SAFETY] BLOCKED: DeleteVirusCopies skipping self process file %ls", fileName);
        return;
    }
    
    const wchar_t* searchPaths[] = {
        L"C:\\Users",
        L"C:\\ProgramData",
        L"C:\\Windows\\Temp",
        L"C:\\Temp",
        NULL
    };
    
    for (int i = 0; searchPaths[i]; i++) {
        wchar_t searchPattern[MAX_PATH] = {0};
        swprintf(searchPattern, MAX_PATH, L"%ls\\%ls", searchPaths[i], fileName);
        
        WIN32_FIND_DATAW findData;
        HANDLE hFind = FindFirstFileW(searchPattern, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                wchar_t fullPath[MAX_PATH] = {0};
                swprintf(fullPath, MAX_PATH, L"%ls\\%ls", searchPaths[i], findData.cFileName);
                
                if (wcscmp(fullPath, originalPath) != 0) {
                    DeleteFileW(fullPath);
                }
            } while (FindNextFileW(hFind, &findData));
            FindClose(hFind);
        }
    }
    
    const wchar_t* wildPatterns[] = {
        L"C:\\Users\\*\\AppData\\Roaming\\*.exe",
        L"C:\\Users\\*\\AppData\\Local\\Temp\\*.exe",
        NULL
    };
    
    for (int i = 0; wildPatterns[i]; i++) {
        WIN32_FIND_DATAW findData;
        HANDLE hFind = FindFirstFileW(wildPatterns[i], &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (wcscmp(findData.cFileName, fileName) == 0) {
                    wchar_t fullPath[MAX_PATH] = {0};
                    swprintf(fullPath, MAX_PATH, L"%ls\\%ls", searchPaths[i > 0 ? i - 1 : 0], findData.cFileName);
                    if (wcscmp(fullPath, originalPath) != 0) {
                        DeleteFileW(fullPath);
                    }
                }
            } while (FindNextFileW(hFind, &findData));
            FindClose(hFind);
        }
    }
}

static const wchar_t* g_actionNames[] = {
    L"None",
    L"Observe",
    L"Notify",
    L"LimitNetwork",
    L"SuspendThreads",
    L"SuspendProcess",
    L"Terminate",
    L"Quarantine",
    L"Delete",
    L"Blacklist",
    L"Restore",
    L"FullCleanup",
    L"RepeatedKill",
    L"WatchdogKill"
};

const wchar_t* ResponseCenterGetActionName(ResponseAction action) {
    if (action >= RESPONSE_NONE && action <= RESPONSE_WATCHDOG_KILL) {
        return g_actionNames[action];
    }
    return L"Unknown";
}

void TerminateAllThreads(DWORD pid) {
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) return;
    
    THREADENTRY32 te = {0};
    te.dwSize = sizeof(te);
    if (Thread32First(hThreadSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_TERMINATE, FALSE, te.th32ThreadID);
                if (hThread) {
                    TerminateThread(hThread, 1);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hThreadSnap, &te));
    }
    CloseHandle(hThreadSnap);
}

void TerminateProcessTree(DWORD pid) {
    wchar_t procName[260] = {0};
    
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    
    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                wcscpy(procName, pe.szExeFile);
            }
        } while (Process32NextW(hSnap, &pe));
    }
    
    if (pid == GetCurrentProcessId()) {
        CloseHandle(hSnap);
        return;
    }
    
    if (IsCriticalSystemProcess(procName)) {
        DaemonLog(L"[CRITICAL-PROTECT] BLOCKED: TerminateProcessTree for critical system process %ls pid=%lu", procName, pid);
        CloseHandle(hSnap);
        return;
    }
    
    if (IsSelfProcessName(procName)) {
        DaemonLog(L"[SELF-PROTECT] BLOCKED: TerminateProcessTree for self process %ls pid=%lu", procName, pid);
        CloseHandle(hSnap);
        return;
    }
    
    if (IsSystemProcessName(procName)) {
        DaemonLog(L"[SAFETY] BLOCKED: TerminateProcessTree for system process %ls pid=%lu", procName, pid);
        CloseHandle(hSnap);
        return;
    }
    
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ParentProcessID == pid) {
                TerminateProcessTree(pe.th32ProcessID);
            }
        } while (Process32NextW(hSnap, &pe));
    }
    
    TerminateAllThreads(pid);
    
    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProc) {
        TerminateProcess(hProc, 1);
        CloseHandle(hProc);
    }
    CloseHandle(hSnap);
}

void ForceDeleteFile(const wchar_t* path) {
    if (!path || !path[0]) return;
    
    DWORD attr = GetFileAttributesW(path);
    if (attr == INVALID_FILE_ATTRIBUTES) return;
    
    if (attr & FILE_ATTRIBUTE_READONLY) {
        SetFileAttributesW(path, attr & ~FILE_ATTRIBUTE_READONLY);
    }
    
    DeleteFileW(path);
    
    for (int i = 0; i < 10; i++) {
        if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
            break;
        }
        Sleep(100);
        DeleteFileW(path);
    }
}

BOOL ResponseCenterInit(ResponseCenter* rc, BOOL requireUserConfirm) {
    if (!rc) return FALSE;
    memset(rc, 0, sizeof(ResponseCenter));
    InitializeCriticalSection(&rc->cs);
    rc->hResponseEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    rc->requireUserConfirm = requireUserConfirm;
    return rc->hResponseEvent != NULL;
}

void ResponseCenterCleanup(ResponseCenter* rc) {
    if (!rc) return;
    EnterCriticalSection(&rc->cs);
    ResponseEntry* entry = rc->head;
    while (entry) {
        ResponseEntry* next = entry->next;
        free(entry);
        entry = next;
    }
    rc->head = NULL;
    rc->entryCount = 0;
    LeaveCriticalSection(&rc->cs);
    DeleteCriticalSection(&rc->cs);
    if (rc->hResponseEvent) {
        CloseHandle(rc->hResponseEvent);
        rc->hResponseEvent = NULL;
    }
}

BOOL ResponseCenterQueueResponse(ResponseCenter* rc, DWORD pid, const wchar_t* name,
                                 const wchar_t* imagePath, ResponseAction action,
                                 const wchar_t* reason) {
    if (!rc || pid == 0) return FALSE;
    EnterCriticalSection(&rc->cs);
    ResponseEntry** pp = &rc->head;
    while (*pp) {
        if ((*pp)->pid == pid && (*pp)->action == action && !(*pp)->executed) {
            LeaveCriticalSection(&rc->cs);
            return TRUE;
        }
        pp = &(*pp)->next;
    }
    ResponseEntry* entry = (ResponseEntry*)malloc(sizeof(ResponseEntry));
    if (!entry) {
        LeaveCriticalSection(&rc->cs);
        return FALSE;
    }
    memset(entry, 0, sizeof(ResponseEntry));
    entry->pid = pid;
    if (name && name[0]) {
        wcsncpy(entry->name, name, sizeof(entry->name) / sizeof(wchar_t) - 1);
        entry->name[sizeof(entry->name) / sizeof(wchar_t) - 1] = L'\0';
    } else {
        wcscpy(entry->name, L"unknown");
    }
    if (imagePath && imagePath[0]) {
        wcsncpy(entry->imagePath, imagePath, sizeof(entry->imagePath) / sizeof(wchar_t) - 1);
        entry->imagePath[sizeof(entry->imagePath) / sizeof(wchar_t) - 1] = L'\0';
    }
    entry->action = action;
    if (reason && reason[0]) {
        entry->reason = wcsdup(reason);
    }
    entry->timestamp = GetTickCount64();
    entry->executed = FALSE;
    if (action == RESPONSE_TERMINATE || action == RESPONSE_DELETE || 
        action == RESPONSE_QUARANTINE || action == RESPONSE_FULL_CLEANUP ||
        action == RESPONSE_REPEATED_KILL) {
        entry->userConfirmed = TRUE;
    } else {
        entry->userConfirmed = !rc->requireUserConfirm;
    }
    entry->next = NULL;
    *pp = entry;
    rc->entryCount++;
    LeaveCriticalSection(&rc->cs);
    SetEvent(rc->hResponseEvent);
    return TRUE;
}

BOOL ResponseLimitNetwork(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return FALSE;
    
    wchar_t imagePath[MAX_PATH] = {0};
    DWORD sz = MAX_PATH;
    QueryFullProcessImageNameW(hProcess, 0, imagePath, &sz);
    CloseHandle(hProcess);
    
    wchar_t ruleName[MAX_PATH] = {0};
    swprintf(ruleName, MAX_PATH, L"ProcessGuardian_Block_%lu", pid);
    
    HKEY hPolicy;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules", 0, KEY_WRITE, &hPolicy) == ERROR_SUCCESS) {
        wchar_t ruleValue[MAX_PATH * 4] = {0};
        swprintf(ruleValue, MAX_PATH * 4, 
            L"v2.22|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Profile=Any|App=%ls|Name=%ls|",
            imagePath, ruleName);
        
        RegSetValueExW(hPolicy, ruleName, 0, REG_SZ, (BYTE*)ruleValue, 
                       (DWORD)(wcslen(ruleValue) + 1) * sizeof(wchar_t));
        RegCloseKey(hPolicy);
        
        HANDLE hSvc = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (hSvc) {
            HANDLE hFirewall = OpenServiceW(hSvc, L"MpsSvc", SERVICE_ALL_ACCESS);
            if (hFirewall) {
                SERVICE_STATUS status;
                ControlService(hFirewall, SERVICE_CONTROL_STOP, &status);
                CloseServiceHandle(hFirewall);
            }
            CloseServiceHandle(hSvc);
        }
        
        return TRUE;
    }
    
    return FALSE;
}

BOOL ResponseSuspendProcess(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!hProcess) return FALSE;
    typedef DWORD (WINAPI *NtSuspendProcessFunc)(HANDLE);
    NtSuspendProcessFunc NtSuspendProcess = (NtSuspendProcessFunc)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSuspendProcess");
    if (!NtSuspendProcess) {
        CloseHandle(hProcess);
        return FALSE;
    }
    DWORD result = NtSuspendProcess(hProcess);
    CloseHandle(hProcess);
    return result == 0;
}

BOOL ResponseResumeProcess(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!hProcess) return FALSE;
    typedef DWORD (WINAPI *NtResumeProcessFunc)(HANDLE);
    NtResumeProcessFunc NtResumeProcess = (NtResumeProcessFunc)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtResumeProcess");
    if (!NtResumeProcess) {
        CloseHandle(hProcess);
        return FALSE;
    }
    DWORD result = NtResumeProcess(hProcess);
    CloseHandle(hProcess);
    return result == 0;
}

BOOL ResponseTerminateProcess(DWORD pid) {
    wchar_t procName[260] = {0};
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProc) {
        DWORD sz = MAX_PATH;
        QueryFullProcessImageNameW(hProc, 0, procName, &sz);
        CloseHandle(hProc);
        wchar_t* p = wcsrchr(procName, L'\\');
        if (p) wcscpy(procName, p + 1);
    } else {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = {0};
            pe.dwSize = sizeof(pe);
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    if (pe.th32ProcessID == pid) {
                        wcscpy(procName, pe.szExeFile);
                        break;
                    }
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
    }
    
    if (IsCriticalSystemProcess(procName)) {
        DaemonLog(L"[CRITICAL-PROTECT] BLOCKED: ResponseTerminateProcess for critical system process %ls (PID=%lu)", procName, pid);
        return FALSE;
    }
    
    if (IsSystemProcessName(procName)) {
        DaemonLog(L"[SAFETY] BLOCKED: ResponseTerminateProcess for system process %ls (PID=%lu)", procName, pid);
        return FALSE;
    }
    
    for (int i = 0; i < 5; i++) {
        TerminateProcessTree(pid);
        Sleep(50);
    }
    return TRUE;
}

BOOL ResponseQuarantine(DWORD pid, const wchar_t* imagePath) {
    if (!imagePath || !imagePath[0]) return FALSE;
    
    wchar_t procName[260] = {0};
    const wchar_t* p = wcsrchr(imagePath, L'\\');
    if (p) wcscpy(procName, p + 1);
    
    if (IsCriticalSystemProcess(procName)) {
        DaemonLog(L"[CRITICAL-PROTECT] BLOCKED: ResponseQuarantine for critical system process %ls (PID=%lu)", procName, pid);
        return FALSE;
    }
    
    if (IsSystemProcessName(procName)) {
        DaemonLog(L"[SAFETY] BLOCKED: ResponseQuarantine for system process %ls (PID=%lu)", procName, pid);
        return FALSE;
    }
    
    for (int i = 0; i < 5; i++) {
        TerminateProcessTree(pid);
        Sleep(50);
    }
    
    wchar_t quarantinePath[MAX_PATH] = {0};
    swprintf(quarantinePath, MAX_PATH, L"C:\\ProgramData\\ProcessGuardian\\quarantine\\%ls",
             wcsrchr(imagePath, L'\\') ? wcsrchr(imagePath, L'\\') + 1 : imagePath);
    CreateDirectoryW(L"C:\\ProgramData\\ProcessGuardian\\quarantine", NULL);
    
    for (int i = 0; i < 3; i++) {
        if (MoveFileW(imagePath, quarantinePath)) {
            return TRUE;
        }
        Sleep(100);
    }
    
    return FALSE;
}

BOOL ResponseDelete(DWORD pid, const wchar_t* imagePath) {
    wchar_t procName[260] = {0};
    if (imagePath && imagePath[0]) {
        const wchar_t* p = wcsrchr(imagePath, L'\\');
        if (p) wcscpy(procName, p + 1);
    } else {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = {0};
            pe.dwSize = sizeof(pe);
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    if (pe.th32ProcessID == pid) {
                        wcscpy(procName, pe.szExeFile);
                        break;
                    }
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
    }
    
    if (IsCriticalSystemProcess(procName)) {
        DaemonLog(L"[CRITICAL-PROTECT] BLOCKED: ResponseDelete for critical system process %ls (PID=%lu)", procName, pid);
        return FALSE;
    }
    
    if (IsSystemProcessName(procName)) {
        DaemonLog(L"[SAFETY] BLOCKED: ResponseDelete for system process %ls (PID=%lu)", procName, pid);
        return FALSE;
    }
    
    for (int i = 0; i < 10; i++) {
        TerminateAllThreads(pid);
        TerminateProcessTree(pid);
        Sleep(50);
    }
    
    if (imagePath && imagePath[0]) {
        ForceDeleteFile(imagePath);
        DeleteVirusCopies(imagePath);
    }
    
    return TRUE;
}

BOOL ResponseCenterExecuteResponse(ResponseCenter* rc, ResponseEntry* entry) {
    if (!rc || !entry || entry->executed) return FALSE;
    
    if (entry->pid == 0 || entry->pid == 4) {
        DaemonLog(L"[SAFETY-GUARD] BLOCKED: ResponseCenter skipping kernel process PID=%lu", entry->pid);
        return FALSE;
    }
    
    if (!entry->name || !entry->name[0] || _wcsicmp(entry->name, L"unknown") == 0) {
        if (entry->pid != 0) {
            DaemonLog(L"[SAFETY-GUARD] ALLOWED: Process with unknown name but valid PID=%lu", entry->pid);
        } else {
            DaemonLog(L"[SAFETY-GUARD] BLOCKED: ResponseCenter skipping process with unknown name PID=%lu", entry->pid);
            return FALSE;
        }
    }
    
    if (IsCriticalSystemProcess(entry->name)) {
        DaemonLog(L"[CRITICAL-PROTECT] BLOCKED: ResponseCenter skipping critical system process %ls (PID=%lu)", entry->name, entry->pid);
        return FALSE;
    }
    
    if (IsSystemProcessName(entry->name)) {
        DaemonLog(L"[SAFETY] BLOCKED: ResponseCenter skipping system process %ls (PID=%lu)", entry->name, entry->pid);
        return FALSE;
    }
    
    if (entry->imagePath && entry->imagePath[0]) {
        wchar_t signer[256] = {0};
        if (CheckFileSignature(entry->imagePath, signer, 256)) {
            DaemonLog(L"[SIGNATURE-PROTECT] BLOCKED: ResponseCenter skipping signed process PID=%lu name=%ls signer=%ls", 
                      entry->pid, entry->name, signer);
            return FALSE;
        }
    }
    
    BOOL result = FALSE;
    switch (entry->action) {
        case RESPONSE_LIMIT_NETWORK:
            result = ResponseLimitNetwork(entry->pid);
            break;
        case RESPONSE_SUSPEND_PROCESS:
            result = ResponseSuspendProcess(entry->pid);
            break;
        case RESPONSE_TERMINATE:
            result = ResponseTerminateProcess(entry->pid);
            break;
        case RESPONSE_QUARANTINE:
            result = ResponseQuarantine(entry->pid, entry->imagePath);
            break;
        case RESPONSE_DELETE:
            result = ResponseDelete(entry->pid, entry->imagePath);
            break;
        case RESPONSE_RESTORE:
            result = TRUE;
            break;
        case RESPONSE_NOTIFY:
        case RESPONSE_OBSERVE:
            result = TRUE;
            break;
        case RESPONSE_REPEATED_KILL:
            for (int i = 0; i < 10; i++) {
                TerminateAllThreads(entry->pid);
                TerminateProcessTree(entry->pid);
                Sleep(50);
            }
            if (entry->imagePath && entry->imagePath[0]) {
                ForceDeleteFile(entry->imagePath);
            }
            result = TRUE;
            break;
        case RESPONSE_WATCHDOG_KILL:
            DaemonLog(L"[WATCHDOG-KILL] Executing watchdog group termination for %ls (PID=%lu)", entry->name, entry->pid);
            for (int i = 0; i < 5; i++) {
                TerminateAllThreads(entry->pid);
                TerminateProcessTree(entry->pid);
                Sleep(100);
            }
            result = TRUE;
            break;
        case RESPONSE_FULL_CLEANUP:
            for (int i = 0; i < 10; i++) {
                TerminateAllThreads(entry->pid);
                TerminateProcessTree(entry->pid);
                Sleep(50);
            }
            if (entry->imagePath && entry->imagePath[0]) {
                ForceDeleteFile(entry->imagePath);
                DeleteVirusCopies(entry->imagePath);
                wchar_t dirPath[MAX_PATH] = {0};
                wcscpy(dirPath, entry->imagePath);
                wchar_t* lastSlash = wcsrchr(dirPath, L'\\');
                if (lastSlash) {
                    *lastSlash = L'\0';
                    RemoveDirectoryW(dirPath);
                }
            }
            result = TRUE;
            break;
        default:
            result = FALSE;
            break;
    }
    if (result) {
        entry->executed = TRUE;
    }
    return result;
}

BOOL ResponseCenterExecuteByPid(ResponseCenter* rc, DWORD pid, ResponseAction action,
                                 const wchar_t* reason) {
    if (!rc || pid == 0) return FALSE;
    EnterCriticalSection(&rc->cs);
    ResponseEntry* entry = rc->head;
    while (entry) {
        if (entry->pid == pid && entry->action == action) {
            LeaveCriticalSection(&rc->cs);
            return ResponseCenterExecuteResponse(rc, entry);
        }
        entry = entry->next;
    }
    LeaveCriticalSection(&rc->cs);
    if (ResponseCenterQueueResponse(rc, pid, NULL, NULL, action, reason)) {
        return ResponseCenterExecuteByPid(rc, pid, action, reason);
    }
    return FALSE;
}

void ResponseCenterProcessQueue(ResponseCenter* rc) {
    if (!rc) return;
    EnterCriticalSection(&rc->cs);
    ResponseEntry** pp = &rc->head;
    while (*pp) {
        ResponseEntry* entry = *pp;
        if (!entry->executed && entry->userConfirmed) {
            ResponseCenterExecuteResponse(rc, entry);
        }
        if (entry->executed) {
            *pp = entry->next;
            if (entry->reason) free((void*)entry->reason);
            free(entry);
            rc->entryCount--;
            continue;
        }
        pp = &entry->next;
    }
    LeaveCriticalSection(&rc->cs);
}

void ResponseCenterRemove(ResponseCenter* rc, DWORD pid) {
    if (!rc || pid == 0) return;
    EnterCriticalSection(&rc->cs);
    ResponseEntry** pp = &rc->head;
    while (*pp) {
        ResponseEntry* entry = *pp;
        if (entry->pid == pid) {
            *pp = entry->next;
            if (entry->reason) free((void*)entry->reason);
            free(entry);
            rc->entryCount--;
            break;
        }
        pp = &entry->next;
    }
    LeaveCriticalSection(&rc->cs);
}

void ResponseCenterPurgeOldEntries(ResponseCenter* rc, uint64_t maxAgeMs) {
    if (!rc) return;
    uint64_t now = GetTickCount64();
    EnterCriticalSection(&rc->cs);
    ResponseEntry** pp = &rc->head;
    while (*pp) {
        ResponseEntry* entry = *pp;
        if ((now - entry->timestamp) > maxAgeMs) {
            *pp = entry->next;
            if (entry->reason) free((void*)entry->reason);
            free(entry);
            rc->entryCount--;
            continue;
        }
        pp = &entry->next;
    }
    LeaveCriticalSection(&rc->cs);
}

void ResponseCenterDump(ResponseCenter* rc) {
    if (!rc) return;
    EnterCriticalSection(&rc->cs);
    ResponseEntry* entry = rc->head;
    while (entry) {
        wprintf(L"[ResponseCenter] PID=%lu Name=%ls Action=%ls Executed=%s Reason=%ls\n",
                entry->pid, entry->name, ResponseCenterGetActionName(entry->action),
                entry->executed ? L"true" : L"false",
                entry->reason ? entry->reason : L"none");
        entry = entry->next;
    }
    LeaveCriticalSection(&rc->cs);
}