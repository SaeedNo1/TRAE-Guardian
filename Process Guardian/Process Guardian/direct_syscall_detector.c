#define UNICODE
#define _UNICODE

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DAEMON_LOG(message, ...) OutputDebugStringW(message)

static BOOL IsProcessSigned(DWORD pid) {
    wchar_t path[MAX_PATH] = {0};
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return FALSE;
    
    if (!GetProcessImageFileNameW(hProc, path, MAX_PATH)) {
        CloseHandle(hProc);
        return FALSE;
    }
    CloseHandle(hProc);
    
    WINTRUST_FILE_INFO fileInfo = {0};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = path;
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;
    
    GUID guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG result = WinVerifyTrust(NULL, &guid, &fileInfo);
    return (result == ERROR_SUCCESS);
}

static BOOL IsSystemModule(const wchar_t* modName) {
    static const wchar_t* systemModules[] = {
        L"ntdll.dll",
        L"kernel32.dll",
        L"kernelbase.dll",
        L"advapi32.dll",
        L"user32.dll",
        L"gdi32.dll",
        L"combase.dll",
        L"rpcrt4.dll",
        L"ucrtbase.dll",
        L"vcruntime140.dll",
        NULL
    };
    
    for (int i = 0; systemModules[i]; i++) {
        if (_wcsicmp(modName, systemModules[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

static BOOL PatchSyscallInstructions(HANDLE hProc, BYTE* buffer, SIZE_T size, LPVOID baseAddr) {
    BOOL patched = FALSE;
    
    for (SIZE_T i = 0; i < size - 1; i++) {
        if (buffer[i] == 0x0F) {
            if (buffer[i+1] == 0x05 || buffer[i+1] == 0x34 || buffer[i+1] == 0x35) {
                LPVOID patchAddr = (LPVOID)((uintptr_t)baseAddr + i);
                BYTE retOpcode = 0xC3;
                
                DWORD oldProtect = 0;
                if (VirtualProtectEx(hProc, patchAddr, 2, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    SIZE_T bytesWritten = 0;
                    if (WriteProcessMemory(hProc, patchAddr, &retOpcode, 1, &bytesWritten)) {
                        DAEMON_LOG(L"[SYSCALL-PATCH] Patched syscall instruction at %p with RET", patchAddr);
                        patched = TRUE;
                    }
                    VirtualProtectEx(hProc, patchAddr, 2, oldProtect, &oldProtect);
                }
                
                i++;
            }
        }
    }
    
    return patched;
}

static BOOL ScanProcessForSyscalls(DWORD pid, const wchar_t* name, const wchar_t* imagePath) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
    if (!hProc) return FALSE;
    
    HMODULE hMods[1024] = {0};
    DWORD cbNeeded = 0;
    
    if (!EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
        CloseHandle(hProc);
        return FALSE;
    }
    
    DWORD modCount = cbNeeded / sizeof(HMODULE);
    BOOL foundSyscall = FALSE;
    
    for (DWORD i = 0; i < modCount; i++) {
        wchar_t modName[MAX_PATH] = {0};
        if (!GetModuleFileNameExW(hProc, hMods[i], modName, MAX_PATH)) continue;
        
        const wchar_t* shortName = wcsrchr(modName, L'\\');
        if (shortName) shortName++;
        else shortName = modName;
        
        if (IsSystemModule(shortName)) continue;
        
        MODULEINFO modInfo = {0};
        if (!GetModuleInformation(hProc, hMods[i], &modInfo, sizeof(modInfo))) continue;
        
        if (modInfo.SizeOfImage == 0) continue;
        
        BYTE* buffer = (BYTE*)malloc(modInfo.SizeOfImage);
        if (!buffer) continue;
        
        SIZE_T bytesRead = 0;
        if (ReadProcessMemory(hProc, modInfo.lpBaseOfDll, buffer, modInfo.SizeOfImage, &bytesRead)) {
            for (SIZE_T j = 0; j < bytesRead - 1; j++) {
                if (buffer[j] == 0x0F) {
                    if (buffer[j+1] == 0x05 || buffer[j+1] == 0x34 || buffer[j+1] == 0x35) {
                        DAEMON_LOG(L"[SYSCALL-DETECT] Direct syscall pattern (0F 05/0F 34/0F 35) found in process: %ls (PID=%lu) module=%ls",
                                   name ? name : L"unknown", pid, modName);
                        
                        if (PatchSyscallInstructions(hProc, buffer, bytesRead, modInfo.lpBaseOfDll)) {
                            DAEMON_LOG(L"[SYSCALL-PATCH] Successfully patched all syscall instructions in module: %ls", modName);
                        }
                        
                        foundSyscall = TRUE;
                        break;
                    }
                }
            }
        }
        free(buffer);
        
        if (foundSyscall) break;
    }
    
    CloseHandle(hProc);
    return foundSyscall;
}

static DWORD WINAPI SyscallScanThread(LPVOID param) {
    HANDLE hStopEvent = (HANDLE)param;
    
    while (WaitForSingleObject(hStopEvent, 2000) == WAIT_TIMEOUT) {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) continue;
        
        PROCESSENTRY32W pe = {0};
        pe.dwSize = sizeof(PROCESSENTRY32W);
        
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;
                if (pe.th32ProcessID == GetCurrentProcessId()) continue;
                
                wchar_t procPath[MAX_PATH] = {0};
                HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                if (hProc) {
                    if (!GetProcessImageFileNameW(hProc, procPath, MAX_PATH)) {
                        wcsncpy(procPath, pe.szExeFile, MAX_PATH - 1);
                    }
                    CloseHandle(hProc);
                }
                
                if (IsProcessSigned(pe.th32ProcessID)) continue;
                
                ScanProcessForSyscalls(pe.th32ProcessID, pe.szExeFile, procPath);
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    
    return 0;
}

HANDLE StartDirectSyscallDetector(HANDLE hStopEvent) {
    return CreateThread(NULL, 0, SyscallScanThread, hStopEvent, 0, NULL);
}