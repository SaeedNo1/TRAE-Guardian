#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <ntstatus.h>

typedef NTSTATUS (NTAPI *NtQuerySystemInformationFunc)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NtQueryObjectFunc)(HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef struct {
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct {
    ULONG HandleCount;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

int main() {
    printf("Testing Handle Scan...\n");
    
    NtQuerySystemInformationFunc NtQuerySystemInformation = (NtQuerySystemInformationFunc)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    NtQueryObjectFunc NtQueryObject = (NtQueryObjectFunc)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");
    
    if (!NtQuerySystemInformation || !NtQueryObject) {
        printf("ERROR: NtQuerySystemInformation or NtQueryObject not found\n");
        return 1;
    }
    
    ULONG bufSize = 0x400000;
    BYTE* buf = (BYTE*)malloc(bufSize);
    if (!buf) {
        printf("ERROR: Memory allocation failed\n");
        return 1;
    }
    
    printf("Querying system handle information...\n");
    NTSTATUS status = NtQuerySystemInformation(16, buf, bufSize, &bufSize);
    while (status == 0xC0000004) {
        free(buf);
        bufSize *= 2;
        buf = (BYTE*)malloc(bufSize);
        if (!buf) {
            printf("ERROR: Memory reallocation failed\n");
            return 1;
        }
        status = NtQuerySystemInformation(16, buf, bufSize, &bufSize);
    }
    
    if (status != 0) {
        printf("ERROR: NtQuerySystemInformation failed, status=%lu\n", status);
        free(buf);
        return 1;
    }
    
    SYSTEM_HANDLE_INFORMATION* shi = (SYSTEM_HANDLE_INFORMATION*)buf;
    printf("Found %lu handles\n", shi->HandleCount);
    
    DWORD targetPid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe = {0};
        pe.dwSize = sizeof(pe);
        if (Process32First(hSnapshot, &pe)) {
            do {
                if (wcsstr(pe.szExeFile, L"test_threat")) {
                    targetPid = pe.th32ProcessID;
                    printf("Found test_threat.exe PID=%lu\n", targetPid);
                    break;
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    
    if (targetPid == 0) {
        printf("ERROR: test_threat.exe not found\n");
        free(buf);
        return 1;
    }
    
    HANDLE hProc = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetPid);
    if (!hProc) {
        printf("ERROR: OpenProcess failed for PID=%lu, error=%lu\n", targetPid, GetLastError());
        free(buf);
        return 1;
    }
    
    printf("Scanning handles for PID=%lu...\n", targetPid);
    for (ULONG i = 0; i < shi->HandleCount; i++) {
        if (shi->Handles[i].ProcessId != targetPid) continue;
        
        HANDLE hDup = NULL;
        if (DuplicateHandle(hProc, (HANDLE)(ULONG_PTR)shi->Handles[i].Handle, GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            wchar_t objName[512] = {0};
            DWORD retLen = 0;
            NTSTATUS qStatus = NtQueryObject(hDup, 1, objName, sizeof(objName), &retLen);
            if (qStatus == 0 && objName[0]) {
                printf("Handle %lu: %ls\n", shi->Handles[i].Handle, objName);
                if (wcsstr(objName, L"PhysicalDrive") || wcsstr(objName, L"Harddisk") || wcsstr(objName, L"Volume")) {
                    printf("FOUND DANGEROUS HANDLE!\n");
                }
            }
            CloseHandle(hDup);
        } else {
            printf("DuplicateHandle failed for handle %lu, error=%lu\n", shi->Handles[i].Handle, GetLastError());
        }
    }
    
    CloseHandle(hProc);
    free(buf);
    
    printf("Done!\n");
    return 0;
}