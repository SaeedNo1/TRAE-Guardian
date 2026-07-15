#include <windows.h>
#include <stdio.h>

typedef NTSTATUS (NTAPI *NtQueryObjectFunc)(HANDLE, ULONG, PVOID, ULONG, PULONG);

int main() {
    printf("Testing DuplicateHandle for PhysicalDrive...\n");
    
    HANDLE hDrive = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hDrive == INVALID_HANDLE_VALUE) {
        printf("Open PhysicalDrive0 failed: %lu\n", GetLastError());
        return 1;
    }
    printf("PhysicalDrive0 opened successfully, handle=%p\n", hDrive);
    
    DWORD pid = GetCurrentProcessId();
    printf("Current PID: %lu\n", pid);
    
    HANDLE hProc = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        printf("OpenProcess failed: %lu\n", GetLastError());
        CloseHandle(hDrive);
        return 1;
    }
    printf("OpenProcess succeeded\n");
    
    HANDLE hDup = NULL;
    BOOL result = DuplicateHandle(hProc, hDrive, GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS);
    if (!result) {
        printf("DuplicateHandle FAILED: %lu\n", GetLastError());
        CloseHandle(hProc);
        CloseHandle(hDrive);
        return 1;
    }
    printf("DuplicateHandle SUCCESS, duplicated handle=%p\n", hDup);
    
    NtQueryObjectFunc queryObj = (NtQueryObjectFunc)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");
    if (!queryObj) {
        printf("NtQueryObject not found\n");
        CloseHandle(hDup);
        CloseHandle(hProc);
        CloseHandle(hDrive);
        return 1;
    }
    
    wchar_t objName[512] = {0};
    DWORD retLen = 0;
    NTSTATUS status = queryObj(hDup, 1, objName, sizeof(objName), &retLen);
    printf("NtQueryObject status=0x%X, retLen=%lu\n", status, retLen);
    
    if (status == 0 && retLen >= 16) {
        USHORT length = *(USHORT*)objName;
        ULONG_PTR bufferPtr = *(ULONG_PTR*)((BYTE*)objName + 8);
        
        if (length > 0 && length < sizeof(objName)) {
            const wchar_t* actualName = NULL;
            if (bufferPtr >= (ULONG_PTR)objName && bufferPtr < (ULONG_PTR)((BYTE*)objName + sizeof(objName))) {
                actualName = (const wchar_t*)bufferPtr;
            } else {
                actualName = (wchar_t*)((BYTE*)objName + 16);
            }
            
            wprintf(L"Object name: %ls\n", actualName);
        }
    }
    
    CloseHandle(hDup);
    CloseHandle(hProc);
    CloseHandle(hDrive);
    printf("Test completed\n");
    return 0;
}
