#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")

void SimulateRemoteInjection() {
    const char* targetProc = "explorer.exe";
    printf("[MEMZ] Simulating remote thread injection into %s...\n", targetProc);
}

void SimulateBootloaderAttack() {
    printf("[MEMZ] Simulating bootloader modification...\n");
    HANDLE hDisk = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ, 
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk != INVALID_HANDLE_VALUE) {
        BYTE mbr[512] = {0};
        DWORD bytesRead;
        ReadFile(hDisk, mbr, 512, &bytesRead, NULL);
        CloseHandle(hDisk);
        printf("[MEMZ] Bootloader data read\n");
    }
}

void SimulateDeviceIoControl() {
    printf("[MEMZ] Simulating DeviceIoControl usage...\n");
    HANDLE hDisk = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ, 
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk != INVALID_HANDLE_VALUE) {
        DWORD bytesReturned;
        DeviceIoControl(hDisk, 0, NULL, 0, NULL, 0, &bytesReturned, NULL);
        CloseHandle(hDisk);
    }
}

void SimulateNtApiCalls() {
    printf("[MEMZ] Simulating NT API calls...\n");
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        FARPROC NtOpenFile = GetProcAddress(hNtdll, "NtOpenFile");
        FARPROC NtWriteFile = GetProcAddress(hNtdll, "NtWriteFile");
        if (NtOpenFile && NtWriteFile) {
            printf("[MEMZ] NT APIs loaded successfully\n");
        }
    }
}

int main() {
    printf("MEMZ Simulator - Demonstrating MEMZ-like PE characteristics\n");
    printf("Features: DeviceIoControl, NtOpenFile, NtWriteFile\n\n");
    
    const char* maliciousStrings[] = {
        "MBR_OVERWRITE",
        "BOOTLOADER_PAYLOAD",
        "REMOTE_INJECT",
        "PROCESS_HIJACK",
        "KERNEL_PATCH",
        NULL
    };
    
    for (int i = 0; maliciousStrings[i]; i++) {
        printf("[MEMZ] String present: %s\n", maliciousStrings[i]);
    }
    
    SimulateRemoteInjection();
    SimulateBootloaderAttack();
    SimulateDeviceIoControl();
    SimulateNtApiCalls();
    
    printf("\nWaiting for detection (30 seconds)...\n");
    for (int i = 0; i < 30; i++) {
        printf("  Waiting %d/30...\r", i+1);
        fflush(stdout);
        Sleep(1000);
    }
    printf("\n");
    
    return 0;
}
