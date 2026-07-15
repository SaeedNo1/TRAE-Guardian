#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
    printf("[TEST] Process Injection Simulation\n");
    
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    if (!hProc) {
        printf("[FAIL] OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }
    printf("[OK] OpenProcess succeeded\n");
    
    LPVOID addr = VirtualAllocEx(hProc, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!addr) {
        printf("[FAIL] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return 1;
    }
    printf("[OK] VirtualAllocEx succeeded (RWX memory)\n");
    
    char payload[256] = "injected_payload";
    SIZE_T bytesWritten = 0;
    BOOL writeOk = WriteProcessMemory(hProc, addr, payload, sizeof(payload), &bytesWritten);
    if (!writeOk) {
        printf("[FAIL] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, addr, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }
    printf("[OK] WriteProcessMemory succeeded\n");
    
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL);
    if (!hThread) {
        printf("[FAIL] CreateRemoteThread failed: %lu\n", GetLastError());
    } else {
        printf("[OK] CreateRemoteThread succeeded\n");
        CloseHandle(hThread);
    }
    
    VirtualFreeEx(hProc, addr, 0, MEM_RELEASE);
    CloseHandle(hProc);
    
    printf("[TEST] Injection simulation completed - should be detected!\n");
    Sleep(5000);
    return 0;
}