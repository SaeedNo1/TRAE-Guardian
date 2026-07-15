#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <pid>\n", argv[0]);
        return 1;
    }
    DWORD pid = (DWORD)atoi(argv[1]);
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
    printf("Terminated pid=%lu\n", pid);
    return 0;
}