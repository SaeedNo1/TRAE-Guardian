#include <windows.h>
#include <stdio.h>
#include <time.h>

#define NUM_TESTS 100
#define NUM_FILES 50

int main() {
    printf("Performance Test Starting...\n");
    printf("Running %d process creation tests and %d file operation tests\n", NUM_TESTS, NUM_FILES);
    
    clock_t start = clock();
    
    for (int i = 0; i < NUM_TESTS; i++) {
        STARTUPINFOW si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        
        wchar_t cmdLine[256];
        swprintf(cmdLine, 256, L"cmd.exe /c echo test%d", i);
        
        CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
        
        WaitForSingleObject(pi.hProcess, 1000);
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        if ((i + 1) % 10 == 0) {
            printf("Completed %d/%d process tests\n", i + 1, NUM_TESTS);
        }
    }
    
    for (int i = 0; i < NUM_FILES; i++) {
        wchar_t filePath[256];
        swprintf(filePath, 256, L"C:\\temp\\test_perf_%d.txt", i);
        
        CreateDirectoryW(L"C:\\temp", NULL);
        
        HANDLE hFile = CreateFileW(filePath, GENERIC_WRITE, 0, NULL, 
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            char data[1024];
            sprintf(data, "Test data for file %d\n", i);
            DWORD bytesWritten;
            WriteFile(hFile, data, strlen(data), &bytesWritten, NULL);
            CloseHandle(hFile);
        }
        
        DeleteFileW(filePath);
        
        if ((i + 1) % 10 == 0) {
            printf("Completed %d/%d file tests\n", i + 1, NUM_FILES);
        }
    }
    
    clock_t end = clock();
    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
    
    printf("Performance Test Completed!\n");
    printf("Total elapsed time: %.2f seconds\n", elapsed);
    printf("Average time per process: %.4f ms\n", (elapsed / NUM_TESTS) * 1000);
    printf("Average time per file operation: %.4f ms\n", (elapsed / NUM_FILES) * 1000);
    
    return 0;
}