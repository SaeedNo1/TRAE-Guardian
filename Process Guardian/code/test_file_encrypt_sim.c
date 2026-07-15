#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[]) {
    printf("[TEST] File Encryption Simulation (Ransomware-like behavior)\n");
    
    char tempDir[MAX_PATH];
    GetTempPathA(MAX_PATH, tempDir);
    
    for (int i = 0; i < 20; i++) {
        char filePath[MAX_PATH];
        sprintf(filePath, "%stest_file_%d.txt", tempDir, i);
        
        HANDLE hFile = CreateFileA(filePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            char data[100];
            sprintf(data, "This is test file %d content", i);
            DWORD bytesWritten;
            WriteFile(hFile, data, strlen(data), &bytesWritten, NULL);
            CloseHandle(hFile);
            printf("[OK] Created file: %s\n", filePath);
        }
    }
    
    printf("[TEST] Created test files - now simulating encryption...\n");
    
    for (int i = 0; i < 20; i++) {
        char filePath[MAX_PATH];
        sprintf(filePath, "%stest_file_%d.txt", tempDir, i);
        
        HANDLE hFile = CreateFileA(filePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD fileSize = GetFileSize(hFile, NULL);
            if (fileSize > 0) {
                BYTE* buffer = (BYTE*)malloc(fileSize);
                if (buffer) {
                    DWORD bytesRead;
                    ReadFile(hFile, buffer, fileSize, &bytesRead, NULL);
                    
                    for (DWORD j = 0; j < bytesRead; j++) {
                        buffer[j] ^= 0xAA;
                    }
                    
                    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
                    DWORD bytesWritten;
                    WriteFile(hFile, buffer, bytesRead, &bytesWritten, NULL);
                    
                    free(buffer);
                }
            }
            CloseHandle(hFile);
            printf("[OK] Encrypted file: %s\n", filePath);
        }
    }
    
    printf("[TEST] File encryption simulation completed - should be detected!\n");
    Sleep(5000);
    return 0;
}