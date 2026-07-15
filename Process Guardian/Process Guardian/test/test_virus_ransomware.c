#include <windows.h>
#include <stdio.h>

#pragma comment(linker, "/MERGE:.text=.data")

unsigned char encrypted_data[] = {
    0x8B, 0x45, 0x08, 0x83, 0xC0, 0x01, 0x89, 0x45, 0x08, 0xEB, 0xF9,
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x53, 0x56, 0x57, 0x8B, 0xF9
};

int main() {
    const char* powershell = "powershell -encodedcommand SGVsbG8gV29ybGQ=";
    const char* deleteFile = "DeleteFile";
    const char* encrypt = "CryptEncrypt";
    const char* decrypt = "CryptDecrypt";
    
    printf("Test ransomware - PowerShell + encryption\n");
    
    SYSTEMTIME st;
    GetSystemTime(&st);
    
    Sleep(3000);
    return 0;
}