#define UNICODE
#define _UNICODE

#include <windows.h>
#include <stdio.h>

unsigned char syscallStub[] = {
    0x48, 0x83, 0xEC, 0x28,     
    0x48, 0x89, 0x54, 0x24, 0x18, 
    0x48, 0x89, 0x4C, 0x24, 0x10, 
    0x48, 0x8B, 0x44, 0x24, 0x20, 
    0x0F, 0x05,              
    0x48, 0x83, 0xC4, 0x28,     
    0xC3                      
};

int main() {
    printf("Test Direct Syscall Program\n");
    printf("This program contains direct syscall instruction pattern (0F 05)\n");
    printf("It should be detected and terminated by the guardian daemon\n");
    printf("Press any key to continue...\n");
    getchar();

    SIZE_T stubSize = sizeof(syscallStub);
    LPVOID alloc = VirtualAlloc(NULL, stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!alloc) {
        printf("VirtualAlloc failed\n");
        return 1;
    }

    memcpy(alloc, syscallStub, stubSize);
    
    printf("Direct syscall stub allocated at: %p\n", alloc);
    printf("Waiting for detection...\n");

    while (1) {
        Sleep(1000);
        printf("Still running...\n");
    }

    return 0;
}