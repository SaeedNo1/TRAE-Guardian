#include <windows.h>
#include <stdio.h>

int main(void) {
    printf("Background process PID=%lu\n", GetCurrentProcessId());
    fflush(stdout);
    Sleep(60000);
    return 0;
}