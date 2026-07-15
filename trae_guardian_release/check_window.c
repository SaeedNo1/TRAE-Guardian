#include <windows.h>
#include <stdio.h>

int main() {
    HWND hwnd = FindWindowW(NULL, L"Process Guardian");
    printf("FindWindow by title 'Process Guardian': %p\n", hwnd);
    if (hwnd) {
        printf("IsVisible: %d\n", IsWindowVisible(hwnd));
        wchar_t buf[256] = {0};
        GetWindowTextW(hwnd, buf, 256);
        printf("Window text: %ls\n", buf);
    }
    
    hwnd = FindWindowW(L"Qt6QWindowIcon", NULL);
    printf("\nFindWindow by class 'Qt6QWindowIcon': %p\n", hwnd);
    if (hwnd) {
        printf("IsVisible: %d\n", IsWindowVisible(hwnd));
        wchar_t buf[256] = {0};
        GetWindowTextW(hwnd, buf, 256);
        printf("Window text: %ls\n", buf);
    }
    
    hwnd = FindWindowW(L"Qt5QWindowIcon", NULL);
    printf("\nFindWindow by class 'Qt5QWindowIcon': %p\n", hwnd);
    if (hwnd) {
        printf("IsVisible: %d\n", IsWindowVisible(hwnd));
        wchar_t buf[256] = {0};
        GetWindowTextW(hwnd, buf, 256);
        printf("Window text: %ls\n", buf);
    }
    
    return 0;
}