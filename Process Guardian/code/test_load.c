#include <windows.h>
#include <stdio.h>

int main() {
    const wchar_t* paths[] = {
        L"C:\\Users\\BaikerrNO1\\Documents\\trae_projects\\Process Guardian\\bin\\core\\service_manager.dll",
        L"C:\\Users\\BaikerrNO1\\Documents\\trae_projects\\Process Guardian\\bin\\AI\\ai_client.dll",
        NULL
    };
    for (int i = 0; paths[i]; ++i) {
        HMODULE h = LoadLibraryW(paths[i]);
        if (h) {
            wprintf(L"OK: %s\n", paths[i]);
            FreeLibrary(h);
        } else {
            wprintf(L"FAIL %lu: %s\n", GetLastError(), paths[i]);
        }
    }
    return 0;
}
