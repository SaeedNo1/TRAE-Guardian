#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#pragma pack(push, 8)
typedef struct {
    wchar_t name[260];
    DWORD pid;
    BOOL isTree;
    BOOL isRepeated;
} ProtectedEntry;
#pragma pack(pop)

int main() {
    wchar_t dataPath[MAX_PATH];
    GetModuleFileNameW(NULL, dataPath, MAX_PATH);
    wchar_t* slash = wcsrchr(dataPath, L'\\');
    if (slash) *slash = L'\0';
    wcscat_s(dataPath, MAX_PATH, L"\\data\\config.dat");
    
    FILE* f = _wfopen(dataPath, L"wb");
    if (!f) {
        wprintf(L"Cannot open %ls\n", dataPath);
        return 1;
    }
    
    int count = 1;
    fwrite(&count, sizeof(int), 1, f);
    
    ProtectedEntry entry = {0};
    wcscpy_s(entry.name, 260, L"test_threat.exe");
    entry.pid = 0;
    entry.isTree = FALSE;
    entry.isRepeated = TRUE;
    
    fwrite(&entry, sizeof(ProtectedEntry), 1, f);
    fclose(f);
    
    wprintf(L"Created config.dat at %ls\n", dataPath);
    wprintf(L"ProtectedEntry size: %zu\n", sizeof(ProtectedEntry));
    wprintf(L"isRepeated: %d\n", entry.isRepeated);
    return 0;
}