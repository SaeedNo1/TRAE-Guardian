#define WIN32_LEAN_AND_MEAN
#ifndef UNICODE
#define UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winreg.h>

static void TestProcessEnumeration(void) {
    printf("=== Process Enumeration Test ===\n");
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        printf("FAILED: CreateToolhelp32Snapshot returned INVALID_HANDLE_VALUE\n");
        printf("Error: %lu\n", GetLastError());
        return;
    }
    
    PROCESSENTRY32W pe;
    memset(&pe, 0, sizeof(PROCESSENTRY32W));
    pe.dwSize = sizeof(PROCESSENTRY32W);
    
    if (!Process32FirstW(hSnap, &pe)) {
        printf("FAILED: Process32FirstW failed\n");
        printf("Error: %lu\n", GetLastError());
        CloseHandle(hSnap);
        return;
    }
    
    int count = 0;
    do {
        count++;
    } while (Process32NextW(hSnap, &pe));
    
    CloseHandle(hSnap);
    printf("SUCCESS: Found %d processes\n", count);
}

static void TestServiceEnumeration(void) {
    printf("\n=== Service Enumeration Test ===\n");
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) {
        printf("FAILED: OpenSCManagerW failed\n");
        printf("Error: %lu\n", GetLastError());
        return;
    }
    
    DWORD bytesNeeded = 0, servicesReturned = 0;
    EnumServicesStatusW(hSCM, SERVICE_WIN32, SERVICE_STATE_ALL,
        NULL, 0, &bytesNeeded, &servicesReturned, NULL);
    
    if (GetLastError() != ERROR_MORE_DATA) {
        printf("FAILED: EnumServicesStatusW failed\n");
        printf("Error: %lu\n", GetLastError());
        CloseServiceHandle(hSCM);
        return;
    }
    
    LPENUM_SERVICE_STATUS pServices = (LPENUM_SERVICE_STATUS)malloc(bytesNeeded);
    if (!pServices) {
        printf("FAILED: Memory allocation failed\n");
        CloseServiceHandle(hSCM);
        return;
    }
    
    if (!EnumServicesStatusW(hSCM, SERVICE_WIN32, SERVICE_STATE_ALL,
        pServices, bytesNeeded, &bytesNeeded, &servicesReturned, NULL)) {
        printf("FAILED: EnumServicesStatusW failed\n");
        printf("Error: %lu\n", GetLastError());
        free(pServices);
        CloseServiceHandle(hSCM);
        return;
    }
    
    printf("SUCCESS: Found %lu services\n", servicesReturned);
    free(pServices);
    CloseServiceHandle(hSCM);
}

static void TestRegistryAccess(void) {
    printf("\n=== Registry Access Test ===\n");
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
        0, KEY_READ, &hKey);
    
    if (result != ERROR_SUCCESS) {
        printf("FAILED: RegOpenKeyExW failed\n");
        printf("Error: %ld\n", result);
        return;
    }
    
    wchar_t value[256];
    DWORD bufSize = sizeof(value);
    result = RegQueryValueExW(hKey, L"ProgramFilesDir", NULL, NULL, (LPBYTE)value, &bufSize);
    
    if (result != ERROR_SUCCESS) {
        printf("FAILED: RegQueryValueExW failed\n");
        printf("Error: %ld\n", result);
        RegCloseKey(hKey);
        return;
    }
    
    printf("SUCCESS: ProgramFilesDir = %ls\n", value);
    RegCloseKey(hKey);
}

static void TestDiskPartitions(void) {
    printf("\n=== Disk Partition Test ===\n");
    DWORD drives = GetLogicalDriveStringsW(0, NULL);
    if (drives == 0) {
        printf("FAILED: GetLogicalDriveStringsW failed\n");
        printf("Error: %lu\n", GetLastError());
        return;
    }
    
    wchar_t* driveStrings = (wchar_t*)malloc(drives);
    if (!driveStrings) {
        printf("FAILED: Memory allocation failed\n");
        return;
    }
    
    if (!GetLogicalDriveStringsW(drives, driveStrings)) {
        printf("FAILED: GetLogicalDriveStringsW failed\n");
        printf("Error: %lu\n", GetLastError());
        free(driveStrings);
        return;
    }
    
    int count = 0;
    wchar_t* p = driveStrings;
    while (*p) {
        UINT type = GetDriveTypeW(p);
        printf("Drive: %ls (Type: %u)\n", p, type);
        p += wcslen(p) + 1;
        count++;
    }
    
    printf("SUCCESS: Found %d drives\n", count);
    free(driveStrings);
}

static void TestDebugPrivilege(void) {
    printf("\n=== Debug Privilege Test ===\n");
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("FAILED: OpenProcessToken failed\n");
        printf("Error: %lu\n", GetLastError());
        return;
    }
    
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        printf("FAILED: LookupPrivilegeValueW failed\n");
        printf("Error: %lu\n", GetLastError());
        CloseHandle(hToken);
        return;
    }
    
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, 0)) {
        printf("FAILED: AdjustTokenPrivileges failed\n");
        printf("Error: %lu\n", GetLastError());
        CloseHandle(hToken);
        return;
    }
    
    printf("SUCCESS: Debug privilege enabled\n");
    CloseHandle(hToken);
}

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    printf("========================================\n");
    printf("TRAE Guardian - System Test Suite\n");
    printf("========================================\n\n");
    
    TestProcessEnumeration();
    TestServiceEnumeration();
    TestRegistryAccess();
    TestDiskPartitions();
    TestDebugPrivilege();
    
    printf("\n========================================\n");
    printf("All tests completed\n");
    printf("========================================\n");
    
    system("pause");
    return 0;
}