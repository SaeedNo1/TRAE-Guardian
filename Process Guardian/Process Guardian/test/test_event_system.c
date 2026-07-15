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
#include <winreg.h>

#define TEST_LOG L"C:\\tmp\\event_system_test.log"

static void Log(const wchar_t* format, ...) {
    wchar_t message[4096];
    va_list args;
    va_start(args, format);
    vswprintf(message, sizeof(message)/sizeof(wchar_t), format, args);
    va_end(args);
    
    FILE* f = _wfopen(TEST_LOG, L"a");
    if (!f) return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    fwprintf(f, L"[%04d-%02d-%02d %02d:%02d:%02d] %ls\n",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, message);
    fclose(f);
    wprintf(L"%ls\n", message);
}

static DWORD FindProcessByName(const wchar_t* name) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe;
    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return pid;
}

static BOOL IsDaemonRunning() {
    return FindProcessByName(L"trae_guardian_daemon.exe") != 0;
}

static void Test1_RegistryWrite() {
    Log(L"=== Test 1: Registry Write to Run Key ===");
    
    HKEY hKey;
    LONG result = RegCreateKeyExW(HKEY_CURRENT_USER, 
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    
    if (result != ERROR_SUCCESS) {
        Log(L"FAIL: Cannot open Run key, error=%ld", result);
        return;
    }
    
    wchar_t valueName[32];
    swprintf(valueName, 32, L"Test_%lu", GetCurrentProcessId());
    wchar_t valueData[MAX_PATH];
    swprintf(valueData, MAX_PATH, L"\"%ls\" --test", GetCommandLineW());
    
    result = RegSetValueExW(hKey, valueName, 0, REG_SZ, 
                           (const BYTE*)valueData, 
                           (wcslen(valueData) + 1) * sizeof(wchar_t));
    
    if (result == ERROR_SUCCESS) {
        Log(L"SUCCESS: Wrote to HKCU\\...\\Run\\%ls", valueName);
        Log(L"VALUE: %ls", valueData);
        Log(L"Daemon should detect this registry modification!");
        Log(L"Keeping registry value for 30 seconds...");
        
        Sleep(30000);
        
        RegDeleteValueW(hKey, valueName);
        Log(L"Cleanup: Removed test registry value");
    } else {
        Log(L"FAIL: RegSetValueExW failed, error=%ld", result);
    }
    
    RegCloseKey(hKey);
}

static void Test2_RegistryDelete() {
    Log(L"=== Test 2: Registry Delete ===");
    
    HKEY hKey;
    LONG result = RegCreateKeyExW(HKEY_CURRENT_USER, 
        L"SOFTWARE\\TRAE_Test",
        0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey, NULL);
    
    if (result != ERROR_SUCCESS) {
        Log(L"FAIL: Cannot create test key, error=%ld", result);
        return;
    }
    
    wchar_t testValue[] = L"test_data";
    result = RegSetValueExW(hKey, L"TestValue", 0, REG_SZ,
                           (const BYTE*)testValue,
                           (wcslen(testValue) + 1) * sizeof(wchar_t));
    
    if (result != ERROR_SUCCESS) {
        Log(L"FAIL: Cannot set test value, error=%ld", result);
        RegCloseKey(hKey);
        return;
    }
    
    Log(L"SUCCESS: Created test key and value");
    
    result = RegDeleteValueW(hKey, L"TestValue");
    if (result == ERROR_SUCCESS) {
        Log(L"SUCCESS: Deleted test value");
        Log(L"Daemon should detect registry deletion!");
        Sleep(3000);
    } else {
        Log(L"FAIL: RegDeleteValueW failed, error=%ld", result);
    }
    
    RegCloseKey(hKey);
    RegDeleteKeyW(HKEY_CURRENT_USER, L"SOFTWARE\\TRAE_Test");
}

static void Test3_SystemRegistryWrite() {
    Log(L"=== Test 3: System Registry Write (HKLM) ===");
    
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        Log(L"INFO: Can read HKLM Run key (no write access expected for non-admin)");
        RegCloseKey(hKey);
        
        result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
            L"SOFTWARE\\TRAE_Test_System",
            0, KEY_WRITE, &hKey);
        
        if (result == ERROR_SUCCESS) {
            wchar_t valueName[32];
            swprintf(valueName, 32, L"SystemTest_%lu", GetCurrentProcessId());
            result = RegSetValueExW(hKey, valueName, 0, REG_SZ,
                                   (const BYTE*)L"test", 8);
            
            if (result == ERROR_SUCCESS) {
                Log(L"SUCCESS: Wrote to HKLM\\SOFTWARE\\TRAE_Test_System");
                Log(L"Daemon should detect SYSTEM registry modification!");
                Sleep(3000);
                RegDeleteValueW(hKey, valueName);
            } else {
                Log(L"INFO: Cannot write to HKLM, error=%ld (expected without admin)", result);
            }
            RegCloseKey(hKey);
            RegDeleteKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\TRAE_Test_System");
        } else {
            Log(L"INFO: Cannot open HKLM for write, error=%ld (expected without admin)", result);
        }
    } else {
        Log(L"FAIL: Cannot read HKLM Run key, error=%ld", result);
    }
}

static void Test4_ProcessSpawn() {
    Log(L"=== Test 4: Process Spawn ===");
    
    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};
    
    wchar_t cmdLine[MAX_PATH] = L"cmd.exe /c echo Test Process Spawn";
    BOOL success = CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    
    if (success) {
        Log(L"SUCCESS: Created test process, PID=%lu", pi.dwProcessId);
        Log(L"Daemon should detect new process spawn!");
        
        WaitForSingleObject(pi.hProcess, 2000);
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        Log(L"Process completed");
    } else {
        Log(L"FAIL: CreateProcessW failed, error=%lu", GetLastError());
    }
}

static void Test5_ProcessChainSpawn() {
    Log(L"=== Test 5: Process Chain Spawn ===");
    
    for (int i = 0; i < 3; i++) {
        STARTUPINFOW si = {0};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi = {0};
        
        wchar_t cmdLine[MAX_PATH];
        swprintf(cmdLine, MAX_PATH, L"cmd.exe /c echo Chain spawn %d && timeout /t 1 /nobreak >nul", i);
        
        BOOL success = CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
        
        if (success) {
            Log(L"SUCCESS: Created chain process %d, PID=%lu", i, pi.dwProcessId);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            Log(L"FAIL: CreateProcessW failed for chain %d, error=%lu", i, GetLastError());
        }
        
        Sleep(500);
    }
    
    Log(L"Daemon should detect multiple process spawns!");
    Sleep(2000);
}

static void Test6_FileWrite() {
    Log(L"=== Test 6: File Write Activity ===");
    
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    wchar_t fileName[MAX_PATH];
    swprintf(fileName, MAX_PATH, L"%ls\\trae_test_%lu.tmp", tempPath, GetCurrentProcessId());
    
    FILE* f = _wfopen(fileName, L"w");
    if (f) {
        for (int i = 0; i < 100; i++) {
            fwprintf(f, L"Test line %d\n", i);
        }
        fclose(f);
        Log(L"SUCCESS: Wrote test file: %ls", fileName);
        Log(L"Daemon may detect file write activity!");
        
        Sleep(2000);
        
        DeleteFileW(fileName);
        Log(L"Cleanup: Removed test file");
    } else {
        Log(L"FAIL: Cannot create test file, error=%lu", GetLastError());
    }
}

static void Test7_SelfCopy() {
    Log(L"=== Test 7: Self Copy ===");
    
    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(NULL, selfPath, MAX_PATH);
    
    wchar_t copyPath[MAX_PATH];
    swprintf(copyPath, MAX_PATH, L"%ls_copy.exe", selfPath);
    
    BOOL success = CopyFileW(selfPath, copyPath, FALSE);
    
    if (success) {
        Log(L"SUCCESS: Copied self to: %ls", copyPath);
        Log(L"Daemon should detect self-copy behavior!");
        
        Sleep(2000);
        
        DeleteFileW(copyPath);
        Log(L"Cleanup: Removed self-copy");
    } else {
        Log(L"FAIL: CopyFileW failed, error=%lu", GetLastError());
    }
}

static void Test8_SleepLoop() {
    Log(L"=== Test 8: Long Running Suspicious Process ===");
    Log(L"This process will run for 30 seconds to test observation mode");
    Log(L"PID=%lu", GetCurrentProcessId());
    
    for (int i = 0; i < 30; i++) {
        Sleep(1000);
        Log(L"Still running... (%d/30)", i + 1);
    }
    
    Log(L"Test process exiting");
}

static void PrintUsage() {
    wprintf(L"Usage: test_event_system.exe [test_number]\n");
    wprintf(L"Tests:\n");
    wprintf(L"  1 - Registry Write to Run Key\n");
    wprintf(L"  2 - Registry Delete\n");
    wprintf(L"  3 - System Registry Write (HKLM)\n");
    wprintf(L"  4 - Process Spawn\n");
    wprintf(L"  5 - Process Chain Spawn\n");
    wprintf(L"  6 - File Write Activity\n");
    wprintf(L"  7 - Self Copy\n");
    wprintf(L"  8 - Long Running Process\n");
    wprintf(L"  all - Run all tests\n");
}

int main(int argc, char** argv) {
    CreateDirectoryW(L"C:\\tmp", NULL);
    
    Log(L"========================================");
    Log(L"Event System Test Suite v1.0");
    Log(L"PID=%lu", GetCurrentProcessId());
    Log(L"Daemon running: %s", IsDaemonRunning() ? L"YES" : L"NO");
    Log(L"========================================");
    
    if (!IsDaemonRunning()) {
        Log(L"WARNING: Daemon is not running! Some tests may not trigger events.");
        Log(L"Start trae_guardian_daemon.exe for full test coverage.");
    }
    
    if (argc < 2) {
        PrintUsage();
        return 1;
    }
    
    const char* testNum = argv[1];
    
    if (strcmp(testNum, "all") == 0) {
        Test1_RegistryWrite();
        Sleep(1000);
        Test2_RegistryDelete();
        Sleep(1000);
        Test3_SystemRegistryWrite();
        Sleep(1000);
        Test4_ProcessSpawn();
        Sleep(1000);
        Test5_ProcessChainSpawn();
        Sleep(1000);
        Test6_FileWrite();
        Sleep(1000);
        Test7_SelfCopy();
    } else if (strcmp(testNum, "1") == 0) {
        Test1_RegistryWrite();
    } else if (strcmp(testNum, "2") == 0) {
        Test2_RegistryDelete();
    } else if (strcmp(testNum, "3") == 0) {
        Test3_SystemRegistryWrite();
    } else if (strcmp(testNum, "4") == 0) {
        Test4_ProcessSpawn();
    } else if (strcmp(testNum, "5") == 0) {
        Test5_ProcessChainSpawn();
    } else if (strcmp(testNum, "6") == 0) {
        Test6_FileWrite();
    } else if (strcmp(testNum, "7") == 0) {
        Test7_SelfCopy();
    } else if (strcmp(testNum, "8") == 0) {
        Test8_SleepLoop();
    } else {
        Log(L"ERROR: Unknown test number: %s", testNum);
        PrintUsage();
        return 1;
    }
    
    Log(L"========================================");
    Log(L"Test completed");
    Log(L"Check daemon.log for event processing");
    Log(L"========================================");
    
    return 0;
}