#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#define TEST_LOG_FILE L"C:\\ProgramData\\ProcessGuardian\\test_results.log"

static void LogTestResult(const wchar_t* testName, BOOL passed, const wchar_t* details) {
    FILE* f = _wfopen(TEST_LOG_FILE, L"a");
    if (!f) {
        f = _wfopen(L"C:\\tmp\\test_results.log", L"a");
    }
    if (!f) return;
    
    SYSTEMTIME st;
    GetLocalTime(&st);
    fwprintf(f, L"[%04d-%02d-%02d %02d:%02d:%02d] [%ls] %ls - %ls\n",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
             passed ? L"PASS" : L"FAIL", testName, details ? details : L"");
    fclose(f);
    
    wprintf(L"[%ls] %ls: %ls\n", passed ? L"PASS" : L"FAIL", testName, details ? details : L"");
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
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return pid;
}

static BOOL TestDaemonRunning() {
    wprintf(L"\n=== Test 1: Daemon Process Running ===\n");
    DWORD pid = FindProcessByName(L"trae_guardian_daemon.exe");
    if (pid != 0) {
        wchar_t details[256];
        swprintf(details, 256, L"Daemon found with PID=%lu", pid);
        LogTestResult(L"Daemon Running", TRUE, details);
        return TRUE;
    } else {
        LogTestResult(L"Daemon Running", FALSE, L"Daemon process not found");
        return FALSE;
    }
}

static BOOL TestPopupNotifierExists() {
    wprintf(L"\n=== Test 2: Popup Notifier Exists ===\n");
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    wchar_t* p = wcsrchr(path, L'\\');
    if (p) *p = L'\0';
    wcscat(path, L"\\popup_notifier.exe");
    
    if (_waccess(path, 0) == 0) {
        LogTestResult(L"Popup Notifier Exists", TRUE, path);
        return TRUE;
    } else {
        LogTestResult(L"Popup Notifier Exists", FALSE, L"popup_notifier.exe not found");
        return FALSE;
    }
}

static BOOL TestPopupNotifierDetails() {
    wprintf(L"\n=== Test 3: Popup Notifier Arguments ===\n");
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    wchar_t* p = wcsrchr(path, L'\\');
    if (p) *p = L'\0';
    wcscat(path, L"\\popup_notifier.exe");
    
    wchar_t cmdLine[4096];
    swprintf(cmdLine, 4096, L"\"%ls\" -title \"Test Alert\" -type \"Malware Test\" -name \"test.exe\" -path \"C:\\test\\test.exe\" -evidence \"Test evidence\" -score 85", path);
    
    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};
    
    BOOL ok = CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS, NULL, NULL, &si, &pi);
    
    if (ok) {
        WaitForSingleObject(pi.hProcess, 3000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        LogTestResult(L"Popup Notifier Arguments", TRUE, L"Popup started successfully with detailed arguments");
        return TRUE;
    } else {
        wchar_t details[256];
        swprintf(details, 256, L"CreateProcess failed: %lu", GetLastError());
        LogTestResult(L"Popup Notifier Arguments", FALSE, details);
        return FALSE;
    }
}

static BOOL TestPhysicalDriveDetection() {
    wprintf(L"\n=== Test 4: PhysicalDrive Handle Detection ===\n");
    HANDLE hDrive = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ, 
                                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, 
                                OPEN_EXISTING, 0, NULL);
    
    if (hDrive != INVALID_HANDLE_VALUE) {
        CloseHandle(hDrive);
        LogTestResult(L"PhysicalDrive Access", TRUE, L"Successfully opened PhysicalDrive0 (this should trigger daemon detection)");
        Sleep(2000);
        return TRUE;
    } else {
        wchar_t details[256];
        swprintf(details, 256, L"Cannot open PhysicalDrive0: %lu (admin rights required)", GetLastError());
        LogTestResult(L"PhysicalDrive Access", FALSE, details);
        return FALSE;
    }
}

static BOOL TestRegistryMonitor() {
    wprintf(L"\n=== Test 5: Registry Monitor ===\n");
    HKEY hKey = NULL;
    LONG result = RegCreateKeyExW(HKEY_CURRENT_USER, 
                                  L"Software\\Microsoft\\Windows\\CurrentVersion\\Run\\TestGuardian",
                                  0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    
    if (result == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"TestValue", 0, REG_SZ, (BYTE*)L"test.exe", (DWORD)(wcslen(L"test.exe") + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
        
        RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run\\TestGuardian");
        
        LogTestResult(L"Registry Monitor", TRUE, L"Modified Run key (this should trigger daemon detection)");
        Sleep(1000);
        return TRUE;
    } else {
        wchar_t details[256];
        swprintf(details, 256, L"Registry operation failed: %lu", result);
        LogTestResult(L"Registry Monitor", FALSE, details);
        return FALSE;
    }
}

static BOOL TestConfigFileExists() {
    wprintf(L"\n=== Test 6: Configuration Files ===\n");
    wchar_t basePath[MAX_PATH];
    GetModuleFileNameW(NULL, basePath, MAX_PATH);
    wchar_t* p = wcsrchr(basePath, L'\\');
    if (p) *p = L'\0';
    
    wchar_t paths[3][MAX_PATH];
    swprintf(paths[0], MAX_PATH, L"%ls\\data\\config.dat", basePath);
    swprintf(paths[1], MAX_PATH, L"%ls\\data\\settings.ini", basePath);
    swprintf(paths[2], MAX_PATH, L"%ls\\data\\sys_backup\\mbr.snapshot", basePath);
    
    BOOL allExist = TRUE;
    for (int i = 0; i < 3; i++) {
        if (_waccess(paths[i], 0) != 0) {
            wchar_t details[256];
            swprintf(details, 256, L"Missing: %ls", paths[i]);
            LogTestResult(L"Configuration Files", FALSE, details);
            allExist = FALSE;
        }
    }
    
    if (allExist) {
        LogTestResult(L"Configuration Files", TRUE, L"All config files exist");
    }
    return allExist;
}

static BOOL TestNamedPipe() {
    wprintf(L"\n=== Test 7: Named Pipe Communication ===\n");
    HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\GuardianAIAction",
                               GENERIC_READ | GENERIC_WRITE, 0, NULL,
                               OPEN_EXISTING, 0, NULL);
    
    if (hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipe);
        LogTestResult(L"Named Pipe", TRUE, L"GuardianAIAction pipe is accessible");
        return TRUE;
    } else {
        LogTestResult(L"Named Pipe", FALSE, L"GuardianAIAction pipe not available");
        return FALSE;
    }
}

static BOOL TestMBRBackupExists() {
    wprintf(L"\n=== Test 8: MBR Backup ===\n");
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    wchar_t* p = wcsrchr(path, L'\\');
    if (p) *p = L'\0';
    wcscat(path, L"\\data\\sys_backup\\mbr.snapshot");
    
    if (_waccess(path, 0) == 0) {
        LogTestResult(L"MBR Backup", TRUE, L"MBR backup file exists");
        return TRUE;
    } else {
        LogTestResult(L"MBR Backup", FALSE, L"MBR backup file not found");
        return FALSE;
    }
}

int main(int argc, char** argv) {
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);
    wprintf(L"========================================\n");
    wprintf(L"TRAE Guardian Test Suite\n");
    wprintf(L"========================================\n\n");
    
    CreateDirectoryW(L"C:\\ProgramData\\ProcessGuardian", NULL);
    CreateDirectoryW(L"C:\\tmp", NULL);
    
    int passed = 0;
    int total = 0;
    
    if (TestDaemonRunning()) passed++;
    total++;
    
    if (TestPopupNotifierExists()) passed++;
    total++;
    
    if (TestPopupNotifierDetails()) passed++;
    total++;
    
    if (TestPhysicalDriveDetection()) passed++;
    total++;
    
    if (TestRegistryMonitor()) passed++;
    total++;
    
    if (TestConfigFileExists()) passed++;
    total++;
    
    if (TestNamedPipe()) passed++;
    total++;
    
    if (TestMBRBackupExists()) passed++;
    total++;
    
    wprintf(L"\n========================================\n");
    wprintf(L"Test Results: %d/%d passed\n", passed, total);
    wprintf(L"========================================\n");
    
    if (passed == total) {
        LogTestResult(L"Overall", TRUE, L"All tests passed");
        return 0;
    } else {
        LogTestResult(L"Overall", FALSE, L"Some tests failed");
        return 1;
    }
}