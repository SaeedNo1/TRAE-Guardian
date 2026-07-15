#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <tlhelp32.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shlobj.h>

#pragma comment(lib, "ws2_32.lib")

#define TEST_NAME L"test_single.exe"
#define TEST_LOG L"C:\\tmp\\single_test.log"
#define DAEMON_PIPE L"\\\\.\\pipe\\GuardianAIAction"

static void LogResult(const wchar_t* scene, const wchar_t* result, const wchar_t* format, ...) {
    wchar_t details[4096];
    if (format) {
        va_list args;
        va_start(args, format);
        vswprintf(details, sizeof(details)/sizeof(wchar_t), format, args);
        va_end(args);
    } else {
        wcscpy(details, L"");
    }
    
    FILE* f = _wfopen(TEST_LOG, L"a");
    if (f) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fwprintf(f, L"[%04d-%02d-%02d %02d:%02d:%02d] [%ls] %ls - %ls\n",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                 result, scene, details);
        fclose(f);
    }
    wprintf(L"[%ls] %ls: %ls\n", result, scene, details);
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

static BOOL SendPipeCommand(const char* cmd) {
    HANDLE hPipe = CreateFileW(DAEMON_PIPE, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) return FALSE;
    DWORD written = 0;
    BOOL ok = WriteFile(hPipe, cmd, (DWORD)strlen(cmd), &written, NULL);
    if (ok) {
        char resp[4096] = {0};
        DWORD read = 0;
        ReadFile(hPipe, resp, sizeof(resp) - 1, &read, NULL);
    }
    CloseHandle(hPipe);
    return ok;
}

static void GetDaemonDataPath(wchar_t* out, DWORD len) {
    wchar_t appData[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, appData) == S_OK) {
        swprintf(out, len, L"%ls\\ProcessGuardian", appData);
    } else {
        GetModuleFileNameW(NULL, out, len);
        wchar_t* p = wcsrchr(out, L'\\');
        if (p) *p = L'\0';
    }
}

static void WriteDaemonLog(const wchar_t* format, ...) {
    wchar_t message[4096];
    va_list args;
    va_start(args, format);
    vswprintf(message, sizeof(message)/sizeof(wchar_t), format, args);
    va_end(args);
    
    wchar_t path[MAX_PATH];
    GetDaemonDataPath(path, MAX_PATH);
    wcscat(path, L"\\daemon.log");
    FILE* f = _wfopen(path, L"a");
    if (f) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fwprintf(f, L"[%04d-%02d-%02d %02d:%02d:%02d] %ls\n",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, message);
        fclose(f);
    }
}

static void WritePopupFlag(const wchar_t* procName, const wchar_t* path, const wchar_t* reason) {
    wchar_t flagPath[MAX_PATH];
    GetDaemonDataPath(flagPath, MAX_PATH);
    wcscat(flagPath, L"\\ai_confirmed_popup.flag");
    FILE* f = _wfopen(flagPath, L"w");
    if (f) {
        fwprintf(f, L"task=test_single\n");
        fwprintf(f, L"task_id=single001\n");
        fwprintf(f, L"proc=%ls\n", procName);
        fwprintf(f, L"path=%ls\n", path);
        fwprintf(f, L"reason=%ls\n", reason);
        fclose(f);
    }
}

static void TestPhysicalDriveAccess() {
    wprintf(L"\n=== Scene: PhysicalDrive Access (Real) ===\n");
    wprintf(L"Attempting to open PhysicalDrive0...\n");
    
    HANDLE hDrive = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                OPEN_EXISTING, 0, NULL);
    
    if (hDrive != INVALID_HANDLE_VALUE) {
        wprintf(L"SUCCESS: Opened PhysicalDrive0\n");
        WriteDaemonLog(L"[DANGEROUS] test_single.exe opened PhysicalDrive0 handle");
        WriteDaemonLog(L"[ATTACK] PID=%lu opened disk: \\Device\\Harddisk0\\DR0", GetCurrentProcessId());
        WritePopupFlag(L"test_single.exe", L"C:\\tmp\\test_single.exe", L"PhysicalDrive access");
        
        wprintf(L"Waiting 5 seconds for daemon response...\n");
        Sleep(5000);
        CloseHandle(hDrive);
        
        DWORD pid = FindProcessByName(TEST_NAME);
        if (pid == 0) {
            LogResult(L"PhysicalDrive Access", L"PASS", L"Process terminated by daemon");
        } else {
            LogResult(L"PhysicalDrive Access", L"PARTIAL", L"Process still running");
        }
    } else {
        LogResult(L"PhysicalDrive Access", L"SKIP", L"Cannot open PhysicalDrive (admin rights needed)");
    }
}

static void TestNetworkFlood() {
    wprintf(L"\n=== Scene: Network Flood (Real) ===\n");
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    
    SOCKET socks[50];
    int sockCount = 0;
    for (int i = 0; i < 50; i++) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
        if (s != INVALID_SOCKET) {
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(80);
            inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);
            connect(s, (struct sockaddr*)&addr, sizeof(addr));
            socks[sockCount++] = s;
        }
        Sleep(20);
    }
    
    wprintf(L"Opened %d connections\n", sockCount);
    WriteDaemonLog(L"[NETWORK-WARN] test_single.exe opened 50+ TCP connections");
    WriteDaemonLog(L"[FLOW-DANGER] PID=%lu excessive network flow", GetCurrentProcessId());
    
    wprintf(L"Waiting 5 seconds for daemon response...\n");
    Sleep(5000);
    
    for (int i = 0; i < sockCount; i++) {
        closesocket(socks[i]);
    }
    WSACleanup();
    
    DWORD pid = FindProcessByName(TEST_NAME);
    if (pid == 0) {
        LogResult(L"Network Flood", L"PASS", L"Process terminated by daemon");
    } else {
        LogResult(L"Network Flood", L"INFO", L"Connections opened and closed (check daemon.log)");
    }
}

static void TestRegistryTamper() {
    wprintf(L"\n=== Scene: Registry Tamper (Real) ===\n");
    HKEY hKey = NULL;
    LONG result = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run\\VirusTest",
                    0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    
    if (hKey) {
        RegSetValueExW(hKey, L"Malicious", 0, REG_SZ, (BYTE*)L"C:\\virus.exe", 
                       (DWORD)(wcslen(L"C:\\virus.exe") + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
        wprintf(L"SUCCESS: Modified HKCU Run key\n");
        
        WriteDaemonLog(L"[REGISTRY-CHANGE] Run key modified by test_single.exe");
        WriteDaemonLog(L"[ATTACK] PID=%lu modifying startup registry keys", GetCurrentProcessId());
        
        wprintf(L"Waiting 5 seconds for daemon response...\n");
        Sleep(5000);
        
        RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run\\VirusTest");
        
        DWORD pid = FindProcessByName(TEST_NAME);
        if (pid == 0) {
            LogResult(L"Registry Tamper", L"PASS", L"Process terminated by daemon");
        } else {
            LogResult(L"Registry Tamper", L"PARTIAL", L"Registry modified but process still running");
        }
    } else {
        LogResult(L"Registry Tamper", L"SKIP", L"Cannot create registry key");
    }
}

static void TestFileModification() {
    wprintf(L"\n=== Scene: Rapid File Modification (Ransomware) ===\n");
    wchar_t tempDir[MAX_PATH];
    GetTempPathW(MAX_PATH, tempDir);
    
    wprintf(L"Creating 60 files rapidly...\n");
    for (int i = 0; i < 60; i++) {
        wchar_t filePath[MAX_PATH];
        swprintf(filePath, MAX_PATH, L"%ls\\test_ransomware_%d.txt", tempDir, i);
        FILE* f = _wfopen(filePath, L"w");
        if (f) {
            fwprintf(f, L"encrypted_file_%d\n", i);
            fclose(f);
        }
        Sleep(20);
    }
    
    wprintf(L"Created 60 files\n");
    WriteDaemonLog(L"[FILE-ALERT] Rapid file modification detected - possible ransomware");
    WriteDaemonLog(L"[ATTACK] PID=%lu created 60+ files in short time", GetCurrentProcessId());
    
    wprintf(L"Waiting 5 seconds for daemon response...\n");
    Sleep(5000);
    
    for (int i = 0; i < 60; i++) {
        wchar_t filePath[MAX_PATH];
        swprintf(filePath, MAX_PATH, L"%ls\\test_ransomware_%d.txt", tempDir, i);
        DeleteFileW(filePath);
    }
    
    DWORD pid = FindProcessByName(TEST_NAME);
    if (pid == 0) {
        LogResult(L"File Modification", L"PASS", L"Process terminated by daemon");
    } else {
        LogResult(L"File Modification", L"INFO", L"Rapid file creation test completed");
    }
}

static void WatchdogMain(int id) {
    wchar_t myPath[MAX_PATH];
    GetModuleFileNameW(NULL, myPath, MAX_PATH);
    wchar_t targetName[260];
    swprintf(targetName, 260, L"test_single.exe");
    
    wprintf(L"Watchdog %d started, monitoring: %ls\n", id, targetName);
    
    while (TRUE) {
        Sleep(300);
        DWORD targetPid = FindProcessByName(targetName);
        if (targetPid == 0) {
            wprintf(L"Watchdog %d: Process terminated, restarting...\n", id);
            STARTUPINFOW si = {0};
            si.cb = sizeof(si);
            PROCESS_INFORMATION pi = {0};
            wchar_t cmdLine[MAX_PATH * 2];
            swprintf(cmdLine, MAX_PATH * 2, L"\"%ls\" watchdog %d", myPath, 3 - id);
            CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            Sleep(1000);
        }
    }
}

static void TestWatchdog() {
    wprintf(L"\n=== Scene: Multi-Process Watchdog ===\n");
    wchar_t myPath[MAX_PATH];
    GetModuleFileNameW(NULL, myPath, MAX_PATH);
    
    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi1 = {0}, pi2 = {0};
    
    wchar_t cmdLine1[MAX_PATH * 2];
    swprintf(cmdLine1, MAX_PATH * 2, L"\"%ls\" watchdog 1", myPath);
    CreateProcessW(NULL, cmdLine1, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi1);
    Sleep(500);
    
    wchar_t cmdLine2[MAX_PATH * 2];
    swprintf(cmdLine2, MAX_PATH * 2, L"\"%ls\" watchdog 2", myPath);
    CreateProcessW(NULL, cmdLine2, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi2);
    
    wprintf(L"Started watchdog processes: PID1=%lu PID2=%lu\n", pi1.dwProcessId, pi2.dwProcessId);
    CloseHandle(pi1.hProcess);
    CloseHandle(pi1.hThread);
    CloseHandle(pi2.hProcess);
    CloseHandle(pi2.hThread);
    
    WriteDaemonLog(L"[ATTACK] Multi-process watchdog detected");
    WriteDaemonLog(L"[REPEATED] test_single.exe added to repeated kill list");
    
    wprintf(L"Waiting 10 seconds for daemon to terminate watchdogs...\n");
    Sleep(10000);
    
    int runningCount = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        memset(&pe, 0, sizeof(pe));
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, TEST_NAME) == 0 && pe.th32ProcessID != GetCurrentProcessId()) {
                    runningCount++;
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    
    if (runningCount == 0) {
        LogResult(L"Watchdog", L"PASS", L"All watchdog processes terminated by daemon");
    } else {
        LogResult(L"Watchdog", L"FAIL", L"Watchdog processes still running (%d instances)", runningCount);
    }
}

static void TestAIPipeKill() {
    wprintf(L"\n=== Scene: AI Pipe Command (kill_pid) ===\n");
    char cmd[4096];
    snprintf(cmd, 4096, "{\"cmd\":\"kill_pid\",\"pid\":%lu}", GetCurrentProcessId());
    
    wprintf(L"Sending kill_pid command for PID=%lu\n", GetCurrentProcessId());
    
    if (SendPipeCommand(cmd)) {
        wprintf(L"Waiting 3 seconds for daemon response...\n");
        Sleep(3000);
        
        DWORD pid = FindProcessByName(TEST_NAME);
        if (pid == 0) {
            LogResult(L"AI Pipe Command", L"PASS", L"Process terminated by daemon via pipe");
        } else {
            LogResult(L"AI Pipe Command", L"PARTIAL", L"Pipe command sent but process still running");
        }
    } else {
        LogResult(L"AI Pipe Command", L"FAIL", L"Cannot connect to pipe");
    }
}

static void TestAIPipeRepeated() {
    wprintf(L"\n=== Scene: AI Pipe Command (repeated_kill) ===\n");
    char cmd[4096];
    snprintf(cmd, 4096, "{\"cmd\":\"repeated_kill\",\"name\":\"test_single.exe\",\"tree\":true}");
    
    wprintf(L"Sending repeated_kill command\n");
    
    if (SendPipeCommand(cmd)) {
        wprintf(L"Waiting 3 seconds for daemon response...\n");
        Sleep(3000);
        
        LogResult(L"AI Pipe Repeated Kill", L"INFO", L"Command sent (check daemon.log)");
    } else {
        LogResult(L"AI Pipe Repeated Kill", L"FAIL", L"Cannot connect to pipe");
    }
}

static void TestFakeETWLog() {
    wprintf(L"\n=== Scene: Fake ETW Log Injection ===\n");
    WriteDaemonLog(L"[ETW-PROCESS] New process created: test_single.exe PID=%lu", GetCurrentProcessId());
    WriteDaemonLog(L"[ETW-REGISTRY] test_single.exe SetValueKey: \\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malicious");
    WriteDaemonLog(L"[ETW-FILEIO] test_single.exe Write: C:\\WINDOWS\\system32\\cmd.exe");
    WriteDaemonLog(L"[ETW-IMAGE] test_single.exe ImageLoad: C:\\evil.dll");
    WriteDaemonLog(L"[ETW-ALERT] Multiple suspicious ETW events");
    
    wprintf(L"Waiting 3 seconds for daemon response...\n");
    Sleep(3000);
    
    DWORD pid = FindProcessByName(TEST_NAME);
    if (pid == 0) {
        LogResult(L"Fake ETW Log", L"PASS", L"Process terminated by daemon");
    } else {
        LogResult(L"Fake ETW Log", L"INFO", L"Fake ETW logs written (daemon checks real events)");
    }
}

static void TestFakeMBRTamper() {
    wprintf(L"\n=== Scene: MBR Tamper Fake Log ===\n");
    WriteDaemonLog(L"[DANGEROUS] test_single.exe modified MBR on PhysicalDrive0");
    WriteDaemonLog(L"[MBR-TAMPER] PID=%lu wrote 512 bytes to boot sector", GetCurrentProcessId());
    WriteDaemonLog(L"[ATTACK] Unsigned process accessing disk boot sector");
    WritePopupFlag(L"test_single.exe", L"C:\\tmp\\test_single.exe", L"MBR tampering");
    
    wprintf(L"Waiting 5 seconds for daemon response...\n");
    Sleep(5000);
    
    DWORD pid = FindProcessByName(TEST_NAME);
    if (pid == 0) {
        LogResult(L"MBR Tamper", L"PASS", L"Process terminated by daemon");
    } else {
        LogResult(L"MBR Tamper", L"PARTIAL", L"Fake MBR logs written (daemon checks real MBR)");
    }
}

static void TestFakeInjection() {
    wprintf(L"\n=== Scene: Process Injection Fake Log ===\n");
    WriteDaemonLog(L"[INJECT] test_single.exe opened explorer.exe with PROCESS_ALL_ACCESS");
    WriteDaemonLog(L"[ATTACK] PID=%lu called CreateRemoteThread on explorer.exe", GetCurrentProcessId());
    WritePopupFlag(L"test_single.exe", L"C:\\tmp\\test_single.exe", L"Process injection");
    
    wprintf(L"Waiting 3 seconds for daemon response...\n");
    Sleep(3000);
    
    DWORD pid = FindProcessByName(TEST_NAME);
    if (pid == 0) {
        LogResult(L"Process Injection", L"PASS", L"Process terminated by daemon");
    } else {
        LogResult(L"Process Injection", L"INFO", L"Fake injection logs written");
    }
}

static void ShowUsage() {
    wprintf(L"Usage: test_single.exe [scene]\n");
    wprintf(L"\nScenes:\n");
    wprintf(L"  1  - PhysicalDrive Access (Real)\n");
    wprintf(L"  2  - Network Flood (Real)\n");
    wprintf(L"  3  - Registry Tamper (Real)\n");
    wprintf(L"  4  - Rapid File Modification (Real)\n");
    wprintf(L"  5  - Multi-Process Watchdog\n");
    wprintf(L"  6  - AI Pipe Command (kill_pid)\n");
    wprintf(L"  7  - AI Pipe Command (repeated_kill)\n");
    wprintf(L"  8  - Fake ETW Log Injection\n");
    wprintf(L"  9  - Fake MBR Tamper Log\n");
    wprintf(L"  10 - Fake Process Injection Log\n");
    wprintf(L"  all - Run all scenes (not recommended)\n");
}

int main(int argc, char** argv) {
    if (argc >= 3 && strcmp(argv[1], "watchdog") == 0) {
        WatchdogMain(atoi(argv[2]));
        return 0;
    }
    
    CreateDirectoryW(L"C:\\tmp", NULL);
    
    if (argc < 2) {
        ShowUsage();
        return 0;
    }
    
    wprintf(L"========================================\n");
    wprintf(L"Single Scene Test Suite\n");
    wprintf(L"========================================\n\n");
    
    int scene = atoi(argv[1]);
    
    switch (scene) {
        case 1: TestPhysicalDriveAccess(); break;
        case 2: TestNetworkFlood(); break;
        case 3: TestRegistryTamper(); break;
        case 4: TestFileModification(); break;
        case 5: TestWatchdog(); break;
        case 6: TestAIPipeKill(); break;
        case 7: TestAIPipeRepeated(); break;
        case 8: TestFakeETWLog(); break;
        case 9: TestFakeMBRTamper(); break;
        case 10: TestFakeInjection(); break;
        default:
            wprintf(L"Unknown scene: %d\n", scene);
            ShowUsage();
            break;
    }
    
    wprintf(L"\n========================================\n");
    wprintf(L"Test completed.\n");
    wprintf(L"Test log: %ls\n", TEST_LOG);
    wprintf(L"========================================\n");
    
    return 0;
}