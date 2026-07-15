#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <io.h>

#define SERVICE_NAME L"GuardianDaemon"
#define DAEMON_EXE L"trae_guardian_daemon.exe"
#define MUTEX_NAME L"Global\\TRAE_Guardian_Daemon_Mutex"
#define STOP_DAEMON_EVENT L"Global\\TRAE_Guardian_Stop_Event"

static SERVICE_STATUS g_status;
static SERVICE_STATUS_HANDLE g_handle;
static HANDLE g_stopEvent = NULL;

static void GetModuleDir(wchar_t* out, DWORD len) {
    GetModuleFileNameW(NULL, out, len);
    wchar_t* p = wcsrchr(out, L'\\');
    if (p) *p = L'\0';
}

static void WriteLog(const wchar_t* fmt, ...) {
    wchar_t dir[MAX_PATH];
    GetModuleDir(dir, MAX_PATH);
    /* Wrapper lives in bin\permission; data is in the parent bin directory */
    wchar_t* p = wcsrchr(dir, L'\\');
    if (p) *p = L'\0';
    wcscat(dir, L"\\data\\service_wrapper.log");
    FILE* f = _wfopen(dir, L"a");
    if (!f) return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    fwprintf(f, L"[%04d-%02d-%02d %02d:%02d:%02d] ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    va_list ap;
    va_start(ap, fmt);
    vfwprintf(f, fmt, ap);
    va_end(ap);
    fwprintf(f, L"\n");
    fclose(f);
}

static BOOL GetDaemonPath(wchar_t* out, DWORD len) {
    wchar_t dir[MAX_PATH];
    GetModuleDir(dir, MAX_PATH);
    
    wcscpy(out, dir);
    wcscat(out, L"\\");
    wcscat(out, DAEMON_EXE);
    if (_waccess(out, 0) == 0) return TRUE;
    
    wchar_t parentDir[MAX_PATH];
    wcscpy(parentDir, dir);
    wchar_t* p = wcsrchr(parentDir, L'\\');
    if (p) *p = L'\0';
    wcscpy(out, parentDir);
    wcscat(out, L"\\");
    wcscat(out, DAEMON_EXE);
    if (_waccess(out, 0) == 0) return TRUE;
    
    wchar_t grandparentDir[MAX_PATH];
    wcscpy(grandparentDir, dir);
    p = wcsrchr(grandparentDir, L'\\');
    if (p) *p = L'\0';
    p = wcsrchr(grandparentDir, L'\\');
    if (p) *p = L'\0';
    wcscpy(out, grandparentDir);
    wcscat(out, L"\\");
    wcscat(out, DAEMON_EXE);
    if (_waccess(out, 0) == 0) return TRUE;
    
    return FALSE;
}

static BOOL IsDaemonRunning(DWORD excludePid) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return FALSE;
    PROCESSENTRY32W pe;
    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);
    BOOL found = FALSE;
    wchar_t expectedPath[MAX_PATH];
    if (!GetDaemonPath(expectedPath, MAX_PATH)) {
        CloseHandle(hSnap);
        return FALSE;
    }
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, DAEMON_EXE) == 0 && pe.th32ProcessID != excludePid) {
                HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                if (hProc) {
                    wchar_t path[MAX_PATH];
                    DWORD len = MAX_PATH;
                    if (QueryFullProcessImageNameW(hProc, 0, path, &len)) {
                        if (_wcsicmp(path, expectedPath) == 0) {
                            found = TRUE;
                        }
                    }
                    CloseHandle(hProc);
                }
                if (found) break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return found;
}

static void KillDaemonByMutex(void) {
    HANDLE hMutex = OpenMutexW(MUTEX_ALL_ACCESS, FALSE, MUTEX_NAME);
    if (hMutex) {
        WriteLog(L"Found existing daemon mutex, acquiring to terminate old instance");
        CloseHandle(hMutex);
    }
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe;
    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);
    wchar_t expectedPath[MAX_PATH];
    if (!GetDaemonPath(expectedPath, MAX_PATH)) {
        CloseHandle(hSnap);
        return;
    }
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, DAEMON_EXE) == 0) {
                HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProc) {
                    wchar_t path[MAX_PATH];
                    DWORD len = MAX_PATH;
                    if (QueryFullProcessImageNameW(hProc, 0, path, &len)) {
                        if (_wcsicmp(path, expectedPath) == 0) {
                            TerminateProcess(hProc, 0);
                            WriteLog(L"Killed old daemon PID=%lu", pe.th32ProcessID);
                        }
                    }
                    CloseHandle(hProc);
                }
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    Sleep(500);
}

static BOOL StartDaemon(void) {
    KillDaemonByMutex();
    
    wchar_t dir[MAX_PATH];
    GetModuleDir(dir, MAX_PATH);
    
    WriteLog(L"Wrapper running from: %ls", dir);
    
    wchar_t exePath[MAX_PATH];
    BOOL found = FALSE;
    
    wcscpy(exePath, dir);
    wcscat(exePath, L"\\");
    wcscat(exePath, DAEMON_EXE);
    WriteLog(L"Trying path 1: %ls", exePath);
    if (_waccess(exePath, 0) == 0) {
        found = TRUE;
    }
    
    if (!found) {
        wchar_t parentDir[MAX_PATH];
        wcscpy(parentDir, dir);
        wchar_t* p = wcsrchr(parentDir, L'\\');
        if (p) *p = L'\0';
        wcscpy(exePath, parentDir);
        wcscat(exePath, L"\\");
        wcscat(exePath, DAEMON_EXE);
        WriteLog(L"Trying path 2 (parent): %ls", exePath);
        if (_waccess(exePath, 0) == 0) {
            found = TRUE;
        }
    }
    
    if (!found) {
        wchar_t grandparentDir[MAX_PATH];
        wcscpy(grandparentDir, dir);
        wchar_t* p = wcsrchr(grandparentDir, L'\\');
        if (p) *p = L'\0';
        p = wcsrchr(grandparentDir, L'\\');
        if (p) *p = L'\0';
        wcscpy(exePath, grandparentDir);
        wcscat(exePath, L"\\");
        wcscat(exePath, DAEMON_EXE);
        WriteLog(L"Trying path 3 (grandparent): %ls", exePath);
        if (_waccess(exePath, 0) == 0) {
            found = TRUE;
        }
    }
    
    if (!found) {
        WriteLog(L"ERROR: Daemon executable not found in any path");
        return FALSE;
    }
    
    WriteLog(L"Found daemon at: %ls", exePath);
    
    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};
    DWORD flags = CREATE_NEW_PROCESS_GROUP;
    
    wchar_t* p = wcsrchr(exePath, L'\\');
    if (p) *p = L'\0';
    WriteLog(L"Setting working directory to: %ls", exePath);
    
    wcscat(exePath, L"\\");
    wcscat(exePath, DAEMON_EXE);
    
    if (!CreateProcessW(exePath, NULL, NULL, NULL, FALSE, flags, NULL, dir, &si, &pi)) {
        DWORD err = GetLastError();
        WriteLog(L"CreateProcess failed: %lu", err);
        if (err == ERROR_FILE_NOT_FOUND) {
            WriteLog(L"File not found - checking if file exists: %d", _waccess(exePath, 0) == 0);
        } else if (err == ERROR_ACCESS_DENIED) {
            WriteLog(L"Access denied - SYSTEM may not have permission");
        }
        return FALSE;
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    WriteLog(L"Daemon started PID=%lu", pi.dwProcessId);
    return TRUE;
}

static void WINAPI ServiceCtrl(DWORD ctrl) {
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
        g_status.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_handle, &g_status);
        if (g_stopEvent) SetEvent(g_stopEvent);
    }
}

static void WINAPI ServiceMain(DWORD argc, LPWSTR* argv) {
    (void)argc; (void)argv;
    g_stopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    
    memset(&g_status, 0, sizeof(g_status));
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_status.dwCurrentState = SERVICE_START_PENDING;
    g_status.dwWin32ExitCode = 0;
    g_status.dwCheckPoint = 0;
    g_status.dwWaitHint = 5000;
    
    g_handle = RegisterServiceCtrlHandlerW(SERVICE_NAME, ServiceCtrl);
    if (!g_handle) return;
    SetServiceStatus(g_handle, &g_status);
    
    WriteLog(L"Service starting");
    StartDaemon();
    
    g_status.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_handle, &g_status);
    
    int restartCount = 0;
    const int maxRestarts = 3;
    const int restartDelayMs = 5000;
    
    while (WaitForSingleObject(g_stopEvent, 1000) == WAIT_TIMEOUT) {
        HANDLE hStopEvent = OpenEventW(EVENT_ALL_ACCESS, FALSE, STOP_DAEMON_EVENT);
        if (hStopEvent) {
            DWORD state = WaitForSingleObject(hStopEvent, 0);
            CloseHandle(hStopEvent);
            if (state == WAIT_OBJECT_0) {
                WriteLog(L"Stop event signaled, not restarting daemon");
                continue;
            }
        }
        
        if (!IsDaemonRunning(0)) {
            WriteLog(L"Daemon not running, restarting (%d/%d)", restartCount + 1, maxRestarts);
            if (restartCount < maxRestarts) {
                StartDaemon();
                restartCount++;
                Sleep(restartDelayMs);
            } else {
                WriteLog(L"Max restart attempts reached, stopping service");
                break;
            }
        } else {
            restartCount = 0;
        }
    }
    
    g_status.dwCurrentState = SERVICE_STOP_PENDING;
    SetServiceStatus(g_handle, &g_status);
    
    HANDLE hStopEvent = OpenEventW(EVENT_ALL_ACCESS, FALSE, STOP_DAEMON_EVENT);
    if (hStopEvent) {
        SetEvent(hStopEvent);
        CloseHandle(hStopEvent);
        WriteLog(L"Signaled stop event to daemon");
    }
    
    Sleep(3000);
    KillDaemonByMutex();
    
    g_status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_handle, &g_status);
    CloseHandle(g_stopEvent);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hInstance; (void)hPrevInstance; (void)lpCmdLine; (void)nCmdShow;
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    int result = wmain(argc, argv);
    if (argv) LocalFree(argv);
    return result;
}

int wmain(int argc, wchar_t** argv) {
    if (argc >= 2) {
        if (_wcsicmp(argv[1], L"run") == 0) {
            SERVICE_TABLE_ENTRYW ste[] = {
                { (LPWSTR)SERVICE_NAME, ServiceMain },
                { NULL, NULL }
            };
            StartServiceCtrlDispatcherW(ste);
            return 0;
        }
    }
    SERVICE_TABLE_ENTRYW ste[] = {
        { (LPWSTR)SERVICE_NAME, ServiceMain },
        { NULL, NULL }
    };
    StartServiceCtrlDispatcherW(ste);
    return 0;
}