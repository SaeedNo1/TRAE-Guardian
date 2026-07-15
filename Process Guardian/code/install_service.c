#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#define SERVICE_NAME L"GuardianDaemon"
#define WRAPPER_EXE L"trae_guardian_service_wrapper.exe"
#define DAEMON_EXE L"trae_guardian_daemon.exe"

static void GetModuleDir(wchar_t* out, DWORD len) {
    GetModuleFileNameW(NULL, out, len);
    wchar_t* p = wcsrchr(out, L'\\');
    if (p) *p = L'\0';
}

static void WToA(const wchar_t* src, char* dst, int dstLen) {
    WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, dstLen, NULL, NULL);
}

static void GetLogPath(char* out, int len) {
    wchar_t dirW[MAX_PATH];
    GetModuleDir(dirW, MAX_PATH);
    wchar_t* p = wcsrchr(dirW, L'\\');
    if (p) *p = L'\0';
    wcscat(dirW, L"\\data\\install_service.log");
    WToA(dirW, out, len);
}

static void WriteLog(const char* fmt, ...) {
    char path[MAX_PATH];
    GetLogPath(path, MAX_PATH);
    FILE* f = fopen(path, "a");
    if (!f) return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fprintf(f, "\n");
    fclose(f);
}

static BOOL ServiceExists(SC_HANDLE hSCM, const wchar_t* name) {
    /* Try to open with START permission; marked-for-delete services cannot be opened this way */
    SC_HANDLE hSvc = OpenServiceW(hSCM, name, SERVICE_QUERY_STATUS | SERVICE_START);
    if (hSvc) {
        CloseServiceHandle(hSvc);
        return TRUE;
    }
    return FALSE;
}

static BOOL WaitForServiceDeleted(SC_HANDLE hSCM, const wchar_t* name, DWORD timeoutMs) {
    DWORD start = GetTickCount();
    while (GetTickCount() - start < timeoutMs) {
        if (!ServiceExists(hSCM, name)) return TRUE;
        Sleep(200);
    }
    return !ServiceExists(hSCM, name);
}

static void KillExistingDaemon(void) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe;
    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, DAEMON_EXE) == 0 ||
                _wcsicmp(pe.szExeFile, WRAPPER_EXE) == 0) {
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProc) {
                    TerminateProcess(hProc, 0);
                    CloseHandle(hProc);
                    char procNameA[260];
                    WToA(pe.szExeFile, procNameA, sizeof(procNameA));
                    WriteLog("Killed old process %s PID=%lu", procNameA, pe.th32ProcessID);
                }
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    Sleep(800);
}

static BOOL WaitForServiceState(SC_HANDLE hSvc, DWORD wanted, DWORD timeoutMs) {
    DWORD start = GetTickCount();
    while (GetTickCount() - start < timeoutMs) {
        SERVICE_STATUS status;
        if (QueryServiceStatus(hSvc, &status)) {
            if (status.dwCurrentState == wanted) return TRUE;
        }
        Sleep(500);
    }
    return FALSE;
}

static int DoInstall(void) {
    WriteLog("Install started");
    
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) {
        DWORD err = GetLastError();
        WriteLog("OpenSCManager failed: %lu", err);
        return err;
    }
    
    wchar_t dir[MAX_PATH];
    GetModuleDir(dir, MAX_PATH);
    wchar_t wrapperPath[MAX_PATH];
    wcscpy(wrapperPath, dir);
    wcscat(wrapperPath, L"\\");
    wcscat(wrapperPath, WRAPPER_EXE);
    /* Quote the path because it contains spaces ("Process Guardian") */
    wchar_t quotedWrapperPath[MAX_PATH + 4];
    quotedWrapperPath[0] = L'"';
    wcscpy(quotedWrapperPath + 1, wrapperPath);
    wcscat(quotedWrapperPath, L"\"");
    char wrapperPathA[MAX_PATH];
    WToA(wrapperPath, wrapperPathA, sizeof(wrapperPathA));
    WriteLog("Wrapper path: %s", wrapperPathA);
    
    KillExistingDaemon();
    
    SC_HANDLE hSvc = OpenServiceW(hSCM, SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (!hSvc) {
        hSvc = CreateServiceW(hSCM, SERVICE_NAME, L"TRAE Guardian Daemon",
                              SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                              SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                              quotedWrapperPath, NULL, NULL, NULL, NULL, NULL);
        if (!hSvc) {
            DWORD err = GetLastError();
            WriteLog("CreateService failed: %lu", err);
            CloseServiceHandle(hSCM);
            return err;
        }
        WriteLog("Service created");
    } else {
        WriteLog("Service already exists, deleting to ensure clean config");
        CloseServiceHandle(hSvc);
        hSvc = OpenServiceW(hSCM, SERVICE_NAME, SERVICE_ALL_ACCESS | DELETE);
        if (hSvc) {
            DeleteService(hSvc);
            CloseServiceHandle(hSvc);
        }
        WriteLog("Waiting for old service to be removed");
        if (!WaitForServiceDeleted(hSCM, SERVICE_NAME, 10000)) {
            WriteLog("Old service still not removed, cannot recreate");
            CloseServiceHandle(hSCM);
            return ERROR_SERVICE_MARKED_FOR_DELETE;
        }
        hSvc = CreateServiceW(hSCM, SERVICE_NAME, L"TRAE Guardian Daemon",
                              SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                              SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                              quotedWrapperPath, NULL, NULL, NULL, NULL, NULL);
        if (!hSvc) {
            DWORD err = GetLastError();
            WriteLog("CreateService after delete failed: %lu", err);
            CloseServiceHandle(hSCM);
            return err;
        }
        WriteLog("Service recreated");
    }
    
    if (!StartServiceW(hSvc, 0, NULL)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            WriteLog("Service already running");
        } else {
            WriteLog("StartService failed: %lu, recreating service", err);
            CloseServiceHandle(hSvc);
            hSvc = OpenServiceW(hSCM, SERVICE_NAME, SERVICE_ALL_ACCESS | DELETE);
            if (hSvc) {
                DeleteService(hSvc);
                CloseServiceHandle(hSvc);
            }
            WriteLog("Waiting for old service to be removed");
            if (!WaitForServiceDeleted(hSCM, SERVICE_NAME, 10000)) {
                WriteLog("Old service still not removed, cannot recreate");
                CloseServiceHandle(hSCM);
                return ERROR_SERVICE_MARKED_FOR_DELETE;
            }
            hSvc = CreateServiceW(hSCM, SERVICE_NAME, L"TRAE Guardian Daemon",
                                  SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                  SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                  quotedWrapperPath, NULL, NULL, NULL, NULL, NULL);
            if (!hSvc) {
                DWORD createErr = GetLastError();
                WriteLog("Recreate CreateService failed: %lu", createErr);
                CloseServiceHandle(hSCM);
                return createErr;
            }
            WriteLog("Service recreated with path: %s", wrapperPathA);
            if (!StartServiceW(hSvc, 0, NULL)) {
                DWORD startErr = GetLastError();
                WriteLog("StartService after recreate failed: %lu", startErr);
                CloseServiceHandle(hSvc);
                CloseServiceHandle(hSCM);
                return startErr;
            }
            WriteLog("Service start command sent after recreate");
        }
    } else {
        WriteLog("Service start command sent");
    }
    
    WaitForServiceState(hSvc, SERVICE_RUNNING, 15000);
    
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    WriteLog("Install finished");
    return 0;
}

static int DoUninstall(void) {
    WriteLog("Uninstall started");
    KillExistingDaemon();
    
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return GetLastError();
    
    SC_HANDLE hSvc = OpenServiceW(hSCM, SERVICE_NAME, SERVICE_STOP | DELETE);
    if (hSvc) {
        SERVICE_STATUS status;
        ControlService(hSvc, SERVICE_CONTROL_STOP, &status);
        WaitForServiceState(hSvc, SERVICE_STOPPED, 10000);
        DeleteService(hSvc);
        CloseServiceHandle(hSvc);
        WriteLog("Service deleted");
    }
    CloseServiceHandle(hSCM);
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        fwprintf(stderr, L"Usage: install_service.exe [install|uninstall]\n");
        return 1;
    }
    
    if (_wcsicmp(argv[1], L"install") == 0) {
        return DoInstall();
    } else if (_wcsicmp(argv[1], L"uninstall") == 0) {
        return DoUninstall();
    }
    
    fwprintf(stderr, L"Unknown command: %s\n", argv[1]);
    return 1;
}