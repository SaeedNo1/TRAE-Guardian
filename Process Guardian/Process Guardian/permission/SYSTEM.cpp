#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>

static HMODULE g_hModule = NULL;

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    (void)lpReserved;
    if (dwReason == DLL_PROCESS_ATTACH) {
        g_hModule = hModule;
    }
    return TRUE;
}

static void GetModuleDir(wchar_t* out, DWORD len) {
    if (g_hModule) {
        GetModuleFileNameW(g_hModule, out, len);
    } else {
        GetModuleFileNameW(NULL, out, len);
    }
    wchar_t* p = wcsrchr(out, L'\\');
    if (p) *p = L'\0';
}

static void GetInstallServicePath(wchar_t* out, DWORD len) {
    GetModuleDir(out, len);
    wcscat(out, L"\\install_service.exe");
}

static BOOL KillProcessByPID(DWORD pid) {
    if (pid == 0 || pid == 4) return FALSE;
    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProc) {
        HANDLE hToken;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            TOKEN_PRIVILEGES tp;
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
            AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, 0);
            CloseHandle(hToken);
        }
        hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    }
    if (!hProc) return FALSE;
    BOOL result = TerminateProcess(hProc, 1);
    CloseHandle(hProc);
    return result;
}

static void KillExistingGuardian(void) {
    const wchar_t* names[] = {
        L"trae_guardian_daemon.exe",
        L"trae_guardian_service_wrapper.exe",
        NULL
    };
    for (int n = 0; names[n]; n++) {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) continue;
        PROCESSENTRY32W pe = {0};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, names[n]) == 0) {
                    KillProcessByPID(pe.th32ProcessID);
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    Sleep(800);
}

extern "C" __declspec(dllexport) BOOL RestartDaemon(HWND hwnd) {
    (void)hwnd;
    KillExistingGuardian();

    wchar_t installPath[MAX_PATH];
    GetInstallServicePath(installPath, MAX_PATH);

    SHELLEXECUTEINFOW sei = {0};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";
    sei.lpFile = installPath;
    sei.lpParameters = L"install";
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    sei.nShow = SW_HIDE;

    BOOL ok = ShellExecuteExW(&sei);
    if (ok && sei.hProcess) {
        WaitForSingleObject(sei.hProcess, 30000);
        DWORD exitCode = 0;
        if (GetExitCodeProcess(sei.hProcess, &exitCode)) {
            if (exitCode != 0) ok = FALSE;
        }
        CloseHandle(sei.hProcess);
    }

    if (ok) {
        Sleep(2000);
        
        SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (hSCM) {
            SC_HANDLE hService = OpenServiceW(hSCM, L"GuardianDaemon", SERVICE_START);
            if (hService) {
                StartServiceW(hService, 0, NULL);
                CloseHandle(hService);
            }
            CloseHandle(hSCM);
        }
        
        Sleep(1000);
        
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = {0};
            pe.dwSize = sizeof(pe);
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    if (_wcsicmp(pe.szExeFile, L"trae_guardian_daemon.exe") == 0) {
                        ok = TRUE;
                        break;
                    }
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
    }

    return ok;
}
