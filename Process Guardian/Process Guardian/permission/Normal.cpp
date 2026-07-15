#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

static void GetModuleDir(wchar_t* out, DWORD len) {
    GetModuleFileNameW(NULL, out, len);
    wchar_t* p = wcsrchr(out, L'\\');
    if (p) *p = L'\0';
}

static void GetDaemonPath(wchar_t* out, DWORD len) {
    GetModuleDir(out, len);
    wcscat(out, L"\\trae_guardian_daemon.exe");
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

    wchar_t daemonPath[MAX_PATH];
    GetDaemonPath(daemonPath, MAX_PATH);

    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};
    DWORD flags = CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;

    wchar_t cmd[MAX_PATH + 32];
    swprintf(cmd, MAX_PATH + 32, L"\"%s\" --hidden", daemonPath);

    BOOL ok = CreateProcessW(NULL, cmd, NULL, NULL, FALSE, flags, NULL, NULL, &si, &pi);
    if (ok) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    return ok;
}
