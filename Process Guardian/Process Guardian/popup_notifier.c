#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>
#include <wtsapi32.h>
#include <shellapi.h>
#include <sddl.h>

#pragma comment(lib, "wtsapi32.lib")

#define POPUP_MUTEX L"Global\\TRAE_Guardian_Popup_Mutex"

static void WriteLog(const wchar_t* fmt, ...) {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    wchar_t* p = wcsrchr(path, L'\\');
    if (p) *p = L'\0';
    wcscat(path, L"\\data\\popup_notifier.log");
    FILE* f = _wfopen(path, L"a");
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

static BOOL ShowPopupInSession(DWORD sessionId, const wchar_t* title, const wchar_t* message) {
    DWORD resp = 0;
    BOOL ok = WTSSendMessageW(
        WTS_CURRENT_SERVER_HANDLE,
        sessionId,
        (LPWSTR)title,
        (DWORD)(wcslen(title) * sizeof(wchar_t)),
        (LPWSTR)message,
        (DWORD)(wcslen(message) * sizeof(wchar_t)),
        MB_OK | MB_ICONERROR | MB_SYSTEMMODAL | MB_TOPMOST,
        30,
        &resp,
        FALSE
    );
    WriteLog(L"WTSSendMessage session=%lu ok=%d resp=%lu", sessionId, ok, resp);
    return ok;
}

static BOOL ShowPopupToAllSessions(const wchar_t* title, const wchar_t* message) {
    PWTS_SESSION_INFOW sessions = NULL;
    DWORD count = 0;
    BOOL ok = WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count);
    if (!ok) {
        WriteLog(L"WTSEnumerateSessions failed: %lu", GetLastError());
        return FALSE;
    }
    
    BOOL anyOk = FALSE;
    for (DWORD i = 0; i < count; i++) {
        DWORD sessionId = sessions[i].SessionId;
        if (sessions[i].State == WTSActive && sessionId != 0) {
            WriteLog(L"Found active session: %lu", sessionId);
            if (ShowPopupInSession(sessionId, title, message)) {
                anyOk = TRUE;
                break;
            }
        }
    }
    
    if (sessions) WTSFreeMemory(sessions);
    return anyOk;
}

static BOOL ShowLocalPopup(const wchar_t* title, const wchar_t* message) {
    int resp = MessageBoxW(NULL, message, title, MB_OK | MB_ICONERROR | MB_SYSTEMMODAL | MB_TOPMOST);
    WriteLog(L"MessageBox returned: %d", resp);
    return (resp == IDOK);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    HANDLE hMutex = CreateMutexW(NULL, TRUE, POPUP_MUTEX);
    if (!hMutex || GetLastError() == ERROR_ALREADY_EXISTS) {
        WriteLog(L"Popup already showing, skipping");
        if (hMutex) CloseHandle(hMutex);
        return 0;
    }
    
    wchar_t title[MAX_PATH] = L"TRAE Guardian Alert";
    wchar_t procName[256] = L"";
    wchar_t imagePath[MAX_PATH] = L"";
    wchar_t threatType[256] = L"";
    wchar_t evidence[1024] = L"";
    int score = 0;
    
    int argc;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv) {
        for (int i = 1; i < argc; i++) {
            if (i + 1 < argc && wcscmp(argv[i], L"-title") == 0) {
                wcsncpy(title, argv[i+1], MAX_PATH - 1);
                title[MAX_PATH - 1] = L'\0';
                i++;
            } else if (i + 1 < argc && wcscmp(argv[i], L"-name") == 0) {
                wcsncpy(procName, argv[i+1], 255);
                procName[255] = L'\0';
                i++;
            } else if (i + 1 < argc && wcscmp(argv[i], L"-path") == 0) {
                wcsncpy(imagePath, argv[i+1], MAX_PATH - 1);
                imagePath[MAX_PATH - 1] = L'\0';
                i++;
            } else if (i + 1 < argc && wcscmp(argv[i], L"-type") == 0) {
                wcsncpy(threatType, argv[i+1], 255);
                threatType[255] = L'\0';
                i++;
            } else if (i + 1 < argc && wcscmp(argv[i], L"-evidence") == 0) {
                wcsncpy(evidence, argv[i+1], 1023);
                evidence[1023] = L'\0';
                i++;
            } else if (i + 1 < argc && wcscmp(argv[i], L"-score") == 0) {
                score = _wtoi(argv[i+1]);
                i++;
            }
        }
        LocalFree(argv);
    }
    
    wchar_t message[4096];
    if (threatType[0] || procName[0]) {
        swprintf(message, 4096, L"════════════════════════════════════════\n"
            L"    TRAE Guardian - 安全威胁警报\n"
            L"════════════════════════════════════════\n\n"
            L"【威胁类型】: %ls\n"
            L"【进程名称】: %ls\n"
            L"【文件路径】: %ls\n"
            L"【风险评分】: %d/100\n\n"
            L"════════════════════════════════════════\n"
            L"【详细检测信息】:\n%s\n"
            L"════════════════════════════════════════\n\n"
            L"已自动执行防护措施以保护您的系统。",
            threatType[0] ? threatType : L"未知威胁",
            procName[0] ? procName : L"未知",
            imagePath[0] ? imagePath : L"未知",
            score,
            evidence[0] ? evidence : L"未提供详细信息");
    } else {
        wcscpy(message, L"════════════════════════════════════════\n"
            L"    TRAE Guardian - 安全威胁警报\n"
            L"════════════════════════════════════════\n\n"
            L"您的系统已检测到安全威胁。\n\n"
            L"已自动执行防护措施以保护您的系统。");
    }
    
    WriteLog(L"Popup requested: title=%ls type=%ls name=%ls score=%d", title, threatType, procName, score);
    
    BOOL isSystem = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        DWORD sz = 0;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &sz);
        if (sz > 0) {
            PTOKEN_USER tu = (PTOKEN_USER)malloc(sz);
            if (tu && GetTokenInformation(hToken, TokenUser, tu, sz, &sz)) {
                LPWSTR sidStr = NULL;
                if (ConvertSidToStringSidW(tu->User.Sid, &sidStr)) {
                    if (wcscmp(sidStr, L"S-1-5-18") == 0) isSystem = TRUE;
                    LocalFree(sidStr);
                }
            }
            if (tu) free(tu);
        }
        CloseHandle(hToken);
    }
    
    WriteLog(L"Running as SYSTEM: %d", isSystem);
    
    BOOL result = FALSE;
    
    if (isSystem) {
        WriteLog(L"Trying WTSSendMessage to all active sessions");
        result = ShowPopupToAllSessions(title, message);
        if (!result) {
            WriteLog(L"WTSSendMessage failed, trying local MessageBox");
            result = ShowLocalPopup(title, message);
        }
    } else {
        WriteLog(L"Trying local MessageBox");
        result = ShowLocalPopup(title, message);
    }
    
    WriteLog(L"Popup result: %d", result);
    
    if (hMutex) CloseHandle(hMutex);
    return result ? 0 : 1;
}