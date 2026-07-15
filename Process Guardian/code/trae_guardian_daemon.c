#define UNICODE
#define _UNICODE

#include <windows.h>
#include <shellapi.h>
#include "daemon_core.h"

static BOOL IsRunningAsAdmin(void) {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID adminGroup = NULL;

    if (!AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        return FALSE;
    }

    if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
        isAdmin = FALSE;
    }

    FreeSid(adminGroup);
    return isAdmin;
}

static void RelaunchAsAdmin(void) {
    wchar_t exePath[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    SHELLEXECUTEINFOW sei = {0};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";
    sei.lpFile = exePath;
    sei.nShow = SW_HIDE;
    ShellExecuteExW(&sei);
}

static HANDLE g_hStopEvent = NULL;
static HANDLE g_hMutex = NULL;
static HANDLE g_hStopExternal = NULL;
DaemonState g_state;

static BOOL AcquireSingletonMutex(void) {
    g_hMutex = CreateMutexW(NULL, TRUE, DAEMON_MUTEX);
    if (g_hMutex == NULL) return FALSE;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(g_hMutex);
        g_hMutex = NULL;
        return FALSE;
    }
    return TRUE;
}

static BOOL WINAPI ConsoleHandlerRoutine(DWORD ctrlType) {
    (void)ctrlType;
    if (g_hStopEvent) SetEvent(g_hStopEvent);
    return TRUE;
}

static DWORD WINAPI StopEventWatcherThread(LPVOID param) {
    (void)param;
    if (g_hStopExternal) {
        WaitForSingleObject(g_hStopExternal, INFINITE);
        if (g_hStopEvent) SetEvent(g_hStopEvent);
    }
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    (void)argv;
    (void)argc;

    if (!IsRunningAsAdmin()) {
        RelaunchAsAdmin();
        return 0;
    }

    if (!AcquireSingletonMutex()) {
        return 1;
    }

    g_hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    SetConsoleCtrlHandler(ConsoleHandlerRoutine, TRUE);

    g_hStopExternal = OpenEventW(EVENT_ALL_ACCESS, FALSE, STOP_DAEMON_EVENT);
    if (g_hStopExternal) {
        HANDLE hThread = CreateThread(NULL, 0, StopEventWatcherThread, NULL, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }

    wchar_t basePath[MAX_PATH] = {0};
    DaemonGetBasePath(basePath, MAX_PATH);

    memset(&g_state, 0, sizeof(g_state));
    g_state.running = TRUE;
    g_state.hStopEvent = g_hStopEvent;

    DaemonLog(L"=== Trae Guardian Daemon starting ===");
    DaemonLog(L"Base path: %ls", basePath);

    DaemonLoadSettings(&g_state);
    DaemonLog(L"Settings loaded: checkInterval=%dms", g_state.checkInterval);

    CoreModules cm = {0};
    if (!CoreModulesInit(&cm, basePath)) {
        DaemonLog(L"FATAL: CoreModulesInit failed");
        return 1;
    }
    g_state.cm = &cm;

    DaemonLoadAll(&g_state);
    DaemonLoadDlls(&g_state);

    CoreModulesStartThreads(&cm);
    StartEtwMonitoring(&g_state);
    DaemonStartAiTaskThread(&g_state);
    StartAiActionPipeServer(&g_state);

    DaemonLog(L"=== Daemon started successfully ===");

    int interval = g_state.checkInterval > 0 ? g_state.checkInterval : 500;
    while (WaitForSingleObject(g_hStopEvent, interval) == WAIT_TIMEOUT) {
        DaemonTick(&g_state);
    }

    DaemonLog(L"=== Daemon shutting down ===");
    g_state.running = FALSE;

    StopEtwMonitoring();
    CoreModulesStopThreads(&cm);
    CoreModulesCleanup(&cm);

    if (g_hMutex) {
        ReleaseMutex(g_hMutex);
        CloseHandle(g_hMutex);
    }
    if (g_hStopEvent) CloseHandle(g_hStopEvent);
    if (g_hStopExternal) CloseHandle(g_hStopExternal);

    DaemonLog(L"=== Daemon stopped ===");
    return 0;
}