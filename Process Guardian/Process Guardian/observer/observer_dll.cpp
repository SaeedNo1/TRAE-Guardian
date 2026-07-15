#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#include "observer_dll.h"
#include <pdh.h>
#include <pdhmsg.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <mutex>
#include <atomic>

#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

#include <softpub.h>
#include <wintrust.h>

static void DllLog(const char* msg) {
    wchar_t path[MAX_PATH] = {0};
    GetModuleFileNameW(GetModuleHandleW(L"observer.dll"), path, MAX_PATH);
    wchar_t* p = wcsrchr(path, L'\\');
    if (p) *p = L'\0';
    wcscat(path, L"\\observer_dll_debug.log");
    char pathA[MAX_PATH];
    WideCharToMultiByte(CP_UTF8, 0, path, -1, pathA, MAX_PATH, NULL, NULL);
    FILE* f = fopen(pathA, "a");
    if (!f) return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] %s\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, msg);
    fclose(f);
}

static BOOL GetProcessFilePath(DWORD pid, WCHAR* out, DWORD outSize)
{
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return FALSE;
    DWORD len = outSize;
    BOOL ok = QueryFullProcessImageNameW(hProc, 0, out, &len);
    CloseHandle(hProc);
    return ok;
}

static BOOL GetProcessUserName(DWORD pid, WCHAR* out, DWORD outSize)
{
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return FALSE;
    HANDLE hToken = NULL;
    BOOL ok = FALSE;
    if (OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
        DWORD needed = 0;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &needed);
        if (needed > 0) {
            std::vector<BYTE> buf(needed);
            if (GetTokenInformation(hToken, TokenUser, buf.data(), needed, &needed)) {
                TOKEN_USER* tu = (TOKEN_USER*)buf.data();
                SID_NAME_USE use;
                WCHAR domain[256] = {0};
                DWORD domLen = 256;
                DWORD nameLen = outSize;
                if (LookupAccountSidW(NULL, tu->User.Sid, out, &nameLen, domain, &domLen, &use)) {
                    ok = TRUE;
                }
            }
        }
        CloseHandle(hToken);
    }
    CloseHandle(hProc);
    return ok;
}

static BOOL GetProcessSignerName(const WCHAR* filePath, WCHAR* out, DWORD outSize)
{
    out[0] = L'\0';
    WINTRUST_FILE_INFO fi = {0};
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = filePath;
    fi.hFile = NULL;
    fi.pgKnownSubject = NULL;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wd = {0};
    wd.cbStruct = sizeof(wd);
    wd.pPolicyCallbackData = NULL;
    wd.pSIPClientData = NULL;
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.hWVTStateData = NULL;
    wd.pwszURLReference = NULL;
    wd.dwUIContext = 0;

    LONG status = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wd);
    BOOL ok = (status == ERROR_SUCCESS);

    if (ok) {
        HCERTSTORE hStore = NULL;
        HCRYPTMSG hMsg = NULL;
        if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, filePath,
                             CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                             CERT_QUERY_FORMAT_FLAG_BINARY,
                             0, NULL, NULL, NULL, &hStore, &hMsg, NULL)) {
            DWORD signerCount = 0;
            DWORD cbCount = sizeof(DWORD);
            if (CryptMsgGetParam(hMsg, CMSG_SIGNER_COUNT_PARAM, 0, &signerCount, &cbCount)) {
                if (signerCount > 0) {
                    DWORD cb = 0;
                    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &cb);
                    if (cb > 0) {
                        std::vector<BYTE> sigInfo(cb);
                        if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, sigInfo.data(), &cb)) {
                            CMSG_SIGNER_INFO* psi = (CMSG_SIGNER_INFO*)sigInfo.data();
                            CERT_INFO ci = {0};
                            ci.Issuer = psi->Issuer;
                            ci.SerialNumber = psi->SerialNumber;
                            PCCERT_CONTEXT ctx = CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                                            0, CERT_FIND_SUBJECT_CERT, &ci, NULL);
                            if (ctx) {
                                DWORD len = CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, out, outSize);
                                if (len > 1) ok = TRUE;
                                CertFreeCertificateContext(ctx);
                            }
                        }
                    }
                }
            }
            CertCloseStore(hStore, 0);
            CryptMsgClose(hMsg);
        }
    }

    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wd);
    return ok;
}

static void GetProcessBaseName(DWORD pid, WCHAR* out, DWORD outSize)
{
    out[0] = L'\0';
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                wcsncpy(out, pe.szExeFile, outSize - 1);
                out[outSize - 1] = L'\0';
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

struct Observation {
    DWORD pid = 0;
    PDH_HQUERY query = NULL;
    PDH_HCOUNTER gpuUtil = NULL;
    PDH_HCOUNTER vram = NULL;

    ULONGLONG prevProcTotal = 0;
    ULONGLONG prevSysIdle = 0;
    ULONGLONG prevSysKernel = 0;
    ULONGLONG prevSysUser = 0;
    BOOL hasPrev = FALSE;

    ObserverProcessInfo info = {0};
    std::vector<ObserverStatsPoint> history;
    std::mutex mtx;
};

static std::mutex g_obsMutex;
static std::vector<Observation*> g_observations;
static std::atomic<BOOL> g_pdhReady(FALSE);

static Observation* FindObservation(DWORD pid)
{
    for (auto* o : g_observations) {
        if (o->pid == pid) return o;
    }
    return NULL;
}

static BOOL InitPdhCounters(Observation* o)
{
    if (PdhOpenQueryW(NULL, 0, &o->query) != ERROR_SUCCESS) return FALSE;
    if (PdhAddCounterW(o->query, L"\\GPU Engine(*)\\Utilization Percentage", 0, &o->gpuUtil) != ERROR_SUCCESS) {
        PdhCloseQuery(o->query);
        o->query = NULL;
        return FALSE;
    }
    if (PdhAddCounterW(o->query, L"\\GPU Adapter Memory(*)\\Dedicated Usage", 0, &o->vram) != ERROR_SUCCESS) {
        PdhCloseQuery(o->query);
        o->query = NULL;
        return FALSE;
    }
    g_pdhReady = TRUE;
    return TRUE;
}

static double CollectGpuUtil(Observation* o)
{
    if (!o->gpuUtil) return 0.0;
    DWORD bufSize = 0;
    DWORD itemCount = 0;
    PdhGetFormattedCounterArrayW(o->gpuUtil, PDH_FMT_DOUBLE, &bufSize, &itemCount, NULL);
    if (bufSize == 0) return 0.0;
    std::vector<BYTE> buf(bufSize);
    PDH_FMT_COUNTERVALUE_ITEM_W* items = (PDH_FMT_COUNTERVALUE_ITEM_W*)buf.data();
    if (PdhGetFormattedCounterArrayW(o->gpuUtil, PDH_FMT_DOUBLE, &bufSize, &itemCount, items) != ERROR_SUCCESS) return 0.0;

    double total = 0.0;
    wchar_t pidStr[32];
    _snwprintf(pidStr, 32, L"pid_%u", o->pid);
    for (DWORD i = 0; i < itemCount; ++i) {
        if (items[i].szName && wcsstr(items[i].szName, pidStr)) {
            total += items[i].FmtValue.doubleValue;
        }
    }
    if (total < 0) total = 0;
    if (total > 100) total = 100;
    return total;
}

static double CollectVram(Observation* o)
{
    if (!o->vram) return 0.0;
    DWORD bufSize = 0;
    DWORD itemCount = 0;
    PdhGetFormattedCounterArrayW(o->vram, PDH_FMT_DOUBLE, &bufSize, &itemCount, NULL);
    if (bufSize == 0) return 0.0;
    std::vector<BYTE> buf(bufSize);
    PDH_FMT_COUNTERVALUE_ITEM_W* items = (PDH_FMT_COUNTERVALUE_ITEM_W*)buf.data();
    if (PdhGetFormattedCounterArrayW(o->vram, PDH_FMT_DOUBLE, &bufSize, &itemCount, items) != ERROR_SUCCESS) return 0.0;

    double total = 0.0;
    wchar_t pidStr[32];
    _snwprintf(pidStr, 32, L"pid_%u", o->pid);
    for (DWORD i = 0; i < itemCount; ++i) {
        if (items[i].szName && wcsstr(items[i].szName, pidStr)) {
            total += items[i].FmtValue.doubleValue;
        }
    }
    return total / (1024.0 * 1024.0);
}

static void EnableDebugPrivilege(void)
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return;
    TOKEN_PRIVILEGES tp = {0};
    if (LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &tp.Privileges[0].Luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
    }
    CloseHandle(hToken);
}

static BOOL SampleViaDaemon(Observation* o, ObserverStatsPoint* point)
{
    DllLog("SampleViaDaemon trying");
    HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\GuardianAIAction",
                               GENERIC_READ | GENERIC_WRITE,
                               0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        DllLog("SampleViaDaemon pipe not available");
        return FALSE;
    }
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "{\"cmd\":\"sample_process\",\"pid\":%lu}", o->pid);
    DWORD written = 0;
    WriteFile(hPipe, cmd, (DWORD)strlen(cmd), &written, NULL);
    FlushFileBuffers(hPipe);
    char resp[4096] = {0};
    DWORD read = 0;
    ReadFile(hPipe, resp, sizeof(resp) - 1, &read, NULL);
    CloseHandle(hPipe);
    DllLog(resp);
    if (!strstr(resp, "\"ok\":true")) return FALSE;
    double cpu = 0.0, gpu = 0.0, mem = 0.0, vram = 0.0;
    const char* p = strstr(resp, "\"cpu\":");
    if (p) cpu = atof(p + 6);
    p = strstr(resp, "\"gpu\":");
    if (p) gpu = atof(p + 6);
    p = strstr(resp, "\"mem\":");
    if (p) mem = atof(p + 6);
    p = strstr(resp, "\"vram\":");
    if (p) vram = atof(p + 8);
    QueryPerformanceCounter(&point->timestamp);
    point->cpuPercent = cpu;
    point->gpuPercent = gpu;
    point->memMB = mem;
    point->vramMB = vram;
    return TRUE;
}

static BOOL SampleOnce(Observation* o, ObserverStatsPoint* point)
{
    char logBuf[256];
    snprintf(logBuf, sizeof(logBuf), "SampleOnce pid=%lu", o->pid);
    DllLog(logBuf);
    EnableDebugPrivilege();
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, o->pid);
    if (!hProc) {
        snprintf(logBuf, sizeof(logBuf), "OpenProcess failed pid=%lu err=%lu, try daemon", o->pid, GetLastError());
        DllLog(logBuf);
        if (SampleViaDaemon(o, point)) {
            DllLog("SampleOnce via daemon ok");
            return TRUE;
        }
        DllLog("SampleOnce via daemon failed");
        return FALSE;
    }

    FILETIME createTime, exitTime, kernelTime, userTime;
    ULARGE_INTEGER procKernel, procUser;
    BOOL ok = GetProcessTimes(hProc, &createTime, &exitTime, &kernelTime, &userTime);
    procKernel.LowPart = kernelTime.dwLowDateTime; procKernel.HighPart = kernelTime.dwHighDateTime;
    procUser.LowPart = userTime.dwLowDateTime; procUser.HighPart = userTime.dwHighDateTime;

    PROCESS_MEMORY_COUNTERS pmc = {0};
    BOOL memOk = GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc));
    CloseHandle(hProc);

    if (!ok) return FALSE;

    ULARGE_INTEGER sysIdle, sysKernel, sysUser;
    if (!GetSystemTimes((FILETIME*)&sysIdle, (FILETIME*)&sysKernel, (FILETIME*)&sysUser)) {
        sysIdle.QuadPart = sysKernel.QuadPart = sysUser.QuadPart = 0;
    }

    double cpu = 0.0;
    if (o->hasPrev) {
        ULONGLONG procDelta = (procKernel.QuadPart + procUser.QuadPart) - o->prevProcTotal;
        ULONGLONG sysTotalDelta = (sysKernel.QuadPart + sysUser.QuadPart) - (o->prevSysKernel + o->prevSysUser);
        if (sysTotalDelta > 0) {
            cpu = (double)procDelta / (double)sysTotalDelta * 100.0;
            if (cpu < 0) cpu = 0;
            if (cpu > 100) cpu = 100;
        }
    }

    o->prevProcTotal = procKernel.QuadPart + procUser.QuadPart;
    o->prevSysIdle = sysIdle.QuadPart;
    o->prevSysKernel = sysKernel.QuadPart;
    o->prevSysUser = sysUser.QuadPart;
    o->hasPrev = TRUE;

    QueryPerformanceCounter(&point->timestamp);
    point->cpuPercent = cpu;
    point->memMB = memOk ? (pmc.WorkingSetSize / (1024.0 * 1024.0)) : 0.0;

    if (o->query) {
        PdhCollectQueryData(o->query);
        point->gpuPercent = CollectGpuUtil(o);
        point->vramMB = CollectVram(o);
    } else {
        point->gpuPercent = 0.0;
        point->vramMB = 0.0;
    }

    snprintf(logBuf, sizeof(logBuf), "SampleOnce ok pid=%lu cpu=%.2f mem=%.2f", o->pid, point->cpuPercent, point->memMB);
    DllLog(logBuf);
    return TRUE;
}

static DWORD WINAPI ObserverThread(LPVOID param)
{
    (void)param;
    const DWORD intervalMs = 2000;
    while (TRUE) {
        Sleep(intervalMs);
        std::lock_guard<std::mutex> lock(g_obsMutex);
        for (auto* o : g_observations) {
            ObserverStatsPoint pt = {0};
            if (SampleOnce(o, &pt)) {
                std::lock_guard<std::mutex> olock(o->mtx);
                if (o->history.size() >= OBSERVER_MAX_HISTORY) {
                    o->history.erase(o->history.begin());
                }
                o->history.push_back(pt);
            }
        }
    }
    return 0;
}

static void EnsureThreadStarted()
{
    static HANDLE hThread = NULL;
    static std::mutex threadMutex;
    std::lock_guard<std::mutex> lock(threadMutex);
    if (!hThread) {
        hThread = CreateThread(NULL, 0, ObserverThread, NULL, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
}

OBSERVER_API BOOL __stdcall ObserveProcess(DWORD pid)
{
    char logBuf[256];
    snprintf(logBuf, sizeof(logBuf), "ObserveProcess pid=%lu", pid);
    DllLog(logBuf);
    if (pid == 0 || pid == 4) return FALSE;
    EnsureThreadStarted();
    std::lock_guard<std::mutex> lock(g_obsMutex);
    if (FindObservation(pid)) {
        DllLog("ObserveProcess already exists");
        return TRUE;
    }
    Observation* o = new Observation();
    o->pid = pid;
    InitPdhCounters(o);
    GetProcessBaseName(pid, o->info.processName, OBSERVER_MAX_NAME);
    GetProcessFilePath(pid, o->info.filePath, MAX_PATH);
    GetProcessUserName(pid, o->info.userName, OBSERVER_MAX_NAME);
    o->info.hasValidSignature = GetProcessSignerName(o->info.filePath, o->info.signerName, OBSERVER_MAX_NAME);
    o->info.pid = pid;
    QueryPerformanceCounter(&o->info.timestamp);

    /* Take one immediate sample so the UI shows data right away */
    ObserverStatsPoint pt = {0};
    if (SampleOnce(o, &pt)) {
        std::lock_guard<std::mutex> olock(o->mtx);
        o->history.push_back(pt);
    }

    g_observations.push_back(o);
    return TRUE;
}

OBSERVER_API BOOL __stdcall StopObservation(DWORD pid)
{
    std::lock_guard<std::mutex> lock(g_obsMutex);
    for (auto it = g_observations.begin(); it != g_observations.end(); ++it) {
        if ((*it)->pid == pid) {
            Observation* o = *it;
            if (o->query) PdhCloseQuery(o->query);
            delete o;
            g_observations.erase(it);
            return TRUE;
        }
    }
    return FALSE;
}

OBSERVER_API BOOL __stdcall StopAllObservations(void)
{
    std::lock_guard<std::mutex> lock(g_obsMutex);
    for (auto* o : g_observations) {
        if (o->query) PdhCloseQuery(o->query);
        delete o;
    }
    g_observations.clear();
    return TRUE;
}

OBSERVER_API BOOL __stdcall GetObserverStats(DWORD pid, ObserverStatsEx* out, DWORD size)
{
    char logBuf[256];
    snprintf(logBuf, sizeof(logBuf), "GetObserverStats pid=%lu", pid);
    DllLog(logBuf);
    if (!out || size < sizeof(ObserverStatsEx)) return FALSE;
    memset(out, 0, sizeof(ObserverStatsEx));
    std::lock_guard<std::mutex> lock(g_obsMutex);
    Observation* o = FindObservation(pid);
    if (!o) {
        DllLog("GetObserverStats observation not found");
        return FALSE;
    }

    {
        std::lock_guard<std::mutex> olock(o->mtx);
        out->info = o->info;
        out->historyCount = (int)o->history.size();
        snprintf(logBuf, sizeof(logBuf), "GetObserverStats historyCount=%d", out->historyCount);
        DllLog(logBuf);
        for (int i = 0; i < out->historyCount && i < OBSERVER_MAX_HISTORY; ++i) {
            out->history[i] = o->history[i];
        }
        if (out->historyCount > 0) {
            out->current = o->history.back();
        }
    }
    return TRUE;
}

OBSERVER_API BOOL __stdcall GetProcessStatsEx(DWORD pid, ObserverStatsEx* out, DWORD size)
{
    if (!out || size < sizeof(ObserverStatsEx)) return FALSE;
    if (!FindObservation(pid)) {
        if (!ObserveProcess(pid)) return FALSE;
    }
    ObserverStatsPoint pt = {0};
    Observation* o = NULL;
    {
        std::lock_guard<std::mutex> lock(g_obsMutex);
        o = FindObservation(pid);
    }
    if (o && SampleOnce(o, &pt)) {
        std::lock_guard<std::mutex> olock(o->mtx);
        if (o->history.size() >= OBSERVER_MAX_HISTORY) {
            o->history.erase(o->history.begin());
        }
        o->history.push_back(pt);
    }
    return GetObserverStats(pid, out, size);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    (void)hModule; (void)lpReserved;
    if (reason == DLL_PROCESS_DETACH) {
        StopAllObservations();
    }
    return TRUE;
}
