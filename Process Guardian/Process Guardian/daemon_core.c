#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include "daemon_core.h"
#include "etw_monitor.h"
#include "ai_client.h"
#include "thread_modules.h"
#include "pe_analysis.h"
#include <windows.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <time.h>
#include <io.h>
#include <shlobj.h>
#include <wintrust.h>
#include <softpub.h>
#include <psapi.h>
#include <sddl.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "observer/observer_dll.h"

static FILE* g_logFile = NULL;
static CRITICAL_SECTION g_cs;
static BOOL g_csInit = FALSE;
static CRITICAL_SECTION g_logCs;
static BOOL g_logCsInit = FALSE;
static long long g_logMaxBytes = 10 * 1024 * 1024; /* default 10 MB */

#define POPUP_COOLDOWN_SECONDS 7200
#define BEHAVIOR_COOLDOWN_SECONDS 60

static uint64_t HashStringFNV1a(const wchar_t* s) {
    if (!s || !s[0]) return 0;
    uint64_t hash = 14695981039346656037ULL;
    while (*s) {
        hash ^= (uint64_t)*s;
        hash *= 1099511628211ULL;
        s++;
    }
    return hash;
}

static uint32_t HashString(const wchar_t* s) {
    return (uint32_t)HashStringFNV1a(s);
}

typedef struct {
    uint32_t procHash;
    uint64_t lastPopupTime;
    uint64_t lastBehaviorWarnTime;
} CooldownEntry;

static CooldownEntry g_cooldowns[128] = {0};
static CRITICAL_SECTION g_cooldownCs;
static BOOL g_cooldownCsInit = FALSE;

#define SIGNATURE_CACHE_SIZE 256
typedef struct {
    uint64_t pathHash;
    BOOL isSigned;
    wchar_t signer[256];
    uint64_t timestamp;
} SignatureCacheEntry;
static SignatureCacheEntry g_signatureCache[SIGNATURE_CACHE_SIZE] = {0};
static CRITICAL_SECTION g_signatureCacheCs;
static BOOL g_signatureCacheCsInit = FALSE;

static void InitSignatureCacheCs(void) {
    if (!g_signatureCacheCsInit) {
        InitializeCriticalSection(&g_signatureCacheCs);
        g_signatureCacheCsInit = TRUE;
    }
}

BOOL CheckFileSignatureCached(const wchar_t* path, wchar_t* signer, DWORD signerSz) {
    if (!path || !path[0]) return FALSE;
    
    if (!g_signatureCacheCsInit) {
        InitializeCriticalSection(&g_signatureCacheCs);
        g_signatureCacheCsInit = TRUE;
    }
    
    uint64_t pathHash = HashStringFNV1a(path);
    
    EnterCriticalSection(&g_signatureCacheCs);
    for (int i = 0; i < SIGNATURE_CACHE_SIZE; i++) {
        if (g_signatureCache[i].pathHash == pathHash) {
            if ((GetTickCount64() - g_signatureCache[i].timestamp) < 3600000) {
                if (signer && signerSz > 0) {
                    wcsncpy(signer, g_signatureCache[i].signer, signerSz - 1);
                    signer[signerSz - 1] = L'\0';
                }
                LeaveCriticalSection(&g_signatureCacheCs);
                return g_signatureCache[i].isSigned;
            }
            break;
        }
    }
    LeaveCriticalSection(&g_signatureCacheCs);
    
    wchar_t tempSigner[256] = {0};
    BOOL result = CheckFileSignature(path, tempSigner, 256);
    
    EnterCriticalSection(&g_signatureCacheCs);
    int emptySlot = -1;
    uint64_t oldest = (uint64_t)-1;
    for (int i = 0; i < SIGNATURE_CACHE_SIZE; i++) {
        if (g_signatureCache[i].pathHash == 0) {
            emptySlot = i;
            break;
        }
        if (g_signatureCache[i].timestamp < oldest) {
            oldest = g_signatureCache[i].timestamp;
            emptySlot = i;
        }
    }
    if (emptySlot >= 0) {
        g_signatureCache[emptySlot].pathHash = pathHash;
        g_signatureCache[emptySlot].isSigned = result;
        wcsncpy(g_signatureCache[emptySlot].signer, tempSigner, 255);
        g_signatureCache[emptySlot].signer[255] = L'\0';
        g_signatureCache[emptySlot].timestamp = GetTickCount64();
    }
    LeaveCriticalSection(&g_signatureCacheCs);
    
    if (signer && signerSz > 0) {
        wcsncpy(signer, tempSigner, signerSz - 1);
        signer[signerSz - 1] = L'\0';
    }
    return result;
}

static void InitCooldownCs(void) {
    if (!g_cooldownCsInit) {
        InitializeCriticalSection(&g_cooldownCs);
        g_cooldownCsInit = TRUE;
    }
}

static uint32_t GetProcHash(const wchar_t* name, const wchar_t* path) {
    if (!name || !name[0]) return 0;
    uint32_t h = HashString(name);
    if (path && path[0]) {
        h = h ^ HashString(path);
    }
    return h;
}

static BOOL CheckAndUpdatePopupCooldown(const wchar_t* procName, const wchar_t* procPath) {
    if (!procName || !procName[0]) return TRUE;
    if (!g_cooldownCsInit) InitCooldownCs();
    uint32_t procHash = GetProcHash(procName, procPath);
    if (procHash == 0) return TRUE;
    
    uint64_t now = GetTickCount64();
    EnterCriticalSection(&g_cooldownCs);
    
    for (int i = 0; i < 128; i++) {
        if (g_cooldowns[i].procHash == procHash) {
            if ((now - g_cooldowns[i].lastPopupTime) < POPUP_COOLDOWN_SECONDS * 1000LL) {
                LeaveCriticalSection(&g_cooldownCs);
                DaemonLog(L"[COOLDOWN] Popup blocked for %ls (cooldown active)", procName);
                return FALSE;
            }
            g_cooldowns[i].lastPopupTime = now;
            LeaveCriticalSection(&g_cooldownCs);
            return TRUE;
        }
    }
    
    for (int i = 0; i < 128; i++) {
        if (g_cooldowns[i].procHash == 0) {
            g_cooldowns[i].procHash = procHash;
            g_cooldowns[i].lastPopupTime = now;
            g_cooldowns[i].lastBehaviorWarnTime = 0;
            LeaveCriticalSection(&g_cooldownCs);
            return TRUE;
        }
    }
    
    g_cooldowns[0].procHash = procHash;
    g_cooldowns[0].lastPopupTime = now;
    g_cooldowns[0].lastBehaviorWarnTime = 0;
    LeaveCriticalSection(&g_cooldownCs);
    return TRUE;
}

static BOOL CheckAndUpdateBehaviorCooldown(const wchar_t* procName, const wchar_t* procPath) {
    if (!procName || !procName[0]) return TRUE;
    if (!g_cooldownCsInit) InitCooldownCs();
    uint32_t procHash = GetProcHash(procName, procPath);
    if (procHash == 0) return TRUE;
    
    uint64_t now = GetTickCount64();
    EnterCriticalSection(&g_cooldownCs);
    
    for (int i = 0; i < 128; i++) {
        if (g_cooldowns[i].procHash == procHash) {
            if ((now - g_cooldowns[i].lastBehaviorWarnTime) < BEHAVIOR_COOLDOWN_SECONDS * 1000LL) {
                LeaveCriticalSection(&g_cooldownCs);
                return FALSE;
            }
            g_cooldowns[i].lastBehaviorWarnTime = now;
            LeaveCriticalSection(&g_cooldownCs);
            return TRUE;
        }
    }
    
    for (int i = 0; i < 128; i++) {
        if (g_cooldowns[i].procHash == 0) {
            g_cooldowns[i].procHash = procHash;
            g_cooldowns[i].lastBehaviorWarnTime = now;
            g_cooldowns[i].lastPopupTime = 0;
            LeaveCriticalSection(&g_cooldownCs);
            return TRUE;
        }
    }
    
    g_cooldowns[0].procHash = procHash;
    g_cooldowns[0].lastBehaviorWarnTime = now;
    g_cooldowns[0].lastPopupTime = 0;
    LeaveCriticalSection(&g_cooldownCs);
    return TRUE;
}
typedef BOOL (*FnDeletePartition)(int, int);

typedef int  (*FnGetAllServices)(void**);
typedef BOOL (*FnStopServiceByName)(const wchar_t*);
typedef BOOL (*FnStartServiceByName)(const wchar_t*);

typedef int  (*FnGetAllDisks)(void**);
typedef int  (*FnGetPartitionsOnDisk)(int, void**);

typedef void (*FnAddSvcRepeated)(const wchar_t*);
typedef void (*FnRemoveSvcRepeated)(const wchar_t*);
typedef BOOL (*FnIsSvcRepeated)(const wchar_t*);

typedef void (*FnAddPartRepeated)(int, int, const wchar_t*);
typedef void (*FnRemovePartRepeated)(int, int);
typedef BOOL (*FnIsPartRepeated)(int, int);
typedef BOOL (*FnDeleteServiceByName)(const wchar_t*);
typedef BOOL (*FnDeleteRegistryEntry)(HKEY, const wchar_t*, const wchar_t*);

static FnDeleteServiceByName g_svcDelete = NULL;
static FnDeleteRegistryEntry g_regDelete = NULL;
static FnDeletePartition g_partDelete = NULL;

static FnGetAllServices  g_svcGetAll = NULL;
static FnStopServiceByName g_svcStop = NULL;
static FnStartServiceByName g_svcStart = NULL;
static FnAddSvcRepeated g_svcAddRepeated = NULL;
static FnRemoveSvcRepeated g_svcRemoveRepeated = NULL;
static FnIsSvcRepeated g_svcIsRepeated = NULL;

static FnGetAllDisks     g_partGetDisks = NULL;
static FnGetPartitionsOnDisk g_partGetParts = NULL;
static FnAddPartRepeated g_partAddRepeated = NULL;
static FnRemovePartRepeated g_partRemoveRepeated = NULL;
static FnIsPartRepeated g_partIsRepeated = NULL;

void DaemonLog(const wchar_t* fmt, ...);

static void DStartupLog(const char* msg) {
    FILE* f = fopen("C:\\tmp\\daemon_startup.log", "a");
    if (!f) return;
    SYSTEMTIME st; GetLocalTime(&st);
    fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] %s\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, msg);
    fclose(f);
}

void DaemonGetBasePath(wchar_t* out, DWORD len) {
    if (!out || len < 2) return;
    out[0] = L'\0';
    HMODULE hMod = GetModuleHandleW(NULL);
    DWORD n = GetModuleFileNameW(hMod, out, len);
    if (n == 0 || n >= len) {
        out[0] = L'\0';
        return;
    }
    wchar_t* p = wcsrchr(out, L'\\');
    if (p) *p = L'\0';
}

static void GetDataPath(wchar_t* out, DWORD len, const wchar_t* fileName) {
    DaemonGetBasePath(out, len);
    wchar_t testPath[MAX_PATH];
    swprintf(testPath, MAX_PATH, L"%ls\\data", out);
    if (GetFileAttributesW(testPath) == INVALID_FILE_ATTRIBUTES) {
        wchar_t* p = wcsrchr(out, L'\\');
        if (p) *p = L'\0';
    }
    wcscat(out, L"\\data\\");
    wcscat(out, fileName);
}

void CacheFilePath(DWORD pid, const wchar_t* procName, const wchar_t* filePath) {
    if (!procName || !filePath || !filePath[0]) return;
    wchar_t cachePath[MAX_PATH];
    GetDataPath(cachePath, MAX_PATH, L"pending_delete_cache.txt");
    FILE* f = _wfopen(cachePath, L"at, ccs=UTF-8");
    if (!f) return;
    SYSTEMTIME st; GetLocalTime(&st);
    fwprintf(f, L"%lu|%ls|%ls|%04d-%02d-%02d %02d:%02d:%02d\n", pid, procName, filePath, 
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    fclose(f);
    DaemonLog(L"[CACHE] Cached file path for %ls (PID=%lu): %ls", procName, pid, filePath);
}

BOOL DeleteCachedFile(DWORD pid, const wchar_t* procName) {
    if (!procName) return FALSE;
    
    if (IsSelfProcessName(procName)) {
        DaemonLog(L"[SAFETY] BLOCKED: DeleteCachedFile skipping self process %ls", procName);
        return FALSE;
    }
    
    wchar_t cachePath[MAX_PATH];
    GetDataPath(cachePath, MAX_PATH, L"pending_delete_cache.txt");
    FILE* f = _wfopen(cachePath, L"rt, ccs=UTF-8");
    if (!f) return FALSE;
    
    wchar_t tempPath[MAX_PATH];
    GetDataPath(tempPath, MAX_PATH, L"pending_delete_cache.tmp");
    FILE* ft = _wfopen(tempPath, L"wt, ccs=UTF-8");
    if (!ft) { fclose(f); return FALSE; }
    
    BOOL deleted = FALSE;
    wchar_t line[2048];
    while (fgetws(line, 2048, f)) {
        wchar_t* nl = wcschr(line, L'\n'); if (nl) *nl = 0;
        wchar_t* cr = wcschr(line, L'\r'); if (cr) *cr = 0;
        if (!line[0]) continue;
        
        DWORD cachedPid = 0;
        wchar_t cachedName[256] = {0};
        wchar_t cachedPath[MAX_PATH] = {0};
        wchar_t timeStr[64] = {0};
        if (swscanf(line, L"%lu|%255[^|]|%511[^|]|%63[^\n]", &cachedPid, cachedName, cachedPath, timeStr) >= 3) {
            if (cachedPid == pid && _wcsicmp(cachedName, procName) == 0) {
                if (IsSelfProcessName(cachedName)) {
                    DaemonLog(L"[SAFETY] BLOCKED: DeleteCachedFile skipping self process file %ls", cachedPath);
                    fwprintf(ft, L"%ls\n", line);
                    continue;
                }
                BOOL delOk = DeleteFileW(cachedPath);
                if (delOk) {
                    DaemonLog(L"[CACHE] Deleted cached file: %ls", cachedPath);
                    deleted = TRUE;
                } else {
                    DaemonLog(L"[CACHE] DeleteFile failed for %ls, error=%lu", cachedPath, GetLastError());
                    fwprintf(ft, L"%ls\n", line);
                }
            } else {
                fwprintf(ft, L"%ls\n", line);
            }
        }
    }
    fclose(f);
    fclose(ft);
    DeleteFileW(cachePath);
    MoveFileW(tempPath, cachePath);
    return deleted;
}

void CleanupStaleCache(void) {
    DaemonLog(L"[CACHE] CleanupStaleCache called");
    wchar_t cachePath[MAX_PATH];
    GetDataPath(cachePath, MAX_PATH, L"pending_delete_cache.txt");
    FILE* f = _wfopen(cachePath, L"rt, ccs=UTF-8");
    if (!f) {
        DaemonLog(L"[CACHE] Cache file not found");
        return;
    }
    
    wchar_t tempPath[MAX_PATH];
    GetDataPath(tempPath, MAX_PATH, L"pending_delete_cache.tmp");
    FILE* ft = _wfopen(tempPath, L"wt, ccs=UTF-8");
    if (!ft) { fclose(f); return; }
    
    uint64_t now = GetTickCount64();
    wchar_t line[2048];
    while (fgetws(line, 2048, f)) {
        wchar_t* nl = wcschr(line, L'\n'); if (nl) *nl = 0;
        wchar_t* cr = wcschr(line, L'\r'); if (cr) *cr = 0;
        if (!line[0]) continue;
        
        DWORD cachedPid = 0;
        wchar_t cachedName[256] = {0};
        wchar_t cachedPath[MAX_PATH] = {0};
        wchar_t timeStr[64] = {0};
        if (swscanf(line, L"%lu|%255[^|]|%511[^|]|%63[^\n]", &cachedPid, cachedName, cachedPath, timeStr) >= 3) {
            if (GetFileAttributesW(cachedPath) == INVALID_FILE_ATTRIBUTES) {
                DaemonLog(L"[CACHE] Stale cache entry removed: %ls", cachedName);
            } else {
                fwprintf(ft, L"%ls\n", line);
            }
        }
    }
    fclose(f);
    fclose(ft);
    DeleteFileW(cachePath);
    MoveFileW(tempPath, cachePath);
}

static void InitLogger(void) {
    if (g_csInit) return;
    InitializeCriticalSection(&g_cs);
    g_csInit = TRUE;
    InitializeCriticalSection(&g_logCs);
    g_logCsInit = TRUE;

    wchar_t basePath[MAX_PATH];
    DaemonGetBasePath(basePath, MAX_PATH);
    wchar_t iniPath[MAX_PATH];
    swprintf(iniPath, MAX_PATH, L"%ls\\data\\settings.ini", basePath);
    DWORD mb = GetPrivateProfileIntW(L"Settings", L"LogMaxSizeMB", 10, iniPath);
    if (mb < 1) mb = 1;
    g_logMaxBytes = (long long)mb * 1024 * 1024;

    wchar_t path[MAX_PATH];
    GetDataPath(path, MAX_PATH, L"daemon.log");
    g_logFile = _wfopen(path, L"a");
}

static void RotateLogFile(const wchar_t* logPath) {
    if (!g_logFile) return;
    fclose(g_logFile);
    g_logFile = NULL;

    wchar_t oldPath[MAX_PATH];
    swprintf(oldPath, MAX_PATH, L"%ls.old", logPath);
    DeleteFileW(oldPath);
    MoveFileW(logPath, oldPath);

    g_logFile = _wfopen(logPath, L"a");
}

static void ActionLogManagerInit(ActionLogManager* alm) {
    if (!alm) return;
    ZeroMemory(alm, sizeof(ActionLogManager));
    InitializeCriticalSection(&alm->cs);
}

static void ActionLogManagerCleanup(ActionLogManager* alm) {
    if (!alm) return;
    for (int i = 0; i < alm->procCount; i++) {
        DeleteCriticalSection(&alm->procs[i].cs);
    }
    DeleteCriticalSection(&alm->cs);
}

static ProcActionLog* ActionLogManagerGetOrCreate(ActionLogManager* alm, DWORD pid, const wchar_t* procName, const wchar_t* imagePath) {
    if (!alm) return NULL;
    EnterCriticalSection(&alm->cs);
    for (int i = 0; i < alm->procCount; i++) {
        if (alm->procs[i].pid == pid) {
            LeaveCriticalSection(&alm->cs);
            return &alm->procs[i];
        }
    }
    if (alm->procCount >= MAX_PROC_ACTIONS) {
        LeaveCriticalSection(&alm->cs);
        return NULL;
    }
    ProcActionLog* pal = &alm->procs[alm->procCount++];
    ZeroMemory(pal, sizeof(ProcActionLog));
    InitializeCriticalSection(&pal->cs);
    pal->pid = pid;
    wcsncpy(pal->procName, procName ? procName : L"unknown", 259);
    wcsncpy(pal->imagePath, imagePath ? imagePath : L"", MAX_PATH - 1);
    pal->startTime = GetTickCount64();
    LeaveCriticalSection(&alm->cs);
    return pal;
}

static int ActionLogManagerAddEntry(ActionLogManager* alm, DWORD pid, ActionType type, 
                                     const wchar_t* targetPath, const wchar_t* valueName,
                                     const wchar_t* newValue, const wchar_t* oldValue) {
    if (!alm || !targetPath) return -1;
    EnterCriticalSection(&alm->cs);
    if (alm->entryCount >= MAX_ACTION_ENTRIES) {
        for (int i = 0; i < MAX_ACTION_ENTRIES / 2; i++) {
            alm->entries[i] = alm->entries[i + MAX_ACTION_ENTRIES / 2];
        }
        alm->entryCount = MAX_ACTION_ENTRIES / 2;
    }
    ActionEntry* ae = &alm->entries[alm->entryCount++];
    ae->id = alm->entryCount;
    ae->pid = pid;
    ae->type = type;
    wcsncpy(ae->targetPath, targetPath, 511);
    wcsncpy(ae->valueName, valueName ? valueName : L"", 255);
    wcsncpy(ae->newValue, newValue ? newValue : L"", 1023);
    wcsncpy(ae->oldValue, oldValue ? oldValue : L"", 1023);
    ae->timestamp = GetTickCount64();
    
    ProcActionLog* pal = NULL;
    for (int i = 0; i < alm->procCount; i++) {
        if (alm->procs[i].pid == pid) {
            pal = &alm->procs[i];
            break;
        }
    }
    if (pal && pal->actionCount < MAX_PROC_ACTIONS) {
        EnterCriticalSection(&pal->cs);
        pal->actions[pal->actionCount++] = ae->id;
        LeaveCriticalSection(&pal->cs);
    }
    LeaveCriticalSection(&alm->cs);
    return ae->id;
}

static void ActionLogManagerCloseProcess(ActionLogManager* alm, DWORD pid) {
    if (!alm) return;
    EnterCriticalSection(&alm->cs);
    for (int i = 0; i < alm->procCount; i++) {
        if (alm->procs[i].pid == pid) {
            alm->procs[i].endTime = GetTickCount64();
            break;
        }
    }
    LeaveCriticalSection(&alm->cs);
}

static BOOL ActionLogManagerRestoreByPid(ActionLogManager* alm, DWORD pid) {
    if (!alm) return FALSE;
    EnterCriticalSection(&alm->cs);
    
    ProcActionLog* pal = NULL;
    for (int i = 0; i < alm->procCount; i++) {
        if (alm->procs[i].pid == pid) {
            pal = &alm->procs[i];
            break;
        }
    }
    if (!pal || pal->actionCount == 0) {
        LeaveCriticalSection(&alm->cs);
        return FALSE;
    }
    
    DaemonLog(L"[DIRECTED-RESTORE] Starting directed restore for PID=%lu (%ls), actions=%d", 
              pid, pal->procName, pal->actionCount);
    
    for (int i = pal->actionCount - 1; i >= 0; i--) {
        int entryId = pal->actions[i];
        ActionEntry* ae = NULL;
        for (int j = 0; j < alm->entryCount; j++) {
            if (alm->entries[j].id == entryId) {
                ae = &alm->entries[j];
                break;
            }
        }
        if (!ae) continue;
        
        switch (ae->type) {
            case ACTION_TYPE_REG_SET: {
                if (ae->oldValue[0]) {
                    wchar_t keyPath[MAX_PATH] = {0};
                    wchar_t valueName[256] = {0};
                    wchar_t* lastBackslash = wcsrchr(ae->targetPath, L'\\');
                    if (lastBackslash) {
                        wcsncpy(keyPath, ae->targetPath, lastBackslash - ae->targetPath);
                        wcscpy(valueName, lastBackslash + 1);
                    } else {
                        wcscpy(keyPath, ae->targetPath);
                        wcscpy(valueName, ae->valueName);
                    }
                    
                    HKEY hKey = NULL;
                    if (wcsncmp(keyPath, L"HKEY_LOCAL_MACHINE\\", 19) == 0) {
                        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath + 19, 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
                            RegSetValueExW(hKey, valueName, 0, REG_SZ, 
                                           (const BYTE*)ae->oldValue, 
                                           (wcslen(ae->oldValue) + 1) * sizeof(wchar_t));
                            RegCloseKey(hKey);
                            DaemonLog(L"[DIRECTED-RESTORE] Restored registry value: %ls -> %ls", 
                                      ae->targetPath, ae->oldValue);
                        }
                    } else if (wcsncmp(keyPath, L"HKEY_USERS\\", 12) == 0) {
                        if (RegOpenKeyExW(HKEY_USERS, keyPath + 12, 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
                            RegSetValueExW(hKey, valueName, 0, REG_SZ, 
                                           (const BYTE*)ae->oldValue, 
                                           (wcslen(ae->oldValue) + 1) * sizeof(wchar_t));
                            RegCloseKey(hKey);
                            DaemonLog(L"[DIRECTED-RESTORE] Restored registry value: %ls -> %ls", 
                                      ae->targetPath, ae->oldValue);
                        }
                    }
                }
                break;
            }
            case ACTION_TYPE_REG_DELETE_VALUE: {
                if (ae->oldValue[0]) {
                    wchar_t keyPath[MAX_PATH] = {0};
                    wchar_t* lastBackslash = wcsrchr(ae->targetPath, L'\\');
                    if (lastBackslash) {
                        wcsncpy(keyPath, ae->targetPath, lastBackslash - ae->targetPath);
                    } else {
                        wcscpy(keyPath, ae->targetPath);
                    }
                    
                    HKEY hKey = NULL;
                    if (wcsncmp(keyPath, L"HKEY_LOCAL_MACHINE\\", 19) == 0) {
                        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath + 19, 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
                            RegSetValueExW(hKey, ae->valueName, 0, REG_SZ, 
                                           (const BYTE*)ae->oldValue, 
                                           (wcslen(ae->oldValue) + 1) * sizeof(wchar_t));
                            RegCloseKey(hKey);
                            DaemonLog(L"[DIRECTED-RESTORE] Restored deleted registry value: %ls -> %ls", 
                                      ae->targetPath, ae->oldValue);
                        }
                    } else if (wcsncmp(keyPath, L"HKEY_USERS\\", 12) == 0) {
                        if (RegOpenKeyExW(HKEY_USERS, keyPath + 12, 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
                            RegSetValueExW(hKey, ae->valueName, 0, REG_SZ, 
                                           (const BYTE*)ae->oldValue, 
                                           (wcslen(ae->oldValue) + 1) * sizeof(wchar_t));
                            RegCloseKey(hKey);
                            DaemonLog(L"[DIRECTED-RESTORE] Restored deleted registry value: %ls -> %ls", 
                                      ae->targetPath, ae->oldValue);
                        }
                    }
                }
                break;
            }
            case ACTION_TYPE_FILE_DELETE: {
                if (ae->oldValue[0] && ae->oldValue[0] != L'-') {
                    DaemonLog(L"[DIRECTED-RESTORE] Cannot restore deleted file (requires backup): %ls", 
                              ae->targetPath);
                }
                break;
            }
            case ACTION_TYPE_FILE_WRITE: {
                if (ae->oldValue[0] && ae->oldValue[0] != L'-') {
                    DaemonLog(L"[DIRECTED-RESTORE] Cannot restore overwritten file (requires backup): %ls", 
                              ae->targetPath);
                }
                break;
            }
            default:
                DaemonLog(L"[DIRECTED-RESTORE] Unsupported action type %d for path: %ls", 
                          ae->type, ae->targetPath);
                break;
        }
    }
    
    DaemonLog(L"[DIRECTED-RESTORE] Directed restore completed for PID=%lu", pid);
    LeaveCriticalSection(&alm->cs);
    return TRUE;
}

void ActionLogRestoreByPid(DWORD pid) {
    extern DaemonState g_state;
    ActionLogManagerRestoreByPid(&g_state.actionLogManager, pid);
}

void DaemonLog(const wchar_t* fmt, ...) {
    if (!g_logFile) return;
    if (!g_logCsInit) return;
    EnterCriticalSection(&g_logCs);

    long pos = ftell(g_logFile);
    if (pos >= g_logMaxBytes) {
        wchar_t path[MAX_PATH];
        GetDataPath(path, MAX_PATH, L"daemon.log");
        RotateLogFile(path);
    }

    time_t now = time(NULL);
    struct tm* tm_now = localtime(&now);
    wchar_t ts[64];
    wcsftime(ts, 64, L"%Y-%m-%d %H:%M:%S", tm_now);

    /* Format full message into a wide buffer */
    wchar_t buf[4096];
    int len = swprintf(buf, 4096, L"[%ls] ", ts);
    if (len < 0) len = 0;
    va_list ap;
    va_start(ap, fmt);
    int msgLen = vswprintf(buf + len, 4096 - len, fmt, ap);
    va_end(ap);
    if (msgLen < 0) msgLen = 0;
    len += msgLen;
    if (len < 4096) {
        buf[len++] = L'\n';
        buf[len] = L'\0';
    }

    /* Convert to UTF-8 and write as bytes so non-ASCII paths are preserved */
    char utf8[16384];
    int cb = WideCharToMultiByte(CP_UTF8, 0, buf, len, utf8, sizeof(utf8), NULL, NULL);
    if (cb > 0) {
        fwrite(utf8, 1, cb, g_logFile);
    }
    fflush(g_logFile);
    LeaveCriticalSection(&g_logCs);
}

/* Forward declarations for AI-driven action helpers */
void AddRepeatedKillByName(DaemonState* s, const wchar_t* name);
void RecoverFromEtwLogs(DaemonState* s, DWORD targetPid);
static void SaveProcs(DaemonState* s);
static BOOL CleanTargetPath(const wchar_t* target);
static void QuarantineDirectory(const wchar_t* dir);
static void CreateHighRiskPopupFlag(const wchar_t* taskName, const wchar_t* taskId,
                                    const wchar_t* procName, const wchar_t* path,
                                    const char* reason, int score);
static void WriteAiNotification(const char* level, const wchar_t* taskName, const wchar_t* taskId,
                                const wchar_t* procName, const char* path, const char* reason);
static void WriteAiPromptInject(const wchar_t* procName, const wchar_t* objectType,
                                const wchar_t* modifiedObject, const char* systemPrompt,
                                const char* userPrompt);
BOOL CheckFileSignatureCached(const wchar_t* path, wchar_t* signer, DWORD signerSz);
BOOL IsSelfProcessName(const wchar_t* name);
BOOL IsCriticalSystemProcess(const wchar_t* name);
BOOL IsSystemProcessName(const wchar_t* name);
static BOOL IsAntivirusProcessName(const wchar_t* name);
static BOOL IsProcessRunningAsSystem(DWORD pid);
static BOOL ShowPopupAndWait(const wchar_t* title, const wchar_t* message, const wchar_t* proc, const wchar_t* path);
static void ShowSecurityAlertPopup(const wchar_t* title, const wchar_t* message);

/* Lightweight per-PID tracking of suspicious registry activity */
#define MAX_ROGUE_PID_TRACK 64
#define ROGUE_TRACK_WINDOW_MS 60000
typedef struct {
    DWORD pid;
    DWORD windowStart;
    int extCount;
    int startupCount;
    int serviceCount;
    int browserCount;
} RoguePidTrack;
static RoguePidTrack g_rogueTrack[MAX_ROGUE_PID_TRACK];

static void InitRogueTrack() {
    memset(g_rogueTrack, 0, sizeof(g_rogueTrack));
}

static RoguePidTrack* GetRogueTrack(DWORD pid) {
    for (int i = 0; i < MAX_ROGUE_PID_TRACK; i++) {
        if (g_rogueTrack[i].pid == pid) return &g_rogueTrack[i];
    }
    DWORD now = GetTickCount();
    int best = -1;
    DWORD oldest = 0;
    for (int i = 0; i < MAX_ROGUE_PID_TRACK; i++) {
        if (g_rogueTrack[i].pid == 0) { best = i; break; }
        if (best == -1 || (now - g_rogueTrack[i].windowStart) > oldest) {
            oldest = now - g_rogueTrack[i].windowStart;
            best = i;
        }
    }
    if (best >= 0) {
        memset(&g_rogueTrack[best], 0, sizeof(RoguePidTrack));
        g_rogueTrack[best].pid = pid;
        g_rogueTrack[best].windowStart = now;
    }
    return best >= 0 ? &g_rogueTrack[best] : NULL;
}

static BOOL IsNumericExtensionKey(const wchar_t* path) {
    if (!path) return FALSE;
    const wchar_t* dot = wcsrchr(path, L'.');
    if (!dot) return FALSE;
    dot++;
    if (!*dot) return FALSE;
    while (*dot) {
        if (!iswdigit(*dot)) return FALSE;
        dot++;
    }
    return TRUE;
}

static int TrackRogueRegActivity(DaemonState* s, DWORD pid, const wchar_t* path, int* outScore) {
    if (!path || !path[0]) return 0;
    EnterCriticalSection(&g_cs);
    RoguePidTrack* t = GetRogueTrack(pid);
    if (!t) { LeaveCriticalSection(&g_cs); return 0; }
    DWORD now = GetTickCount();
    if ((now - t->windowStart) > ROGUE_TRACK_WINDOW_MS) {
        memset(t, 0, sizeof(RoguePidTrack));
        t->pid = pid;
        t->windowStart = now;
    }

    int addedScore = 0;
    BOOL fromHKCR = (_wcsnicmp(path, L"HKEY_CLASSES_ROOT\\", 19) == 0);

    /* Numeric extension keys like .012, .050 are classic PUP residue */
    if (wcsstr(path, L"\\Classes\\.") || (fromHKCR && wcsstr(path, L"\\."))) {
        t->extCount++;
        addedScore += IsNumericExtensionKey(path) ? 55 : 30;
    }

    /* Startup entries */
    if (wcsstr(path, L"\\Run\\") ||
        wcsstr(path, L"\\RunOnce\\") ||
        wcsstr(path, L"\\RunOnceEx\\") ||
        wcsstr(path, L"\\Windows\\CurrentVersion\\Run")) {
        t->startupCount++;
        addedScore += 30;
    }

    /* Services */
    if (wcsstr(path, L"\\Services\\")) {
        t->serviceCount++;
        addedScore += 25;
    }

    /* Browser hijack */
    if (wcsstr(path, L"Start Page") ||
        wcsstr(path, L"Default_Page_URL") ||
        wcsstr(path, L"Search Page") ||
        wcsstr(path, L"SearchProvider") ||
        wcsstr(path, L"DefaultSearchProvider") ||
        wcsstr(path, L"SearchURL") ||
        wcsstr(path, L"Homepage")) {
        t->browserCount++;
        addedScore += 45;
    }

    *outScore = addedScore;
    int burst = (t->extCount >= 5 || t->startupCount >= 3 ||
                 t->serviceCount >= 3 || t->browserCount >= 2) ? 1 : 0;
    LeaveCriticalSection(&g_cs);
    return burst;
}

static SignerScoreEntry* GetSignerScore(DaemonState* s, const wchar_t* signer) {
    if (!signer || !signer[0]) return NULL;
    for (int i = 0; i < s->signerScoreCount; i++) {
        if (_wcsicmp(s->signerScores[i].signer, signer) == 0) {
            return &s->signerScores[i];
        }
    }
    if (s->signerScoreCount >= MAX_RASCAL_SIGNERS) return NULL;
    SignerScoreEntry* entry = &s->signerScores[s->signerScoreCount++];
    memset(entry, 0, sizeof(SignerScoreEntry));
    wcsncpy(entry->signer, signer, 255);
    entry->signer[255] = L'\0';
    return entry;
}

static void UpdateSignerScore(DaemonState* s, const wchar_t* signer, const wchar_t* imgPath, int type) {
    if (!signer || !signer[0]) return;
    SignerScoreEntry* entry = GetSignerScore(s, signer);
    if (!entry) return;
    entry->lastUpdateTick = GetTickCount();

    if (type == 1) {
        entry->regWriteCount++;
        entry->score += 0.15f;
    } else if (type == 2) {
        entry->installedAppCount++;
        entry->score += 10.0f;
    } else if (type == 3) {
        entry->blockOtherCount++;
        entry->score += 15.0f;
    }
}

static float CalculateSignerTotalScore(DaemonState* s, const wchar_t* signer) {
    SignerScoreEntry* entry = GetSignerScore(s, signer);
    if (!entry) return 0.0f;
    float total = entry->score;
    total += entry->aiReputation;
    return total;
}

static BOOL IsSignerRascal(DaemonState* s, const wchar_t* signer) {
    float score = CalculateSignerTotalScore(s, signer);
    return score > 60.0f;
}

static void MarkRascalSigner(DaemonState* s, const wchar_t* signer) {
    float score = CalculateSignerTotalScore(s, signer);
    DaemonLog(L"[RASCAL] Signer '%ls' score=%.1f (reg=%d,install=%d,block=%d,reputation=%.1f)",
              signer, score, 
              GetSignerScore(s, signer) ? GetSignerScore(s, signer)->regWriteCount : 0,
              GetSignerScore(s, signer) ? GetSignerScore(s, signer)->installedAppCount : 0,
              GetSignerScore(s, signer) ? GetSignerScore(s, signer)->blockOtherCount : 0,
              GetSignerScore(s, signer) ? GetSignerScore(s, signer)->aiReputation : 0.0f);
}

static UnsignedScoreEntry* GetUnsignedScore(DaemonState* s, const wchar_t* imagePath) {
    if (!imagePath || !imagePath[0]) return NULL;
    for (int i = 0; i < s->unsignedScoreCount; i++) {
        if (_wcsicmp(s->unsignedScores[i].imagePath, imagePath) == 0) {
            return &s->unsignedScores[i];
        }
    }
    if (s->unsignedScoreCount >= MAX_UNSIGNED_SCORES) return NULL;
    UnsignedScoreEntry* entry = &s->unsignedScores[s->unsignedScoreCount++];
    memset(entry, 0, sizeof(UnsignedScoreEntry));
    wcsncpy(entry->imagePath, imagePath, MAX_PATH - 1);
    entry->imagePath[MAX_PATH - 1] = L'\0';
    return entry;
}

static void ClearDirectoryRecursive(const wchar_t* dirPath) {
    wchar_t searchPath[MAX_PATH];
    swprintf(searchPath, MAX_PATH, L"%ls\\*", dirPath);
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) return;
    do {
        if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0) continue;
        wchar_t fullPath[MAX_PATH];
        swprintf(fullPath, MAX_PATH, L"%ls\\%ls", dirPath, findData.cFileName);
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            ClearDirectoryRecursive(fullPath);
            RemoveDirectoryW(fullPath);
        } else {
            DeleteFileW(fullPath);
        }
    } while (FindNextFileW(hFind, &findData));
    FindClose(hFind);
}



static void TerminateProcessByHandle(HANDLE hProc) {
    if (!hProc || hProc == INVALID_HANDLE_VALUE) return;
    
    DWORD pid = GetProcessId(hProc);
    wchar_t path[MAX_PATH] = {0};
    DWORD sz = MAX_PATH;
    if (QueryFullProcessImageNameW(hProc, 0, path, &sz) && path[0]) {
        wchar_t signer[256] = {0};
        if (CheckFileSignatureCached(path, signer, 256)) {
            DaemonLog(L"[SIGNATURE-PROTECT] BLOCKED: TerminateProcessByHandle for signed process pid=%lu path=%ls signer=%ls", pid, path, signer);
            return;
        }
    }
    
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te = {0};
        te.dwSize = sizeof(te);
        if (Thread32First(hThreadSnap, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    HANDLE hThread = OpenThread(THREAD_TERMINATE, FALSE, te.th32ThreadID);
                    if (hThread) {
                        TerminateThread(hThread, 1);
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(hThreadSnap, &te));
        }
        CloseHandle(hThreadSnap);
    }
    TerminateProcess(hProc, 1);
}

static void RepeatTerminateProcess(DWORD pid) {
    for (int i = 0; i < 5; i++) {
        TerminateProcessTree(pid);
        Sleep(100);
    }
}

static BOOL SafeTerminateProcess(HANDLE hProc, const wchar_t* procPath) {
    if (!hProc || hProc == INVALID_HANDLE_VALUE) return FALSE;
    
    DWORD pid = GetProcessId(hProc);
    if (pid == GetCurrentProcessId()) return FALSE;
    
    wchar_t path[MAX_PATH] = {0};
    if (procPath && procPath[0]) {
        wcscpy(path, procPath);
    } else {
        DWORD sz = MAX_PATH;
        QueryFullProcessImageNameW(hProc, 0, path, &sz);
    }
    
    wchar_t name[MAX_PATH] = {0};
    if (path[0]) {
        const wchar_t* slash = wcsrchr(path, L'\\');
        if (slash) wcscpy(name, slash + 1);
    }
    
    if (name[0] && IsSelfProcessName(name)) {
        DaemonLog(L"[SELF-PROTECT] BLOCKED: SafeTerminateProcess for self process pid=%lu path=%ls", pid, path);
        return FALSE;
    }
    
    if (name[0] && IsCriticalSystemProcess(name)) {
        DaemonLog(L"[CRITICAL-PROTECT] BLOCKED: SafeTerminateProcess for critical system process pid=%lu path=%ls", pid, path);
        return FALSE;
    }
    
    if (path[0]) {
        wchar_t signer[256] = {0};
        if (CheckFileSignatureCached(path, signer, 256)) {
            DaemonLog(L"[SIGNATURE-PROTECT] BLOCKED: SafeTerminateProcess for signed process pid=%lu path=%ls signer=%ls", pid, path, signer);
            return FALSE;
        }
    }
    
    DaemonLog(L"[SAFE-TERMINATE] Terminating process pid=%lu", pid);
    BOOL result = TerminateProcess(hProc, 1);
    return result;
}

static void AggressiveTerminateProcess(DWORD pid, const wchar_t* procName) {
    if (pid == GetCurrentProcessId()) return;
    
    if (procName && procName[0]) {
        if (IsCriticalSystemProcess(procName)) {
            DaemonLog(L"[CRITICAL-PROTECT] BLOCKED: Aggressive termination of critical system process %ls pid=%lu", procName, pid);
            return;
        }
        if (IsSelfProcessName(procName)) {
            DaemonLog(L"[SELF-PROTECT] BLOCKED: Aggressive termination of self process %ls pid=%lu", procName, pid);
            return;
        }
    }
    
    wchar_t imgPath[MAX_PATH] = {0};
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProc) {
        DWORD pathSize = MAX_PATH;
        QueryFullProcessImageNameW(hProc, 0, imgPath, &pathSize);
        CloseHandle(hProc);
    }
    
    if (imgPath[0]) {
        wchar_t name[MAX_PATH] = {0};
        const wchar_t* slash = wcsrchr(imgPath, L'\\');
        if (slash) wcscpy(name, slash + 1);
        if (name[0] && IsSelfProcessName(name)) {
            DaemonLog(L"[SELF-PROTECT] BLOCKED: Aggressive termination of self process %ls pid=%lu", imgPath, pid);
            return;
        }
    }
    
    if (imgPath[0]) {
        wchar_t signer[256] = {0};
        if (CheckFileSignatureCached(imgPath, signer, 256)) {
            DaemonLog(L"[SIGNATURE-PROTECT] BLOCKED: Aggressive termination of signed process %ls pid=%lu signer=%ls", 
                      procName ? procName : L"unknown", pid, signer);
            return;
        }
    }
    
    DaemonLog(L"[AGGRESSIVE] Starting aggressive termination for pid=%lu name=%ls", pid, procName ? procName : L"unknown");
    
    for (int phase = 0; phase < 3; phase++) {
        DaemonLog(L"[AGGRESSIVE] Phase %d: Killing process tree", phase + 1);
        for (int i = 0; i < 10; i++) {
            DWORD currentPid = pid;
            if (procName && procName[0]) {
                currentPid = GetPidByName(procName);
            }
            if (currentPid != 0) {
                TerminateProcessTree(currentPid);
            }
            Sleep(50);
        }
        
        if (procName && procName[0]) {
            DWORD checkPid = GetPidByName(procName);
            if (checkPid == 0) {
                DaemonLog(L"[AGGRESSIVE] Process %ls terminated successfully", procName);
                return;
            }
            DaemonLog(L"[AGGRESSIVE] Process %ls still running, trying thread-level termination", procName);
            
            HANDLE hProc = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, checkPid);
            if (hProc) {
                TerminateProcessByHandle(hProc);
                CloseHandle(hProc);
            }
            Sleep(100);
        }
    }
    
    if (procName && procName[0]) {
        DaemonLog(L"[AGGRESSIVE] Adding %ls to repeated kill list", procName);
    }
}

static void UpdateUnsignedScore(DaemonState* s, const wchar_t* imagePath, int type);
static DWORD GetPidByImagePath(const wchar_t* imagePath);

static void HandleUnsignedCriticalAttack(DaemonState* s, DWORD pid, const wchar_t* procName, const wchar_t* imagePath, const wchar_t* reason) {
    if (IsSelfProcessName(procName)) {
        DaemonLog(L"[SAFETY] refusing to terminate self process: %ls pid=%lu", procName, pid);
        return;
    }
    if (IsSystemProcessName(procName)) {
        DaemonLog(L"[SAFETY] refusing to terminate system process: %ls pid=%lu", procName, pid);
        return;
    }
    if (IsAntivirusProcessName(procName)) {
        DaemonLog(L"[SAFETY] refusing to terminate antivirus process: %ls pid=%lu", procName, pid);
        return;
    }

    int score = 0;
    if (s->cm) {
        score = ScoreCenterGetTotalScore(&s->cm->sc, pid);
    }
    UnsignedScoreEntry* entry = GetUnsignedScore(s, imagePath);
    if (entry && score == 0) score = (int)entry->score;

    DaemonLog(L"[ATTACK] unsigned %ls detected: pid=%lu proc=%ls path=%ls score=%d", reason, pid, procName, imagePath, score);

    if (score >= THRESHOLD_REMOVED) {
        DaemonLog(L"[TERMINATE] confirmed threat (score=%d >= %d), terminating: %ls", score, THRESHOLD_REMOVED, procName);
        AggressiveTerminateProcess(pid, procName);
        AddRepeatedKillByName(s, procName);
        SaveProcs(s);
        
        if (imagePath && imagePath[0]) {
            DaemonLog(L"[QUARANTINE] Attempting to quarantine: %ls", imagePath);
            QuarantineDirectory(imagePath);
            DaemonLog(L"[CLEAN] Attempting to clean: %ls", imagePath);
            CleanTargetPath(imagePath);
        }
        
        wchar_t popupTitle[256];
        swprintf(popupTitle, 256, L"TRAE Guardian - Threat Removed");
        ShowSecurityAlertPopupEx(popupTitle, L"恶意软件", procName, imagePath, reason, (int)score);
        
        CreateHighRiskPopupFlag(L"protection", L"protection", procName, reason, "Confirmed threat removed", (int)score);
        
        RecoverFromEtwLogs(s, pid);
        
        char reasonA[256] = {0};
        char pathA[MAX_PATH] = {0};
        WideCharToMultiByte(CP_UTF8, 0, reason, -1, reasonA, sizeof(reasonA) - 1, NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, imagePath, -1, pathA, sizeof(pathA) - 1, NULL, NULL);
        WriteAiNotification("CONFIRMED", L"protection", L"protection", procName, pathA, reasonA);
    } else {
        DaemonLog(L"[OBSERVE] suspicious process (score=%.2f < %d), monitoring only: %ls", score, THRESHOLD_REMOVED, procName);
        UpdateUnsignedScore(s, imagePath, 5);
        CreateHighRiskPopupFlag(L"protection", L"protection", procName, reason, "Suspicious process detected", (int)score);
        char reasonA[256] = {0};
        char pathA[MAX_PATH] = {0};
        WideCharToMultiByte(CP_UTF8, 0, reason, -1, reasonA, sizeof(reasonA) - 1, NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, imagePath, -1, pathA, sizeof(pathA) - 1, NULL, NULL);
        WriteAiNotification("WARNING", L"protection", L"protection", procName, pathA, reasonA);
    }
}

static void UpdateUnsignedScore(DaemonState* s, const wchar_t* imagePath, int type) {
    if (!imagePath || !imagePath[0]) return;
    UnsignedScoreEntry* entry = GetUnsignedScore(s, imagePath);
    if (!entry) return;
    entry->lastUpdateTick = GetTickCount();

    if (type == 1) {
        entry->regWriteCount++;
        entry->score += 0.5f;
    } else if (type == 2) {
        entry->regDeleteCount++;
        entry->score += 5.0f;
    } else if (type == 3) {
        entry->sysRegDeleteCount++;
        entry->score += 20.0f;
    } else if (type == 4) {
        entry->injectCount++;
        entry->score += 15.0f;
    } else if (type == 5) {
        entry->selfCopyCount++;
        entry->score += 5.0f;
    }
}

static BOOL IsUnsignedRascal(DaemonState* s, const wchar_t* imagePath) {
    UnsignedScoreEntry* entry = GetUnsignedScore(s, imagePath);
    if (!entry) return FALSE;
    return entry->score > 60.0f;
}

static void MarkUnsignedRascal(DaemonState* s, const wchar_t* imagePath, const wchar_t* procName) {
    UnsignedScoreEntry* entry = GetUnsignedScore(s, imagePath);
    if (!entry) return;
    DaemonLog(L"[RASCAL-UNSIGNED] '%ls' score=%.1f (regWrite=%d,regDel=%d,sysRegDel=%d,inject=%d,selfCopy=%d)",
              imagePath, entry->score,
              entry->regWriteCount, entry->regDeleteCount, entry->sysRegDeleteCount,
              entry->injectCount, entry->selfCopyCount);
    AddRepeatedKillByName(s, procName);
    SaveProcs(s);
    CreateHighRiskPopupFlag(L"protection", L"protection", procName, imagePath, "Rascal unsigned software detected", entry->score);
    
    if (entry->score >= THRESHOLD_REMOVED) {
        DWORD pid = GetPidByImagePath(imagePath);
        HandleUnsignedCriticalAttack(s, pid, procName, imagePath, L"rascal software");
    }
}

static BOOL IsSystemRegPath(const wchar_t* path) {
    if (!path || !path[0]) return FALSE;
    static const wchar_t* sysPaths[] = {
        L"HKEY_LOCAL_MACHINE\\SYSTEM\\",
        L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\",
        L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\",
        L"HKEY_LOCAL_MACHINE\\SECURITY\\",
        NULL
    };
    for (int i = 0; sysPaths[i]; i++) {
        if (_wcsnicmp(path, sysPaths[i], wcslen(sysPaths[i])) == 0) return TRUE;
    }
    return FALSE;
}

static void LoadProcs(DaemonState* s) {
    wchar_t path[MAX_PATH];
    /* Use the same file as the GUI so both sides see the same repeated-kill list. */
    GetDataPath(path, MAX_PATH, L"config.dat");
    FILE* f = _wfopen(path, L"rb");
    /* Backwards compatibility: fall back to old managed.dat if config.dat does not exist yet. */
    if (!f) {
        GetDataPath(path, MAX_PATH, L"managed.dat");
        f = _wfopen(path, L"rb");
    }
    if (!f) { s->procCount = 0; return; }
    fread(&s->procCount, sizeof(int), 1, f);
    if (s->procCount > MAX_PROC) s->procCount = MAX_PROC;
    fread(s->procs, sizeof(ProtectedEntry), s->procCount, f);
    fclose(f);

    /* Safety: drop any system/antivirus/DLL entries that may have been added by
     * earlier buggy builds. */
    int j = 0;
    for (int i = 0; i < s->procCount; i++) {
        const wchar_t* ext = wcsrchr(s->procs[i].name, L'.');
        if (IsSystemProcessName(s->procs[i].name) || IsAntivirusProcessName(s->procs[i].name) ||
            IsCriticalSystemProcess(s->procs[i].name) ||
            (ext && !_wcsicmp(ext, L".dll"))) {
            DaemonLog(L"[SAFETY] removed invalid entry from repeated-kill list: %ls", s->procs[i].name);
        } else {
            if (i != j) s->procs[j] = s->procs[i];
            j++;
        }
    }
    if (j != s->procCount) {
        s->procCount = j;
        SaveProcs(s);
    }
}

static void SaveProcs(DaemonState* s) {
    wchar_t path[MAX_PATH];
    GetDataPath(path, MAX_PATH, L"config.dat");
    FILE* f = _wfopen(path, L"wb");
    if (!f) return;
    fwrite(&s->procCount, sizeof(int), 1, f);
    if (s->procCount > 0) {
        fwrite(s->procs, sizeof(ProtectedEntry), s->procCount, f);
    }
    fclose(f);
}

static void LoadSvcs(DaemonState* s) {
    wchar_t path[MAX_PATH];
    GetDataPath(path, MAX_PATH, L"svc_repeated.dat");
    FILE* f = _wfopen(path, L"rb");
    if (!f) { s->svcCount = 0; return; }
    fread(&s->svcCount, sizeof(int), 1, f);
    if (s->svcCount > MAX_SVC) s->svcCount = MAX_SVC;
    fread(s->svcs, sizeof(SvcRepeatedEntry), s->svcCount, f);
    fclose(f);
}

static void LoadRegs(DaemonState* s) {
    s->regCount = 0;
    wchar_t path[MAX_PATH];
    GetDataPath(path, MAX_PATH, L"repeated_reg.txt");
    FILE* f = _wfopen(path, L"rt, ccs=UTF-8");
    if (!f) return;
    wchar_t line[1024];
    while (fgetws(line, 1024, f) && s->regCount < MAX_REG) {
        wchar_t* nl = wcschr(line, L'\n'); if (nl) *nl = 0;
        wchar_t* cr = wcschr(line, L'\r'); if (cr) *cr = 0;
        if (line[0] == L'#' || line[0] == 0) continue;
        wcscpy(s->regs[s->regCount].fullPath, line);
        s->regCount++;
    }
    fclose(f);
}

static void LoadParts(DaemonState* s) {
    s->partCount = 0;
    wchar_t path[MAX_PATH];
    GetDataPath(path, MAX_PATH, L"repeated_part.txt");
    FILE* f = _wfopen(path, L"rt, ccs=UTF-8");
    if (!f) return;
    wchar_t line[1024];
    while (fgetws(line, 1024, f) && s->partCount < MAX_PART) {
        wchar_t* nl = wcschr(line, L'\n'); if (nl) *nl = 0;
        wchar_t* cr = wcschr(line, L'\r'); if (cr) *cr = 0;
        if (line[0] == L'#' || line[0] == 0) continue;
        /* Expected format: diskNumber,partitionNumber,location */
        int disk = -1, part = -1;
        wchar_t loc[512] = {0};
        if (swscanf(line, L"%d,%d,%511[^\n]", &disk, &part, loc) >= 2) {
            s->parts[s->partCount].diskNumber = disk;
            s->parts[s->partCount].partitionNumber = part;
            wcsncpy(s->parts[s->partCount].location, loc, 511);
            s->parts[s->partCount].location[511] = L'\0';
            s->partCount++;
        }
    }
    fclose(f);
}

/* ======================== AI task loading ======================== */
static char* ReadFileUtf8(const wchar_t* path, long* outSz) {
    FILE* f = _wfopen(path, L"rb");
    if (!f) { *outSz = 0; return NULL; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    char* buf = (char*)malloc(sz + 1);
    if (!buf) { fclose(f); *outSz = 0; return NULL; }
    fread(buf, 1, sz, f); buf[sz] = 0; fclose(f);
    *outSz = sz;
    return buf;
}

static const char* json_find_str_a(const char* json, const char* key, char* out, int outSz) {
    char pat[64]; snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char* p = strstr(json, pat);
    if (!p) { out[0] = 0; return NULL; }
    p = strchr(p, ':');
    if (!p) { out[0] = 0; return NULL; }
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') { out[0] = 0; return NULL; }
    p++;
    int i = 0;
    while (*p && *p != '"' && i < outSz - 1) {
        if (*p == '\\' && p[1]) p++;
        out[i++] = *p++;
    }
    out[i] = 0;
    return out;
}

static int json_find_int_a(const char* json, const char* key, int defaultVal) {
    char pat[64]; snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char* p = strstr(json, pat);
    if (!p) return defaultVal;
    p = strchr(p, ':');
    if (!p) return defaultVal;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    return atoi(p);
}

static int json_find_bool_a(const char* json, const char* key, int defaultVal) {
    char pat[64]; snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char* p = strstr(json, pat);
    if (!p) return defaultVal;
    p = strchr(p, ':');
    if (!p) return defaultVal;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (strncmp(p, "true", 4) == 0) return 1;
    if (strncmp(p, "false", 5) == 0) return 0;
    return defaultVal;
}

static void LoadAiTasks(DaemonState* s) {
    s->aiTaskCount = 0;
    wchar_t path[MAX_PATH];
    GetDataPath(path, MAX_PATH, L"ai_tasks.json");
    long sz = 0;
    char* buf = ReadFileUtf8(path, &sz);
    if (!buf) return;

    const char* tasks = strstr(buf, "\"tasks\"");
    if (!tasks) { free(buf); return; }
    tasks = strchr(tasks, '[');
    if (!tasks) { free(buf); return; }
    tasks++;

    int depth = 1;
    while (*tasks && depth > 0 && s->aiTaskCount < MAX_AI_TASKS) {
        if (*tasks == '[') depth++;
        else if (*tasks == ']') { depth--; if (depth == 0) break; }
        if (*tasks == '{') {
            const char* objStart = tasks;
            int od = 1;
            tasks++;
            while (*tasks && od > 0) {
                if (*tasks == '{') od++;
                else if (*tasks == '}') od--;
                if (od > 0) tasks++;
            }
            int objLen = (int)(tasks - objStart + 1);
            if (objLen >= 8192) continue;
            char obj[8192];
            memcpy(obj, objStart, objLen); obj[objLen] = 0;

            AiTask* t = &s->aiTasks[s->aiTaskCount];
            memset(t, 0, sizeof(AiTask));

            char id[64] = "", name[256] = "", startT[32] = "", endT[32] = "";
            char memFile[MAX_PATH] = "", soulFile[MAX_PATH] = "";
            json_find_str_a(obj, "id", id, sizeof(id));
            json_find_str_a(obj, "name", name, sizeof(name));
            json_find_str_a(obj, "startTime", startT, sizeof(startT));
            json_find_str_a(obj, "endTime", endT, sizeof(endT));
            json_find_str_a(obj, "memoryFile", memFile, sizeof(memFile));
            json_find_str_a(obj, "soulFile", soulFile, sizeof(soulFile));
            MultiByteToWideChar(CP_UTF8, 0, id, -1, t->id, 64);
            MultiByteToWideChar(CP_UTF8, 0, name, -1, t->name, 256);
            MultiByteToWideChar(CP_UTF8, 0, startT, -1, t->startTime, 32);
            MultiByteToWideChar(CP_UTF8, 0, endT, -1, t->endTime, 32);
            MultiByteToWideChar(CP_UTF8, 0, memFile, -1, t->memoryFile, MAX_PATH);
            MultiByteToWideChar(CP_UTF8, 0, soulFile, -1, t->soulFile, MAX_PATH);
            t->readIntervalSec = json_find_int_a(obj, "readIntervalSec", 300);
            t->readBytes = json_find_int_a(obj, "readBytes", 4096);
            t->enabled = json_find_bool_a(obj, "enabled", 1);
            t->lastCheckTick = 0;

            /* Parse targets */
            const char* ta = strstr(obj, "\"targets\"");
            if (ta) {
                ta = strchr(ta, '[');
                if (ta) {
                    ta++;
                    int td = 1;
                    while (*ta && td > 0 && t->targetCount < MAX_AI_TARGETS) {
                        if (*ta == '[') td++;
                        else if (*ta == ']') { td--; if (td == 0) break; }
                        if (*ta == '{') {
                            const char* tStart = ta;
                            int tod = 1;
                            ta++;
                            while (*ta && tod > 0) {
                                if (*ta == '{') tod++;
                                else if (*ta == '}') tod--;
                                if (tod > 0) ta++;
                            }
                            int tLen = (int)(ta - tStart + 1);
                            if (tLen < 4096) {
                                char tobj[4096];
                                memcpy(tobj, tStart, tLen); tobj[tLen] = 0;
                                char tname[260] = "", ttype[32] = "";
                                int pid = json_find_int_a(tobj, "pid", 0);
                                int tree = json_find_bool_a(tobj, "tree", 0);
                                json_find_str_a(tobj, "name", tname, sizeof(tname));
                                json_find_str_a(tobj, "type", ttype, sizeof(ttype));
                                if (tname[0]) {
                                    AiTarget* at = &t->targets[t->targetCount++];
                                    MultiByteToWideChar(CP_UTF8, 0, tname, -1, at->name, 260);
                                    at->pid = pid;
                                    at->tree = tree ? TRUE : FALSE;
                                    if (_stricmp(ttype, "service") == 0) at->type = 2;
                                    else if (_stricmp(ttype, "registry") == 0) at->type = 3;
                                    else if (_stricmp(ttype, "partition") == 0) at->type = 4;
                                    else at->type = 1;
                                }
                            }
                        }
                        ta++;
                    }
                }
            }
            s->aiTaskCount++;
        }
        tasks++;
    }
    free(buf);
    DaemonLog(L"AI tasks loaded: %d", s->aiTaskCount);
}

static void LoadRegProtected(DaemonState* s) {
    s->regProtCount = 0;
    wchar_t path[MAX_PATH];
    GetDataPath(path, MAX_PATH, L"protected_reg.txt");
    FILE* f = _wfopen(path, L"rt, ccs=UTF-8");
    if (!f) return;
    wchar_t line[1024];
    while (fgetws(line, 1024, f) && s->regProtCount < MAX_REG_PROTECTED) {
        wchar_t* nl = wcschr(line, L'\n'); if (nl) *nl = 0;
        wchar_t* cr = wcschr(line, L'\r'); if (cr) *cr = 0;
        if (line[0] == L'#' || line[0] == 0) continue;
        wcscpy(s->regProt[s->regProtCount].fullPath, line);
        DWORD h = 5381;
        const wchar_t* q = line;
        while (*q) { h = ((h << 5) + h) + (DWORD)towlower(*q); q++; }
        wchar_t basePath[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, basePath))) {
            swprintf(s->regProt[s->regProtCount].snapshotFile, 512, L"%ls\\ProcessGuardian\\registry\\%08x.snapshot", basePath, h);
        } else {
            swprintf(s->regProt[s->regProtCount].snapshotFile, 512, L"%ls\\registry\\%08x.snapshot", path, h);
        }
        s->regProtCount++;
    }
    fclose(f);
}

static HKEY ParseRegRoot(const wchar_t** path) {
    if (wcsncmp(*path, L"HKEY_LOCAL_MACHINE\\", 19) == 0) { *path += 19; return HKEY_LOCAL_MACHINE; }
    if (wcsncmp(*path, L"HKEY_CURRENT_USER\\", 18) == 0) { *path += 18; return HKEY_CURRENT_USER; }
    if (wcsncmp(*path, L"HKEY_CLASSES_ROOT\\", 18) == 0) { *path += 18; return HKEY_CLASSES_ROOT; }
    if (wcsncmp(*path, L"HKEY_USERS\\", 11) == 0) { *path += 11; return HKEY_USERS; }
    if (wcsncmp(*path, L"HKEY_CURRENT_CONFIG\\", 20) == 0) { *path += 20; return HKEY_CURRENT_CONFIG; }
    return NULL;
}

static void AddSysRegPath(DaemonState* s, const wchar_t* fullPath, BOOL isKey) {
    if (s->sysRegProtCount >= MAX_SYS_REG_PROTECTED) return;
    wcscpy(s->sysRegProt[s->sysRegProtCount].fullPath, fullPath);
    s->sysRegProt[s->sysRegProtCount].isKey = isKey;
    DWORD h = 5381;
    const wchar_t* q = fullPath;
    while (*q) { h = ((h << 5) + h) + (DWORD)towlower(*q); q++; }
    wchar_t base[MAX_PATH];
    DaemonGetBasePath(base, MAX_PATH);
    swprintf(s->sysRegProt[s->sysRegProtCount].snapshotFile, 512, L"%ls\\data\\sys_registry\\%08x.snapshot", base, h);
    s->sysRegProtCount++;
}

static void ExpandSysRegKeyPath(DaemonState* s, const wchar_t* fullPath) {
    const wchar_t* sub = fullPath;
    HKEY hRoot = ParseRegRoot(&sub);
    if (!hRoot) return;
    HKEY hKey;
    if (RegOpenKeyExW(hRoot, sub, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS) return;
    DWORD idx = 0;
    wchar_t valName[16383];
    DWORD valNameLen;
    for (;;) {
        valNameLen = sizeof(valName) / sizeof(valName[0]);
        LONG ret = RegEnumValueW(hKey, idx, valName, &valNameLen, NULL, NULL, NULL, NULL);
        if (ret == ERROR_NO_MORE_ITEMS) break;
        if (ret == ERROR_SUCCESS && valNameLen > 0) {
            wchar_t valuePath[1024];
            swprintf(valuePath, 1024, L"%ls\\%ls", fullPath, valName);
            AddSysRegPath(s, valuePath, FALSE);
        }
        idx++;
    }
    RegCloseKey(hKey);
}

static BOOL IsRegValuePath(const wchar_t* fullPath) {
    const wchar_t* sub = fullPath;
    HKEY hRoot = ParseRegRoot(&sub);
    if (!hRoot) return FALSE;
    HKEY hKey;
    LONG ret = RegOpenKeyExW(hRoot, sub, 0, KEY_QUERY_VALUE, &hKey);
    if (ret == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return FALSE; /* It is a key, not a value */
    }
    /* Try opening parent key and checking value existence */
    wchar_t buf[1024];
    wcscpy(buf, sub);
    wchar_t* lastSlash = wcsrchr(buf, L'\\');
    if (!lastSlash) return FALSE;
    *lastSlash = L'\0';
    const wchar_t* valueName = lastSlash + 1;
    ret = RegOpenKeyExW(hRoot, buf, 0, KEY_QUERY_VALUE, &hKey);
    if (ret != ERROR_SUCCESS) return FALSE;
    DWORD type = 0;
    DWORD size = 0;
    ret = RegQueryValueExW(hKey, valueName, NULL, &type, NULL, &size);
    RegCloseKey(hKey);
    return ret == ERROR_SUCCESS;
}

static void LoadSysRegProtected(DaemonState* s) {
    s->sysRegProtCount = 0;
    wchar_t path[MAX_PATH];
    GetDataPath(path, MAX_PATH, L"protected_sys_reg.txt");
    FILE* f = _wfopen(path, L"rt, ccs=UTF-8");
    if (!f) return;
    wchar_t line[1024];
    while (fgetws(line, 1024, f) && s->sysRegProtCount < MAX_SYS_REG_PROTECTED) {
        wchar_t* nl = wcschr(line, L'\n'); if (nl) *nl = 0;
        wchar_t* cr = wcschr(line, L'\r'); if (cr) *cr = 0;
        if (line[0] == L'#' || line[0] == 0) continue;
        if (IsRegValuePath(line)) {
            AddSysRegPath(s, line, FALSE);
        } else {
            AddSysRegPath(s, line, TRUE);
        }
    }
    fclose(f);
}

static void LoadPartProtected(DaemonState* s) {
    s->partProtCount = 0;
    wchar_t path[MAX_PATH];
    GetDataPath(path, MAX_PATH, L"protected_part.txt");
    FILE* f = _wfopen(path, L"rt, ccs=UTF-8");
    if (!f) return;
    wchar_t line[1024];
    while (fgetws(line, 1024, f) && s->partProtCount < MAX_PART_PROTECTED) {
        wchar_t* nl = wcschr(line, L'\n'); if (nl) *nl = 0;
        wchar_t* cr = wcschr(line, L'\r'); if (cr) *cr = 0;
        if (line[0] == L'#' || line[0] == 0) continue;
        int disk = _wtoi(line);
        if (disk <= 0) continue;
        s->partProt[s->partProtCount].diskNumber = disk;
        wchar_t base[MAX_PATH];
        DaemonGetBasePath(base, MAX_PATH);
        swprintf(s->partProt[s->partProtCount].snapshotFile, 512, L"%ls\\partitions\\disk%d.snapshot", base, disk);
        s->partProtCount++;
    }
    fclose(f);
}

static int CaptureProcessSnapshot(ProcSnapshotEntry* out, int maxCount) {
    if (!out || maxCount <= 0) return 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);
    int count = 0;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (count >= maxCount) break;
            out[count].pid = pe.th32ProcessID;
            wcsncpy(out[count].name, pe.szExeFile, 259);
            out[count].name[259] = L'\0';
            out[count].imagePath[0] = L'\0';
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (hProc) {
                DWORD sz = MAX_PATH;
                QueryFullProcessImageNameW(hProc, 0, out[count].imagePath, &sz);
                CloseHandle(hProc);
            }
            count++;
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return count;
}

static void UpdateProcessSnapshot(DaemonState* s) {
    (void)s;
}

static int FindNewProcesses(DaemonState* s, const ProcSnapshotEntry* current, int currentCount,
                            ProcSnapshotEntry* newProcs, int maxNew) {
    (void)s;
    if (!current || !newProcs || maxNew <= 0) return 0;
    int count = (currentCount < maxNew) ? currentCount : maxNew;
    for (int i = 0; i < count; i++) {
        newProcs[i] = current[i];
    }
    return count;
}

/* =====================================================================
 * Runtime-based common process tracking.
 *
 * We keep a "process record sheet" (proc_records.txt) that stores every
 * observed process image path together with its cumulative runtime.
 * At each census tick we capture the running processes and add the
 * elapsed time since the last census to each matching record.
 *
 * The common-process list is the top N records by runtime, where N is
 * derived from the average number of processes seen per census.
 * Users can also add entries manually via manual_common.txt.
 * ===================================================================== */

static int ProcRecordCompareByRuntime(const void* a, const void* b) {
    const ProcRecordEntry* ra = (const ProcRecordEntry*)a;
    const ProcRecordEntry* rb = (const ProcRecordEntry*)b;
    if (ra->totalRuntimeMs < rb->totalRuntimeMs) return 1;
    if (ra->totalRuntimeMs > rb->totalRuntimeMs) return -1;
    return 0;
}

static int ProcRecordCompareByAge(const void* a, const void* b) {
    const ProcRecordEntry* ra = (const ProcRecordEntry*)a;
    const ProcRecordEntry* rb = (const ProcRecordEntry*)b;
    if (ra->firstSeenTick < rb->firstSeenTick) return -1;
    if (ra->firstSeenTick > rb->firstSeenTick) return 1;
    return 0;
}

static void LoadProcRecords(DaemonState* s) {
    s->procRecordCount = 0;
    wchar_t path[MAX_PATH];
    GetDataPath(path, MAX_PATH, L"proc_records.txt");
    FILE* f = _wfopen(path, L"rt, ccs=UTF-8");
    if (!f) return;
    wchar_t line[1024];
    while (fgetws(line, 1024, f) && s->procRecordCount < MAX_PROC_RECORDS) {
        wchar_t* nl = wcschr(line, L'\n'); if (nl) *nl = 0;
        wchar_t* cr = wcschr(line, L'\r'); if (cr) *cr = 0;
        if (line[0] == L'#' || line[0] == 0) continue;
        wchar_t* p1 = wcschr(line, L'|');
        if (!p1) continue;
        *p1 = 0; p1++;
        wchar_t* p2 = wcschr(p1, L'|');
        if (!p2) continue;
        *p2 = 0; p2++;
        wchar_t* p3 = wcschr(p2, L'|');
        if (!p3) continue;
        *p3 = 0; p3++;
        wcsncpy(s->procRecords[s->procRecordCount].imagePath, line, MAX_PATH - 1);
        s->procRecords[s->procRecordCount].imagePath[MAX_PATH - 1] = L'\0';
        s->procRecords[s->procRecordCount].totalRuntimeMs = _wtoi64(p1);
        s->procRecords[s->procRecordCount].firstSeenTick = _wtoi64(p2);
        s->procRecords[s->procRecordCount].lastSeenTick = _wtoi64(p3);
        s->procRecordCount++;
    }
    fclose(f);
}

static void SaveProcRecords(DaemonState* s) {
    wchar_t path[MAX_PATH];
    GetDataPath(path, MAX_PATH, L"proc_records.txt");
    FILE* f = _wfopen(path, L"w, ccs=UTF-8");
    if (!f) return;
    fwprintf(f, L"# imagePath|totalRuntimeMs|firstSeenTick|lastSeenTick\n");
    for (int i = 0; i < s->procRecordCount; i++) {
        if (s->procRecords[i].imagePath[0]) {
            fwprintf(f, L"%ls|%llu|%llu|%llu\n",
                     s->procRecords[i].imagePath,
                     s->procRecords[i].totalRuntimeMs,
                     s->procRecords[i].firstSeenTick,
                     s->procRecords[i].lastSeenTick);
        }
    }
    fclose(f);
}

static void LoadManualCommonProcesses(DaemonState* s) {
    s->manualCommonProcCount = 0;
    wchar_t path[MAX_PATH];
    GetDataPath(path, MAX_PATH, L"manual_common.txt");
    FILE* f = _wfopen(path, L"rt, ccs=UTF-8");
    if (!f) return;
    wchar_t line[MAX_PATH];
    while (fgetws(line, MAX_PATH, f) && s->manualCommonProcCount < MAX_MANUAL_COMMON) {
        wchar_t* nl = wcschr(line, L'\n'); if (nl) *nl = 0;
        wchar_t* cr = wcschr(line, L'\r'); if (cr) *cr = 0;
        if (line[0] == L'#' || line[0] == 0) continue;
        wcsncpy(s->manualCommonProcs[s->manualCommonProcCount].imagePath, line, MAX_PATH - 1);
        s->manualCommonProcs[s->manualCommonProcCount].imagePath[MAX_PATH - 1] = L'\0';
        s->manualCommonProcCount++;
    }
    fclose(f);
}

static void SaveCommonProcesses(DaemonState* s) {
    wchar_t path[MAX_PATH];
    GetDataPath(path, MAX_PATH, L"common_procs.txt");
    FILE* f = _wfopen(path, L"w, ccs=UTF-8");
    if (!f) return;
    fwprintf(f, L"# Auto-generated from process runtime records + manual entries\n");
    for (int i = 0; i < s->commonProcCount; i++) {
        if (s->commonProcs[i].imagePath[0]) {
            fwprintf(f, L"%ls\n", s->commonProcs[i].imagePath);
        }
    }
    fclose(f);
}

static BOOL IsCommonProcess(DaemonState* s, const wchar_t* imagePath) {
    if (!imagePath || !imagePath[0]) return FALSE;
    for (int i = 0; i < s->commonProcCount; i++) {
        if (_wcsicmp(s->commonProcs[i].imagePath, imagePath) == 0) return TRUE;
    }
    for (int i = 0; i < s->manualCommonProcCount; i++) {
        if (_wcsicmp(s->manualCommonProcs[i].imagePath, imagePath) == 0) return TRUE;
    }
    return FALSE;
}

static void LoadCommonProcesses(DaemonState* s) {
    s->commonProcCount = 0;
    wchar_t path[MAX_PATH];
    GetDataPath(path, MAX_PATH, L"common_procs.txt");
    FILE* f = _wfopen(path, L"rt, ccs=UTF-8");
    if (!f) return;
    wchar_t line[MAX_PATH];
    while (fgetws(line, MAX_PATH, f) && s->commonProcCount < MAX_COMMON_PROCS) {
        wchar_t* nl = wcschr(line, L'\n'); if (nl) *nl = 0;
        wchar_t* cr = wcschr(line, L'\r'); if (cr) *cr = 0;
        if (line[0] == L'#' || line[0] == 0) continue;
        wcsncpy(s->commonProcs[s->commonProcCount].imagePath, line, MAX_PATH - 1);
        s->commonProcs[s->commonProcCount].imagePath[MAX_PATH - 1] = L'\0';
        s->commonProcCount++;
    }
    fclose(f);
}

static BOOL IsOwnGuardianProcessPath(const wchar_t* path) {
    if (!path || !path[0]) return FALSE;
    return (wcsstr(path, L"trae_guardian_daemon") ||
            wcsstr(path, L"trae_guardian_service_wrapper"));
}

static BOOL ShouldIncludeInCommonLibrary(DaemonState* s, const wchar_t* imagePath) {
    if (!imagePath || !imagePath[0]) return FALSE;
    if (IsOwnGuardianProcessPath(imagePath)) return TRUE;
    wchar_t signer[256] = {0};
    if (!CheckFileSignatureCached(imagePath, signer, 256)) return FALSE;
    return TRUE;
}

static void ComputeCommonProcesses(DaemonState* s) {
    SYSTEMTIME st; GetLocalTime(&st);
    int today = st.wYear * 10000 + st.wMonth * 100 + st.wDay;
    int currentMonth = today / 100;

    /* Only refresh the common-process library on days 1-7 of each month. */
    if (st.wDay < 1 || st.wDay > 7) {
        DaemonLog(L"Common-process library refresh skipped (day=%d, only 1-7)", st.wDay);
        return;
    }
    if (s->currentCommonMonth == currentMonth) {
        DaemonLog(L"Common-process library already refreshed this month");
        return;
    }

    /* Top N records by cumulative runtime, N = average processes per census */
    int target = s->avgProcCount;
    if (target < 16) target = 16;
    if (target > MAX_COMMON_PROCS) target = MAX_COMMON_PROCS;

    /* Sort records by runtime descending */
    qsort(s->procRecords, s->procRecordCount, sizeof(ProcRecordEntry), ProcRecordCompareByRuntime);

    s->commonProcCount = 0;
    for (int i = 0; i < s->procRecordCount && s->commonProcCount < target; i++) {
        if (!s->procRecords[i].imagePath[0]) continue;
        if (!ShouldIncludeInCommonLibrary(s, s->procRecords[i].imagePath)) {
            DaemonLog(L"Common-process excluded (no valid signature): %ls", s->procRecords[i].imagePath);
            continue;
        }
        wcsncpy(s->commonProcs[s->commonProcCount].imagePath, s->procRecords[i].imagePath, MAX_PATH - 1);
        s->commonProcs[s->commonProcCount].imagePath[MAX_PATH - 1] = L'\0';
        s->commonProcCount++;
    }

    /* Append manual entries */
    for (int i = 0; i < s->manualCommonProcCount && s->commonProcCount < MAX_COMMON_PROCS; i++) {
        /* avoid duplicates */
        BOOL dup = FALSE;
        for (int j = 0; j < s->commonProcCount; j++) {
            if (_wcsicmp(s->commonProcs[j].imagePath, s->manualCommonProcs[i].imagePath) == 0) { dup = TRUE; break; }
        }
        if (!dup) {
            wcsncpy(s->commonProcs[s->commonProcCount].imagePath, s->manualCommonProcs[i].imagePath, MAX_PATH - 1);
            s->commonProcs[s->commonProcCount].imagePath[MAX_PATH - 1] = L'\0';
            s->commonProcCount++;
        }
    }

    s->currentCommonMonth = currentMonth;
    SaveCommonProcesses(s);
    DaemonLog(L"Common-process library refreshed for %d: %d entries", currentMonth, s->commonProcCount);
}

static void UpdateProcRecords(DaemonState* s) {
    ULONGLONG now = GetTickCount64();
    if (s->lastCensusTick == 0) {
        s->lastCensusTick = now;
        return;
    }
    ULONGLONG elapsed = now - s->lastCensusTick;
    if (elapsed < (ULONGLONG)s->censusIntervalMs) return;

    ProcSnapshotEntry current[MAX_PROC_SNAPSHOT];
    int currentCount = CaptureProcessSnapshot(current, MAX_PROC_SNAPSHOT);

    /* Update average process count per census */
    if (s->censusCount == 0) {
        s->avgProcCount = currentCount;
    } else {
        s->avgProcCount = (s->avgProcCount * s->censusCount + currentCount) / (s->censusCount + 1);
    }
    s->censusCount++;

    /* Accumulate runtime for currently running processes */
    for (int i = 0; i < currentCount; i++) {
        if (!current[i].imagePath[0]) continue;
        int found = -1;
        for (int j = 0; j < s->procRecordCount; j++) {
            if (_wcsicmp(s->procRecords[j].imagePath, current[i].imagePath) == 0) {
                found = j;
                break;
            }
        }
        if (found >= 0) {
            s->procRecords[found].totalRuntimeMs += elapsed;
            s->procRecords[found].lastSeenTick = now;
        } else if (s->procRecordCount < s->maxProcRecordCount) {
            wcsncpy(s->procRecords[s->procRecordCount].imagePath, current[i].imagePath, MAX_PATH - 1);
            s->procRecords[s->procRecordCount].imagePath[MAX_PATH - 1] = L'\0';
            s->procRecords[s->procRecordCount].totalRuntimeMs = elapsed;
            s->procRecords[s->procRecordCount].firstSeenTick = now;
            s->procRecords[s->procRecordCount].lastSeenTick = now;
            s->procRecordCount++;
        }
    }

    /* If record sheet is full, drop the oldest record(s) */
    while (s->procRecordCount >= s->maxProcRecordCount) {
        qsort(s->procRecords, s->procRecordCount, sizeof(ProcRecordEntry), ProcRecordCompareByAge);
        /* Remove the first (oldest) record by shifting */
        for (int i = 1; i < s->procRecordCount; i++) {
            s->procRecords[i - 1] = s->procRecords[i];
        }
        s->procRecordCount--;
    }

    s->lastCensusTick = now;
    ComputeCommonProcesses(s);
    SaveProcRecords(s);
    SaveCommonProcesses(s);
}

static void UpdateCommonProcesses(DaemonState* s) {
    UpdateProcRecords(s);
}

void DaemonLoadAll(DaemonState* s) {
    InitLogger();
    InitRogueTrack();
    ActionLogManagerInit(&s->actionLogManager);
    
    wchar_t rulesPath[MAX_PATH];
    GetDataPath(rulesPath, MAX_PATH, L"rules.json");
    RuleEngineInit(&s->ruleEngine, rulesPath);
    RuleEngineLoadRules(&s->ruleEngine);
    DaemonLog(L"Rule engine initialized with %d rules", s->ruleEngine.ruleCount);
    
    ScoreCenterInit(&s->scoreCenter);
    DaemonLog(L"Score center initialized");
    
    StateMachineInit(&s->stateMachine);
    DaemonLog(L"State machine initialized");
    
    ResponseCenterInit(&s->responseCenter, FALSE);
    DaemonLog(L"Response center initialized");
    
    LoadProcs(s);
    LoadSvcs(s);
    LoadRegs(s);
    LoadParts(s);
    LoadRegProtected(s);
    LoadSysRegProtected(s);
    LoadPartProtected(s);
    LoadAiTasks(s);
    wchar_t base[MAX_PATH];
    DaemonGetBasePath(base, MAX_PATH);
    TzLoad(&s->tz, base);
    LoadProcRecords(s);
    LoadManualCommonProcesses(s);
    LoadCommonProcesses(s);
    ComputeCommonProcesses(s);
    DaemonLog(L"Config loaded: proc=%d svc=%d reg=%d part=%d regProt=%d sysRegProt=%d partProt=%d aiTasks=%d tz=%d common=%d records=%d",
              s->procCount, s->svcCount, s->regCount, s->partCount,
              s->regProtCount, s->sysRegProtCount, s->partProtCount,
              s->aiTaskCount, s->tz.count, s->commonProcCount, s->procRecordCount);
}

void DaemonLoadSettings(DaemonState* s) {
    InitLogger();
    wchar_t path[MAX_PATH];
    GetDataPath(path, MAX_PATH, L"settings.ini");
    wchar_t buf[32];
    GetPrivateProfileStringW(L"Settings", L"CheckInterval", L"500", buf, 32, path);
    s->checkInterval = _wtoi(buf);
    if (s->checkInterval < 100) s->checkInterval = 100;
    if (s->checkInterval > 60000) s->checkInterval = 60000;
    GetPrivateProfileStringW(L"Settings", L"ReloadInterval", L"30000", buf, 32, path);
    s->reloadInterval = _wtoi(buf);
    GetPrivateProfileStringW(L"Settings", L"CensusInterval", L"30000", buf, 32, path);
    s->censusIntervalMs = _wtoi(buf);
    if (s->censusIntervalMs < 1000) s->censusIntervalMs = 1000;
    if (s->censusIntervalMs > 600000) s->censusIntervalMs = 600000;
    GetPrivateProfileStringW(L"Settings", L"MaxProcRecords", L"500", buf, 32, path);
    s->maxProcRecordCount = _wtoi(buf);
    if (s->maxProcRecordCount < 100) s->maxProcRecordCount = 100;
    if (s->maxProcRecordCount > MAX_PROC_RECORDS) s->maxProcRecordCount = MAX_PROC_RECORDS;
    if (s->reloadInterval < 1000) s->reloadInterval = 1000;
    if (s->reloadInterval > 3600000) s->reloadInterval = 3600000;

    GetPrivateProfileStringW(L"Protection", L"RegProtection", L"1", buf, 32, path);
    s->enableRegProtection = (_wtoi(buf) != 0);
    GetPrivateProfileStringW(L"Protection", L"PartProtection", L"1", buf, 32, path);
    s->enablePartProtection = (_wtoi(buf) != 0);
    GetPrivateProfileStringW(L"Protection", L"SysCriticalProtection", L"1", buf, 32, path);
    s->enableSysCriticalProtection = (_wtoi(buf) != 0);
    GetPrivateProfileStringW(L"Protection", L"AiAssist", L"0", buf, 32, path);
    s->enableAiAssist = (_wtoi(buf) != 0);
    
    GetPrivateProfileStringW(L"Settings", L"ScoreResetInterval", L"604800000", buf, 32, path);
    s->scoreResetIntervalMs = _wtoi(buf);
    if (s->scoreResetIntervalMs < 604800000) s->scoreResetIntervalMs = 604800000;
    if (s->scoreResetIntervalMs > 31536000000ULL) s->scoreResetIntervalMs = 31536000000ULL;
    s->lastScoreResetTick = GetTickCount64();

    GetPrivateProfileStringW(L"Scan", L"HighFreqInterval", L"20", buf, 32, path);
    s->highFreqScanIntervalMs = _wtoi(buf);
    if (s->highFreqScanIntervalMs < 5) s->highFreqScanIntervalMs = 5;
    if (s->highFreqScanIntervalMs > 1000) s->highFreqScanIntervalMs = 1000;

    GetPrivateProfileStringW(L"Scan", L"LowFreqInterval", L"10000", buf, 32, path);
    s->lowFreqScanIntervalMs = _wtoi(buf);
    if (s->lowFreqScanIntervalMs < 1000) s->lowFreqScanIntervalMs = 1000;
    if (s->lowFreqScanIntervalMs > 100000) s->lowFreqScanIntervalMs = 100000;

    DaemonLog(L"Settings loaded: check=%dms reload=%dms regProt=%d partProt=%d sysProt=%d aiAssist=%d scoreReset=%dms highFreq=%dms lowFreq=%dms",
              s->checkInterval, s->reloadInterval,
              s->enableRegProtection, s->enablePartProtection,
              s->enableSysCriticalProtection, s->enableAiAssist,
              s->scoreResetIntervalMs);
}

void DaemonLoadDlls(DaemonState* s) {
    (void)s;
    wchar_t base[MAX_PATH];
    DaemonGetBasePath(base, MAX_PATH);
    wchar_t path[MAX_PATH];
    
    swprintf(path, MAX_PATH, L"%ls\\core\\service_manager.dll", base);
    DWORD fa = GetFileAttributesW(path);
    HMODULE hSvc = LoadLibraryW(path);
    if (hSvc) {
        g_svcDelete = (FnDeleteServiceByName)GetProcAddress(hSvc, "DeleteServiceByName");
        g_svcGetAll = (FnGetAllServices)GetProcAddress(hSvc, "GetAllServices");
        g_svcStop = (FnStopServiceByName)GetProcAddress(hSvc, "StopServiceByName");
        g_svcStart = (FnStartServiceByName)GetProcAddress(hSvc, "StartServiceByName");
        g_svcAddRepeated = (FnAddSvcRepeated)GetProcAddress(hSvc, "AddToRepeatedDeleteList");
        g_svcRemoveRepeated = (FnRemoveSvcRepeated)GetProcAddress(hSvc, "RemoveFromRepeatedDeleteList");
        g_svcIsRepeated = (FnIsSvcRepeated)GetProcAddress(hSvc, "IsServiceRepeatedDelete");
        DaemonLog(L"service_manager.dll loaded");
    } else {
        DWORD e = GetLastError();
        DaemonLog(L"service_manager.dll load failed: %lu path=%ls attrs=%lu", e, path, fa);
    }

    swprintf(path, MAX_PATH, L"%ls\\core\\registry_manager.dll", base);
    fa = GetFileAttributesW(path);
    HMODULE hReg = LoadLibraryW(path);
    if (hReg) {
        g_regDelete = (FnDeleteRegistryEntry)GetProcAddress(hReg, "DeleteRegistryEntry");
        DaemonLog(L"registry_manager.dll loaded");
    } else {
        DWORD e = GetLastError();
        DaemonLog(L"registry_manager.dll load failed: %lu path=%ls attrs=%lu", e, path, fa);
    }

    swprintf(path, MAX_PATH, L"%ls\\core\\partition_manager.dll", base);
    fa = GetFileAttributesW(path);
    HMODULE hPart = LoadLibraryW(path);
    if (hPart) {
        g_partDelete = (FnDeletePartition)GetProcAddress(hPart, "DeletePartition");
        g_partGetDisks = (FnGetAllDisks)GetProcAddress(hPart, "GetAllDisks");
        g_partGetParts = (FnGetPartitionsOnDisk)GetProcAddress(hPart, "GetPartitionsOnDisk");
        g_partAddRepeated = (FnAddPartRepeated)GetProcAddress(hPart, "AddToRepeatedDeleteList");
        g_partRemoveRepeated = (FnRemovePartRepeated)GetProcAddress(hPart, "RemoveFromRepeatedDeleteList");
        g_partIsRepeated = (FnIsPartRepeated)GetProcAddress(hPart, "IsPartitionRepeatedDelete");
        DaemonLog(L"partition_manager.dll loaded");
    } else {
        DWORD e = GetLastError();
        DaemonLog(L"partition_manager.dll load failed: %lu path=%ls attrs=%lu", e, path, fa);
    }
    DaemonLog(L"base path: %ls baseLen=%lu", base, (DWORD)wcslen(base));
}

DWORD GetPidByName(const wchar_t* name) {
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
                DaemonLog(L"[DEBUG] GetPidByName: exact match %ls -> %lu", pe.szExeFile, pid);
                break;
            }
            size_t exeLen = wcslen(pe.szExeFile);
            size_t nameLen = wcslen(name);
            if (exeLen > 4 && _wcsicmp(pe.szExeFile + exeLen - 4, L".exe") == 0) {
                wchar_t strippedExe[MAX_PATH];
                wcsncpy_s(strippedExe, MAX_PATH, pe.szExeFile, exeLen - 4);
                strippedExe[exeLen - 4] = L'\0';
                if (_wcsicmp(strippedExe, name) == 0) {
                    pid = pe.th32ProcessID;
                    DaemonLog(L"[DEBUG] GetPidByName: stripped exe match %ls -> %lu", pe.szExeFile, pid);
                    break;
                }
            }
            if (nameLen > 4 && _wcsicmp(name + nameLen - 4, L".exe") == 0) {
                wchar_t strippedName[MAX_PATH];
                wcsncpy_s(strippedName, MAX_PATH, name, nameLen - 4);
                strippedName[nameLen - 4] = L'\0';
                if (_wcsicmp(pe.szExeFile, strippedName) == 0) {
                    pid = pe.th32ProcessID;
                    DaemonLog(L"[DEBUG] GetPidByName: stripped name match %ls -> %lu", pe.szExeFile, pid);
                    break;
                }
            }
            if (wcsstr(pe.szExeFile, L"test_threat")) {
                DaemonLog(L"[DEBUG] GetPidByName: candidate %ls, name=%ls, cmp=%d", pe.szExeFile, name, _wcsicmp(pe.szExeFile, name));
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    if (pid == 0 && name && name[0]) {
        DaemonLog(L"[DEBUG] GetPidByName: no match found for %ls", name);
    }
    return pid;
}

static void EnableDebugPrivilege(void) {
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
        AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
        CloseHandle(hToken);
    }
}

/* ======================== AI monitoring ======================== */
typedef int (*FnAiLoadKey)(const char*, char*, int);
typedef int (*FnAiAsk)(const char*, const char*, const char*, const char*, const char*, const char*, int, float, int, AiResult*);

static FnAiLoadKey g_aiLoadKey = NULL;
static FnAiAsk     g_aiAsk = NULL;
static HMODULE     g_hAiClient = NULL;
static BOOL        g_aiClientTried = FALSE;

static char g_aiProvider[256] = "api.siliconflow.cn";
static char g_aiEndpoint[256] = "/v1/chat/completions";
static char g_aiModel[128] = AIC_DEFAULT_MODEL;

static void LoadAiClientDll(void) {
    if (g_aiClientTried) return;
    g_aiClientTried = TRUE;
    wchar_t base[MAX_PATH];
    DaemonGetBasePath(base, MAX_PATH);
    wchar_t path[MAX_PATH];
    swprintf(path, MAX_PATH, L"%ls\\AI\\ai_client.dll", base);
    DWORD fa = GetFileAttributesW(path);
    g_hAiClient = LoadLibraryW(path);
    if (!g_hAiClient) {
        DWORD e = GetLastError();
        DaemonLog(L"ai_client.dll load failed: %lu path=%ls attrs=%lu", e, path, fa);
        return;
    }
    g_aiLoadKey = (FnAiLoadKey)GetProcAddress(g_hAiClient, "Ai_LoadKey");
    g_aiAsk = (FnAiAsk)GetProcAddress(g_hAiClient, "Ai_Ask");
    if (!g_aiLoadKey || !g_aiAsk) {
        DaemonLog(L"ai_client.dll exports missing");
        FreeLibrary(g_hAiClient);
        g_hAiClient = NULL;
        return;
    }
    DaemonLog(L"ai_client.dll loaded");
}

/* ======================== AI web search DLL ======================== */
typedef int (*FnWebSearch)(const char*, char*, int);
static FnWebSearch g_webSearch = NULL;
static HMODULE    g_hWebSearch = NULL;
static BOOL       g_webSearchTried = FALSE;

static void LoadAiWebSearchDll(void) {
    if (g_webSearchTried) return;
    g_webSearchTried = TRUE;
    wchar_t base[MAX_PATH];
    DaemonGetBasePath(base, MAX_PATH);
    wchar_t path[MAX_PATH];
    swprintf(path, MAX_PATH, L"%ls\\AI\\ai_web_search.dll", base);
    DWORD fa = GetFileAttributesW(path);
    g_hWebSearch = LoadLibraryW(path);
    if (!g_hWebSearch) {
        DWORD e = GetLastError();
        DaemonLog(L"ai_web_search.dll load failed: %lu path=%ls attrs=%lu", e, path, fa);
        return;
    }
    g_webSearch = (FnWebSearch)GetProcAddress(g_hWebSearch, "WebSearch");
    if (!g_webSearch) {
        DaemonLog(L"ai_web_search.dll exports missing");
        FreeLibrary(g_hWebSearch);
        g_hWebSearch = NULL;
        return;
    }
    DaemonLog(L"ai_web_search.dll loaded");
}

/* Wrapper that returns an allocated UTF-8 string of web search results.
 * Caller frees. Returns NULL on failure or empty results. */
static char* FetchWebReputation(const wchar_t* processName, const wchar_t* signer) {
    if (!g_webSearch) return NULL;
    char procA[256] = "";
    WideCharToMultiByte(CP_UTF8, 0, processName ? processName : L"", -1, procA, sizeof(procA), NULL, NULL);
    char signerA[256] = "";
    if (signer && signer[0]) {
        WideCharToMultiByte(CP_UTF8, 0, signer, -1, signerA, sizeof(signerA), NULL, NULL);
    }
    char query[600];
    if (signerA[0]) {
        snprintf(query, sizeof(query),
            "%s %s reputation review user feedback is it safe or rogue PUP",
            procA, signerA);
    } else {
        snprintf(query, sizeof(query),
            "%s reputation review user feedback is it safe or rogue PUP",
            procA);
    }
    char* buf = (char*)malloc(8192);
    if (!buf) return NULL;
    int n = g_webSearch(query, buf, 8192);
    if (n <= 0) { free(buf); return NULL; }
    return buf;
}

static void ParseAiConfigLine(const char* line, char* keyOut, int keySz, char* valOut, int valSz) {
    keyOut[0] = valOut[0] = 0;
    const char* eq = strchr(line, '=');
    if (!eq) return;
    int klen = (int)(eq - line);
    while (klen > 0 && (line[klen - 1] == ' ' || line[klen - 1] == '\t')) klen--;
    if (klen <= 0 || klen >= keySz) return;
    memcpy(keyOut, line, klen); keyOut[klen] = 0;

    const char* v = eq + 1;
    while (*v == ' ' || *v == '\t') v++;
    int vlen = (int)strlen(v);
    while (vlen > 0 && (v[vlen - 1] == '\n' || v[vlen - 1] == '\r')) vlen--;
    if (vlen >= valSz) vlen = valSz - 1;
    memcpy(valOut, v, vlen); valOut[vlen] = 0;
}

static void LoadAiConfig(void) {
    wchar_t wpath[MAX_PATH];
    GetDataPath(wpath, MAX_PATH, L"ai_config.txt");
    FILE* f = _wfopen(wpath, L"rt, ccs=UTF-8");
    if (!f) {
        /* fallback: old api_key.dat */
        GetDataPath(wpath, MAX_PATH, L"api_key.dat");
        return;
    }
    wchar_t wline[1024];
    while (fgetws(wline, 1024, f)) {
        if (wline[0] == L'#' || wline[0] == L'\n' || wline[0] == L'\r' || wline[0] == 0) continue;
        char line[1024];
        WideCharToMultiByte(CP_UTF8, 0, wline, -1, line, 1024, NULL, NULL);
        char key[64] = {0}, val[512] = {0};
        ParseAiConfigLine(line, key, sizeof(key), val, sizeof(val));
        if (_stricmp(key, "provider") == 0 && val[0]) strncpy(g_aiProvider, val, sizeof(g_aiProvider) - 1);
        else if (_stricmp(key, "endpoint") == 0 && val[0]) strncpy(g_aiEndpoint, val, sizeof(g_aiEndpoint) - 1);
        else if (_stricmp(key, "model") == 0 && val[0]) strncpy(g_aiModel, val, sizeof(g_aiModel) - 1);
    }
    fclose(f);
}

int LoadApiKey(char* out, int outSz) {
    LoadAiConfig();
    out[0] = 0;
    wchar_t wpath[MAX_PATH];
    GetDataPath(wpath, MAX_PATH, L"ai_config.txt");
    FILE* f = _wfopen(wpath, L"rt, ccs=UTF-8");
    if (!f) return -1;
    wchar_t wline[1024];
    while (fgetws(wline, 1024, f)) {
        if (wline[0] == L'#' || wline[0] == L'\n' || wline[0] == L'\r' || wline[0] == 0) continue;
        char line[1024];
        WideCharToMultiByte(CP_UTF8, 0, wline, -1, line, 1024, NULL, NULL);
        char key[64] = {0}, val[512] = {0};
        ParseAiConfigLine(line, key, sizeof(key), val, sizeof(val));
        if (_stricmp(key, "api_key") == 0 && val[0]) {
            strncpy(out, val, outSz - 1);
            out[outSz - 1] = 0;
            fclose(f);
            return 0;
        }
    }
    fclose(f);
    /* fallback: old encrypted api_key.dat */
    LoadAiClientDll();
    if (!g_aiLoadKey) return -1;
    GetDataPath(wpath, MAX_PATH, L"api_key.dat");
    char path[MAX_PATH];
    WideCharToMultiByte(CP_UTF8, 0, wpath, -1, path, MAX_PATH, NULL, NULL);
    return g_aiLoadKey(path, out, outSz);
}

static int AskAi(const char* apiKey, const char* systemPrompt, const char* userPrompt,
                 float temperature, int maxTokens, AiResult* out) {
    LoadAiClientDll();
    LoadAiWebSearchDll();
    LoadAiConfig();
    if (!g_aiAsk) return -1;
    return g_aiAsk(apiKey, g_aiProvider, g_aiEndpoint, systemPrompt, userPrompt, g_aiModel, 180000, temperature, maxTokens, out);
}

static char* ReadFileAnsi(const wchar_t* path, long* outSz) {
    return ReadFileUtf8(path, outSz);
}

static BOOL ReadProcessMemoryBytes(DWORD pid, int maxBytes, BYTE* buf, int* outRead) {
    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return FALSE;
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = NULL;
    int total = 0;
    while (total < maxBytes && VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            int need = maxBytes - total;
            if ((SIZE_T)need > mbi.RegionSize) need = (int)mbi.RegionSize;
            SIZE_T rd = 0;
            ReadProcessMemory(hProc, mbi.BaseAddress, buf + total, need, &rd);
            total += (int)rd;
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }
    CloseHandle(hProc);
    *outRead = total;
    return total > 0;
}

static void HexEncode(const BYTE* in, int len, char* out, int outSz) {
    int o = 0;
    for (int i = 0; i < len && o < outSz - 3; i++) {
        o += snprintf(out + o, outSz - o, "%02X ", in[i]);
    }
    if (o > 0) out[o - 1] = 0;
}

static const char* ParseAiLevel(const char* json, char* levelOut, int levelSz,
                                char* pathOut, int pathSz,
                                char* reasonOut, int reasonSz) {
    levelOut[0] = pathOut[0] = reasonOut[0] = 0;
    const char* p = strstr(json, "\"level\"");
    if (p) {
        p = strchr(p, ':'); if (p) { p++; while (*p == ' ' || *p == '\t' || *p == '"') p++;
            int i = 0; while (*p && *p != '"' && i < levelSz - 1) levelOut[i++] = *p++; levelOut[i] = 0; }
    }
    p = strstr(json, "\"path\"");
    if (p) {
        p = strchr(p, ':'); if (p) { p++; while (*p == ' ' || *p == '\t' || *p == '"') p++;
            int i = 0; while (*p && *p != '"' && i < pathSz - 1) pathOut[i++] = *p++; pathOut[i] = 0; }
    }
    p = strstr(json, "\"reason\"");
    if (p) {
        p = strchr(p, ':'); if (p) { p++; while (*p == ' ' || *p == '\t' || *p == '"') p++;
            int i = 0; while (*p && *p != '"' && i < reasonSz - 1) reasonOut[i++] = *p++; reasonOut[i] = 0; }
    }
    return levelOut;
}

/* Parse AI search requests.
 * Recognizes: "search_logs": "keyword"  and  "search_knowledge": "keyword".
 * typeOut will be "logs" or "knowledge" (empty if no search).
 */
static void ParseAiSearch(const char* json, char* searchOut, int searchSz,
                          char* typeOut, int typeSz) {
    searchOut[0] = 0;
    typeOut[0] = 0;
    const char* fields[] = { "\"search_logs\"", "\"search_knowledge\"", "\"search\"" };
    const char* types[] = { "logs", "knowledge", "logs" };
    for (int f = 0; f < 3; f++) {
        const char* p = strstr(json, fields[f]);
        if (p) {
            p = strchr(p, ':');
            if (p) {
                p++;
                while (*p == ' ' || *p == '\t' || *p == '"') p++;
                int i = 0;
                while (*p && *p != '"' && i < searchSz - 1) searchOut[i++] = *p++;
                searchOut[i] = 0;
                strncpy(typeOut, types[f], typeSz - 1);
                typeOut[typeSz - 1] = 0;
                return;
            }
        }
    }
}

#define MAX_AI_ACTIONS 8
typedef struct {
    char type[32];
    wchar_t target[MAX_PATH];
    BOOL tree;
} AiAction;

static int ParseAiActions(const char* json, AiAction* actions, int maxActions) {
    int count = 0;
    const char* arr = strstr(json, "\"actions\"");
    if (!arr) return 0;
    arr = strchr(arr, '[');
    if (!arr) return 0;
    arr++;
    int depth = 1;
    const char* objStart = NULL;
    while (*arr && count < maxActions) {
        if (*arr == '{') {
            if (depth == 1) objStart = arr;
            depth++;
        } else if (*arr == '}') {
            depth--;
            if (depth == 1 && objStart) {
                int objLen = (int)(arr - objStart + 1);
                if (objLen < 4096) {
                    char obj[4096];
                    memcpy(obj, objStart, objLen); obj[objLen] = 0;
                    char type[32] = "", target[MAX_PATH] = "";
                    int tree = 0;
                    json_find_str_a(obj, "type", type, sizeof(type));
                    json_find_str_a(obj, "target", target, sizeof(target));
                    tree = json_find_bool_a(obj, "tree", 0);
                    if (type[0] && target[0]) {
                        AiAction* a = &actions[count++];
                        strncpy(a->type, type, sizeof(a->type) - 1);
                        a->type[sizeof(a->type) - 1] = 0;
                        MultiByteToWideChar(CP_UTF8, 0, target, -1, a->target, MAX_PATH);
                        a->tree = tree ? TRUE : FALSE;
                    }
                }
                objStart = NULL;
            }
        }
        arr++;
    }
    return count;
}

static BOOL ParseAiBoolField(const char* json, const char* key) {
    char buf[64];
    buf[0] = 0;
    const char* p = strstr(json, key);
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p++;
            while (*p == ' ' || *p == '\t' || *p == '"') p++;
            int i = 0;
            while (*p && *p != ',' && *p != '}' && *p != '\n' && *p != '\r' && i < 63) {
                buf[i++] = *p++;
            }
            buf[i] = 0;
        }
    }
    return (_stricmp(buf, "true") == 0);
}

static BOOL ParseAiNeedsApproval(const char* json) {
    return ParseAiBoolField(json, "\"needsApproval\"");
}

static BOOL ParseAiRepeatedKill(const char* json) {
    return ParseAiBoolField(json, "\"repeatedKill\"");
}

static int ParseAiCleanupList(const char* json, char** outItems, int maxItems, int itemSize) {
    int count = 0;
    const char* arr = strstr(json, "\"cleanup\"");
    if (!arr) return 0;
    arr = strchr(arr, '[');
    if (!arr) return 0;
    arr++;
    while (*arr && count < maxItems) {
        while (*arr == ' ' || *arr == '\t' || *arr == '\n' || *arr == '\r' || *arr == ',') arr++;
        if (*arr == ']') break;
        if (*arr == '"') {
            arr++;
            int i = 0;
            while (*arr && *arr != '"' && i < itemSize - 1) {
                if (*arr == '\\' && arr[1]) arr++;
                outItems[count][i++] = *arr++;
            }
            outItems[count][i] = 0;
            if (i > 0) count++;
            if (*arr == '"') arr++;
        } else {
            arr++;
        }
    }
    return count;
}

static BOOL KillProcessByName(const wchar_t* name, BOOL tree);

static BOOL ExecuteAiActions(DaemonState* s, const char* level, const AiAction* actions, int count,
                              const wchar_t* procName, const wchar_t* contextTask, const wchar_t* contextId) {
    BOOL anyOk = FALSE;
    for (int i = 0; i < count; i++) {
        const AiAction* a = &actions[i];
        BOOL ok = FALSE;
        if (_stricmp(a->type, "repeated_kill") == 0) {
            EnterCriticalSection(&g_cs);
            if (s->procCount < MAX_PROC) {
                ProtectedEntry* e = &s->procs[s->procCount++];
                ZeroMemory(e, sizeof(*e));
                wcsncpy(e->name, a->target, 259);
                e->isRepeated = TRUE;
                e->isTree = a->tree;
                SaveProcs(s);
                ok = TRUE;
            }
            LeaveCriticalSection(&g_cs);
            DaemonLog(L"[AI-ACTION] repeated_kill %ls -> %ls", a->target, ok ? L"ok" : L"failed");
        } else if (_stricmp(a->type, "delete_path") == 0) {
            EnterCriticalSection(&g_cs);
            ok = CleanTargetPath(a->target);
            LeaveCriticalSection(&g_cs);
            DaemonLog(L"[AI-ACTION] delete_path %ls -> %ls", a->target, ok ? L"ok" : L"failed");
        } else if (_stricmp(a->type, "quarantine_path") == 0) {
            EnterCriticalSection(&g_cs);
            QuarantineDirectory(a->target);
            LeaveCriticalSection(&g_cs);
            ok = TRUE;
            DaemonLog(L"[AI-ACTION] quarantine_path %ls -> ok", a->target);
        }
        if (ok) anyOk = TRUE;

        char targetA[MAX_PATH] = "";
        WideCharToMultiByte(CP_UTF8, 0, a->target, -1, targetA, sizeof(targetA), NULL, NULL);
        char actionDesc[512];
        snprintf(actionDesc, sizeof(actionDesc), "%s %s (tree=%d)", a->type, targetA, a->tree);
        WriteAiNotification(level, contextTask ? contextTask : L"protection",
                            contextId ? contextId : L"protection",
                            procName ? procName : L"-", targetA, actionDesc);
    }
    return anyOk;
}

/* Search daemon.log for lines containing keyword (case-insensitive).
   Returns a newly allocated UTF-8 string with up to maxLines matching lines. */
static char* SearchLogByKeyword(const wchar_t* keywordW, int maxLines) {
    char* result = (char*)malloc(1);
    if (!result) return NULL;
    result[0] = 0;
    int resultCap = 1;
    int resultLen = 0;
    int found = 0;

    wchar_t logPath[MAX_PATH];
    GetDataPath(logPath, MAX_PATH, L"daemon.log");
    FILE* f = _wfopen(logPath, L"rb");
    if (!f) { free(result); return NULL; }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz <= 0) { fclose(f); free(result); return NULL; }
    if (sz > 8 * 1024 * 1024) sz = 8 * 1024 * 1024; /* max 8 MB */
    char* buf = (char*)malloc(sz + 1);
    if (!buf) { fclose(f); free(result); return NULL; }
    fseek(f, 0, SEEK_SET);
    size_t n = fread(buf, 1, sz, f);
    buf[n] = 0;
    fclose(f);

    char keywordA[512] = "";
    WideCharToMultiByte(CP_UTF8, 0, keywordW, -1, keywordA, sizeof(keywordA), NULL, NULL);
    size_t kwLen = strlen(keywordA);
    if (kwLen == 0) { free(buf); return result; }

    char* line = buf;
    while (*line && found < maxLines) {
        char* end = strchr(line, '\n');
        if (!end) end = line + strlen(line);
        int lineLen = (int)(end - line);
        if (lineLen > 0) {
            /* case-insensitive substring search */
            BOOL match = FALSE;
            for (int i = 0; i <= lineLen - (int)kwLen; i++) {
                if (_strnicmp(line + i, keywordA, (int)kwLen) == 0) { match = TRUE; break; }
            }
            if (match) {
                int need = lineLen + 2;
                if (resultLen + need + 1 > resultCap) {
                    resultCap = (resultLen + need + 1) * 2;
                    result = (char*)realloc(result, resultCap);
                }
                memcpy(result + resultLen, line, lineLen);
                resultLen += lineLen;
                result[resultLen++] = '\r';
                result[resultLen++] = '\n';
                result[resultLen] = 0;
                found++;
            }
        }
        if (*end == '\n') line = end + 1; else break;
    }
    free(buf);
    return result;
}

/* Search ai_knowledge.md (and SOUL.md as memory) for a keyword.
 * Returns an allocated UTF-8 string with matching lines. Caller frees.
 */
static char* SearchKnowledgeByKeyword(const wchar_t* keywordW, int maxLines) {
    char* result = (char*)malloc(1);
    if (!result) return NULL;
    result[0] = 0;
    int resultCap = 1;
    int resultLen = 0;
    int found = 0;

    char keywordA[512] = "";
    WideCharToMultiByte(CP_UTF8, 0, keywordW, -1, keywordA, sizeof(keywordA), NULL, NULL);
    size_t kwLen = strlen(keywordA);
    if (kwLen == 0) return result;

    const wchar_t* files[2] = { L"ai_memory\\ai_knowledge.md", L"ai_memory\\SOUL.md" };
    for (int fidx = 0; fidx < 2 && found < maxLines; fidx++) {
        wchar_t path[MAX_PATH];
        GetDataPath(path, MAX_PATH, files[fidx]);
        FILE* f = _wfopen(path, L"rb");
        if (!f) continue;
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        if (sz <= 0) { fclose(f); continue; }
        if (sz > 8 * 1024 * 1024) sz = 8 * 1024 * 1024;
        char* buf = (char*)malloc(sz + 1);
        if (!buf) { fclose(f); continue; }
        fseek(f, 0, SEEK_SET);
        size_t n = fread(buf, 1, sz, f);
        buf[n] = 0;
        fclose(f);

        char* line = buf;
        while (*line && found < maxLines) {
            char* end = strchr(line, '\n');
            if (!end) end = line + strlen(line);
            int lineLen = (int)(end - line);
            if (lineLen > 0) {
                BOOL match = FALSE;
                for (int i = 0; i <= lineLen - (int)kwLen; i++) {
                    if (_strnicmp(line + i, keywordA, (int)kwLen) == 0) { match = TRUE; break; }
                }
                if (match) {
                    int need = lineLen + 4 + 64;
                    if (resultLen + need + 1 > resultCap) {
                        resultCap = (resultLen + need + 1) * 2;
                        result = (char*)realloc(result, resultCap);
                    }
                    const char* src = (fidx == 0) ? "[knowledge] " : "[SOUL] ";
                    int tagLen = (int)strlen(src);
                    memcpy(result + resultLen, src, tagLen);
                    resultLen += tagLen;
                    memcpy(result + resultLen, line, lineLen);
                    resultLen += lineLen;
                    result[resultLen++] = '\r';
                    result[resultLen++] = '\n';
                    found++;
                }
            }
            if (*end == '\n') line = end + 1; else break;
        }
        free(buf);
    }
    result[resultLen] = 0;
    return result;
}

/* Search the appropriate signature database based on signature status.
 * isSigned=0 -> virus_signatures.md (unsigned malware, auto-clean)
 * isSigned=1 -> rogue_signatures.md  (signed PUP/aggressive vendors, repeated kill)
 * Returns an allocated UTF-8 string with matching lines. Caller frees. */
static char* SearchSignatureDB(const wchar_t* keywordW, int isSigned, int maxLines) {
    char* result = (char*)malloc(1);
    if (!result) return NULL;
    result[0] = 0;
    int resultCap = 1;
    int resultLen = 0;
    int found = 0;

    char keywordA[512] = "";
    WideCharToMultiByte(CP_UTF8, 0, keywordW, -1, keywordA, sizeof(keywordA), NULL, NULL);
    size_t kwLen = strlen(keywordA);
    if (kwLen == 0) return result;

    const wchar_t* file = isSigned ? L"ai_memory\\rogue_signatures.md"
                                  : L"ai_memory\\virus_signatures.md";
    wchar_t path[MAX_PATH];
    GetDataPath(path, MAX_PATH, file);
    FILE* f = _wfopen(path, L"rb");
    if (!f) return result;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz <= 0) { fclose(f); return result; }
    if (sz > 8 * 1024 * 1024) sz = 8 * 1024 * 1024;
    char* buf = (char*)malloc(sz + 1);
    if (!buf) { fclose(f); return result; }
    fseek(f, 0, SEEK_SET);
    size_t n = fread(buf, 1, sz, f);
    buf[n] = 0;
    fclose(f);

    const char* tag = isSigned ? "[rogue-db] " : "[virus-db] ";
    int tagLen = (int)strlen(tag);
    char* line = buf;
    while (*line && found < maxLines) {
        char* end = strchr(line, '\n');
        if (!end) end = line + strlen(line);
        int lineLen = (int)(end - line);
        if (lineLen > 0) {
            BOOL match = FALSE;
            for (int i = 0; i <= lineLen - (int)kwLen; i++) {
                if (_strnicmp(line + i, keywordA, (int)kwLen) == 0) { match = TRUE; break; }
            }
            if (match) {
                int need = lineLen + tagLen + 4;
                if (resultLen + need + 1 > resultCap) {
                    resultCap = (resultLen + need + 1) * 2;
                    result = (char*)realloc(result, resultCap);
                }
                memcpy(result + resultLen, tag, tagLen);
                resultLen += tagLen;
                memcpy(result + resultLen, line, lineLen);
                resultLen += lineLen;
                result[resultLen++] = '\r';
                result[resultLen++] = '\n';
                found++;
            }
        }
        if (*end == '\n') line = end + 1; else break;
    }
    free(buf);
    result[resultLen] = 0;
    return result;
}

/* ======================== Threat evaluation helpers ======================== */

static BOOL GetProcessImagePath(DWORD pid, wchar_t* out, DWORD outSz) {
    out[0] = L'\0';
    if (pid == 0 || pid == 4) return FALSE;
    
    for (int retry = 0; retry < 3; retry++) {
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProc) {
            hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        }
        if (!hProc) {
            if (retry == 0) {
                DaemonLog(L"[PATH-DEBUG] OpenProcess failed for PID=%lu, error=%lu, retry=%d", 
                          pid, GetLastError(), retry);
            }
            Sleep(100);
            continue;
        }
        
        DWORD sz = outSz;
        BOOL ok = QueryFullProcessImageNameW(hProc, 0, out, &sz);
        if (ok && out[0]) {
            CloseHandle(hProc);
            DaemonLog(L"[PATH-DEBUG] QueryFullProcessImageNameW succeeded for PID=%lu: %ls", pid, out);
            return TRUE;
        }
        
        if (!ok) {
            DaemonLog(L"[PATH-DEBUG] QueryFullProcessImageNameW failed for PID=%lu, error=%lu, retry=%d", 
                      pid, GetLastError(), retry);
        }
        
        sz = outSz;
        ok = GetModuleFileNameExW(hProc, NULL, out, sz);
        if (ok && out[0]) {
            CloseHandle(hProc);
            DaemonLog(L"[PATH-DEBUG] GetModuleFileNameExW succeeded for PID=%lu: %ls", pid, out);
            return TRUE;
        }
        
        if (!ok) {
            DaemonLog(L"[PATH-DEBUG] GetModuleFileNameExW failed for PID=%lu, error=%lu", 
                      pid, GetLastError());
        }
        
        CloseHandle(hProc);
        if (retry < 2) {
            Sleep(100);
        }
    }
    
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = {0};
        pe.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (pe.th32ProcessID == pid) {
                    if (pe.szExeFile && pe.szExeFile[0]) {
                        wcscpy(out, pe.szExeFile);
                        DaemonLog(L"[PATH-DEBUG] CreateToolhelp32Snapshot succeeded for PID=%lu: %ls", pid, out);
                        CloseHandle(hSnap);
                        return TRUE;
                    }
                    break;
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    
    DaemonLog(L"[PATH-DEBUG] Failed to get image path for PID=%lu after all methods", pid);
    return FALSE;
}

BOOL CheckFileSignature(const wchar_t* path, wchar_t* signer, DWORD signerSz) {
    signer[0] = L'\0';
    if (!path || !path[0]) return FALSE;

    WINTRUST_FILE_INFO fi = {0};
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = path;
    fi.hFile = NULL;
    fi.pgKnownSubject = NULL;

    GUID act = WINTRUST_ACTION_GENERIC_VERIFY_V2;
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
    wd.dwUIContext = WTD_UICONTEXT_EXECUTE;

    LONG r = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &act, &wd);

    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &act, &wd);

    return (r == ERROR_SUCCESS);
}

static void GetParentProcessInfo(DWORD pid, DWORD* parentPid, wchar_t* parentName, DWORD nameSz);

static BOOL IsProcessRunningAsSystem(DWORD pid) {
    if (pid == 0 || pid == 4) return TRUE;
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return FALSE;

    HANDLE hToken = NULL;
    BOOL ok = OpenProcessToken(hProc, TOKEN_QUERY, &hToken);
    CloseHandle(hProc);
    if (!ok) return FALSE;

    DWORD sz = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &sz);
    BOOL isSys = FALSE;
    if (sz > 0) {
        PTOKEN_USER tu = (PTOKEN_USER)malloc(sz);
        if (tu) {
            if (GetTokenInformation(hToken, TokenUser, tu, sz, &sz)) {
                LPWSTR sidStr = NULL;
                if (ConvertSidToStringSidW(tu->User.Sid, &sidStr)) {
                    if (wcscmp(sidStr, L"S-1-5-18") == 0) isSys = TRUE;
                    LocalFree(sidStr);
                }
            }
            free(tu);
        }
    }
    CloseHandle(hToken);
    return isSys;
}

BOOL IsSelfProcessName(const wchar_t* name) {
    if (!name || !name[0]) return FALSE;
    static const wchar_t* list[] = {
        L"trae_guardian.exe",
        L"trae_guardian_daemon.exe",
        L"trae_guardian_qt.exe",
        L"trae_guardian_service_wrapper.exe",
        L"install_service.exe",
        L"observer.exe",
        L"popup_notifier.exe",
        L"TRAE CN.exe",
        L"TRAE.exe",
        NULL
    };
    for (int i = 0; list[i]; i++) {
        if (!_wcsicmp(name, list[i])) return TRUE;
    }
    return FALSE;
}

BOOL IsCriticalSystemProcess(const wchar_t* name) {
    if (!name || !name[0]) return FALSE;
    static const wchar_t* critical[] = {
        L"System", L"Registry", L"csrss.exe", L"lsass.exe", L"services.exe",
        L"smss.exe", L"wininit.exe", L"winlogon.exe", NULL
    };
    for (int i = 0; critical[i]; i++) {
        if (!_wcsicmp(name, critical[i])) return TRUE;
    }
    return FALSE;
}

BOOL IsSystemProcessName(const wchar_t* name) {
    if (!name || !name[0]) return FALSE;
    if (IsSelfProcessName(name)) return TRUE;
    if (IsCriticalSystemProcess(name)) return TRUE;
    static const wchar_t* list[] = {
        L"svchost.exe", L"explorer.exe", L"dwm.exe", L"taskhostw.exe", L"sihost.exe",
        L"fontdrvhost.exe", L"backgroundTaskHost.exe",
        L"MemCompression.exe", L"Memory Compression",
        L"conhost.exe", L"WerFault.exe", L"WmiPrvSE.exe", L"WmiApSrv.exe",
        L"RuntimeBroker.exe", L"ShellExperienceHost.exe", L"StartMenuExperienceHost.exe",
        L"AppHostSrvc.exe", L"SecurityHealthService.exe", L"SecurityHealthSystray.exe",
        L"TextInputHost.exe", L"InputSwitch.exe", L"sihost.exe", L"SearchIndexer.exe",
        L"SearchProtocolHost.exe", L"SearchFilterHost.exe", L"SearchApp.exe",
        L"MicrosoftEdge.exe", L"msedge.exe", L"microsoftedgecp.exe",
        L"OneDrive.exe", L"onedrive.exe", L"skype.exe", L"SkypeApp.exe",
        L"cmd.exe", L"powershell.exe", L"pwsh.exe",
        L"regedit.exe", L"regedt32.exe", L"taskmgr.exe", L"mmc.exe",
        L"ctfmon.exe", L"cscript.exe", L"wscript.exe", L"mshta.exe",
        L"rundll32.exe", L"regsvr32.exe", L"DllHost.exe", L"exe.exe",
        /* Added: Windows system processes that may lack standard signatures */
        L"ChsIME.exe", L"LogonUI.exe", L"LockApp.exe", L"LockScreen.exe",
        L"LockAppHost.exe", L"WindowsInternal.ComposableShell.Experiences.TextInput.InputApp.exe",
        L"SystemSettings.exe", L"ShellHost.exe", L"EnterpriseClientClipboardServer.exe",
        L"TabTip.exe", L"MicrosoftEdgeUpdate.exe", L"SecurityHealth.exe",
        L"ApplicationFrameHost.exe", L"UserOOBEBroker.exe", L"WinStore.App.exe",
        L"GameBar.exe", L"GameBarFTServer.exe", L"GameBarPresenceWriter.exe",
        L"spoolsv.exe", L"spoolsv.exe", L"PrintIsolationHost.exe",
        L"audiodg.exe", L"SettingSyncHost.exe", L"backgroundTaskHost.exe",
        L"NisSrv.exe", L"MsMpEng.exe", L"SecurityHealthSystray.exe",
        L"SystemProperties.exe", L"SystemPropertiesAdvanced.exe", L"SystemPropertiesHardware.exe",
        L"SystemPropertiesPerformance.exe", L"SystemPropertiesProtection.exe",
        L"SystemPropertiesRemote.exe", L"SystemSettingsAdminFlows.exe",
        L"SystemSettingsBroker.exe", L"SystemSettingsRemoveDevice.exe",
        L"SystemUWPLauncher.exe", L"systray.exe",
        L"WidgetService.exe", L"Widgets.exe", L"PhoneExperienceHost.exe",
        L"MoUsoCoreWorker.exe", L"UsoClient.exe", L"UsoSvc.exe",
        L"wuauclt.exe", L"TiWorker.exe", L"TrustedInstaller.exe",
        L"dashost.exe", L"DeviceCensus.exe", L"DMNotificationClient.exe",
        L"SgrmBroker.exe", L"ClipSVC.exe", L"CoreMessagingRegistrarLoaderHost.exe",
        NULL
    };
    for (int i = 0; list[i]; i++) {
        if (!_wcsicmp(name, list[i])) return TRUE;
    }
    return FALSE;
}

BOOL InjectHookDll(DWORD pid) {
    if (pid == 0 || pid == 4 || pid == GetCurrentProcessId())
        return FALSE;

    wchar_t dllPath[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, dllPath, MAX_PATH);
    wchar_t* backslash = wcsrchr(dllPath, L'\\');
    if (backslash) {
        *(backslash + 1) = L'\0';
        wcscat(dllPath, L"guardian_hook.dll");
    }

    if (!PathFileExistsW(dllPath)) {
        DaemonLog(L"[HOOK-INJECT] guardian_hook.dll not found: %ls", dllPath);
        return FALSE;
    }

    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                               PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
    if (!hProc) {
        DaemonLog(L"[HOOK-INJECT] OpenProcess failed for pid=%lu, error=%lu", pid, GetLastError());
        return FALSE;
    }

    LPVOID pRemotePath = VirtualAllocEx(hProc, NULL, (wcslen(dllPath) + 1) * sizeof(wchar_t),
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemotePath) {
        DaemonLog(L"[HOOK-INJECT] VirtualAllocEx failed for pid=%lu, error=%lu", pid, GetLastError());
        CloseHandle(hProc);
        return FALSE;
    }

    SIZE_T bytesWritten = 0;
    BOOL writeOk = WriteProcessMemory(hProc, pRemotePath, dllPath,
                                      (wcslen(dllPath) + 1) * sizeof(wchar_t), &bytesWritten);
    if (!writeOk) {
        DaemonLog(L"[HOOK-INJECT] WriteProcessMemory failed for pid=%lu, error=%lu", pid, GetLastError());
        VirtualFreeEx(hProc, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW,
                                        pRemotePath, 0, NULL);
    if (!hThread) {
        DaemonLog(L"[HOOK-INJECT] CreateRemoteThread failed for pid=%lu, error=%lu", pid, GetLastError());
        VirtualFreeEx(hProc, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }

    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    VirtualFreeEx(hProc, pRemotePath, 0, MEM_RELEASE);
    CloseHandle(hProc);

    DaemonLog(L"[HOOK-INJECT] Successfully injected guardian_hook.dll into pid=%lu", pid);
    return TRUE;
}

static BOOL IsAntivirusProcessName(const wchar_t* name) {
    if (!name || !name[0]) return FALSE;
    static const wchar_t* list[] = {
        L"MsMpEng.exe", L"MsMpEngCP.exe", L"NisSrv.exe", L"SecurityHealthService.exe",
        L"avp.exe", L"avpui.exe", L"kaspersky.exe", L"ksde.exe",
        L"qqpcrtp.exe", L"QQPCRTP.exe", L"bdagent.exe", L"vsserv.exe",
        L"mcshield.exe", L"mfeann.exe", L"ccsvchst.exe", L"rtsystem.exe",
        L"avast.exe", L"avgui.exe", L"avgsvca.exe", L"ns.exe", NULL
    };
    for (int i = 0; list[i]; i++) {
        if (!_wcsicmp(name, list[i])) return TRUE;
    }
    return FALSE;
}

static BOOL IsTrustedPath(const wchar_t* path) {
    if (!path || !path[0]) return FALSE;
    if (wcslen(path) < 3) return FALSE;
    static const wchar_t* trustedPrefixes[] = {
        L"C:\\Windows\\",
        L"C:\\Program Files\\",
        L"C:\\Program Files (x86)\\",
        L"C:\\ProgramData\\Microsoft\\",
        L"C:\\Windows\\System32\\",
        L"C:\\Windows\\SysWOW64\\",
        L"C:\\Windows\\WinSxS\\",
        NULL
    };
    for (int i = 0; trustedPrefixes[i]; i++) {
        if (_wcsnicmp(path, trustedPrefixes[i], wcslen(trustedPrefixes[i])) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL IsQihoo360ProcessName(const wchar_t* name) {
    if (!name || !name[0]) return FALSE;
    static const wchar_t* list[] = {
        L"360rp.exe", L"360sd.exe", L"360Tray.exe", L"QHActiveDefense.exe",
        L"360Safe.exe", L"360se.exe", L"360chrome.exe", L"360NewsPop.exe",
        L"360UDiskGuard.exe", L"360SafeEx.exe", L"360zip.exe", L"360Dian.exe",
        L"360MobileMgr.exe", L"360Speedld.exe", L"360StartCheck.exe", L"360TopSpeed.exe",
        L"360safebox.exe", L"360Repair.exe", L"360TaskManager.exe", L"360UDisk",
        L"360DrvMgr.exe", L"360NetLoad.exe", L"360NetMon.exe", L"360PatchMgr.exe",
        L"360PwdGuard.exe", L"360rpcService.exe", L"360SafeEnt.exe", L"360SptMem.exe",
        L"360SYSTool.exe", L"360Upgrade.exe", L"360WebSafe.exe", L"360WebShield.exe",
        L"QHActiveDefens.exe", L"QHDownload.exe", L"QHMemScan.exe", L"QHSet.exe",
        L"QHSafeMain.exe", L"QHSafeTray.exe", L"QHSoftMgr.exe", L"QHStat.exe",
        L"Softup.exe", L"360*.exe", NULL
    };
    for (int i = 0; list[i]; i++) {
        if (list[i][wcslen(list[i]) - 1] == L'*') {
            size_t prefixLen = wcslen(list[i]) - 1;
            if (_wcsnicmp(name, list[i], prefixLen) == 0) return TRUE;
        } else if (!_wcsicmp(name, list[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

static int AiThreatLevelValue(const char* level) {
    if (!level || !level[0]) return 0;
    if (!_stricmp(level, "SAFE")) return -1;       /* AI believes this is benign */
    if (!_stricmp(level, "BENIGN")) return -1;     /* alias for SAFE */
    if (!_stricmp(level, "LOW")) return 1;
    if (!_stricmp(level, "MEDIUM")) return 2;
    if (!_stricmp(level, "HIGH")) return 3;
    if (!_stricmp(level, "CONFIRMED")) return 4;
    return 0;
}

int LoadAiThreatThreshold(void) {
    wchar_t path[MAX_PATH];
    DaemonGetBasePath(path, MAX_PATH);
    wcscat(path, L"\\data\\settings.ini");
    return GetPrivateProfileIntW(L"Protection", L"AiThreatThreshold", 3, path);
}

void AiEvaluateSingleProcess(DaemonState* s, DWORD pid, const wchar_t* procName,
                             const wchar_t* imgPath, const wchar_t* modifiedObject,
                             const wchar_t* objectType, const wchar_t* regValueName,
                             const wchar_t* regData, const wchar_t* regOldData,
                             int threshold, const char* apiKey, int pathScore) {
    if (IsSystemProcessName(procName)) return;
    if (IsAntivirusProcessName(procName)) return;
    if (IsSelfProcessName(procName)) return;
    if (!imgPath || !imgPath[0]) return;
    if (TzShouldSkip(&s->tz, imgPath)) return;
    if (IsCommonProcess(s, imgPath)) return;
    if (IsTrustedPath(imgPath)) {
        DaemonLog(L"[SAFETY] process %ls runs from trusted path %ls, skipping AI evaluation", procName, imgPath);
        return;
    }

    wchar_t signer[256] = {0};
    BOOL signedOk = CheckFileSignatureCached(imgPath, signer, 256);
    if (signedOk && signer[0]) {
        if (wcsstr(signer, L"Microsoft") || wcsstr(signer, L"Windows")) return;
    }

    /* Collect parent process for forensics */
    wchar_t parentName[256] = L"unknown";
    DWORD parentPid = 0;
    GetParentProcessInfo(pid, &parentPid, parentName, 256);

    DaemonLog(L"[AI-FORENSICS] queued suspect: name=%ls pid=%lu path=%ls signer=%ls parent=%ls(%lu) object=%ls type=%ls",
              procName, pid, imgPath, signer[0] ? signer : L"none", parentName, parentPid, modifiedObject, objectType);

    /* AI only analyzes local ETW logs and signature databases - NO web search. */
    DaemonLog(L"[AI-ANALYST] starting ETW-based analysis for %ls (pid=%lu)", procName, pid);

    /* Search the appropriate signature DB based on signature status.
     * Use multiple keywords (process name, signer) to gather matching indicators.
     * Note: modifiedObject and objectType are NOT used for DB search because they
     * contain generic terms like "network", "registry" which produce too many false matches.
     * The AI will evaluate behavior based on the actual observed event, not DB matches. */
    char* sigDbResults = NULL;
    int sigDbCap = 1, sigDbLen = 0;
    sigDbResults = (char*)malloc(1);
    if (sigDbResults) sigDbResults[0] = 0;

    const wchar_t* keywords[3];
    int kwCount = 0;
    keywords[kwCount++] = procName;
    if (signer[0]) keywords[kwCount++] = signer;

    for (int ki = 0; ki < kwCount; ki++) {
        char* partial = SearchSignatureDB(keywords[ki], signedOk ? 1 : 0, 60);
        if (partial && partial[0]) {
            int plen = (int)strlen(partial);
            if (sigDbLen + plen + 1 >= sigDbCap) {
                sigDbCap = (sigDbLen + plen + 1) * 2;
                sigDbResults = (char*)realloc(sigDbResults, sigDbCap);
            }
            memcpy(sigDbResults + sigDbLen, partial, plen);
            sigDbLen += plen;
            sigDbResults[sigDbLen] = 0;
        }
        if (partial) free(partial);
    }
    if (sigDbResults && sigDbResults[0]) {
        DaemonLog(L"[AI-PREFETCH] signature DB matches for %ls (%lu bytes, %s DB)",
                  procName, (DWORD)sigDbLen, signedOk ? "rogue" : "virus");
    }

    /* Load SOUL.md and AI knowledge base for the system prompt */
    wchar_t soulPath[MAX_PATH], knowPath[MAX_PATH];
    GetDataPath(soulPath, MAX_PATH, L"ai_memory\\SOUL.md");
    GetDataPath(knowPath, MAX_PATH, L"ai_memory\\ai_knowledge.md");
    long soulSz = 0, knowSz = 0;
    char* soul = ReadFileAnsi(soulPath, &soulSz);
    char* knowledge = ReadFileAnsi(knowPath, &knowSz);

    char systemPrompt[65536];
    snprintf(systemPrompt, sizeof(systemPrompt),
        "%s\n\n%s\n\n"
        "You are a security analyst providing RISK ASSESSMENT ONLY. You analyze ETW behavior logs "
        "to evaluate process risk levels. YOU DO NOT EXECUTE ANY ACTIONS. Your role is purely "
        "advisory - you provide a risk score that the daemon uses to adjust its protection level.\n\n"
        "DATA SOURCE: The daemon provides you with ETW kernel logs showing registry modifications, "
        "process creation/termination, file operations, and network activity. You analyze these "
        "logs to assess risk.\n\n"
        "EVALUATION WORKFLOW:\n"
        "1. ETW Log Analysis: Review the ETW behavior logs for suspicious patterns.\n"
        "2. Pattern Recognition: Look for behaviors like: browser hijacking (Run key modifications), "
        "   persistent installations, aggressive self-protection, unauthorized network activity, "
        "   or file modifications in sensitive directories.\n"
        "3. Risk Assessment: Assign a risk level based on the severity of observed behaviors.\n\n"
        "RISK LEVEL GUIDELINES:\n"
        "- SAFE: Clearly benign software (e.g., signed Microsoft/Windows component, well-known \n"
        "  legitimate updater, or behavior fully consistent with the software's documented purpose).\n"
        "  When you assign SAFE, the daemon will DEDUCT from the process's risk score to prevent \n"
        "  false positives. Use SAFE proactively when evidence strongly suggests legitimacy.\n"
        "- LOW: Normal software behavior, no suspicious patterns detected.\n"
        "- MEDIUM: Minor suspicious behavior (e.g., one-time registry modification, unusual network "
        "  connection), but not clearly malicious.\n"
        "- HIGH: Multiple suspicious behaviors indicating potentially unwanted software (PUP) or "
        "  rogue software (e.g., browser homepage hijacking, aggressive persistence attempts).\n"
        "- CONFIRMED: Clear evidence of rogue/malicious behavior (e.g., blocking competitors, "
        "  unauthorized system modifications, deceptive practices).\n\n"
        "NEVER rate a signed Microsoft/Windows component as dangerous.\n"
        "Treat 'antivirus'/'security suite' products from aggressive vendors according to their "
        "BEHAVIOR, not their name or signature.\n"
        "In the 'reason' field, be specific and concrete: state exactly what suspicious behavior "
        "was observed (e.g., 'hijacked browser homepage', 'added itself to Run key', 'blocked "
        "competitor antivirus').\n"
        "Return JSON only: {\"level\":\"...\",\"reason\":\"...\",\"software\":\"...\"}\n"
        "Use only SAFE/LOW/MEDIUM/HIGH/CONFIRMED.\n"
        "You may request additional context by emitting this key inside the JSON: "
        "\"search_logs\":\"keyword\" to search daemon ETW logs. "
        "Only emit a search key when you genuinely need more context. After receiving results, "
        "reply with the final JSON (no search key).\n\n"
        "IMPORTANT: You are a READ-ONLY analyst. The daemon will handle ALL actions "
        "(termination, cleanup, blocking) automatically based on its own behavior detection "
        "system. Your only output is a risk level and reason.",
        soul ? soul : "",
        knowledge ? knowledge : "");
    if (soul) free(soul);
    if (knowledge) free(knowledge);

    char regDetails[2048] = {0};
    if (regValueName && regValueName[0]) {
        wchar_t wRegDetails[2048] = {0};
        swprintf(wRegDetails, 2048, L"Registry details:\n  - ValueName: %ls\n  - NewValue: %ls\n  - OldValue: %ls\n",
                 regValueName,
                 regData && regData[0] ? regData : L"(empty)",
                 regOldData && regOldData[0] ? regOldData : L"(none)");
        WideCharToMultiByte(CP_UTF8, 0, wRegDetails, -1, regDetails, 2048, NULL, NULL);
    }

    char basePrompt[8192];
    snprintf(basePrompt, sizeof(basePrompt),
        "Process Guard detected modification of %S: %S\n"
        "Exact process: %S (PID=%lu)\n"
        "Executable path: %S\n"
        "Digital signature: %s\n"
        "Signer: %S\n"
        "Parent process: %S (PID=%lu)\n"
        "Daemon's behavioral threat score for this registry path: %d/100 (>=60 already considered suspicious).\n"
        "%s"
        "Task: Identify which software this executable belongs to, what its normal function is, "
        "and whether modifying %S %S is consistent with legitimate behavior or indicates malware/PUP/rogue behavior.\n"
        "Rate the danger as SAFE, LOW, MEDIUM, HIGH, or CONFIRMED and reply with the JSON format specified in the system prompt.",
        objectType, modifiedObject,
        procName, pid,
        imgPath,
        signedOk ? "yes" : "no",
        signer[0] ? signer : L"unknown",
        parentName, parentPid,
        pathScore,
        regDetails,
        objectType, modifiedObject);

    /* Build full base prompt including signature DB results and ETW behavior logs.
     * AI only analyzes local ETW logs and signature databases - NO web search. */
    char fullBasePrompt[32768];
    snprintf(fullBasePrompt, sizeof(fullBasePrompt),
        "%s\n\n"
        "=== SIGNATURE DB MATCHES (%s DB, lines tagged [%s]) ===\n%s\n\n"
        "=== ETW BEHAVIOR LOGS (kernel-level process/registry/file/network activity) ===\n"
        "The daemon has already analyzed these logs. Key observed behaviors include:\n"
        "- Registry modifications to protected keys\n"
        "- Process creation/termination events\n"
        "- File operations in sensitive directories\n"
        "- Network connections (if applicable)\n\n"
        "Additional ETW context can be retrieved via search_logs if needed.",
        basePrompt,
        signedOk ? "rogue" : "virus",
        signedOk ? "rogue-db" : "virus-db",
        (sigDbResults && sigDbResults[0]) ? sigDbResults : "(no matching signature DB entries)");
    if (sigDbResults) { free(sigDbResults); sigDbResults = NULL; }

    char userPrompt[65536];
    char level[16] = {0}, pathOut[512] = {0}, reason[1024] = {0};
    char searchTerm[256] = "";
    char searchType[32] = "";
    AiAction actions[MAX_AI_ACTIONS];
    int actionCount = 0;

    /* Build initial user prompt from fullBasePrompt */
    snprintf(userPrompt, sizeof(userPrompt),
        "%s\n\n"
        "Based on the above web reputation and signature database matches, combined with the "
        "observed behavior, evaluate this process and reply with the JSON format specified "
        "in the system prompt.",
        fullBasePrompt);

    WriteAiPromptInject(procName, objectType, modifiedObject, systemPrompt, userPrompt);

    /* Allow up to 3 search iterations */
    AiResult out = {0};
    for (int searchIter = 0; searchIter < 3; searchIter++) {
        memset(&out, 0, sizeof(out));
        if (AskAi(apiKey, systemPrompt, userPrompt, 0.7f, 32768, &out) != 0) return;
        if (!out.content[0]) return;

        ParseAiLevel(out.content, level, sizeof(level), pathOut, sizeof(pathOut), reason, sizeof(reason));
        ParseAiSearch(out.content, searchTerm, sizeof(searchTerm), searchType, sizeof(searchType));
        memset(actions, 0, sizeof(actions));
        actionCount = ParseAiActions(out.content, actions, MAX_AI_ACTIONS);

        if (!searchTerm[0]) break; /* no more search needed */

        /* Perform requested search and append results to prompt */
        wchar_t searchW[256] = L"";
        MultiByteToWideChar(CP_UTF8, 0, searchTerm, -1, searchW, 256);
        char* searchResults = NULL;
        const char* sourceName = "log";
        if (_stricmp(searchType, "knowledge") == 0) {
            searchResults = SearchKnowledgeByKeyword(searchW, 80);
            sourceName = "knowledge base / memory";
        } else {
            searchResults = SearchLogByKeyword(searchW, 80);
            sourceName = "log";
        }

        snprintf(userPrompt, sizeof(userPrompt),
            "%s\n\n"
            "You requested additional %s context for '%s'. Here are matching lines:\n%s\n\n"
            "Based on this additional context (combined with the web reputation and signature "
            "DB matches above), re-evaluate and reply with the same JSON format.",
            fullBasePrompt, sourceName, searchTerm, searchResults ? searchResults : "(no matching entries)");

        if (searchResults) free(searchResults);
        searchTerm[0] = 0;
        searchType[0] = 0;
    }

    int lv = AiThreatLevelValue(level);
    char* cleanupItems[16];
    for (int i = 0; i < 16; i++) cleanupItems[i] = (char*)malloc(MAX_PATH);

    if (lv >= threshold) {
        DaemonLog(L"AI threat %s for process %ls (signed=%d): %s", level, procName, signedOk, reason);
        WriteAiNotification(level, modifiedObject, L"protection", procName, pathOut[0] ? pathOut : "-", reason);

        if (signedOk) {
            DaemonLog(L"[AI-ANALYST] signed process %ls assessed as %s by AI: %s", procName, level, reason);
            char popupReason[1280];
            snprintf(popupReason, sizeof(popupReason),
                     "AI assessed this signed process as %s. Reason: %s. "
                     "The daemon will use this assessment to adjust protection level.", level, reason);
            int aiPopupScore = 0;
            if (lv == 4) aiPopupScore = 90;
            else if (lv == 3) aiPopupScore = 60;
            else if (lv == 2) aiPopupScore = 30;
            else aiPopupScore = 10;
            CreateHighRiskPopupFlag(modifiedObject, L"protection", procName, imgPath, popupReason, aiPopupScore);
        } else {
            DaemonLog(L"[AI-ANALYST] unsigned process %ls assessed as %s by AI: %s", procName, level, reason);
        }
        
        /* AI provides only risk assessment - add to score center for the daemon's automated response system */
        int aiScore = 0;
        switch (lv) {
            case 4: aiScore = 8; break;  /* CONFIRMED */
            case 3: aiScore = 6; break;  /* HIGH */
            case 2: aiScore = 3; break;  /* MEDIUM */
            case 1: aiScore = 1; break;  /* LOW */
        }
        if (aiScore > 0 && pid > 0) {
            DaemonLog(L"[AI-SCORE] Adding AI score %d for pid=%lu (%ls)", aiScore, pid, procName);
            wchar_t reasonW[1024] = {0};
            MultiByteToWideChar(CP_UTF8, 0, reason, -1, reasonW, 1024);
            if (s->cm) ScoreCenterAddAiScore(&s->cm->sc, pid, aiScore, reasonW);
        }
    } else if (lv < 0) {
        /* AI assessed the process as SAFE/BENIGN - deduct score to counter false positives */
        int deductScore = -4;  /* negative AI score to reduce total */
        if (pid > 0) {
            DaemonLog(L"[AI-SCORE] AI assessed %ls as SAFE/BENIGN; deducting %d from risk score (pid=%lu). Reason: %s",
                      procName, deductScore, pid, reason);
            WriteAiNotification("SAFE", modifiedObject, L"protection", procName,
                                pathOut[0] ? pathOut : "-", reason);
            wchar_t reasonW[1024] = {0};
            MultiByteToWideChar(CP_UTF8, 0, reason, -1, reasonW, 1024);
            if (s->cm) ScoreCenterAddAiScore(&s->cm->sc, pid, deductScore, reasonW);
        }
    }
    for (int i = 0; i < 16; i++) free(cleanupItems[i]);
}
static void AiEvaluateAndAct(DaemonState* s, const wchar_t* modifiedObject,
                             const wchar_t* objectType) {
    if (!s->enableAiAssist) return;

    int threshold = LoadAiThreatThreshold();
    if (threshold < 1 || threshold > 4) threshold = 3;

    char apiKey[512] = {0};
    if (LoadApiKey(apiKey, sizeof(apiKey)) != 0 || !apiKey[0]) return;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnap, &pe)) {
        do {
            wchar_t imgPath[MAX_PATH] = {0};
            if (!GetProcessImagePath(pe.th32ProcessID, imgPath, MAX_PATH)) continue;
            AiEvaluateSingleProcess(s, pe.th32ProcessID, pe.szExeFile, imgPath,
                                    modifiedObject, objectType, NULL, NULL, NULL, threshold, apiKey, 0);
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

static void WriteAiNotification(const char* level, const wchar_t* taskName, const wchar_t* taskId,
                                const wchar_t* procName, const char* path, const char* reason) {
    wchar_t wpath[MAX_PATH];
    GetDataPath(wpath, MAX_PATH, L"ai_notifications.log");
    FILE* f = _wfopen(wpath, L"a");
    if (!f) return;
    SYSTEMTIME st; GetLocalTime(&st);
    fwprintf(f, L"[%04d-%02d-%02d %02d:%02d:%02d] level=%s  task=%ls  task_id=%ls  proc=%ls  path=%s  reason=%s\n",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
             level ? level : "-",
             taskName ? taskName : L"-",
             taskId ? taskId : L"-",
             procName ? procName : L"-",
             path ? path : "-",
             reason ? reason : "-");
    fclose(f);
}

static void JsonEscapeAppend(FILE* f, const char* src) {
    if (!src) return;
    while (*src) {
        switch (*src) {
            case '"': fputs("\\\"", f); break;
            case '\\': fputs("\\\\", f); break;
            case '\n': fputs("\\n", f); break;
            case '\r': fputs("\\r", f); break;
            case '\t': fputs("\\t", f); break;
            default: fputc(*src, f); break;
        }
        src++;
    }
}

static void WriteAiPromptInject(const wchar_t* procName, const wchar_t* objectType,
                                const wchar_t* modifiedObject, const char* systemPrompt,
                                const char* userPrompt) {
    wchar_t wpath[MAX_PATH];
    GetDataPath(wpath, MAX_PATH, L"ai_memory\\ai_chat_inject.jsonl");
    FILE* f = _wfopen(wpath, L"a");
    if (!f) return;
    SYSTEMTIME st; GetLocalTime(&st);
    fwprintf(f, L"{\"time\":\"%04d-%02d-%02d %02d:%02d:%02d\",\"proc\":\"%ls\",\"object\":\"%ls\",\"objectType\":\"%ls\",",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
             procName ? procName : L"-",
             modifiedObject ? modifiedObject : L"-",
             objectType ? objectType : L"-");
    fputs("\"system\":\"", f);
    JsonEscapeAppend(f, systemPrompt);
    fputs("\",\"user\":\"", f);
    JsonEscapeAppend(f, userPrompt);
    fputs("\"}\n", f);
    fclose(f);
}

/* Append a message to the global chat memory file (UTF-8) so the user sees it in Global Chat. */
static void AppendGlobalChatMessage(const char* who, const char* msg) {
    wchar_t mpath[MAX_PATH];
    GetDataPath(mpath, MAX_PATH, L"ai_memory\\global_chat.md");
    FILE* f = _wfopen(mpath, L"a");
    if (!f) return;
    SYSTEMTIME st; GetLocalTime(&st);
    fwprintf(f, L"[%02d:%02d:%02d] %s:\n%s\n\n",
             st.wHour, st.wMinute, st.wSecond, who, msg);
    fclose(f);
}

/* Read up to maxBytes from the end of daemon.log for report generation. */
static char* ReadRecentDaemonLogBytes(int maxBytes) {
    wchar_t logPath[MAX_PATH];
    GetDataPath(logPath, MAX_PATH, L"daemon.log");
    FILE* f = _wfopen(logPath, L"rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz <= 0) { fclose(f); return NULL; }
    long readSz = sz > maxBytes ? maxBytes : sz;
    char* buf = (char*)malloc(readSz + 1);
    if (!buf) { fclose(f); return NULL; }
    fseek(f, sz - readSz, SEEK_SET);
    size_t n = fread(buf, 1, readSz, f);
    buf[n] = 0;
    fclose(f);
    /* Drop first partial line so we start cleanly */
    char* firstLine = strchr(buf, '\n');
    if (firstLine) {
        memmove(buf, firstLine + 1, strlen(firstLine));
    }
    return buf;
}

/* Generate and distribute a daily security report. Called once per day. */
static void GenerateDailyReport(DaemonState* s) {
    DStartupLog("GenerateDailyReport enter");
    if (!s->enableAiAssist) { DStartupLog("GenerateDailyReport AI disabled"); return; }
    char apiKey[512] = {0};
    if (LoadApiKey(apiKey, sizeof(apiKey)) != 0 || !apiKey[0]) { DStartupLog("GenerateDailyReport no key"); return; }
    DStartupLog("GenerateDailyReport key loaded");

    /* Load SOUL.md and knowledge base */
    wchar_t soulPath[MAX_PATH], knowPath[MAX_PATH];
    GetDataPath(soulPath, MAX_PATH, L"ai_memory\\SOUL.md");
    GetDataPath(knowPath, MAX_PATH, L"ai_memory\\ai_knowledge.md");
    long soulSz = 0, knowSz = 0;
    char* soul = ReadFileAnsi(soulPath, &soulSz);
    char* knowledge = ReadFileAnsi(knowPath, &knowSz);
    DStartupLog("GenerateDailyReport files loaded");

    char systemPrompt[65536];
    snprintf(systemPrompt, sizeof(systemPrompt),
        "%s\n\n%s\n\n"
        "You are the security analyst for Process Guardian. Generate a daily security report "
        "in Markdown based on the provided daemon log excerpt. Focus on HIGH, CONFIRMED, "
        "INJECTION, [ACTION], and [AI-ACTION] events. For each incident list: time, process/path, "
        "risk level, and outcome/action taken. End with a brief overall assessment and any "
        "recommended next steps. Keep the report concise but informative.",
        soul ? soul : "",
        knowledge ? knowledge : "");
    if (soul) free(soul);
    if (knowledge) free(knowledge);
    DStartupLog("GenerateDailyReport system prompt built");

    char* logExcerpt = ReadRecentDaemonLogBytes(4 * 1024 * 1024); /* up to 4 MB */
    char userPrompt[256 * 1024];
    snprintf(userPrompt, sizeof(userPrompt),
        "Generate today's daily security report from the following daemon log excerpt.\n\n%s",
        logExcerpt ? logExcerpt : "(no log data available)");
    if (logExcerpt) free(logExcerpt);
    DStartupLog("GenerateDailyReport user prompt built");

    AiResult out = {0};
    DStartupLog("GenerateDailyReport before AskAi");
    if (AskAi(apiKey, systemPrompt, userPrompt, 0.7f, 32768, &out) != 0) {
        DaemonLog(L"[DAILY-REPORT] AI call failed");
        DStartupLog("GenerateDailyReport AskAi failed");
        return;
    }
    DStartupLog("GenerateDailyReport after AskAi");
    if (!out.content[0]) {
        DaemonLog(L"[DAILY-REPORT] AI returned empty content");
        DStartupLog("GenerateDailyReport empty content");
        return;
    }

    /* Distribute report */
    DStartupLog("GenerateDailyReport before WriteAiNotification");
    WriteAiNotification("DAILY_REPORT", L"Daily Report", L"daily", L"-", "-", out.content);
    DStartupLog("GenerateDailyReport before AppendGlobalChatMessage");
    AppendGlobalChatMessage("AI", out.content);
    DaemonLog(L"[DAILY-REPORT] generated and distributed");
    DStartupLog("GenerateDailyReport done");
}

static void CreateHighRiskPopupFlag(const wchar_t* taskName, const wchar_t* taskId,
                                    const wchar_t* procName, const wchar_t* path,
                                    const char* reason, int score) {
    if (!procName || !procName[0]) {
        DaemonLog(L"[POPUP] Skipping popup for empty process name");
        return;
    }
    
    if (!CheckAndUpdatePopupCooldown(procName, path)) {
        return;
    }
    
    if (score < THRESHOLD_REMOVED) {
        DaemonLog(L"[POPUP] Score %d below threshold %d, skipping popup for %ls", score, THRESHOLD_REMOVED, procName);
        return;
    }
    
    wchar_t base[MAX_PATH];
    DaemonGetBasePath(base, MAX_PATH);
    wchar_t popupExe[MAX_PATH];
    swprintf(popupExe, MAX_PATH, L"%ls\\popup_notifier.exe", base);
    
    if (_waccess(popupExe, 0) != 0) {
        DaemonLog(L"[POPUP] popup_notifier.exe not found: %ls", popupExe);
        return;
    }
    
    wchar_t reasonW[1024] = {0};
    if (reason) {
        MultiByteToWideChar(CP_UTF8, 0, reason, -1, reasonW, 1023);
    }
    
    wchar_t title[256] = L"TRAE Guardian - High Risk Alert";
    wchar_t threatType[256] = L"高风险威胁";
    
    wchar_t cmdLine[4096];
    swprintf(cmdLine, 4096, L"\"%ls\" -title \"%ls\" -type \"%ls\" -name \"%ls\" -path \"%ls\" -evidence \"%ls\" -score %d", 
             popupExe, title, threatType, 
             procName ? procName : L"", 
             path ? path : L"unknown", 
             reasonW[0] ? reasonW : L"",
             score);
    
    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};
    DWORD flags = CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS;
    BOOL ok = CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, flags, NULL, NULL, &si, &pi);
    if (ok) {
        DaemonLog(L"[POPUP] Started popup_notifier.exe for high-risk alert PID=%lu", pi.dwProcessId);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        DaemonLog(L"[POPUP] Failed to start popup_notifier.exe: %lu", GetLastError());
    }
}

void ShowSecurityAlertPopupEx(const wchar_t* title, const wchar_t* threatType, const wchar_t* procName, 
                               const wchar_t* imagePath, const wchar_t* evidence, int score) {
    if (procName && procName[0]) {
        if (!CheckAndUpdatePopupCooldown(procName, imagePath)) {
            return;
        }
    }
    
    wchar_t base[MAX_PATH];
    DaemonGetBasePath(base, MAX_PATH);
    wchar_t popupExe[MAX_PATH];
    swprintf(popupExe, MAX_PATH, L"%ls\\popup_notifier.exe", base);
    
    if (_waccess(popupExe, 0) != 0) {
        DaemonLog(L"[POPUP] popup_notifier.exe not found: %ls", popupExe);
        return;
    }
    
    wchar_t cmdLine[4096];
    swprintf(cmdLine, 4096, L"\"%ls\" -title \"%ls\" -type \"%ls\" -name \"%ls\" -path \"%ls\" -evidence \"%ls\" -score %d", 
             popupExe, 
             title ? title : L"TRAE Guardian Alert",
             threatType ? threatType : L"",
             procName ? procName : L"",
             imagePath ? imagePath : L"",
             evidence ? evidence : L"",
             score);
    
    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};
    
    DWORD flags = CREATE_NEW_PROCESS_GROUP;
    BOOL ok = CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, flags, NULL, NULL, &si, &pi);
    
    if (ok) {
        DaemonLog(L"[POPUP] Started popup_notifier.exe PID=%lu type=%ls name=%ls", pi.dwProcessId, threatType, procName);
        WaitForSingleObject(pi.hProcess, 30000);
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        DaemonLog(L"[POPUP] popup_notifier.exe exited with code=%lu", exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        DaemonLog(L"[POPUP] Failed to start popup_notifier.exe: %lu", GetLastError());
    }
}

static void ShowSecurityAlertPopup(const wchar_t* title, const wchar_t* message) {
    ShowSecurityAlertPopupEx(title, L"", L"", L"", message, 0);
}

/* Connect to the GUI popup server and ask the user for confirmation.
 * Returns TRUE only if the GUI is running and the user clicks Yes.
 * Protocol: send four NUL-terminated wchar_t strings (title, message, proc, path),
 *           receive "YES\0" or "NO\0".
 */
static BOOL ShowPopupAndWait(const wchar_t* title, const wchar_t* message, const wchar_t* proc, const wchar_t* path) {
    HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\GuardianPopupServer",
                               GENERIC_READ | GENERIC_WRITE, 0, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        DaemonLog(L"[POPUP] GUI not available for confirmation, default deny");
        return FALSE;
    }

    DWORD written = 0, mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(hPipe, &mode, NULL, NULL);

    WriteFile(hPipe, title, (DWORD)((wcslen(title) + 1) * sizeof(wchar_t)), &written, NULL);
    WriteFile(hPipe, message, (DWORD)((wcslen(message) + 1) * sizeof(wchar_t)), &written, NULL);
    WriteFile(hPipe, proc, (DWORD)((wcslen(proc) + 1) * sizeof(wchar_t)), &written, NULL);
    WriteFile(hPipe, path, (DWORD)((wcslen(path) + 1) * sizeof(wchar_t)), &written, NULL);
    FlushFileBuffers(hPipe);

    wchar_t resp[8] = {0};
    DWORD read = 0;
    BOOL ok = ReadFile(hPipe, resp, sizeof(resp), &read, NULL);
    CloseHandle(hPipe);

    if (ok && read >= sizeof(wchar_t) * 4 && _wcsnicmp(resp, L"YES", 3) == 0) {
        DaemonLog(L"[POPUP] user confirmed action for %ls", proc ? proc : L"-");
        return TRUE;
    }
    DaemonLog(L"[POPUP] user denied or no response for %ls", proc ? proc : L"-");
    return FALSE;
}

static void AppendMemoryLog(const wchar_t* memPath, const char* text) {
    FILE* f = _wfopen(memPath, L"a");
    if (!f) return;
    SYSTEMTIME st; GetLocalTime(&st);
    fwprintf(f, L"\n[%04d-%02d-%02d %02d:%02d:%02d] %s\n",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, text);
    fclose(f);
}

static void ExecuteAiTasks(DaemonState* s) {
    if (s->aiTaskCount == 0) return;

    char apiKey[256] = "";
    if (LoadApiKey(apiKey, sizeof(apiKey)) != 0) {
        static int logged = 0;
        if (!logged) { DaemonLog(L"AI monitor: no API key available"); logged = 1; }
        return;
    }

    /* Load shared SOUL.md */
    wchar_t soulPath[MAX_PATH];
    GetDataPath(soulPath, MAX_PATH, L"ai_memory\\SOUL.md");
    long soulSz = 0;
    char* soul = ReadFileAnsi(soulPath, &soulSz);
    if (!soul) {
        static int logged = 0;
        if (!logged) { DaemonLog(L"AI monitor: SOUL.md not found"); logged = 1; }
        return;
    }

    DWORD now = GetTickCount();
    for (int i = 0; i < s->aiTaskCount; i++) {
        AiTask* t = &s->aiTasks[i];
        if (!t->enabled) continue;
        if (t->lastCheckTick != 0 && (now - t->lastCheckTick) < (DWORD)(t->readIntervalSec * 1000)) continue;
        t->lastCheckTick = now;

        for (int j = 0; j < t->targetCount; j++) {
            AiTarget* at = &t->targets[j];
            if (at->type != 1) continue;  /* Only process monitoring for now */
            if (IsSelfProcessName(at->name)) {
                DaemonLog(L"[SAFETY] skipping AI task for own process %ls", at->name);
                continue;
            }
            DWORD pid = GetPidByName(at->name);
            if (pid == 0) continue;
            at->pid = pid;

            BYTE* mem = (BYTE*)malloc(t->readBytes);
            if (!mem) continue;
            int read = 0;
            if (!ReadProcessMemoryBytes(pid, t->readBytes, mem, &read)) {
                free(mem);
                continue;
            }

            char hex[4096] = "";
            int show = read; if (show > 512) show = 512;
            HexEncode(mem, show, hex, sizeof(hex));

            wchar_t targetPath[MAX_PATH] = {0};
            GetProcessImagePath(pid, targetPath, MAX_PATH);
            wchar_t targetSigner[256] = {0};
            BOOL targetSigned = FALSE;
            if (targetPath[0]) {
                targetSigned = CheckFileSignatureCached(targetPath, targetSigner, 256);
            }

            /* Pre-AI lookup: fetch web reputation + signature DB matches */
            LoadAiWebSearchDll();
            char* webRep = FetchWebReputation(at->name, targetSigner[0] ? targetSigner : NULL);
            char* sigDb = (char*)malloc(1);
            if (sigDb) sigDb[0] = 0;
            int sigDbLen = 0, sigDbCap = 1;
            const wchar_t* sigKw[2];
            int sigKwN = 0;
            sigKw[sigKwN++] = at->name;
            if (targetSigner[0]) sigKw[sigKwN++] = targetSigner;
            for (int ki = 0; ki < sigKwN; ki++) {
                char* part = SearchSignatureDB(sigKw[ki], targetSigned ? 1 : 0, 50);
                if (part && part[0]) {
                    int plen = (int)strlen(part);
                    if (sigDbLen + plen + 1 >= sigDbCap) {
                        sigDbCap = (sigDbLen + plen + 1) * 2;
                        sigDb = (char*)realloc(sigDb, sigDbCap);
                    }
                    memcpy(sigDb + sigDbLen, part, plen);
                    sigDbLen += plen;
                    sigDb[sigDbLen] = 0;
                }
                if (part) free(part);
            }

            char systemPrompt[16384];
            snprintf(systemPrompt, sizeof(systemPrompt),
                "%s\n\n"
                "You are analyzing a running Windows process. The process's executable path, digital signature, "
                "web reputation, and signature database matches are provided.\n"
                "EVALUATION WORKFLOW: web reputation and signature DB matches have ALREADY been fetched for you. "
                "They are in the user prompt. Prefer independent user feedback over vendor marketing claims.\n"
                "DECISION RULES:\n"
                "- UNSIGNED + >=3 [virus-db] matches => CONFIRMED, auto-clean directory.\n"
                "- UNSIGNED + 1-2 [virus-db] matches => HIGH, needsApproval=true.\n"
                "- SIGNED + 0 [rogue-db] matches + positive reputation => LOW.\n"
                "- SIGNED + 1-2 [rogue-db] matches or mixed reputation => HIGH, needsApproval=true, no cleanup.\n"
                "- SIGNED + >=3 [rogue-db] matches + negative reputation => CONFIRMED, repeatedKill=true, no cleanup.\n"
                "In the 'reason' field, be specific and concrete about what suspicious behavior was observed. "
                "Return JSON only with keys: level, reason, software, function, needsApproval, repeatedKill, cleanup.",
                soul ? soul : "");

            char userPrompt[65536];
            snprintf(userPrompt, sizeof(userPrompt),
                "Analyze this process for suspicious behavior.\n"
                "Process: %S\nPID: %lu\nExecutable path: %S\nDigital signature: %s\nSigner: %S\n"
                "Memory sample (hex): %s\n\n"
                "=== WEB REPUTATION (prefer user feedback over vendor claims) ===\n%s\n\n"
                "=== SIGNATURE DB MATCHES (%s DB) ===\n%s\n\n"
                "Respond ONLY with the required JSON object.",
                at->name, pid, targetPath,
                targetSigned ? "yes" : "no",
                targetSigner[0] ? targetSigner : L"unknown",
                hex,
                webRep ? webRep : "(unavailable)",
                targetSigned ? "rogue" : "virus",
                (sigDb && sigDb[0]) ? sigDb : "(no matches)");
            if (webRep) free(webRep);
            if (sigDb) free(sigDb);

            AiResult res = {0};
            int rc = AskAi(apiKey, systemPrompt, userPrompt, 0.7f, 32768, &res);

            char level[32] = "", path[MAX_PATH] = "", reason[1024] = "";
            if (rc == 0 && res.httpStatus == 200 && res.content[0]) {
                ParseAiLevel(res.content, level, sizeof(level), path, sizeof(path), reason, sizeof(reason));
            } else {
                strcpy(level, "LOW");
                snprintf(reason, sizeof(reason), "AI call failed: http=%d err=%s", res.httpStatus, res.errMsg);
            }

            DaemonLog(L"AI check task=%ls proc=%ls level=%s", t->name, at->name, level);
            WriteAiNotification(level, t->name, t->id, at->name, path, reason);

            char memLine[2048];
            char procA[256] = "";
            WideCharToMultiByte(CP_UTF8, 0, at->name, -1, procA, sizeof(procA), NULL, NULL);
            snprintf(memLine, sizeof(memLine), "[%s] proc=%s pid=%lu level=%s reason=%s",
                     level, procA, pid, level, reason);
            AppendMemoryLog(t->memoryFile, memLine);

            /* Convert AI path to wchar_t */
            wchar_t wpath[MAX_PATH] = L"";
            if (path[0]) MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, MAX_PATH);

            if (_stricmp(level, "CONFIRMED") == 0) {
                if (targetSigned) {
                    /* Signed process: do not auto-clean, escalate to HIGH popup */
                    DaemonLog(L"AI CONFIRMED for signed process %ls; converting to HIGH popup instead of auto-clean", at->name);
                    CreateHighRiskPopupFlag(t->name, t->id, at->name, wpath[0] ? wpath : at->name, reason, 90);
                    WriteAiNotification("CONFIRMED_SIGNED", t->name, t->id, at->name, path,
                                        "AI flagged signed process; auto-clean blocked, popup created");
                } else {
                    /* Unsigned process: auto-clean without user authorization */
                    BOOL ok = CleanTargetPath(wpath[0] ? wpath : at->name);
                    DaemonLog(L"AI CONFIRMED auto-clean %ls -> %ls", wpath[0] ? wpath : at->name, ok ? L"ok" : L"failed");
                    WriteAiNotification("CONFIRMED_CLEANED", t->name, t->id, at->name, path,
                                        ok ? "AI automatically cleaned the threat" : "AI auto-clean failed");
                    char cleanLine[1024];
                    char procA2[256] = "", pathA2[MAX_PATH] = "";
                    WideCharToMultiByte(CP_UTF8, 0, at->name, -1, procA2, sizeof(procA2), NULL, NULL);
                    WideCharToMultiByte(CP_UTF8, 0, wpath, -1, pathA2, sizeof(pathA2), NULL, NULL);
                    snprintf(cleanLine, sizeof(cleanLine), "[CONFIRMED_CLEANED] proc=%s path=%s ok=%d",
                             procA2, pathA2, ok);
                    AppendMemoryLog(t->memoryFile, cleanLine);
                }
            } else if (_stricmp(level, "HIGH") == 0) {
                /* Create popup flag for main UI */
                CreateHighRiskPopupFlag(t->name, t->id, at->name, wpath[0] ? wpath : at->name, reason, 60);
            }

            free(mem);
        }
    }
    free(soul);
}

static void GetProcessNameByPid(DWORD pid, wchar_t* out, DWORD outSz);
static BOOL KillTree(DWORD pid);
static BOOL SafeToKillByName(const wchar_t* name);

static BOOL KillTreeEx(DWORD pid, BOOL skipSignatureCheck) {
    if (pid == 0 || pid == 4) return FALSE;

    if (!skipSignatureCheck) {
        wchar_t name[256] = {0};
        GetProcessNameByPid(pid, name, 256);
        if (!SafeToKillByName(name)) return FALSE;
    }

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        memset(&pe, 0, sizeof(pe));
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (pe.th32ParentProcessID == pid) KillTreeEx(pe.th32ProcessID, skipSignatureCheck);
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProc) return FALSE;
    BOOL r = skipSignatureCheck ? TerminateProcess(hProc, 1) : SafeTerminateProcess(hProc, NULL);
    CloseHandle(hProc);
    return r;
}

static BOOL KillTree(DWORD pid) {
    return KillTreeEx(pid, FALSE);
}

void TerminateWatchdogGroup(DaemonState* s, DWORD pid, const wchar_t* procName, const wchar_t* procPath) {
    if (!s) return;
    DaemonLog(L"[WATCHDOG] Initiating group termination for: %ls (PID=%lu)", procName, pid);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    DWORD parentPid = 0;
    wchar_t parentName[256] = {0};
    GetParentProcessInfo(pid, &parentPid, parentName, 256);

    DWORD targetPids[256] = {0};
    int targetCount = 0;

    PROCESSENTRY32W pe;
    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;
            if (IsSystemProcessName(pe.szExeFile)) continue;
            if (IsAntivirusProcessName(pe.szExeFile)) continue;
            if (IsCriticalSystemProcess(pe.szExeFile)) continue;
            if (IsSelfProcessName(pe.szExeFile)) continue;

            wchar_t path[MAX_PATH] = {0};
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (hProc) {
                DWORD sz = MAX_PATH;
                QueryFullProcessImageNameW(hProc, 0, path, &sz);
                CloseHandle(hProc);
            }

            BOOL isRelated = FALSE;
            if (!_wcsicmp(pe.szExeFile, procName)) {
                isRelated = TRUE;
            } else if (procPath[0] && path[0] && !_wcsicmp(path, procPath)) {
                isRelated = TRUE;
            } else if (parentPid != 0 && pe.th32ParentProcessID == parentPid) {
                isRelated = TRUE;
            } else if (pe.th32ProcessID == pid) {
                isRelated = TRUE;
            }

            if (isRelated) {
                wchar_t signer[256] = {0};
                if (!CheckFileSignatureCached(path[0] ? path : L"", signer, 256)) {
                    targetPids[targetCount++] = pe.th32ProcessID;
                    if (targetCount >= 256) break;
                }
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);

    if (targetCount == 0) {
        DaemonLog(L"[WATCHDOG] No related processes found for termination");
        return;
    }

    DaemonLog(L"[WATCHDOG] Found %d related processes, terminating all simultaneously", targetCount);

    HANDLE hProcs[256] = {0};
    int handleCount = 0;
    for (int i = 0; i < targetCount; i++) {
        HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, targetPids[i]);
        if (hProc) {
            hProcs[handleCount++] = hProc;
        }
    }

    for (int i = 0; i < handleCount; i++) {
        TerminateProcess(hProcs[i], 1);
    }

    for (int i = 0; i < handleCount; i++) {
        CloseHandle(hProcs[i]);
    }

    for (int i = 0; i < targetCount; i++) {
        AddRepeatedKillByName(s, procName);
    }

    DaemonLog(L"[WATCHDOG] Group termination complete: %d processes terminated", targetCount);
}

static BOOL SafeToKillByName(const wchar_t* name) {
    if (!name || !name[0]) return FALSE;
    if (IsSystemProcessName(name) || IsAntivirusProcessName(name)) {
        DaemonLog(L"[SAFETY] refusing to kill system/antivirus process: %ls", name);
        return FALSE;
    }
    /* Do not auto-kill signed processes */
    DWORD pid = GetPidByName(name);
    if (pid) {
        wchar_t path[MAX_PATH] = {0};
        GetProcessImagePath(pid, path, MAX_PATH);
        if (path[0]) {
            wchar_t signer[256] = {0};
            if (CheckFileSignatureCached(path, signer, 256)) {
                DaemonLog(L"[SAFETY] refusing to kill signed process: %ls signer=%ls", name, signer);
                return FALSE;
            }
        }
    }
    return TRUE;
}

static BOOL KillProcessByName(const wchar_t* name, BOOL tree) {
    if (!SafeToKillByName(name)) return FALSE;
    DWORD pid = GetPidByName(name);
    if (pid == 0) return FALSE;
    if (tree) return KillTree(pid);
    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProc) return FALSE;
    BOOL r = SafeTerminateProcess(hProc, NULL);
    CloseHandle(hProc);
    return r;
}

void RecoverFromEtwLogs(DaemonState* s, DWORD targetPid) {
    if (!s) return;
    
    wchar_t procName[256] = L"unknown";
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = {0}; pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (pe.th32ProcessID == targetPid) {
                    wcsncpy(procName, pe.szExeFile, 255);
                    procName[255] = L'\0';
                    break;
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    
    DaemonLog(L"[RECOVER] Starting recovery for pid=%lu name=%ls", targetPid, procName);
    
    EnterCriticalSection(&s->actionLogManager.cs);
    
    int recoveredCount = 0;
    int failedCount = 0;
    
    for (int i = s->actionLogManager.entryCount - 1; i >= 0; i--) {
        ActionEntry* entry = &s->actionLogManager.entries[i];
        
        if (entry->pid != targetPid) continue;
        
        DaemonLog(L"[RECOVER] Processing action: type=%d path=%ls value=%ls", 
                  entry->type, entry->targetPath, entry->valueName[0] ? entry->valueName : L"");
        
        switch (entry->type) {
            case ACTION_TYPE_REG_SET: {
                if (entry->oldValue[0]) {
                    HKEY hKey = NULL;
                    wchar_t keyPath[512] = {0};
                    wchar_t valName[256] = {0};
                    
                    wchar_t* p = wcsrchr(entry->targetPath, L'\\');
                    if (p) {
                        wcsncpy(keyPath, entry->targetPath, p - entry->targetPath);
                        wcscpy(valName, p + 1);
                    } else {
                        wcscpy(keyPath, entry->targetPath);
                    }
                    
                    HKEY hRoot = HKEY_LOCAL_MACHINE;
                    const wchar_t* subKey = keyPath;
                    if (wcsncmp(keyPath, L"HKEY_LOCAL_MACHINE\\", 19) == 0) { hRoot = HKEY_LOCAL_MACHINE; subKey += 19; }
                    else if (wcsncmp(keyPath, L"HKEY_CURRENT_USER\\", 18) == 0) { hRoot = HKEY_CURRENT_USER; subKey += 18; }
                    else if (wcsncmp(keyPath, L"HKEY_CLASSES_ROOT\\", 18) == 0) { hRoot = HKEY_CLASSES_ROOT; subKey += 18; }
                    
                    if (RegOpenKeyExW(hRoot, subKey, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                        if (RegSetValueExW(hKey, valName, 0, REG_SZ, (const BYTE*)entry->oldValue, 
                                           (wcslen(entry->oldValue) + 1) * sizeof(wchar_t)) == ERROR_SUCCESS) {
                            DaemonLog(L"[RECOVER] Restored registry value: %ls\\%ls", keyPath, valName);
                            recoveredCount++;
                        } else {
                            DaemonLog(L"[RECOVER] Failed to restore registry value: %ls\\%ls", keyPath, valName);
                            failedCount++;
                        }
                        RegCloseKey(hKey);
                    }
                }
                break;
            }
            
            case ACTION_TYPE_REG_DELETE_VALUE: {
                if (entry->oldValue[0]) {
                    HKEY hKey = NULL;
                    wchar_t keyPath[512] = {0};
                    wchar_t valName[256] = {0};
                    
                    wchar_t* p = wcsrchr(entry->targetPath, L'\\');
                    if (p) {
                        wcsncpy(keyPath, entry->targetPath, p - entry->targetPath);
                        wcscpy(valName, p + 1);
                    } else {
                        wcscpy(keyPath, entry->targetPath);
                    }
                    
                    HKEY hRoot = HKEY_LOCAL_MACHINE;
                    const wchar_t* subKey = keyPath;
                    if (wcsncmp(keyPath, L"HKEY_LOCAL_MACHINE\\", 19) == 0) { hRoot = HKEY_LOCAL_MACHINE; subKey += 19; }
                    else if (wcsncmp(keyPath, L"HKEY_CURRENT_USER\\", 18) == 0) { hRoot = HKEY_CURRENT_USER; subKey += 18; }
                    else if (wcsncmp(keyPath, L"HKEY_CLASSES_ROOT\\", 18) == 0) { hRoot = HKEY_CLASSES_ROOT; subKey += 18; }
                    
                    if (RegOpenKeyExW(hRoot, subKey, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                        if (RegSetValueExW(hKey, valName, 0, REG_SZ, (const BYTE*)entry->oldValue, 
                                           (wcslen(entry->oldValue) + 1) * sizeof(wchar_t)) == ERROR_SUCCESS) {
                            DaemonLog(L"[RECOVER] Restored deleted registry value: %ls\\%ls", keyPath, valName);
                            recoveredCount++;
                        } else {
                            DaemonLog(L"[RECOVER] Failed to restore deleted registry value: %ls\\%ls", keyPath, valName);
                            failedCount++;
                        }
                        RegCloseKey(hKey);
                    }
                }
                break;
            }
            
            case ACTION_TYPE_FILE_RENAME: {
                if (MoveFileW(entry->targetPath, entry->oldValue) == TRUE) {
                    DaemonLog(L"[RECOVER] Restored file name: %ls -> %ls", entry->targetPath, entry->oldValue);
                    recoveredCount++;
                } else {
                    DaemonLog(L"[RECOVER] Failed to restore file name: %ls -> %ls", entry->targetPath, entry->oldValue);
                    failedCount++;
                }
                break;
            }
            
            case ACTION_TYPE_FILE_DELETE:
            case ACTION_TYPE_FILE_WRITE: {
                DaemonLog(L"[RECOVER] Cannot automatically restore file operation: type=%d path=%ls", 
                          entry->type, entry->targetPath);
                break;
            }
            
            default:
                break;
        }
    }
    
    LeaveCriticalSection(&s->actionLogManager.cs);
    
    DaemonLog(L"[RECOVER] Recovery completed: %d recovered, %d failed", recoveredCount, failedCount);
}

void AddRepeatedKillByName(DaemonState* s, const wchar_t* name) {
    if (!s || !name || !name[0]) return;
    if (IsSystemProcessName(name) || IsAntivirusProcessName(name)) {
        DaemonLog(L"[SAFETY] refused repeated-kill for system/antivirus process: %ls", name);
        return;
    }
    if (IsCriticalSystemProcess(name)) {
        DaemonLog(L"[SAFETY] refused repeated-kill for critical system process: %ls", name);
        return;
    }
    const wchar_t* ext = wcsrchr(name, L'.');
    if (ext && !_wcsicmp(ext, L".dll")) {
        DaemonLog(L"[SAFETY] refused repeated-kill for DLL (not a process): %ls", name);
        return;
    }
    if (s->procCount >= MAX_PROC) return;
    for (int i = 0; i < s->procCount; i++) {
        if (!_wcsicmp(s->procs[i].name, name)) {
            s->procs[i].isRepeated = TRUE;
            SaveProcs(s);
            return;
        }
    }
    wcsncpy(s->procs[s->procCount].name, name, 259);
    s->procs[s->procCount].name[259] = L'\0';
    s->procs[s->procCount].pid = 0;
    s->procs[s->procCount].isTree = FALSE;
    s->procs[s->procCount].isRepeated = TRUE;
    s->procCount++;
    SaveProcs(s);
}

static void ExecuteSvcRepeated(DaemonState* s) {
    if (s->svcCount == 0 || !g_svcDelete) return;
    for (int i = 0; i < s->svcCount; i++) {
        if (g_svcDelete(s->svcs[i].name)) {
            DaemonLog(L"Repeated delete service: %ls", s->svcs[i].name);
        }
    }
}

static void ExecuteRegRepeated(DaemonState* s) {
    if (s->regCount == 0 || !g_regDelete) return;
    for (int i = 0; i < s->regCount; i++) {
        HKEY hRoot = HKEY_LOCAL_MACHINE;
        const wchar_t* subKey = s->regs[i].fullPath;
        if (wcsncmp(subKey, L"HKEY_LOCAL_MACHINE\\", 19) == 0) { hRoot = HKEY_LOCAL_MACHINE; subKey += 19; }
        else if (wcsncmp(subKey, L"HKEY_CURRENT_USER\\", 18) == 0) { hRoot = HKEY_CURRENT_USER; subKey += 18; }
        else if (wcsncmp(subKey, L"HKEY_CLASSES_ROOT\\", 18) == 0) { hRoot = HKEY_CLASSES_ROOT; subKey += 18; }
        else if (wcsncmp(subKey, L"HKEY_USERS\\", 11) == 0) { hRoot = HKEY_USERS; subKey += 11; }
        else if (wcsncmp(subKey, L"HKEY_CURRENT_CONFIG\\", 20) == 0) { hRoot = HKEY_CURRENT_CONFIG; subKey += 20; }
        else continue;
        if (g_regDelete(hRoot, subKey, NULL)) {
            DaemonLog(L"Repeated delete registry: %ls", s->regs[i].fullPath);
        }
    }
}

static void ExecutePartRepeated(DaemonState* s) {
    if (s->partCount == 0 || !g_partDelete) return;
    for (int i = 0; i < s->partCount; i++) {
        if (g_partDelete(s->parts[i].diskNumber, s->parts[i].partitionNumber)) {
            DaemonLog(L"Repeated delete partition: disk=%d part=%d", s->parts[i].diskNumber, s->parts[i].partitionNumber);
        }
    }
}

static BOOL ReadPartitionTable(int diskNumber, BYTE* buf, DWORD bufSize) {
    wchar_t path[64];
    swprintf(path, 64, L"\\\\.\\PhysicalDrive%d", diskNumber);
    HANDLE hDisk = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk == INVALID_HANDLE_VALUE) return FALSE;
    DWORD br;
    BOOL ok = ReadFile(hDisk, buf, bufSize, &br, NULL);
    CloseHandle(hDisk);
    return ok && br == bufSize;
}

static BOOL WritePartitionTable(int diskNumber, const BYTE* buf, DWORD bufSize) {
    wchar_t path[64];
    swprintf(path, 64, L"\\\\.\\PhysicalDrive%d", diskNumber);
    HANDLE hDisk = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk == INVALID_HANDLE_VALUE) return FALSE;
    DWORD bw;
    BOOL ok = WriteFile(hDisk, buf, bufSize, &bw, NULL);
    CloseHandle(hDisk);
    return ok && bw == bufSize;
}

static BOOL ParseRegPath(const wchar_t* fullPath, HKEY* root, const wchar_t** subKey, const wchar_t** valueName) {
    if (!fullPath || !fullPath[0]) return FALSE;
    if (wcsncmp(fullPath, L"HKEY_LOCAL_MACHINE\\", 19) == 0) { *root = HKEY_LOCAL_MACHINE; fullPath += 19; }
    else if (wcsncmp(fullPath, L"HKEY_CURRENT_USER\\", 18) == 0) { *root = HKEY_CURRENT_USER; fullPath += 18; }
    else if (wcsncmp(fullPath, L"HKEY_CLASSES_ROOT\\", 18) == 0) { *root = HKEY_CLASSES_ROOT; fullPath += 18; }
    else if (wcsncmp(fullPath, L"HKEY_USERS\\", 11) == 0) { *root = HKEY_USERS; fullPath += 11; }
    else if (wcsncmp(fullPath, L"HKEY_CURRENT_CONFIG\\", 20) == 0) { *root = HKEY_CURRENT_CONFIG; fullPath += 20; }
    else return FALSE;

    *subKey = fullPath;
    *valueName = NULL;
    const wchar_t* last = wcsrchr(fullPath, L'\\');
    if (last) {
        *valueName = last + 1;
    }
    return TRUE;
}

static BOOL ReadRegValueData(const wchar_t* fullPath, BYTE* buf, DWORD* bufSize, DWORD* type) {
    HKEY root; const wchar_t* subKey; const wchar_t* valueName;
    if (!ParseRegPath(fullPath, &root, &subKey, &valueName)) return FALSE;

    HKEY hKey;
    if (RegOpenKeyExW(root, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        /* Maybe fullPath is a key with default value */
        if (RegOpenKeyExW(root, fullPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS) return FALSE;
        valueName = NULL;
    }
    DWORD sz = *bufSize;
    LSTATUS st = RegQueryValueExW(hKey, valueName, NULL, type, buf, &sz);
    RegCloseKey(hKey);
    if (st == ERROR_SUCCESS || st == ERROR_MORE_DATA) {
        *bufSize = sz;
        return TRUE;
    }
    return FALSE;
}

static BOOL WriteRegValueData(const wchar_t* fullPath, DWORD type, const BYTE* buf, DWORD bufSize) {
    HKEY root; const wchar_t* subKey; const wchar_t* valueName;
    if (!ParseRegPath(fullPath, &root, &subKey, &valueName)) return FALSE;

    HKEY hKey;
    if (RegCreateKeyExW(root, subKey, 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) != ERROR_SUCCESS) return FALSE;
    LSTATUS st = RegSetValueExW(hKey, valueName, 0, type, buf, bufSize);
    RegCloseKey(hKey);
    return st == ERROR_SUCCESS;
}

static BOOL IsProtectedDesktopProcess(const wchar_t* name) {
    if (!name || !name[0]) return FALSE;
    static const wchar_t* list[] = {
        L"explorer.exe", L"dwm.exe", L"winlogon.exe", L"sihost.exe",
        L"taskhostw.exe", L"ShellExperienceHost.exe", L"SearchIndexer.exe",
        L"SearchProtocolHost.exe", L"ctfmon.exe", L"fontdrvhost.exe",
        L"backgroundTaskHost.exe", L"RuntimeBroker.exe", L"WmiPrvSE.exe", NULL
    };
    for (int i = 0; list[i]; i++) {
        if (!_wcsicmp(name, list[i])) return TRUE;
    }
    return FALSE;
}

static BOOL IsProcessUnderWindowsDir(const wchar_t* path) {
    if (!path || !path[0]) return FALSE;
    wchar_t winDir[MAX_PATH];
    GetWindowsDirectoryW(winDir, MAX_PATH);
    size_t len = wcslen(winDir);
    return (len > 0 && _wcsnicmp(path, winDir, len) == 0);
}

static BOOL IsUserInteractiveProcess(const wchar_t* name) {
    if (!name || !name[0]) return FALSE;
    static const wchar_t* list[] = {
        L"explorer.exe", L"taskmgr.exe", L"regedit.exe", L"regedt32.exe",
        L"cmd.exe", L"powershell.exe", L"pwsh.exe", L"notepad.exe",
        L"explorer.exe", NULL
    };
    for (int i = 0; list[i]; i++) {
        if (!_wcsicmp(name, list[i])) return TRUE;
    }
    return FALSE;
}

static DWORD GetPidByImagePath(const wchar_t* imagePath) {
    if (!imagePath || !imagePath[0]) return 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = {0}; pe.dwSize = sizeof(pe);
    if (!Process32FirstW(hSnap, &pe)) { CloseHandle(hSnap); return 0; }
    do {
        wchar_t path[MAX_PATH] = {0};
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
        if (hProc) {
            DWORD sz = MAX_PATH;
            QueryFullProcessImageNameW(hProc, 0, path, &sz);
            CloseHandle(hProc);
            if (_wcsicmp(path, imagePath) == 0) {
                CloseHandle(hSnap);
                return pe.th32ProcessID;
            }
        }
    } while (Process32NextW(hSnap, &pe));
    CloseHandle(hSnap);
    return 0;
}

static void KillProcessByPid(DWORD pid) {
    if (pid == 0 || pid == 4) return;
    HANDLE hProc = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProc) {
        wchar_t name[MAX_PATH] = {0};
        DWORD sz = MAX_PATH;
        BOOL gotPath = QueryFullProcessImageNameW(hProc, 0, name, &sz);
        if (!gotPath || !name[0]) {
            /* Cannot identify process: skip to avoid killing system/desktop processes */
            DaemonLog(L"Skipped termination of unidentified process pid=%lu", pid);
            CloseHandle(hProc);
            return;
        }
        wchar_t* base = wcsrchr(name, L'\\');
        if (base) base++; else base = name;
        
        wchar_t signer[256] = {0};
        if (CheckFileSignatureCached(name, signer, 256)) {
            DaemonLog(L"[SIGNATURE-PROTECT] BLOCKED: Termination of signed process pid=%lu path=%ls signer=%ls", pid, name, signer);
            CloseHandle(hProc);
            return;
        }
        
        if (!IsProtectedDesktopProcess(base) && !IsSystemProcessName(base) && !IsAntivirusProcessName(base) && !IsProcessUnderWindowsDir(name)) {
            TerminateProcess(hProc, 1);
            DaemonLog(L"Terminated process pid=%lu path=%ls", pid, name);
        } else {
            DaemonLog(L"Skipped termination of protected process pid=%lu path=%ls", pid, name);
        }
        CloseHandle(hProc);
    }
}

static void EvaluateSuspectProcess(DaemonState* s, ProcSnapshotEntry* p,
                                   const wchar_t* modifiedObject, BOOL critical,
                                   const wchar_t* objectType, int threshold, const char* apiKey,
                                   BOOL aiOk) {
    if (!p || p->pid == 0 || p->pid == 4) return;
    if (TzShouldSkip(&s->tz, p->imagePath)) return;
    if (IsSystemProcessName(p->name)) return;
    if (IsProcessUnderWindowsDir(p->imagePath)) return;
    if (IsUserInteractiveProcess(p->name)) {
        DaemonLog(L"[SKIP] user interactive process: %ls pid=%lu", p->imagePath, p->pid);
        return;
    }
    if (IsSelfProcessName(p->name)) {
        DaemonLog(L"[SKIP] self process: %ls pid=%lu", p->imagePath, p->pid);
        return;
    }

    wchar_t signer[256] = {0};
    BOOL signedOk = FALSE;
    if (p->imagePath[0] && CheckFileSignatureCached(p->imagePath, signer, 256)) {
        signedOk = TRUE;
    }

    if (!signedOk) {
        DaemonLog(L"[VIRUS-PATH] Unsigned process entering virus analyzer: %ls pid=%lu", p->imagePath, p->pid);
        
        if (critical) {
            DaemonLog(L"[VIRUS-ALERT] Unsigned process near critical object modification: %ls pid=%lu object=%ls",
                      p->imagePath, p->pid, modifiedObject);
            CreateHighRiskPopupFlag(L"protection", L"protection", p->name, p->imagePath,
                                    "Unsigned process detected near critical system change", 40);
            {
                char pathA[MAX_PATH] = {0};
                WideCharToMultiByte(CP_UTF8, 0, p->imagePath, -1, pathA, sizeof(pathA) - 1, NULL, NULL);
                WriteAiNotification("WARNING", L"protection", L"protection", p->name, pathA,
                                    "Unsigned process detected near critical system change");
            }
            if (aiOk) {
                DaemonLog(L"[VIRUS-AI] Evaluating unsigned process with AI: %ls pid=%lu", p->name, p->pid);
                AiEvaluateSingleProcess(s, p->pid, p->name, p->imagePath, modifiedObject,
                                        objectType, NULL, NULL, NULL, threshold, apiKey, 0);
            }
        } else {
            DaemonLog(L"[VIRUS-INFO] Monitoring unsigned uncommon process: %ls pid=%lu", p->imagePath, p->pid);
            if (aiOk) {
                AiEvaluateSingleProcess(s, p->pid, p->name, p->imagePath, modifiedObject,
                                        objectType, NULL, NULL, NULL, threshold, apiKey, 0);
            }
        }
    } else {
        DaemonLog(L"[ROGUE-PATH] Signed process entering rogue software analyzer: %ls pid=%lu signer=%ls",
                  p->imagePath, p->pid, signer);
        
        if (critical) {
            if (IsProcessUnderWindowsDir(p->imagePath) || 
                wcsstr(p->imagePath, L"\\Program Files\\") || 
                wcsstr(p->imagePath, L"\\Program Files (x86)\\")) {
                DaemonLog(L"[SAFETY] SKIP: Signed process in trusted path near critical object: %ls pid=%lu",
                          p->imagePath, p->pid);
            } else {
                DaemonLog(L"[ROGUE-ALERT] Signed process near critical object modification: %ls pid=%lu object=%ls",
                          p->imagePath, p->pid, modifiedObject);
                {
                    char pathA[MAX_PATH] = {0};
                    WideCharToMultiByte(CP_UTF8, 0, p->imagePath, -1, pathA, sizeof(pathA) - 1, NULL, NULL);
                    WriteAiNotification("ROGUE-WARNING", L"protection", L"protection", p->name, pathA,
                                        "Signed process detected near critical system change (rogue behavior)");
                }
            }
        }
        
        if (aiOk) {
            DaemonLog(L"[ROGUE-AI] Starting long-term AI behavior analysis for signed process: %ls pid=%lu", p->name, p->pid);
        }
        
        DaemonLog(L"[ROGUE-NOTE] Signed process will only be added to rogue list, never auto-terminated");
    }
}

static void HandleProcessIntruders(DaemonState* s, ProcSnapshotEntry* intruders, int count,
                                   const wchar_t* modifiedObject, BOOL critical) {
    if (count <= 0) return;
    int threshold = LoadAiThreatThreshold();
    char apiKey[512] = {0};
    BOOL aiOk = (s->enableAiAssist && LoadApiKey(apiKey, sizeof(apiKey)) == 0 && apiKey[0]);

    for (int i = 0; i < count; i++) {
        EvaluateSuspectProcess(s, &intruders[i], modifiedObject, critical,
                               L"registry", threshold, apiKey, aiOk);
    }
}

static void HandleUncommonProcesses(DaemonState* s, const wchar_t* modifiedObject, BOOL critical) {
    ProcSnapshotEntry current[MAX_PROC_SNAPSHOT];
    int currentCount = CaptureProcessSnapshot(current, MAX_PROC_SNAPSHOT);
    for (int i = 0; i < currentCount; i++) {
        if (IsCommonProcess(s, current[i].imagePath)) continue;
        if (IsUserInteractiveProcess(current[i].name)) continue;
        EvaluateSuspectProcess(s, &current[i], modifiedObject, FALSE,
                               L"registry", LoadAiThreatThreshold(), NULL, FALSE);
    }
}

static void ExecuteRegProtection(DaemonState* s) {
    if (s->regProtCount == 0) return;
    for (int i = 0; i < s->regProtCount; i++) {
        const wchar_t* path = s->regProt[i].fullPath;
        BYTE current[4096] = {0};
        DWORD curSize = sizeof(current);
        DWORD curType = 0;
        BOOL curOk = ReadRegValueData(path, current, &curSize, &curType);

        FILE* f = _wfopen(s->regProt[i].snapshotFile, L"rb");
        if (!f) {
            /* First run: create snapshot with header + data */
            wchar_t dir[MAX_PATH];
            wcscpy(dir, s->regProt[i].snapshotFile);
            wchar_t* p = wcsrchr(dir, L'\\');
            if (p) { *p = L'\0'; CreateDirectoryW(dir, NULL); }
            f = _wfopen(s->regProt[i].snapshotFile, L"wb");
            if (f) {
                DWORD header[2] = { curType, curOk ? curSize : 0 };
                fwrite(header, sizeof(DWORD), 2, f);
                if (curOk) fwrite(current, 1, curSize, f);
                fclose(f);
            }
            continue;
        }

        DWORD header[2] = {0};
        size_t hr = fread(header, sizeof(DWORD), 2, f);
        if (hr != 2) { fclose(f); continue; }
        DWORD snapType = header[0];
        DWORD snapSize = header[1];
        if (snapSize > sizeof(current)) snapSize = sizeof(current);
        BYTE snapshot[4096] = {0};
        size_t br = fread(snapshot, 1, snapSize, f);
        fclose(f);
        if (br != snapSize) continue;

        BOOL changed = FALSE;
        if (!curOk) {
            changed = (snapSize > 0);
        } else if (curType != snapType || curSize != snapSize || memcmp(current, snapshot, snapSize) != 0) {
            changed = TRUE;
        }

        if (changed) {
            s->wasModifiedThisTick = TRUE;
            DaemonLog(L"Registry modified, restoring: %ls", path);
            if (WriteRegValueData(path, snapType, snapshot, snapSize)) {
                DaemonLog(L"Registry restored: %ls", path);
            } else {
                DaemonLog(L"Registry restore failed: %ls err=%lu", path, GetLastError());
            }
            /* The actual offender is handled by the real-time ETW registry monitor */
        }
    }
    UpdateProcessSnapshot(s);
}

#define REG_KEY_MAGIC 0x4B474552 /* 'REGK' */

typedef struct {
    wchar_t name[256];
    DWORD type;
    DWORD size;
    BYTE data[4096];
} RegKeyValue;

static int EnumRegKeyValues(HKEY hKey, RegKeyValue* out, int maxCount) {
    int count = 0;
    for (DWORD i = 0; i < (DWORD)maxCount; i++) {
        DWORD nameLen = 256;
        DWORD size = sizeof(out[count].data);
        DWORD type;
        LONG ret = RegEnumValueW(hKey, i, out[count].name, &nameLen, NULL, &type, out[count].data, &size);
        if (ret == ERROR_NO_MORE_ITEMS) break;
        if (ret == ERROR_SUCCESS) {
            out[count].type = type;
            out[count].size = size;
            count++;
        }
    }
    return count;
}

static BOOL SaveRegKeySnapshot(const wchar_t* file, RegKeyValue* values, int count) {
    wchar_t dir[MAX_PATH];
    wcscpy(dir, file);
    wchar_t* p = wcsrchr(dir, L'\\');
    if (p) { *p = L'\0'; CreateDirectoryW(dir, NULL); }
    FILE* f = _wfopen(file, L"wb");
    if (!f) return FALSE;
    DWORD magic = REG_KEY_MAGIC;
    fwrite(&magic, sizeof(DWORD), 1, f);
    fwrite(&count, sizeof(DWORD), 1, f);
    for (int i = 0; i < count; i++) {
        DWORD nameLen = (DWORD)(wcslen(values[i].name) + 1);
        fwrite(&nameLen, sizeof(DWORD), 1, f);
        fwrite(values[i].name, sizeof(wchar_t), nameLen, f);
        fwrite(&values[i].type, sizeof(DWORD), 1, f);
        fwrite(&values[i].size, sizeof(DWORD), 1, f);
        if (values[i].size > 0) fwrite(values[i].data, 1, values[i].size, f);
    }
    fclose(f);
    return TRUE;
}

static BOOL LoadRegKeySnapshot(const wchar_t* file, RegKeyValue* out, int maxCount, int* count) {
    FILE* f = _wfopen(file, L"rb");
    if (!f) return FALSE;
    DWORD magic = 0;
    if (fread(&magic, sizeof(DWORD), 1, f) != 1 || magic != REG_KEY_MAGIC) {
        fclose(f);
        return FALSE;
    }
    if (fread(count, sizeof(DWORD), 1, f) != 1) { fclose(f); return FALSE; }
    if (*count > maxCount) *count = maxCount;
    for (int i = 0; i < *count; i++) {
        DWORD nameLen = 0;
        if (fread(&nameLen, sizeof(DWORD), 1, f) != 1) break;
        if (nameLen > 256) nameLen = 256;
        if (nameLen > 0) {
            size_t br = fread(out[i].name, sizeof(wchar_t), nameLen, f);
            out[i].name[255] = L'\0';
            if (br != nameLen) break;
        } else {
            out[i].name[0] = L'\0';
        }
        if (fread(&out[i].type, sizeof(DWORD), 1, f) != 1) break;
        if (fread(&out[i].size, sizeof(DWORD), 1, f) != 1) break;
        if (out[i].size > sizeof(out[i].data)) out[i].size = sizeof(out[i].data);
        if (out[i].size > 0) {
            if (fread(out[i].data, 1, out[i].size, f) != out[i].size) break;
        }
    }
    fclose(f);
    return TRUE;
}

static BOOL RegKeySnapshotChanged(RegKeyValue* current, int currentCount, RegKeyValue* snap, int snapCount) {
    if (currentCount != snapCount) return TRUE;
    for (int i = 0; i < currentCount; i++) {
        BOOL found = FALSE;
        for (int j = 0; j < snapCount; j++) {
            if (wcscmp(current[i].name, snap[j].name) == 0) {
                if (current[i].type != snap[j].type ||
                    current[i].size != snap[j].size ||
                    memcmp(current[i].data, snap[j].data, current[i].size) != 0) {
                    return TRUE;
                }
                found = TRUE;
                break;
            }
        }
        if (!found) return TRUE;
    }
    return FALSE;
}

static BOOL RestoreRegKey(HKEY hKey, RegKeyValue* snap, int snapCount, RegKeyValue* current, int currentCount) {
    for (int i = 0; i < currentCount; i++) {
        BOOL found = FALSE;
        for (int j = 0; j < snapCount; j++) {
            if (wcscmp(current[i].name, snap[j].name) == 0) { found = TRUE; break; }
        }
        if (!found) RegDeleteValueW(hKey, current[i].name);
    }
    for (int j = 0; j < snapCount; j++) {
        RegSetValueExW(hKey, snap[j].name, 0, snap[j].type, snap[j].data, snap[j].size);
    }
    return TRUE;
}

static BOOL OpenSysRegKey(const wchar_t* fullPath, HKEY* hKey) {
    HKEY root; const wchar_t* subKey; const wchar_t* valueName;
    if (!ParseRegPath(fullPath, &root, &subKey, &valueName)) return FALSE;
    return RegOpenKeyExW(root, subKey, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, hKey) == ERROR_SUCCESS;
}

static BOOL IsRegistryEditorRunning(void) {
    static const wchar_t* editors[] = {
        L"regedit.exe", L"regedt32.exe", L"regedit32.exe", NULL
    };
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return FALSE;
    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);
    BOOL found = FALSE;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            for (int i = 0; editors[i]; i++) {
                if (!_wcsicmp(pe.szExeFile, editors[i])) {
                    found = TRUE;
                    break;
                }
            }
        } while (!found && Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return found;
}

static void ExecuteSysRegKeyProtection(DaemonState* s, int idx) {
    const wchar_t* path = s->sysRegProt[idx].fullPath;
    HKEY hKey;
    if (!OpenSysRegKey(path, &hKey)) return;

    RegKeyValue current[64];
    int currentCount = EnumRegKeyValues(hKey, current, 64);

    FILE* f = _wfopen(s->sysRegProt[idx].snapshotFile, L"rb");
    if (!f) {
        SaveRegKeySnapshot(s->sysRegProt[idx].snapshotFile, current, currentCount);
        UpdateProcessSnapshot(s);
        RegCloseKey(hKey);
        return;
    }
    fclose(f);

    RegKeyValue snap[64];
    int snapCount = 0;
    if (!LoadRegKeySnapshot(s->sysRegProt[idx].snapshotFile, snap, 64, &snapCount)) {
        RegCloseKey(hKey);
        return;
    }

    if (RegKeySnapshotChanged(current, currentCount, snap, snapCount)) {
        s->wasModifiedThisTick = TRUE;
        if (IsRegistryEditorRunning()) {
            DaemonLog(L"SYSTEM registry key modified while editor is running, skipping protection: %ls", path);
            UpdateProcessSnapshot(s);
            RegCloseKey(hKey);
            return;
        }
        DaemonLog(L"SYSTEM registry key modified, restoring: %ls", path);
        if (RestoreRegKey(hKey, snap, snapCount, current, currentCount)) {
            DaemonLog(L"SYSTEM registry key restored: %ls", path);
        } else {
            DaemonLog(L"SYSTEM registry key restore failed: %ls", path);
        }
        /* The actual offender is handled by the real-time ETW registry monitor */
    }
    RegCloseKey(hKey);
}

static void ExecuteSysRegValueProtection(DaemonState* s, int idx) {
    const wchar_t* path = s->sysRegProt[idx].fullPath;
    BYTE current[4096] = {0};
    DWORD curSize = sizeof(current);
    DWORD curType = 0;
    BOOL curOk = ReadRegValueData(path, current, &curSize, &curType);

    FILE* f = _wfopen(s->sysRegProt[idx].snapshotFile, L"rb");
    if (!f) {
        wchar_t dir[MAX_PATH];
        wcscpy(dir, s->sysRegProt[idx].snapshotFile);
        wchar_t* p = wcsrchr(dir, L'\\');
        if (p) { *p = L'\0'; CreateDirectoryW(dir, NULL); }
        f = _wfopen(s->sysRegProt[idx].snapshotFile, L"wb");
        if (f) {
            DWORD header[2] = { curType, curOk ? curSize : 0 };
            fwrite(header, sizeof(DWORD), 2, f);
            if (curOk) fwrite(current, 1, curSize, f);
            fclose(f);
        }
        return;
    }

    DWORD header[2] = {0};
    size_t hr = fread(header, sizeof(DWORD), 2, f);
    if (hr != 2) { fclose(f); return; }
    DWORD snapType = header[0];
    DWORD snapSize = header[1];
    if (snapSize > sizeof(current)) snapSize = sizeof(current);
    BYTE snapshot[4096] = {0};
    size_t br = fread(snapshot, 1, snapSize, f);
    fclose(f);
    if (br != snapSize) return;

    BOOL changed = FALSE;
    if (!curOk) {
        changed = (snapSize > 0);
    } else if (curType != snapType || curSize != snapSize || memcmp(current, snapshot, snapSize) != 0) {
        changed = TRUE;
    }

    if (changed) {
        s->wasModifiedThisTick = TRUE;
        if (IsRegistryEditorRunning()) {
            DaemonLog(L"SYSTEM registry modified while editor is running, skipping protection: %ls", path);
            UpdateProcessSnapshot(s);
            return;
        }
        DaemonLog(L"SYSTEM registry modified, restoring: %ls", path);
        if (WriteRegValueData(path, snapType, snapshot, snapSize)) {
            DaemonLog(L"SYSTEM registry restored: %ls", path);
        } else {
            DaemonLog(L"SYSTEM registry restore failed: %ls err=%lu", path, GetLastError());
        }
        /* The actual offender is handled by the real-time ETW registry monitor */
    }
}

static void ExecuteSysRegProtection(DaemonState* s) {
    if (s->sysRegProtCount == 0) return;
    for (int i = 0; i < s->sysRegProtCount; i++) {
        if (s->sysRegProt[i].isKey) {
            ExecuteSysRegKeyProtection(s, i);
        } else {
            ExecuteSysRegValueProtection(s, i);
        }
    }
}

static void EnsureSysBackup(DaemonState* s) {
    wchar_t base[MAX_PATH];
    DaemonGetBasePath(base, MAX_PATH);
    wchar_t backupDir[MAX_PATH];
    swprintf(backupDir, MAX_PATH, L"%ls\\data\\sys_backup", base);
    CreateDirectoryW(backupDir, NULL);

    /* Monthly refresh: if last backup is older than 30 days, delete snapshots so
       they are recreated from the current (presumably clean) system state. */
    wchar_t timePath[MAX_PATH];
    swprintf(timePath, MAX_PATH, L"%ls\\last_backup.time", backupDir);
    SYSTEMTIME stNow; GetLocalTime(&stNow);
    BOOL needRefresh = FALSE;
    FILE* tf = _wfopen(timePath, L"rb");
    if (tf) {
        SYSTEMTIME stLast;
        if (fread(&stLast, sizeof(SYSTEMTIME), 1, tf) == 1) {
            FILETIME ftNow, ftLast;
            SystemTimeToFileTime(&stNow, &ftNow);
            SystemTimeToFileTime(&stLast, &ftLast);
            ULARGE_INTEGER now, last;
            now.LowPart = ftNow.dwLowDateTime; now.HighPart = ftNow.dwHighDateTime;
            last.LowPart = ftLast.dwLowDateTime; last.HighPart = ftLast.dwHighDateTime;
            /* 30 days in 100-ns intervals */
            if (now.QuadPart > last.QuadPart && (now.QuadPart - last.QuadPart) > (ULONGLONG)30 * 24 * 3600 * 10000000ULL) {
                needRefresh = TRUE;
            }
        }
        fclose(tf);
    } else {
        needRefresh = TRUE;
    }

    wchar_t mbrPath[MAX_PATH];
    swprintf(mbrPath, MAX_PATH, L"%ls\\mbr.snapshot", backupDir);

    if (needRefresh) {
        DaemonLog(L"Monthly system backup refresh triggered");
        wchar_t regDir[MAX_PATH];
        swprintf(regDir, MAX_PATH, L"%ls\\data\\sys_registry", base);
        WIN32_FIND_DATAW fd;
        wchar_t search[MAX_PATH];
        swprintf(search, MAX_PATH, L"%ls\\*.snapshot", regDir);
        HANDLE hFind = FindFirstFileW(search, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                wchar_t full[MAX_PATH];
                swprintf(full, MAX_PATH, L"%ls\\%ls", regDir, fd.cFileName);
                DeleteFileW(full);
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
        DeleteFileW(mbrPath);
        tf = _wfopen(timePath, L"wb");
        if (tf) { fwrite(&stNow, sizeof(SYSTEMTIME), 1, tf); fclose(tf); }
    }

    FILE* f = _wfopen(mbrPath, L"rb");
    if (!f) {
        BYTE mbr[8192] = {0};
        if (ReadPartitionTable(0, mbr, 8192)) {
            f = _wfopen(mbrPath, L"wb");
            if (f) { fwrite(mbr, 1, 8192, f); fclose(f); }
            DaemonLog(L"System MBR backup created");
            UpdateProcessSnapshot(s);
        }
    } else {
        fclose(f);
    }
}

/* ======================== Network outbound monitoring ======================== */

typedef struct {
    DWORD pid;
    DWORD remoteAddr;
    DWORD remotePort;
    DWORD tick;
} NetConnEntry;

#define MAX_NET_CONN_TRACK 256
static NetConnEntry s_netConnHistory[MAX_NET_CONN_TRACK];
static int s_netConnCount = 0;
static DWORD s_lastNetTick = 0;

static BOOL IsSuspiciousRemotePort(DWORD port) {
    /* Common C2 / trojan / backdoor ports (also catch non-standard high ports used by malware) */
    switch (port) {
        case 4444: case 5555: case 6666: case 7777: case 8888: case 9999:
        case 12345: case 31337: case 54321:
            return TRUE;
        default:
            return FALSE;
    }
}

static void NetworkMonitorTick(DaemonState* s) {
    (void)s;
    DWORD now = GetTickCount();
    if (now - s_lastNetTick < 3000) return; /* check every 3 seconds */
    s_lastNetTick = now;

    ULONG size = 0;
    DWORD status = GetExtendedTcpTable(NULL, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (status != ERROR_INSUFFICIENT_BUFFER) return;

    PMIB_TCPTABLE_OWNER_PID table = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if (!table) return;

    status = GetExtendedTcpTable(table, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (status != NO_ERROR) {
        free(table);
        return;
    }

    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID* row = &table->table[i];
        if (row->dwState != MIB_TCP_STATE_ESTAB && row->dwState != MIB_TCP_STATE_SYN_SENT) continue;
        if (row->dwRemoteAddr == 0 || row->dwRemoteAddr == 0x0100007F) continue; /* skip 0.0.0.0 and 127.0.0.1 */

        DWORD pid = row->dwOwningPid;
        if (pid == 0 || pid == 4 || pid == GetCurrentProcessId()) continue;

        wchar_t procName[256] = {0};
        GetProcessNameByPid(pid, procName, 256);
        if (!procName[0]) wcscpy(procName, L"unknown");
        
        if (_wcsicmp(procName, L"unknown") == 0) {
            DaemonLog(L"[SAFETY-GUARD] BLOCKED: NetworkMonitor skipping process with unknown name PID=%lu", pid);
            continue;
        }

        /* Skip system/trusted/common/self processes */
        if (IsSelfProcessName(procName)) continue;
        if (IsSystemProcessName(procName)) continue;
        if (IsAntivirusProcessName(procName)) continue;
        if (IsCommonProcess(s, procName)) continue;
        if (TzShouldSkip(&s->tz, procName)) continue;

        DWORD remotePort = ntohs((u_short)row->dwRemotePort);

        /* Check for rapid outbound connections from same PID */
        int samePidCount = 0;
        for (int j = 0; j < s_netConnCount; j++) {
            if (s_netConnHistory[j].pid == pid && (now - s_netConnHistory[j].tick) < 10000) {
                samePidCount++;
            }
        }

        /* Record connection */
        if (s_netConnCount < MAX_NET_CONN_TRACK) {
            s_netConnHistory[s_netConnCount].pid = pid;
            s_netConnHistory[s_netConnCount].remoteAddr = row->dwRemoteAddr;
            s_netConnHistory[s_netConnCount].remotePort = remotePort;
            s_netConnHistory[s_netConnCount].tick = now;
            s_netConnCount++;
        } else {
            /* ring buffer: overwrite oldest */
            memmove(&s_netConnHistory[0], &s_netConnHistory[1], sizeof(NetConnEntry) * (MAX_NET_CONN_TRACK - 1));
            s_netConnHistory[MAX_NET_CONN_TRACK - 1].pid = pid;
            s_netConnHistory[MAX_NET_CONN_TRACK - 1].remoteAddr = row->dwRemoteAddr;
            s_netConnHistory[MAX_NET_CONN_TRACK - 1].remotePort = remotePort;
            s_netConnHistory[MAX_NET_CONN_TRACK - 1].tick = now;
        }

        /* Decision */
        if (samePidCount >= 5 || IsSuspiciousRemotePort(remotePort)) {
            BYTE addr[4];
            addr[0] = (BYTE)(row->dwRemoteAddr & 0xFF);
            addr[1] = (BYTE)((row->dwRemoteAddr >> 8) & 0xFF);
            addr[2] = (BYTE)((row->dwRemoteAddr >> 16) & 0xFF);
            addr[3] = (BYTE)((row->dwRemoteAddr >> 24) & 0xFF);
            wchar_t reason[256];
            if (IsSuspiciousRemotePort(remotePort)) {
                swprintf(reason, 256, L"Suspicious outbound connection to %u.%u.%u.%u:%u", addr[0], addr[1], addr[2], addr[3], remotePort);
            } else {
                swprintf(reason, 256, L"Rapid outbound connections (%d in 10s) to %u.%u.%u.%u:%u", samePidCount, addr[0], addr[1], addr[2], addr[3], remotePort);
            }

            /* Check signature before terminating */
            wchar_t imgPath[MAX_PATH] = {0};
            GetProcessImagePath(pid, imgPath, MAX_PATH);
            BOOL signedOk = FALSE;
            if (imgPath[0]) {
                wchar_t signer[256] = {0};
                signedOk = CheckFileSignatureCached(imgPath, signer, 256);
            }

            if (IsCriticalSystemProcess(procName)) {
                DaemonLog(L"[CRITICAL-PROTECT] BLOCKED: Network termination avoided for critical system process: pid=%lu name=%ls", pid, procName);
            } else if (!imgPath[0]) {
                DaemonLog(L"[SAFETY-GUARD] BLOCKED: Network termination avoided - cannot get image path for pid=%lu name=%ls", pid, procName);
            } else if (signedOk) {
                DaemonLog(L"[NETWORK-WARN] signed pid=%lu proc=%ls %ls - not terminated", pid, procName, reason);
            } else {
                DaemonLog(L"[NETWORK-BLOCK] pid=%lu proc=%ls %ls", pid, procName, reason);
                HANDLE hTerm = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                if (hTerm) { SafeTerminateProcess(hTerm, NULL); CloseHandle(hTerm); }
                AddRepeatedKillByName(s, procName);
                SaveProcs(s);
                CreateHighRiskPopupFlag(L"protection", L"protection", procName, reason, "Suspicious network activity", 50);
            }
            char reasonA[256] = {0};
            char procA[256] = {0};
            WideCharToMultiByte(CP_UTF8, 0, reason, -1, reasonA, sizeof(reasonA) - 1, NULL, NULL);
            WideCharToMultiByte(CP_UTF8, 0, procName, -1, procA, sizeof(procA) - 1, NULL, NULL);
            WriteAiNotification("NETWORK", L"protection", L"protection", procName, procA, reasonA);
        }
    }

    free(table);

    /* prune old entries */
    int write = 0;
    for (int j = 0; j < s_netConnCount; j++) {
        if ((now - s_netConnHistory[j].tick) < 30000) {
            if (write != j) s_netConnHistory[write] = s_netConnHistory[j];
            write++;
        }
    }
    s_netConnCount = write;
}

static void ExecuteSysCriticalProtection(DaemonState* s) {
    EnsureSysBackup(s);

    /* Check critical system processes */
    static const wchar_t* sysProcs[] = {
        L"csrss.exe", L"lsass.exe", L"services.exe", L"smss.exe",
        L"wininit.exe", L"winlogon.exe", L"svchost.exe", NULL
    };
    for (int i = 0; sysProcs[i]; i++) {
        if (GetPidByName(sysProcs[i]) == 0) {
            DaemonLog(L"CRITICAL: system process missing: %ls", sysProcs[i]);
        }
    }

    /* Check disk 0 MBR against backup */
    wchar_t base[MAX_PATH];
    DaemonGetBasePath(base, MAX_PATH);
    wchar_t mbrPath[MAX_PATH];
    swprintf(mbrPath, MAX_PATH, L"%ls\\data\\sys_backup\\mbr.snapshot", base);
    FILE* f = _wfopen(mbrPath, L"rb");
    if (!f) return;
    BYTE backup[8192] = {0};
    size_t br = fread(backup, 1, 8192, f);
    fclose(f);
    if (br != 8192) return;

    BYTE current[8192] = {0};
    if (!ReadPartitionTable(0, current, 8192)) return;
    if (memcmp(current, backup, 8192) != 0) {
        s->wasModifiedThisTick = TRUE;
        DaemonLog(L"CRITICAL: MBR modified, restoring disk=0");
        if (WritePartitionTable(0, backup, 8192)) {
            DaemonLog(L"MBR restored disk=0");
        } else {
            DaemonLog(L"MBR restore failed disk=0 err=%lu", GetLastError());
        }

        ProcSnapshotEntry currentProcs[MAX_PROC_SNAPSHOT];
        int currentCount = CaptureProcessSnapshot(currentProcs, MAX_PROC_SNAPSHOT);
        ProcSnapshotEntry newProcs[MAX_PROC_SNAPSHOT];
        int newCount = FindNewProcesses(s, currentProcs, currentCount, newProcs, MAX_PROC_SNAPSHOT);

        if (newCount > 0) {
            DaemonLog(L"MBR change: %d new process(es) detected", newCount);
            HandleProcessIntruders(s, newProcs, newCount, L"disk 0 MBR", TRUE);
        } else {
            DaemonLog(L"MBR change: no new process, scanning uncommon processes");
            HandleUncommonProcesses(s, L"disk 0 MBR", TRUE);
        }

        DaemonLog(L"MBR incident: terminating all unsigned suspicious processes as watchdog defense");
        for (int i = 0; i < currentCount; i++) {
            const wchar_t* procPath = currentProcs[i].imagePath;
            if (!procPath || !procPath[0]) continue;
            if (IsSelfProcessName(currentProcs[i].name)) continue;
            if (IsSystemProcessName(currentProcs[i].name)) continue;
            if (IsAntivirusProcessName(currentProcs[i].name)) continue;
            wchar_t signer[256] = {0};
            if (!CheckFileSignatureCached(procPath, signer, 256)) {
                DaemonLog(L"[TERMINATE] MBR watchdog: terminating unsigned process: %ls (PID=%lu)", currentProcs[i].name, currentProcs[i].pid);
                AggressiveTerminateProcess(currentProcs[i].pid, currentProcs[i].name);
                AddRepeatedKillByName(s, currentProcs[i].name);
            }
        }
    }
}

static void ExecutePartProtection(DaemonState* s) {
    if (s->partProtCount == 0) return;
    for (int i = 0; i < s->partProtCount; i++) {
        int disk = s->partProt[i].diskNumber;
        BYTE current[8192] = {0};
        if (!ReadPartitionTable(disk, current, 8192)) continue;
        FILE* f = _wfopen(s->partProt[i].snapshotFile, L"rb");
        if (!f) {
            wchar_t dir[MAX_PATH];
            wcscpy(dir, s->partProt[i].snapshotFile);
            wchar_t* p = wcsrchr(dir, L'\\');
            if (p) { *p = L'\0'; CreateDirectoryW(dir, NULL); }
            f = _wfopen(s->partProt[i].snapshotFile, L"wb");
            if (f) { fwrite(current, 1, 8192, f); fclose(f); }
            continue;
        }
        BYTE snapshot[8192] = {0};
        size_t br = fread(snapshot, 1, 8192, f);
        fclose(f);
        if (br != 8192) continue;
        if (memcmp(current, snapshot, 8192) != 0) {
            s->wasModifiedThisTick = TRUE;
            DaemonLog(L"Partition table modified, restoring disk=%d", disk);
            wchar_t path[64];
            swprintf(path, 64, L"\\\\.\\PhysicalDrive%d", disk);
            HANDLE hDisk = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
            if (hDisk != INVALID_HANDLE_VALUE) {
                DWORD bw;
                WriteFile(hDisk, snapshot, 8192, &bw, NULL);
                CloseHandle(hDisk);
                DaemonLog(L"Partition table restored disk=%d", disk);
            } else {
                DaemonLog(L"Cannot open disk for write disk=%d err=%lu", disk, GetLastError());
            }
            ProcSnapshotEntry currentProcs[MAX_PROC_SNAPSHOT];
            int currentCount = CaptureProcessSnapshot(currentProcs, MAX_PROC_SNAPSHOT);
            ProcSnapshotEntry newProcs[MAX_PROC_SNAPSHOT];
            int newCount = FindNewProcesses(s, currentProcs, currentCount, newProcs, MAX_PROC_SNAPSHOT);
            if (newCount > 0) {
                DaemonLog(L"Partition table change: %d new process(es) detected", newCount);
                HandleProcessIntruders(s, newProcs, newCount, path, TRUE);
            } else {
                DaemonLog(L"Partition table change: no new process, scanning uncommon processes");
                HandleUncommonProcesses(s, path, TRUE);
            }
        }
    }
}

static void ExecuteDiskContentProtection(DaemonState* s) {
    static ULONGLONG lastCheckTick = 0;
    ULONGLONG now = GetTickCount64();
    if (now - lastCheckTick < 5000) return;
    lastCheckTick = now;
    
    typedef struct {
        DWORD pid;
        wchar_t name[260];
        ULONGLONG writeBytes;
        int fileCount;
    } DiskActivityEntry;
    
    DiskActivityEntry activity[256] = {0};
    int activityCount = 0;
    
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    
    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(hSnap, &pe)) {
        CloseHandle(hSnap);
        return;
    }
    
    do {
        if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;
        
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
        if (!hProc) continue;
        
        wchar_t imagePath[MAX_PATH] = {0};
        GetModuleFileNameExW(hProc, NULL, imagePath, MAX_PATH);
        
        if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) {
            CloseHandle(hProc);
            continue;
        }
        
        if (!imagePath || !imagePath[0]) {
            CloseHandle(hProc);
            continue;
        }
        
        BOOL isSigned = FALSE;
        if (imagePath[0]) {
            WINTRUST_FILE_INFO fileInfo = {0};
            fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
            fileInfo.pcwszFilePath = imagePath;
            GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            WINTRUST_DATA wd = {0};
            wd.cbStruct = sizeof(WINTRUST_DATA);
            wd.dwUIChoice = WTD_UI_NONE;
            wd.fdwRevocationChecks = WTD_REVOKE_NONE;
            wd.dwUnionChoice = WTD_CHOICE_FILE;
            wd.pFile = &fileInfo;
            LONG result = WinVerifyTrust(NULL, &policyGUID, &wd);
            isSigned = (result == ERROR_SUCCESS);
        }
        
        if (isSigned) {
            CloseHandle(hProc);
            continue;
        }
        
        IO_COUNTERS ioCounters = {0};
        if (GetProcessIoCounters(hProc, &ioCounters)) {
            if (ioCounters.WriteTransferCount > 1024 * 1024 * 100) {
                int idx = -1;
                for (int i = 0; i < activityCount; i++) {
                    if (activity[i].pid == pe.th32ProcessID) {
                        idx = i;
                        break;
                    }
                }
                if (idx < 0 && activityCount < 256) {
                    idx = activityCount++;
                    activity[idx].pid = pe.th32ProcessID;
                    wcscpy(activity[idx].name, pe.szExeFile);
                }
                if (idx >= 0) {
                    activity[idx].writeBytes = ioCounters.WriteTransferCount;
                }
            }
        }
        
        CloseHandle(hProc);
    } while (Process32NextW(hSnap, &pe));
    
    CloseHandle(hSnap);
    
    for (int i = 0; i < activityCount; i++) {
        if (IsSelfProcessName(activity[i].name)) continue;
        if (IsSystemProcessName(activity[i].name)) continue;
        if (IsAntivirusProcessName(activity[i].name)) continue;
        
        if (!activity[i].name || !activity[i].name[0] || _wcsicmp(activity[i].name, L"unknown") == 0) {
            DaemonLog(L"[SAFETY-GUARD] BLOCKED: DiskContentProtection skipping process with unknown name PID=%lu", activity[i].pid);
            continue;
        }
        
        wchar_t imagePath[MAX_PATH] = {0};
        DWORD pid = activity[i].pid;
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProc) {
            GetModuleFileNameExW(hProc, NULL, imagePath, MAX_PATH);
            CloseHandle(hProc);
        }
        
        if (!imagePath || !imagePath[0]) {
            DaemonLog(L"[SAFETY-GUARD] BLOCKED: DiskContentProtection skipping process without image path PID=%lu name=%ls", pid, activity[i].name);
            continue;
        }
        
        DaemonLog(L"[DISK-WARN] Unsigned process %ls (PID=%lu) wrote %llu bytes - potential ransomware",
                  activity[i].name, activity[i].pid, activity[i].writeBytes);
        UpdateUnsignedScore(s, imagePath, 5);
    }
}

static void ExecuteProcRules(DaemonState* s) {
    DaemonLog(L"[DEBUG] ExecuteProcRules: procCount=%d", s->procCount);
    for (int i = 0; i < s->procCount; i++) {
        DaemonLog(L"[DEBUG] ExecuteProcRules: idx=%d name=%ls isRepeated=%d isTree=%d", i, s->procs[i].name, s->procs[i].isRepeated, s->procs[i].isTree);

        if (!s->procs[i].name || !s->procs[i].name[0] || _wcsicmp(s->procs[i].name, L"unknown") == 0) {
            DaemonLog(L"[SAFETY-GUARD] BLOCKED: ExecuteProcRules skipping process with unknown name");
            continue;
        }

        if (IsCriticalSystemProcess(s->procs[i].name) || IsSystemProcessName(s->procs[i].name) ||
            IsAntivirusProcessName(s->procs[i].name)) {
            DaemonLog(L"[CRITICAL-PROTECT] BLOCKED: ExecuteProcRules skipping protected system process: %ls", s->procs[i].name);
            continue;
        }

        const wchar_t* ext = wcsrchr(s->procs[i].name, L'.');
        if (ext && !_wcsicmp(ext, L".dll")) {
            DaemonLog(L"[SAFETY-GUARD] BLOCKED: ExecuteProcRules skipping DLL (not a process): %ls", s->procs[i].name);
            continue;
        }

        DWORD pid = GetPidByName(s->procs[i].name);
        DaemonLog(L"[DEBUG] ExecuteProcRules: idx=%d name=%ls pid=%lu", i, s->procs[i].name, pid);
        if (s->procs[i].isRepeated) {
            DaemonLog(L"[DEBUG] Repeated kill enabled for %ls, pid=%lu", s->procs[i].name, pid);
            if (pid != 0) {
                wchar_t imagePath[MAX_PATH] = {0};
                DWORD pathSize = MAX_PATH;
                HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                if (hProc) {
                    QueryFullProcessImageNameW(hProc, 0, imagePath, &pathSize);
                    CloseHandle(hProc);
                }

                if (!imagePath[0]) {
                    DaemonLog(L"[SAFETY-GUARD] BLOCKED: ExecuteProcRules skipping process without image path PID=%lu name=%ls", pid, s->procs[i].name);
                    continue;
                }

                wchar_t signer[256] = {0};
                if (CheckFileSignatureCached(imagePath, signer, 256)) {
                    DaemonLog(L"[SIGNATURE-PROTECT] BLOCKED: Termination blocked for signed process %ls in repeated kill list (signer=%ls)",
                              s->procs[i].name, signer);
                    s->procs[i].isRepeated = FALSE;
                    SaveProcs(s);
                    continue;
                }

                if (IsProcessUnderWindowsDir(imagePath)) {
                    DaemonLog(L"[SAFETY-GUARD] BLOCKED: ExecuteProcRules skipping Windows directory process: %ls path=%ls", s->procs[i].name, imagePath);
                    s->procs[i].isRepeated = FALSE;
                    SaveProcs(s);
                    continue;
                }

                if (imagePath[0]) {
                    CacheFilePath(pid, s->procs[i].name, imagePath);
                }

                BOOL ok = FALSE;
                if (s->procs[i].isTree) {
                    DaemonLog(L"[DEBUG] Calling KillTreeEx(%lu, TRUE)", pid);
                    ok = KillTreeEx(pid, TRUE);
                } else {
                    DaemonLog(L"[DEBUG] Calling OpenProcess/PROCESS_TERMINATE for pid=%lu", pid);
                    HANDLE hProc2 = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                    if (hProc2) {
                        DaemonLog(L"[DEBUG] OpenProcess succeeded, calling TerminateProcess");
                        ok = TerminateProcess(hProc2, 1);
                        CloseHandle(hProc2);
                        DaemonLog(L"[DEBUG] TerminateProcess returned %d", ok);
                    } else {
                        DaemonLog(L"[DEBUG] OpenProcess failed, error=%lu", GetLastError());
                    }
                }
                if (ok) {
                    DaemonLog(L"Repeated kill: %ls", s->procs[i].name);
                    Sleep(500);
                    DeleteCachedFile(pid, s->procs[i].name);
                } else {
                    DaemonLog(L"[DEBUG] Repeated kill failed for %ls", s->procs[i].name);
                }
            }
        }
    }
}

static BOOL ProcessHasVisibleWindow(DWORD pid) {
    HWND hwnd = GetTopWindow(NULL);
    while (hwnd) {
        DWORD wpid = 0;
        GetWindowThreadProcessId(hwnd, &wpid);
        if (wpid == pid && IsWindowVisible(hwnd)) return TRUE;
        hwnd = GetNextWindow(hwnd, GW_HWNDNEXT);
    }
    return FALSE;
}

static DWORD FindProcessByName(const wchar_t* name) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(PROCESSENTRY32W);
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

static void ProtectDaemonProcesses(DaemonState* s) {
    DWORD wrapperPid = FindProcessByName(SERVICE_WRAPPER_EXE);
    if (wrapperPid != 0) {
        s->serviceWrapperPid = wrapperPid;
    }
}

void DaemonTick(DaemonState* s) {
    EnableDebugPrivilege();
    EnterCriticalSection(&g_cs);
    s->wasModifiedThisTick = FALSE;

    ProtectDaemonProcesses(s);

    DaemonLog(L"[TICK] before ExecuteProcRules");
    ExecuteProcRules(s);
    DaemonLog(L"[TICK] after ExecuteProcRules");
    
    DaemonLog(L"[TICK] before ExecuteSvcRepeated");
    ExecuteSvcRepeated(s);
    DaemonLog(L"[TICK] after ExecuteSvcRepeated");
    
    DaemonLog(L"[TICK] before ExecuteRegRepeated");
    ExecuteRegRepeated(s);
    DaemonLog(L"[TICK] after ExecuteRegRepeated");
    
    DaemonLog(L"[TICK] before ExecutePartRepeated");
    ExecutePartRepeated(s);
    DaemonLog(L"[TICK] after ExecutePartRepeated");
    
    DaemonLog(L"[TICK] before ExecutePartProtection");
    if (s->enablePartProtection) ExecutePartProtection(s);
    DaemonLog(L"[TICK] after ExecutePartProtection");
    
    DaemonLog(L"[TICK] before ExecuteRegProtection");
    if (s->enableRegProtection) ExecuteRegProtection(s);
    DaemonLog(L"[TICK] after ExecuteRegProtection");
    
    DaemonLog(L"[TICK] before ExecuteSysCriticalProtection");
    if (s->enableSysCriticalProtection) {
        DaemonLog(L"[TICK] before ExecuteSysRegProtection");
        ExecuteSysRegProtection(s);
        DaemonLog(L"[TICK] after ExecuteSysRegProtection");
        
        DaemonLog(L"[TICK] before ExecuteSysCriticalProtection");
        ExecuteSysCriticalProtection(s);
        DaemonLog(L"[TICK] after ExecuteSysCriticalProtection");
        
        DaemonLog(L"[TICK] before ExecuteDiskContentProtection");
        ExecuteDiskContentProtection(s);
        DaemonLog(L"[TICK] after ExecuteDiskContentProtection");
        
        DaemonLog(L"[TICK] before NetworkMonitorTick");
        NetworkMonitorTick(s);
        DaemonLog(L"[TICK] after NetworkMonitorTick");
    }
    DaemonLog(L"[TICK] after ExecuteSysCriticalProtection block");
    
    DaemonLog(L"[TICK] before ComputeCommonProcesses");
    if (!s->wasModifiedThisTick) {
        ComputeCommonProcesses(s);
    }
    DaemonLog(L"[TICK] after ComputeCommonProcesses");
    
    static DWORD lastProcScanTick = 0;
    DWORD now = GetTickCount();
    if ((now - lastProcScanTick) > 2000) {
        lastProcScanTick = now;
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = {0};
            pe.dwSize = sizeof(PROCESSENTRY32W);
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    if (pe.th32ProcessID != 0 && pe.th32ProcessID != 4 && pe.th32ProcessID != GetCurrentProcessId()) {
                        const wchar_t* procName = pe.szExeFile;
                    }
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
    }
    
    LeaveCriticalSection(&g_cs);

    /* Daily AI report: run once per calendar day */
    {
        SYSTEMTIME st; GetLocalTime(&st);
        int today = st.wYear * 10000 + st.wMonth * 100 + st.wDay;
        if (s->lastReportDay != today) {
            s->lastReportDay = today;
            GenerateDailyReport(s);
        }
    }
    
    ScoreCenterTick(&s->scoreCenter);
    StateMachineTick(&s->stateMachine);
    ResponseCenterProcessQueue(&s->responseCenter);
}

const wchar_t* DetectEventTypeToString(DetectEventType type) {
    switch (type) {
        case DETECT_EVENT_PROCESS_SPAWN: return L"process_spawn";
        case DETECT_EVENT_PROCESS_TERMINATE: return L"process_terminate";
        case DETECT_EVENT_REGISTRY_WRITE: return L"registry_write";
        case DETECT_EVENT_REGISTRY_DELETE: return L"registry_delete";
        case DETECT_EVENT_FILE_WRITE: return L"file_write";
        case DETECT_EVENT_FILE_DELETE: return L"file_delete";
        case DETECT_EVENT_DISK_HANDLE: return L"disk_handle";
        case DETECT_EVENT_INJECTION: return L"injection";
        case DETECT_EVENT_MBR_ACCESS: return L"mbr";
        case DETECT_EVENT_BOOT_CHANGE: return L"boot_change";
        case DETECT_EVENT_NETWORK: return L"network";
        case DETECT_EVENT_SELF_COPY: return L"self_copy";
        case DETECT_EVENT_MASS_FILE_MODIFY: return L"mass_file_modify";
        case DETECT_EVENT_VSS_DELETE: return L"vss_delete";
        case DETECT_EVENT_LOG_CLEAR: return L"log_clear";
        case DETECT_EVENT_DEFENDER_DISABLE: return L"defender_disable";
        case DETECT_EVENT_MINIMAL_IMPORTS: return L"minimal_imports";
        default: return L"unknown";
    }
}

void DispatchDetectEvent(DaemonState* s, const DetectEvent* event) {
    if (!s || !event) return;
    
    DaemonLog(L"[DISPATCH-DEBUG] Event received: type=%ls pid=%lu name=%ls eventPath=%ls isSigned=%d",
              DetectEventTypeToString(event->type), event->pid, event->processName, 
              event->eventPath, event->isSigned);
    
    if (IsSelfProcessName(event->processName)) {
        DaemonLog(L"[DISPATCH-DEBUG] Skipping self process: %ls", event->processName);
        return;
    }
    if (IsCriticalSystemProcess(event->processName)) {
        DaemonLog(L"[DISPATCH-DEBUG] Skipping critical system process: %ls", event->processName);
        return;
    }
    
    const wchar_t* eventType = DetectEventTypeToString(event->type);
    Rule matchedRule = {0};
    
    int score = RuleEngineEvaluate(&s->ruleEngine, event->pid, event->processName,
                                   event->imagePath, event->signer, event->isSigned,
                                   eventType, event->eventPath, &matchedRule);
    
    if (score > 0 || matchedRule.enabled) {
        DaemonLog(L"[RULE-MATCH] Event=%ls pid=%lu name=%ls rule=%ls score=%d", 
                  eventType, event->pid, event->processName, 
                  matchedRule.id[0] ? matchedRule.id : L"(none)", score);
        
        /* BUGFIX: Previously each event used GetTickCount64() as createTime,
         * producing a different hash key every time. Scores never accumulated.
         * Now we look up an existing entry by PID first and reuse its key. */
        uint64_t key = 0;
        ScoreEntry* existing = NULL;
        if (event->pid != 0) {
            existing = ScoreCenterGetByPid(&s->scoreCenter, event->pid);
        }
        if (existing) {
            key = existing->entryKey;
            DaemonLog(L"[SCORE-DEBUG] Reusing existing score entry for pid=%lu key=%llu", event->pid, key);
        } else {
            uint64_t createTime = GetTickCount64();
            key = ScoreCenterMakeKey(event->pid, createTime);
            DaemonLog(L"[SCORE-DEBUG] Creating new score entry for pid=%lu key=%llu", event->pid, key);
        }

        /* Ensure the entry exists before adding score */
        uint64_t createTimeForLookup = (key != 0) ? (key & 0xFFFFFFFFULL) : GetTickCount64();
        ScoreCenterGetOrCreate(&s->scoreCenter, event->pid, createTimeForLookup,
                               event->processName, event->imagePath);
        
        if (matchedRule.module == RULE_MODULE_STATIC) {
            ScoreCenterAddStaticScore(&s->scoreCenter, key, score, event->eventDetails);
        } else if (matchedRule.module == RULE_MODULE_BEHAVIOR) {
            ScoreCenterAddBehaviorScore(&s->scoreCenter, key, score, event->eventDetails);
        } else if (matchedRule.module == RULE_MODULE_KERNEL) {
            ScoreCenterAddKernelScore(&s->scoreCenter, key, score, event->eventDetails);
        }
        
        int totalScore = ScoreCenterGetTotalScore(&s->scoreCenter, key);
        int level = ScoreCenterGetLevelByScore(&s->scoreCenter, totalScore);
        
        DaemonLog(L"[SCORE] pid=%lu total=%d level=%s", 
                  event->pid, totalScore, ScoreCenterGetLevelName(level));
        
        StateMachineEntry* entry = StateMachineGetOrCreate(&s->stateMachine, event->pid, 
                                                           event->processName, event->imagePath);
        if (entry) {
            entry->scores.staticScore = 0;
            entry->scores.behaviorScore = 0;
            entry->scores.kernelScore = 0;
            entry->scores.aiScore = 0;
            ScoreCenterGetScoreBreakdown(&s->scoreCenter, key, 
                                        &entry->scores.staticScore,
                                        &entry->scores.behaviorScore,
                                        &entry->scores.kernelScore,
                                        &entry->scores.aiScore);
            entry->totalScore = totalScore;
            wcscpy(entry->lastEvidence, event->eventDetails);
            
            ProcessState newState = PROC_STATE_UNKNOWN;
            if (totalScore >= THRESHOLD_REMOVED) {
                newState = PROC_STATE_REMOVED;
            } else if (totalScore >= THRESHOLD_QUARANTINED) {
                newState = PROC_STATE_QUARANTINED;
            } else if (totalScore >= THRESHOLD_RESTRICTED) {
                newState = PROC_STATE_RESTRICTED;
            } else if (totalScore >= THRESHOLD_SUSPICIOUS) {
                newState = PROC_STATE_SUSPICIOUS;
            } else {
                newState = PROC_STATE_OBSERVED;
            }
            
            StateMachineTransition(entry, newState, event->eventDetails);
            
            ResponseAction action = RESPONSE_NONE;
            
            if (matchedRule.response[0]) {
                if (_wcsicmp(matchedRule.response, L"terminate") == 0) {
                    action = RESPONSE_REPEATED_KILL;
                    TerminateWatchdogGroup(s, event->pid, event->processName, event->imagePath);
                } else if (_wcsicmp(matchedRule.response, L"quarantine") == 0) {
                    action = RESPONSE_QUARANTINE;
                } else if (_wcsicmp(matchedRule.response, L"notify") == 0) {
                    action = RESPONSE_NOTIFY;
                } else if (_wcsicmp(matchedRule.response, L"observe") == 0) {
                    action = RESPONSE_OBSERVE;
                }
            }
            
            if (action == RESPONSE_NONE) {
                if (totalScore >= THRESHOLD_QUARANTINED && !event->isSigned) {
                    action = RESPONSE_REPEATED_KILL;
                    TerminateWatchdogGroup(s, event->pid, event->processName, event->imagePath);
                } else if (totalScore >= THRESHOLD_RESTRICTED) {
                    action = RESPONSE_NOTIFY;
                } else if (totalScore >= THRESHOLD_SUSPICIOUS) {
                    action = RESPONSE_OBSERVE;
                }
            }
            
            if (action != RESPONSE_NONE) {
                ResponseCenterQueueResponse(&s->responseCenter, event->pid, 
                                           event->processName, event->imagePath,
                                           action, event->eventDetails);
                DaemonLog(L"[RESPONSE] pid=%lu action=%ls score=%d rule=%ls", 
                          event->pid, ResponseCenterGetActionName(action), totalScore,
                          matchedRule.id[0] ? matchedRule.id : L"(none)");
            }
        }
    }
}

static void ResetAllScores(DaemonState* s) {
    if (!s) return;
    
    for (int i = 0; i < s->unsignedScoreCount; i++) {
        s->unsignedScores[i].score = 0.0f;
        s->unsignedScores[i].regWriteCount = 0;
        s->unsignedScores[i].regDeleteCount = 0;
        s->unsignedScores[i].sysRegDeleteCount = 0;
        s->unsignedScores[i].injectCount = 0;
        s->unsignedScores[i].selfCopyCount = 0;
        s->unsignedScores[i].lastUpdateTick = GetTickCount64();
    }
    
    for (int i = 0; i < s->signerScoreCount; i++) {
        s->signerScores[i].score = 0;
        s->signerScores[i].regWriteCount = 0;
        s->signerScores[i].installedAppCount = 0;
        s->signerScores[i].blockOtherCount = 0;
        s->signerScores[i].aiReputation = 0.0f;
        s->signerScores[i].lastUpdateTick = GetTickCount64();
    }
    
    DaemonLog(L"[SCORE] All scores reset");
}

static DWORD WINAPI AiTaskThreadProc(LPVOID param) {
    DaemonState* s = (DaemonState*)param;
    while (s->running) {
        ExecuteAiTasks(s);
        
        ULONGLONG now = GetTickCount64();
        if (s->scoreResetIntervalMs > 0 && now - s->lastScoreResetTick >= (ULONGLONG)s->scoreResetIntervalMs) {
            ResetAllScores(s);
            s->lastScoreResetTick = now;
        }
        
        Sleep(s->checkInterval ? s->checkInterval : 500);
    }
    return 0;
}

void DaemonStartAiTaskThread(DaemonState* s) {
    if (!s) return;
    s->running = TRUE;
    HANDLE hThread = CreateThread(NULL, 0, AiTaskThreadProc, s, 0, NULL);
    if (hThread) CloseHandle(hThread);
}

/* ======================== AI action pipe server ======================== */
static BOOL RemoveDirectoryRecursive(const wchar_t* path) {
    WIN32_FIND_DATAW fd;
    wchar_t search[MAX_PATH];
    swprintf(search, MAX_PATH, L"%ls\\*", path);
    HANDLE hFind = FindFirstFileW(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return RemoveDirectoryW(path);
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        wchar_t child[MAX_PATH];
        swprintf(child, MAX_PATH, L"%ls\\%ls", path, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            RemoveDirectoryRecursive(child);
        } else {
            SetFileAttributesW(child, FILE_ATTRIBUTE_NORMAL);
            DeleteFileW(child);
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
    SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);
    return RemoveDirectoryW(path);
}

static BOOL DeleteRegPathString(const wchar_t* path) {
    if (!path || !path[0]) return FALSE;
    HKEY hRoot = NULL;
    const wchar_t* subkey = NULL;
    if (_wcsnicmp(path, L"HKCU\\", 5) == 0) { hRoot = HKEY_CURRENT_USER; subkey = path + 5; }
    else if (_wcsnicmp(path, L"HKLM\\", 5) == 0) { hRoot = HKEY_LOCAL_MACHINE; subkey = path + 5; }
    else if (_wcsnicmp(path, L"HKEY_CURRENT_USER\\", 18) == 0) { hRoot = HKEY_CURRENT_USER; subkey = path + 18; }
    else if (_wcsnicmp(path, L"HKEY_LOCAL_MACHINE\\", 19) == 0) { hRoot = HKEY_LOCAL_MACHINE; subkey = path + 19; }
    else return FALSE;
    LONG rc = RegDeleteTreeW(hRoot, subkey);
    return (rc == ERROR_SUCCESS);
}

static BOOL CleanTargetPath(const wchar_t* target) {
    if (!target || !target[0]) return FALSE;

    /* Safety: never clean our own process image or installation directory */
    wchar_t selfPath[MAX_PATH];
    DWORD selfLen = GetModuleFileNameW(NULL, selfPath, MAX_PATH);
    if (selfLen > 0) {
        /* Extract directory prefix of our own executable */
        wchar_t* lastSlash = wcsrchr(selfPath, L'\\');
        if (lastSlash) {
            *lastSlash = L'\0';
            if (_wcsnicmp(target, selfPath, wcslen(selfPath)) == 0 ||
                _wcsicmp(target, lastSlash + 1) == 0) {
                DaemonLog(L"[SAFETY] refusing to clean own process path: %ls", target);
                return FALSE;
            }
        }
        /* Also block by known self process names regardless of path */
        const wchar_t* targetBase = wcsrchr(target, L'\\');
        if (targetBase) targetBase++;
        else targetBase = target;
        if (IsSelfProcessName(targetBase)) {
            DaemonLog(L"[SAFETY] refusing to clean own process name: %ls", target);
            return FALSE;
        }
    }

    /* Safety: never auto-clean a signed process or its installation directory */
    {
        wchar_t checkPath[MAX_PATH] = {0};
        if (wcschr(target, L'\\') || wcschr(target, L'/')) {
            wcsncpy(checkPath, target, MAX_PATH - 1);
            checkPath[MAX_PATH - 1] = L'\0';
        } else {
            DWORD targetPid = GetPidByName(target);
            if (targetPid) GetProcessImagePath(targetPid, checkPath, MAX_PATH);
        }
        if (checkPath[0]) {
            wchar_t targetSigner[256] = {0};
            if (CheckFileSignatureCached(checkPath, targetSigner, 256)) {
                DaemonLog(L"[SAFETY] refusing to auto-clean signed target: %ls signer=%ls", target, targetSigner);
                return FALSE;
            }
        }
    }

    /* Registry path */
    if (_wcsnicmp(target, L"HKCU\\", 5) == 0 ||
        _wcsnicmp(target, L"HKLM\\", 5) == 0 ||
        _wcsnicmp(target, L"HKEY_CURRENT_USER\\", 18) == 0 ||
        _wcsnicmp(target, L"HKEY_LOCAL_MACHINE\\", 19) == 0) {
        return DeleteRegPathString(target);
    }
    /* If it looks like a process name (no path separators), try killing it */
    if (wcschr(target, L'\\') == NULL && wcschr(target, L'/') == NULL) {
        return KillProcessByName(target, FALSE);
    }
    wchar_t path[MAX_PATH];
    wcsncpy(path, target, MAX_PATH - 1);
    path[MAX_PATH - 1] = L'\0';
    DWORD attr = GetFileAttributesW(path);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        return KillProcessByName(path, FALSE);
    }
    if (attr & FILE_ATTRIBUTE_DIRECTORY) {
        return RemoveDirectoryRecursive(path);
    }
    SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);
    return DeleteFileW(path);
}

static void ParseJsonStringValue(const char* json, const char* key, char* out, int outSz) {
    out[0] = 0;
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);
    const char* pb = strstr(json, pattern);
    if (!pb) {
        snprintf(pattern, sizeof(pattern), "\"%s\": \"", key);
        pb = strstr(json, pattern);
    }
    if (pb) {
        pb += strlen(pattern);
        int i = 0;
        while (*pb && *pb != '"' && i < outSz - 1) {
            if (*pb == '\\' && pb[1]) pb++;
            out[i++] = *pb++;
        }
        out[i] = 0;
    }
}

/* JSON helpers for pipe queries */
typedef struct {
    wchar_t name[256];
    wchar_t displayName[256];
    wchar_t path[512];
    DWORD status;
    DWORD startType;
    wchar_t statusStr[64];
    wchar_t startTypeStr[64];
} DaemonServiceEntry;

typedef struct {
    int diskNumber;
    wchar_t model[256];
    ULONGLONG sizeBytes;
    int tableType;
    int partitionCount;
} DaemonDiskInfo;

typedef struct {
    int diskNumber;
    int partitionNumber;
    wchar_t name[256];
    wchar_t location[512];
    wchar_t id[64];
    wchar_t fsType[64];
    wchar_t driveLetter[16];
    ULONGLONG sizeBytes;
    BOOL isBootable;
} DaemonPartitionEntry;

static void PipeJsonEscapeAppend(const wchar_t* in, char* out, int outSz) {
    int j = (int)strlen(out);
    if (!in) in = L"";
    char bufA[1024] = "";
    WideCharToMultiByte(CP_UTF8, 0, in, -1, bufA, sizeof(bufA), NULL, NULL);
    for (int i = 0; bufA[i] && j < outSz - 8; i++) {
        unsigned char c = (unsigned char)bufA[i];
        if (c == '"' || c == '\\') {
            out[j++] = '\\';
            out[j++] = c;
        } else if (c == '\n') { out[j++] = '\\'; out[j++] = 'n'; }
        else if (c == '\r') { out[j++] = '\\'; out[j++] = 'r'; }
        else if (c == '\t') { out[j++] = '\\'; out[j++] = 't'; }
        else if (c < 0x20) {
            j += snprintf(out + j, outSz - j, "\\u%04x", c);
        } else {
            out[j++] = c;
        }
    }
    out[j] = 0;
}

static void PipeJsonEscapeString(const wchar_t* in, char* out, int outSz) {
    out[0] = 0;
    PipeJsonEscapeAppend(in, out, outSz);
}

static void BuildServiceListJson(char* out, int outSz) {
    out[0] = 0;
    if (!g_svcGetAll) {
        snprintf(out, outSz, "{\"ok\":false,\"msg\":\"service_manager not loaded\"}");
        return;
    }
    DaemonServiceEntry* entries = NULL;
    int count = g_svcGetAll((void**)&entries);
    if (count <= 0 || !entries) {
        snprintf(out, outSz, "{\"ok\":true,\"services\":[]}");
        return;
    }
    /* Build into heap to avoid huge stack buffer */
    char* buf = (char*)malloc(2 * 1024 * 1024);
    if (!buf) {
        snprintf(out, outSz, "{\"ok\":false,\"msg\":\"memory\"}");
        free(entries);
        return;
    }
    snprintf(buf, 2 * 1024 * 1024, "{\"ok\":true,\"services\":[");
    int first = 1;
    for (int i = 0; i < count && i < 5000; i++) {
        DaemonServiceEntry* e = &entries[i];
        char nameA[512] = "", displayA[512] = "", pathA[700] = "", statusA[130] = "", startA[130] = "";
        PipeJsonEscapeString(e->name, nameA, sizeof(nameA));
        PipeJsonEscapeString(e->displayName, displayA, sizeof(displayA));
        PipeJsonEscapeString(e->path, pathA, sizeof(pathA));
        PipeJsonEscapeString(e->statusStr, statusA, sizeof(statusA));
        PipeJsonEscapeString(e->startTypeStr, startA, sizeof(startA));
        char item[2048];
        snprintf(item, sizeof(item),
                 "%s{\"name\":\"%s\",\"display\":\"%s\",\"status\":\"%s\",\"start\":\"%s\",\"path\":\"%s\"}",
                 first ? "" : ",", nameA, displayA, statusA, startA, pathA);
        if (strlen(buf) + strlen(item) + 4 >= (size_t)(2 * 1024 * 1024)) break;
        strcat(buf, item);
        first = 0;
    }
    strcat(buf, "]}");
    snprintf(out, outSz, "%s", buf);
    free(buf);
    free(entries);
}

static void BuildDiskListJson(char* out, int outSz) {
    out[0] = 0;
    if (!g_partGetDisks) {
        snprintf(out, outSz, "{\"ok\":false,\"msg\":\"partition_manager not loaded\"}");
        return;
    }
    DaemonDiskInfo* disks = NULL;
    int count = g_partGetDisks((void**)&disks);
    if (count <= 0 || !disks) {
        snprintf(out, outSz, "{\"ok\":true,\"disks\":[]}");
        return;
    }
    char* buf = (char*)malloc(256 * 1024);
    if (!buf) {
        snprintf(out, outSz, "{\"ok\":false,\"msg\":\"memory\"}");
        free(disks);
        return;
    }
    snprintf(buf, 256 * 1024, "{\"ok\":true,\"disks\":[");
    int first = 1;
    for (int i = 0; i < count && i < 64; i++) {
        DaemonDiskInfo* d = &disks[i];
        char modelA[512] = "";
        PipeJsonEscapeString(d->model, modelA, sizeof(modelA));
        char item[1024];
        snprintf(item, sizeof(item),
                 "%s{\"disk\":%d,\"model\":\"%s\",\"size\":%llu,\"type\":%d,\"partitions\":%d}",
                 first ? "" : ",", d->diskNumber, modelA, d->sizeBytes, d->tableType, d->partitionCount);
        if (strlen(buf) + strlen(item) + 4 >= 256 * 1024) break;
        strcat(buf, item);
        first = 0;
    }
    strcat(buf, "]}");
    snprintf(out, outSz, "%s", buf);
    free(buf);
    free(disks);
}

static void BuildPartitionListJson(int diskNumber, char* out, int outSz) {
    out[0] = 0;
    if (!g_partGetParts) {
        snprintf(out, outSz, "{\"ok\":false,\"msg\":\"partition_manager not loaded\"}");
        return;
    }
    DaemonPartitionEntry* parts = NULL;
    int count = g_partGetParts(diskNumber, (void**)&parts);
    if (count <= 0 || !parts) {
        snprintf(out, outSz, "{\"ok\":true,\"partitions\":[]}");
        return;
    }
    char* buf = (char*)malloc(512 * 1024);
    if (!buf) {
        snprintf(out, outSz, "{\"ok\":false,\"msg\":\"memory\"}");
        free(parts);
        return;
    }
    snprintf(buf, 512 * 1024, "{\"ok\":true,\"partitions\":[");
    int first = 1;
    for (int i = 0; i < count && i < 256; i++) {
        DaemonPartitionEntry* p = &parts[i];
        char nameA[512] = "", locA[700] = "", idA[130] = "", fsA[130] = "", letterA[32] = "";
        PipeJsonEscapeString(p->name, nameA, sizeof(nameA));
        PipeJsonEscapeString(p->location, locA, sizeof(locA));
        PipeJsonEscapeString(p->id, idA, sizeof(idA));
        PipeJsonEscapeString(p->fsType, fsA, sizeof(fsA));
        PipeJsonEscapeString(p->driveLetter, letterA, sizeof(letterA));
        char item[2048];
        snprintf(item, sizeof(item),
                 "%s{\"disk\":%d,\"partition\":%d,\"name\":\"%s\",\"location\":\"%s\",\"id\":\"%s\",\"fs\":\"%s\",\"letter\":\"%s\",\"size\":%llu,\"bootable\":%s}",
                 first ? "" : ",", p->diskNumber, p->partitionNumber, nameA, locA, idA, fsA, letterA,
                 p->sizeBytes, p->isBootable ? "true" : "false");
        if (strlen(buf) + strlen(item) + 4 >= 512 * 1024) break;
        strcat(buf, item);
        first = 0;
    }
    strcat(buf, "]}");
    snprintf(out, outSz, "%s", buf);
    free(buf);
    free(parts);
}

static void BuildBootSectorJson(int diskNumber, char* out, int outSz) {
    out[0] = 0;
    if (diskNumber < 0) {
        snprintf(out, outSz, "{\"ok\":false,\"msg\":\"no disk\"}");
        return;
    }
    /* Read first 8192 bytes of disk */
    wchar_t physPath[64];
    swprintf(physPath, 64, L"\\\\.\\PhysicalDrive%d", diskNumber);
    HANDLE hDisk = CreateFileW(physPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk == INVALID_HANDLE_VALUE) {
        snprintf(out, outSz, "{\"ok\":false,\"msg\":\"cannot open disk %d\"}", diskNumber);
        return;
    }
    BYTE boot[8192] = {0};
    DWORD read = 0;
    BOOL ok = ReadFile(hDisk, boot, sizeof(boot), &read, NULL);
    CloseHandle(hDisk);
    if (!ok || read == 0) {
        snprintf(out, outSz, "{\"ok\":false,\"msg\":\"read failed\"}");
        return;
    }
    /* Convert to hex text */
    char hex[sizeof(boot) * 3 + 16] = "";
    int pos = 0;
    for (DWORD i = 0; i < read && pos < sizeof(hex) - 6; i++) {
        pos += snprintf(hex + pos, sizeof(hex) - pos, "%02X ", boot[i]);
        if ((i + 1) % 16 == 0) pos += snprintf(hex + pos, sizeof(hex) - pos, "\n");
    }
    char escaped[sizeof(hex) * 2] = "";
    int j = 0;
    for (int i = 0; hex[i] && j < sizeof(escaped) - 4; i++) {
        char c = hex[i];
        if (c == '"' || c == '\\') { escaped[j++] = '\\'; escaped[j++] = c; }
        else if (c == '\n') { escaped[j++] = '\\'; escaped[j++] = 'n'; }
        else escaped[j++] = c;
    }
    escaped[j] = 0;
    snprintf(out, outSz, "{\"ok\":true,\"disk\":%d,\"hex\":\"%s\"}", diskNumber, escaped);
}

static BOOL SampleProcessViaObserverDll(DWORD pid, double* cpu, double* gpu, double* mem, double* vram) {
    static HMODULE g_hObserverDll = NULL;
    static FnObserverGetStatsEx g_fnObserverGetStatsEx = NULL;
    if (!g_hObserverDll) {
        wchar_t dllPath[MAX_PATH] = {0};
        GetModuleFileNameW(NULL, dllPath, MAX_PATH);
        wchar_t* p = wcsrchr(dllPath, L'\\');
        if (p) *p = L'\0';
        wcscat(dllPath, L"\\Observe\\observer.dll");
        g_hObserverDll = LoadLibraryW(dllPath);
        if (!g_hObserverDll) {
            DaemonLog(L"SampleProcess: failed to load observer.dll err=%lu", GetLastError());
            return FALSE;
        }
        g_fnObserverGetStatsEx = (FnObserverGetStatsEx)GetProcAddress(g_hObserverDll, "GetProcessStatsEx");
        if (!g_fnObserverGetStatsEx) {
            DaemonLog(L"SampleProcess: GetProcessStatsEx not found");
            FreeLibrary(g_hObserverDll);
            g_hObserverDll = NULL;
            return FALSE;
        }
    }
    ObserverStatsEx stats = {0};
    BOOL ok = g_fnObserverGetStatsEx(pid, &stats, sizeof(stats));
    if (ok) {
        *cpu = stats.current.cpuPercent;
        *gpu = stats.current.gpuPercent;
        *mem = stats.current.memMB;
        *vram = stats.current.vramMB;
    }
    return ok;
}

static DWORD WINAPI AiActionPipeThread(LPVOID lpParam) {
    DaemonState* s = (DaemonState*)lpParam;
    while (TRUE) {
        HANDLE hPipe = CreateNamedPipeW(L"\\\\.\\pipe\\GuardianAIAction",
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            4096, 4096, 0, NULL);
        if (hPipe == INVALID_HANDLE_VALUE) { Sleep(1000); continue; }
        BOOL connected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!connected) { CloseHandle(hPipe); continue; }

        char buf[65536] = "";
        DWORD read = 0;
        char resp[AIC_MAX_RESP * 2 + 256] = "{\"ok\":false,\"msg\":\"unknown command\"}";
        if (ReadFile(hPipe, buf, sizeof(buf) - 1, &read, NULL) && read > 0) {
            buf[read] = 0;
            if (strstr(buf, "\"cmd\":\"clean_path\"")) {
                const char* pb = strstr(buf, "\"path\":\"");
                if (pb) {
                    pb += 8;
                    char pathA[MAX_PATH] = "";
                    int i = 0;
                    while (*pb && *pb != '"' && i < MAX_PATH - 1) {
                        if (*pb == '\\' && pb[1]) pb++;
                        pathA[i++] = *pb++;
                    }
                    pathA[i] = 0;
                    wchar_t pathW[MAX_PATH];
                    MultiByteToWideChar(CP_UTF8, 0, pathA, -1, pathW, MAX_PATH);
                    DaemonLog(L"AI action: clean_path %ls", pathW);
                    EnterCriticalSection(&g_cs);
                    BOOL ok = CleanTargetPath(pathW);
                    LeaveCriticalSection(&g_cs);
                    snprintf(resp, sizeof(resp), "{\"ok\":%s,\"msg\":\"%s\"}",
                             ok ? "true" : "false", ok ? "clean done" : "clean failed");
                } else {
                    snprintf(resp, sizeof(resp), "{\"ok\":false,\"msg\":\"missing path\"}");
                }
            } else if (strstr(buf, "\"cmd\":\"kill_pid\"")) {
                DWORD pid = 0;
                const char* pp = strstr(buf, "\"pid\":");
                if (pp) pid = (DWORD)atoi(pp + 6);
                BOOL ok = FALSE;
                if (pid && pid != 4) {
                    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                    if (hProc) { ok = SafeTerminateProcess(hProc, NULL); CloseHandle(hProc); }
                }
                snprintf(resp, sizeof(resp), "{\"ok\":%s}", ok ? "true" : "false");
            } else if (strstr(buf, "\"cmd\":\"repeated_kill\"") || strstr(buf, "\"cmd\":\"protect\"")) {
                char nameA[260] = "";
                ParseJsonStringValue(buf, "name", nameA, sizeof(nameA));
                BOOL isRepeated = (strstr(buf, "\"cmd\":\"repeated_kill\"") != NULL);
                BOOL isTree = (strstr(buf, "\"tree\":true") != NULL) || (strstr(buf, "\"tree\": true") != NULL);
                BOOL ok = FALSE;
                if (nameA[0] && s) {
                    EnterCriticalSection(&g_cs);
                    if (s->procCount < MAX_PROC) {
                        ProtectedEntry* e = &s->procs[s->procCount++];
                        ZeroMemory(e, sizeof(*e));
                        MultiByteToWideChar(CP_UTF8, 0, nameA, -1, e->name, 260);
                        e->isRepeated = isRepeated;
                        e->isTree = isTree;
                        SaveProcs(s);
                        ok = TRUE;
                    }
                    LeaveCriticalSection(&g_cs);
                }
                snprintf(resp, sizeof(resp), "{\"ok\":%s}", ok ? "true" : "false");
            } else if (strstr(buf, "\"cmd\":\"stop_repeated\"") || strstr(buf, "\"cmd\":\"unprotect\"")) {
                char nameA[260] = "";
                ParseJsonStringValue(buf, "name", nameA, sizeof(nameA));
                BOOL ok = FALSE;
                if (nameA[0] && s) {
                    EnterCriticalSection(&g_cs);
                    wchar_t nameW[260];
                    MultiByteToWideChar(CP_UTF8, 0, nameA, -1, nameW, 260);
                    for (int i = 0; i < s->procCount; i++) {
                        if (_wcsicmp(s->procs[i].name, nameW) == 0) {
                            memmove(&s->procs[i], &s->procs[i + 1], (s->procCount - i - 1) * sizeof(ProtectedEntry));
                            s->procCount--;
                            SaveProcs(s);
                            ok = TRUE;
                            break;
                        }
                    }
                    LeaveCriticalSection(&g_cs);
                }
                snprintf(resp, sizeof(resp), "{\"ok\":%s}", ok ? "true" : "false");
            } else if (strstr(buf, "\"cmd\":\"query_image_path\"")) {
                DWORD pid = 0;
                const char* pp = strstr(buf, "\"pid\":");
                if (pp) pid = (DWORD)atoi(pp + 6);
                wchar_t pathW[MAX_PATH] = L"";
                BOOL ok = FALSE;
                if (pid && pid != 4) {
                    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                    if (hProc) {
                        DWORD size = MAX_PATH;
                        ok = QueryFullProcessImageNameW(hProc, 0, pathW, &size);
                        CloseHandle(hProc);
                    }
                }
                char pathA[MAX_PATH * 4] = "";
                WideCharToMultiByte(CP_UTF8, 0, pathW, -1, pathA, sizeof(pathA), NULL, NULL);
                /* JSON escape backslashes */
                char escaped[MAX_PATH * 4] = "";
                int j = 0;
                for (int i = 0; pathA[i] && j < sizeof(escaped) - 2; i++) {
                    if (pathA[i] == '\\' || pathA[i] == '"') escaped[j++] = '\\';
                    escaped[j++] = pathA[i];
                }
                escaped[j] = 0;
                snprintf(resp, sizeof(resp), "{\"ok\":%s,\"path\":\"%s\"}", ok ? "true" : "false", escaped);
            } else if (strstr(buf, "\"cmd\":\"sample_process\"")) {
                DWORD pid = 0;
                const char* pp = strstr(buf, "\"pid\":");
                if (pp) pid = (DWORD)atoi(pp + 6);
                double cpu = 0.0, gpu = 0.0, mem = 0.0, vram = 0.0;
                BOOL ok = FALSE;
                if (pid && pid != 4) {
                    ok = SampleProcessViaObserverDll(pid, &cpu, &gpu, &mem, &vram);
                }
                snprintf(resp, sizeof(resp), "{\"ok\":%s,\"cpu\":%.4f,\"gpu\":%.4f,\"mem\":%.4f,\"vram\":%.4f}",
                         ok ? "true" : "false", cpu, gpu, mem, vram);
            } else if (strstr(buf, "\"cmd\":\"ai_ask\"")) {
                char systemPrompt[4096] = "";
                char userPrompt[4096] = "";
                char apiKey[512] = "";
                ParseJsonStringValue(buf, "systemPrompt", systemPrompt, sizeof(systemPrompt));
                ParseJsonStringValue(buf, "userPrompt", userPrompt, sizeof(userPrompt));
                ParseJsonStringValue(buf, "apiKey", apiKey, sizeof(apiKey));
                if (!apiKey[0]) {
                    LoadApiKey(apiKey, sizeof(apiKey));
                }
                float temperature = 0.7f;
                int maxTokens = 32768;
                const char* tp = strstr(buf, "\"temperature\":");
                if (tp) temperature = (float)atof(tp + 15);
                const char* mp = strstr(buf, "\"maxTokens\":");
                if (mp) maxTokens = atoi(mp + 12);
                DaemonLog(L"[AI_ASK] key=%ls userLen=%d sysLen=%d temp=%.2f max=%d",
                          apiKey[0] ? L"present" : L"missing",
                          (int)strlen(userPrompt), (int)strlen(systemPrompt),
                          temperature, maxTokens);
                AiResult result = {0};
                BOOL ok = FALSE;
                const char* src = NULL;
                if (!apiKey[0]) {
                    src = "api key not loaded";
                } else if (!userPrompt[0]) {
                    src = "user prompt empty";
                } else {
                    int rc = AskAi(apiKey, systemPrompt, userPrompt, temperature, maxTokens, &result);
                    ok = (rc == 0 && result.httpStatus == 200);
                    if (!ok) {
                        if (result.errMsg[0]) {
                            src = result.errMsg;
                        } else if (rc != 0) {
                            src = "ai_client returned error";
                        } else {
                            src = "ai request failed";
                        }
                    } else {
                        src = result.content;
                    }
                }
                char escaped[AIC_MAX_RESP * 2] = "";
                int j = 0;
                for (int i = 0; src[i] && j < sizeof(escaped) - 6; i++) {
                    if (src[i] == '\\' || src[i] == '"') escaped[j++] = '\\';
                    else if (src[i] == '\n') { escaped[j++] = '\\'; escaped[j++] = 'n'; continue; }
                    else if (src[i] == '\r') continue;
                    escaped[j++] = src[i];
                }
                escaped[j] = 0;
                snprintf(resp, sizeof(resp), "{\"ok\":%s,\"httpStatus\":%d,\"content\":\"%s\"}",
                         ok ? "true" : "false", result.httpStatus, escaped);
            } else if (strstr(buf, "\"cmd\":\"clean_residue\"")) {
                /* Clean known PUP residue: numeric extension keys .012..050 under Classes */
                int deleted = 0, failed = 0;
                EnterCriticalSection(&g_cs);
                HKEY roots[2] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };
                const wchar_t* basePaths[2] = { L"Software\\Classes", L"Software\\Classes" };
                for (int r = 0; r < 2; r++) {
                    for (int i = 12; i <= 50; i++) {
                        wchar_t subkey[64];
                        swprintf(subkey, 64, L"%ls\\.%03d", basePaths[r], i);
                        LONG rc = RegDeleteTreeW(roots[r], subkey);
                        if (rc == ERROR_SUCCESS) {
                            deleted++;
                            DaemonLog(L"[CLEAN-RESIDUE] deleted %ls", subkey);
                        } else if (rc != ERROR_FILE_NOT_FOUND) {
                            failed++;
                        }
                    }
                }
                LeaveCriticalSection(&g_cs);
                snprintf(resp, sizeof(resp), "{\"ok\":%s,\"deleted\":%d,\"failed\":%d}",
                         failed == 0 ? "true" : "false", deleted, failed);
            } else if (strstr(buf, "\"cmd\":\"list_services\"")) {
                char* svcResp = (char*)malloc(2 * 1024 * 1024);
                if (svcResp) {
                    BuildServiceListJson(svcResp, 2 * 1024 * 1024);
                    DWORD wrote = 0;
                    WriteFile(hPipe, svcResp, (DWORD)strlen(svcResp), &wrote, NULL);
                    FlushFileBuffers(hPipe);
                    DisconnectNamedPipe(hPipe);
                    CloseHandle(hPipe);
                    free(svcResp);
                    continue;
                }
                snprintf(resp, sizeof(resp), "{\"ok\":false,\"msg\":\"memory\"}");
            } else if (strstr(buf, "\"cmd\":\"list_disks\"")) {
                char* diskResp = (char*)malloc(256 * 1024);
                if (diskResp) {
                    BuildDiskListJson(diskResp, 256 * 1024);
                    DWORD wrote = 0;
                    WriteFile(hPipe, diskResp, (DWORD)strlen(diskResp), &wrote, NULL);
                    FlushFileBuffers(hPipe);
                    DisconnectNamedPipe(hPipe);
                    CloseHandle(hPipe);
                    free(diskResp);
                    continue;
                }
                snprintf(resp, sizeof(resp), "{\"ok\":false,\"msg\":\"memory\"}");
            } else if (strstr(buf, "\"cmd\":\"list_partitions\"")) {
                const char* pp = strstr(buf, "\"disk\":");
                int disk = pp ? atoi(pp + 7) : -1;
                char* partResp = (char*)malloc(512 * 1024);
                if (partResp) {
                    BuildPartitionListJson(disk, partResp, 512 * 1024);
                    DWORD wrote = 0;
                    WriteFile(hPipe, partResp, (DWORD)strlen(partResp), &wrote, NULL);
                    FlushFileBuffers(hPipe);
                    DisconnectNamedPipe(hPipe);
                    CloseHandle(hPipe);
                    free(partResp);
                    continue;
                }
                snprintf(resp, sizeof(resp), "{\"ok\":false,\"msg\":\"memory\"}");
            } else if (strstr(buf, "\"cmd\":\"read_boot_sector\"")) {
                const char* pp = strstr(buf, "\"disk\":");
                int disk = pp ? atoi(pp + 7) : -1;
                char* bootResp = (char*)malloc(64 * 1024);
                if (bootResp) {
                    BuildBootSectorJson(disk, bootResp, 64 * 1024);
                    DWORD wrote = 0;
                    WriteFile(hPipe, bootResp, (DWORD)strlen(bootResp), &wrote, NULL);
                    FlushFileBuffers(hPipe);
                    DisconnectNamedPipe(hPipe);
                    CloseHandle(hPipe);
                    free(bootResp);
                    continue;
                }
                snprintf(resp, sizeof(resp), "{\"ok\":false,\"msg\":\"memory\"}");
            } else if (strstr(buf, "\"cmd\":\"service_stop\"")) {
                char nameA[260] = "";
                ParseJsonStringValue(buf, "name", nameA, sizeof(nameA));
                BOOL ok = FALSE;
                if (nameA[0] && g_svcStop) {
                    wchar_t nameW[260];
                    MultiByteToWideChar(CP_UTF8, 0, nameA, -1, nameW, 260);
                    ok = g_svcStop(nameW);
                }
                snprintf(resp, sizeof(resp), "{\"ok\":%s}", ok ? "true" : "false");
            } else if (strstr(buf, "\"cmd\":\"service_delete\"")) {
                char nameA[260] = "";
                ParseJsonStringValue(buf, "name", nameA, sizeof(nameA));
                BOOL ok = FALSE;
                if (nameA[0] && g_svcDelete) {
                    wchar_t nameW[260];
                    MultiByteToWideChar(CP_UTF8, 0, nameA, -1, nameW, 260);
                    ok = g_svcDelete(nameW);
                }
                snprintf(resp, sizeof(resp), "{\"ok\":%s}", ok ? "true" : "false");
            } else if (strstr(buf, "\"cmd\":\"service_repeated_add\"")) {
                char nameA[260] = "";
                ParseJsonStringValue(buf, "name", nameA, sizeof(nameA));
                BOOL ok = FALSE;
                if (nameA[0] && g_svcAddRepeated) {
                    wchar_t nameW[260];
                    MultiByteToWideChar(CP_UTF8, 0, nameA, -1, nameW, 260);
                    g_svcAddRepeated(nameW);
                    ok = TRUE;
                }
                snprintf(resp, sizeof(resp), "{\"ok\":%s}", ok ? "true" : "false");
            } else if (strstr(buf, "\"cmd\":\"service_repeated_remove\"")) {
                char nameA[260] = "";
                ParseJsonStringValue(buf, "name", nameA, sizeof(nameA));
                BOOL ok = FALSE;
                if (nameA[0] && g_svcRemoveRepeated) {
                    wchar_t nameW[260];
                    MultiByteToWideChar(CP_UTF8, 0, nameA, -1, nameW, 260);
                    g_svcRemoveRepeated(nameW);
                    ok = TRUE;
                }
                snprintf(resp, sizeof(resp), "{\"ok\":%s}", ok ? "true" : "false");
            } else if (strstr(buf, "\"cmd\":\"delete_partition\"")) {
                const char* pd = strstr(buf, "\"disk\":");
                const char* pp = strstr(buf, "\"partition\":");
                int disk = pd ? atoi(pd + 7) : -1;
                int part = pp ? atoi(pp + 12) : -1;
                BOOL ok = FALSE;
                if (disk >= 0 && part >= 0 && g_partDelete) {
                    ok = g_partDelete(disk, part);
                }
                snprintf(resp, sizeof(resp), "{\"ok\":%s}", ok ? "true" : "false");
            } else if (strstr(buf, "\"cmd\":\"partition_repeated_add\"")) {
                const char* pd = strstr(buf, "\"disk\":");
                const char* pp = strstr(buf, "\"partition\":");
                int disk = pd ? atoi(pd + 7) : -1;
                int part = pp ? atoi(pp + 12) : -1;
                BOOL ok = FALSE;
                if (disk >= 0 && part >= 0 && g_partAddRepeated) {
                    g_partAddRepeated(disk, part, L"");
                    ok = TRUE;
                }
                snprintf(resp, sizeof(resp), "{\"ok\":%s}", ok ? "true" : "false");
            } else if (strstr(buf, "\"cmd\":\"partition_repeated_remove\"")) {
                const char* pd = strstr(buf, "\"disk\":");
                const char* pp = strstr(buf, "\"partition\":");
                int disk = pd ? atoi(pd + 7) : -1;
                int part = pp ? atoi(pp + 12) : -1;
                BOOL ok = FALSE;
                if (disk >= 0 && part >= 0 && g_partRemoveRepeated) {
                    g_partRemoveRepeated(disk, part);
                    ok = TRUE;
                }
                snprintf(resp, sizeof(resp), "{\"ok\":%s}", ok ? "true" : "false");
            }
        }
        DWORD wrote = 0;
        WriteFile(hPipe, resp, (DWORD)strlen(resp), &wrote, NULL);
        FlushFileBuffers(hPipe);
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
    return 0;
}

void StartAiActionPipeServer(DaemonState* s) {
    CreateThread(NULL, 0, AiActionPipeThread, s, 0, NULL);
}

/* ======================== ETW real-time registry monitor ======================== */

static EtwMonitor g_etwMonitor;

static BOOL IsProtectedSysRegPath(DaemonState* s, const wchar_t* fullPath) {
    for (int i = 0; i < s->sysRegProtCount; i++) {
        size_t len = wcslen(s->sysRegProt[i].fullPath);
        if (len == 0) continue;
        if (_wcsnicmp(fullPath, s->sysRegProt[i].fullPath, len) == 0) {
            if (fullPath[len] == L'\\' || fullPath[len] == L'\0') return TRUE;
        }
    }
    return FALSE;
}

static BOOL IsProtectedRegPath(DaemonState* s, const wchar_t* fullPath) {
    for (int i = 0; i < s->regProtCount; i++) {
        size_t len = wcslen(s->regProt[i].fullPath);
        if (len == 0) continue;
        if (_wcsnicmp(fullPath, s->regProt[i].fullPath, len) == 0) {
            if (fullPath[len] == L'\\' || fullPath[len] == L'\0') return TRUE;
        }
    }
    return FALSE;
}

static BOOL IsBrowserHijackRegPath(const wchar_t* fullPath) {
    if (!fullPath || !fullPath[0]) return FALSE;
    static const wchar_t* patterns[] = {
        L"Start Page", L"Default_Page_URL", L"Search Page", L"Search Bar",
        L"SearchProvider", L"DefaultSearchProvider", L"SearchURL",
        L"Homepage", L"Home Page", L"StartPage",
        L"\\Google\\Chrome", L"\\Policies\\Google\\Chrome",
        L"\\Microsoft\\Edge", L"\\Mozilla\\Firefox", L"\\Microsoft\\Internet Explorer\\Main",
        L"\\Software\\360", L"\\Software\\Qihoo", L"\\Software\\Qihu",
        NULL
    };
    for (int i = 0; patterns[i]; i++) {
        if (wcsstr(fullPath, patterns[i])) return TRUE;
    }
    return FALSE;
}

static int RegPathThreatScore(const wchar_t* fullPath) {
    if (!fullPath || !fullPath[0]) return 0;
    int score = 0;

    BOOL fromHKCR = (_wcsnicmp(fullPath, L"HKEY_CLASSES_ROOT\\", 19) == 0);
    if (fromHKCR) score += 5;

    if (wcsstr(fullPath, L"Start Page") ||
        wcsstr(fullPath, L"Default_Page_URL") ||
        wcsstr(fullPath, L"Search Page") ||
        wcsstr(fullPath, L"SearchProvider") ||
        wcsstr(fullPath, L"DefaultSearchProvider") ||
        wcsstr(fullPath, L"SearchURL") ||
        wcsstr(fullPath, L"Homepage") ||
        wcsstr(fullPath, L"StartPage")) {
        score += 45;
    }

    if (wcsstr(fullPath, L"\\Run\\") ||
        wcsstr(fullPath, L"\\RunOnce\\") ||
        wcsstr(fullPath, L"\\RunOnceEx\\") ||
        wcsstr(fullPath, L"\\RunServices\\") ||
        wcsstr(fullPath, L"\\RunServicesOnce\\") ||
        wcsstr(fullPath, L"\\Startup\\") ||
        wcsstr(fullPath, L"\\Windows\\CurrentVersion\\Run")) {
        score += 60;
    }

    if (wcsstr(fullPath, L"\\Services\\") ||
        wcsstr(fullPath, L"\\Service\\")) {
        score += 10;
    }

    if (wcsstr(fullPath, L"\\Classes\\") ||
        wcsstr(fullPath, L"\\shell\\") ||
        wcsstr(fullPath, L"\\command\\")) {
        score += 10;
    }

    if (wcsstr(fullPath, L"\\Microsoft\\Windows Defender") ||
        wcsstr(fullPath, L"\\Windows\\CurrentVersion\\Uninstall") ||
        wcsstr(fullPath, L"\\Policies\\Microsoft\\Windows\\Safer\\") ||
        wcsstr(fullPath, L"\\SecurityProviders")) {
        score += 30;
    }

    if (wcsstr(fullPath, L"\\Windows Defender\\Exclusions") ||
        wcsstr(fullPath, L"\\Windows Defender\\Exclusions\\")) {
        score += 50;
    }

    if (wcsstr(fullPath, L"\\DeviceGuard") ||
        wcsstr(fullPath, L"\\Control\\Lsa") ||
        wcsstr(fullPath, L"\\Policies\\System")) {
        score += 35;
    }

    if (wcsstr(fullPath, L"\\Winlogon") ||
        wcsstr(fullPath, L"\\Image File Execution Options") ||
        wcsstr(fullPath, L"\\Appinit_Dlls")) {
        score += 35;
    }

    if (wcsstr(fullPath, L"\\Lsa\\Notification Packages") ||
        wcsstr(fullPath, L"\\Lsa\\Security Packages")) {
        score += 45;
    }

    if (wcsstr(fullPath, L"\\Session Manager\\BootExecute") ||
        wcsstr(fullPath, L"\\Session Manager\\Execute") ||
        wcsstr(fullPath, L"\\Session Manager\\SetupExecute")) {
        score += 40;
    }

    if (wcsstr(fullPath, L"\\Schedule\\TaskCache")) {
        score += 15;
    }

    if (wcsstr(fullPath, L"\\Microsoft\\WBEM") ||
        wcsstr(fullPath, L"\\Microsoft\\Windows\\CurrentVersion\\BITS")) {
        score += 15;
    }

    if (wcsstr(fullPath, L"\\Internet Settings")) {
        score += 10;
    }

    if (wcsstr(fullPath, L"\\Services\\EventLog") ||
        wcsstr(fullPath, L"\\Policies\\Microsoft\\Windows\\EventLog") ||
        wcsstr(fullPath, L"\\Policies\\System\\Audit")) {
        score += 30;
    }

    if (wcsstr(fullPath, L"\\Software\\360") ||
        wcsstr(fullPath, L"\\Software\\Qihoo") ||
        wcsstr(fullPath, L"\\Software\\Qihu") ||
        wcsstr(fullPath, L"\\Software\\2345") ||
        wcsstr(fullPath, L"\\Software\\Kingsoft") ||
        wcsstr(fullPath, L"\\Software\\Baidu") ||
        wcsstr(fullPath, L"\\Software\\Tencent\\QQPC")) {
        score += 15;
    }

    return score;
}

static void GetParentProcessInfo(DWORD pid, DWORD* parentPid, wchar_t* parentName, DWORD nameSz) {
    if (parentPid) *parentPid = 0;
    if (parentName && nameSz) parentName[0] = L'\0';
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = {0}; pe.dwSize = sizeof(pe);
    DWORD ppid = 0;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                ppid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }

    if (ppid && parentPid) *parentPid = ppid;

    if (ppid && parentName && nameSz) {
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (pe.th32ProcessID == ppid) {
                    wcsncpy(parentName, pe.szExeFile, nameSz - 1);
                    parentName[nameSz - 1] = L'\0';
                    break;
                }
            } while (Process32NextW(hSnap, &pe));
        }
    }
    CloseHandle(hSnap);
}

static void OnEtwRegEvent(DWORD pid, UCHAR eventId, const wchar_t* path, const wchar_t* valueName, const wchar_t* data, const wchar_t* oldData, BOOL isSysReg, void* ctx) {
    DaemonState* s = (DaemonState*)ctx;
    if (!s) return;
    DaemonLog(L"[ETW-DEBUG] RegEvent pid=%lu eventId=%u path=%ls value=%ls data=%ls", pid, eventId, path ? path : L"NULL", valueName ? valueName : L"NULL", data ? data : L"NULL");

    wchar_t imgPath[MAX_PATH] = {0};
    wchar_t procName[256] = L"unknown";
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProc) {
        DWORD sz = MAX_PATH;
        QueryFullProcessImageNameW(hProc, 0, imgPath, &sz);
        CloseHandle(hProc);
    }
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = {0}; pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (pe.th32ProcessID == pid) {
                    wcsncpy(procName, pe.szExeFile, 255);
                    procName[255] = L'\0';
                    break;
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    
    if (_wcsicmp(procName, L"unknown") == 0) {
        DaemonLog(L"[SAFETY-GUARD] BLOCKED: RegistryEvent skipping process with unknown name PID=%lu", pid);
        return;
    }

    /* Never investigate or terminate our own processes - CHECK FIRST */
    if (IsSelfProcessName(procName)) {
        return;
    }

    if (!IsSelfProcessName(procName)) {
        ActionLogManagerGetOrCreate(&s->actionLogManager, pid, procName, imgPath);
        ActionType actionType = ACTION_TYPE_REG_SET;
        if (!data || (wcslen(data) == 0 && oldData && wcslen(oldData) > 0)) {
            actionType = ACTION_TYPE_REG_DELETE_VALUE;
        }
        ActionLogManagerAddEntry(&s->actionLogManager, pid, actionType, path, valueName, data, oldData);
    }

    /* Determine signature signer */
    wchar_t signer[256] = {0};
    BOOL signedOk = FALSE;
    BOOL signedByMs = FALSE;
    if (imgPath[0] && CheckFileSignatureCached(imgPath, signer, 256)) {
        signedOk = TRUE;
        if (wcsstr(signer, L"Microsoft") || wcsstr(signer, L"Windows")) signedByMs = TRUE;
    }

    DetectEvent event = {0};
    if (eventId == 3 || eventId == 5) {
        event.type = DETECT_EVENT_REGISTRY_DELETE;
    } else {
        event.type = DETECT_EVENT_REGISTRY_WRITE;
    }
    event.pid = pid;
    wcsncpy(event.processName, procName, 255);
    wcsncpy(event.imagePath, imgPath, MAX_PATH - 1);
    wcsncpy(event.signer, signer, 255);
    event.isSigned = signedOk;
    wcsncpy(event.eventPath, path, 511);
    swprintf(event.eventDetails, 1024, L"%ls modified registry: %ls value=%ls data=%ls", 
             procName, path, valueName ? valueName : L"(none)", data ? data : L"(none)");
    event.timestamp = GetTickCount64();
    
    DispatchDetectEvent(s, &event);

    /* Ignore ETW events for paths we are not explicitly protecting */
    BOOL sys = IsProtectedSysRegPath(s, path);
    BOOL user = IsProtectedRegPath(s, path);
    BOOL browserHijack = IsBrowserHijackRegPath(path);
    int addedScore = 0;
    BOOL burst = TrackRogueRegActivity(s, pid, path, &addedScore);
    int pathScore = RegPathThreatScore(path) + addedScore;
    if (!sys && !user && !browserHijack && pathScore < 60 && !burst) return;

    /* System actor: Microsoft/Windows signed or running as SYSTEM, or other
       well-known system/antivirus/user-interactive/trusted processes. */
    BOOL isSystemActor = (signedByMs || IsProcessRunningAsSystem(pid) ||
                         IsSystemProcessName(procName) || IsAntivirusProcessName(procName) ||
                         IsUserInteractiveProcess(procName) ||
                         IsProcessUnderWindowsDir(imgPath) ||
                         TzShouldSkip(&s->tz, imgPath));

    if (isSystemActor) {
        DaemonLog(L"ETW: registry modified by trusted process, skipping: %ls signer=%ls pid=%lu reg=%ls",
                  imgPath, signer[0] ? signer : L"none", pid, path);
        return;
    }

    if (signedOk && signer[0]) {
        if (IsSystemRegPath(path)) {
            UpdateSignerScore(s, signer, imgPath, 1);
        }
        if (IsSignerRascal(s, signer)) {
            MarkRascalSigner(s, signer);
            AddRepeatedKillByName(s, procName);
            SaveProcs(s);
            CreateHighRiskPopupFlag(L"protection", L"protection", procName, signer, "Rascal software detected", 60);
        }
        DaemonLog(L"[SIGNATURE-PROTECT] BLOCKED: Registry termination avoided for signed process: pid=%lu name=%ls signer=%ls", pid, procName, signer);
        return;
    }

    if (!imgPath[0]) {
        DaemonLog(L"[SAFETY-GUARD] BLOCKED: RegistryEvent termination avoided - cannot get image path for pid=%lu name=%ls", pid, procName);
        return;
    }

    if (!wcschr(path, L'\\')) {
        DaemonLog(L"[ACTION] terminating process that modified registry value directly: pid=%lu proc=%ls reg=%ls", pid, procName, path);
        HANDLE hTerm = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hTerm) { SafeTerminateProcess(hTerm, NULL); CloseHandle(hTerm); }
        AddRepeatedKillByName(s, procName);
        SaveProcs(s);
        wchar_t reason[256];
        swprintf(reason, 256, L"Process %ls modified a registry value directly: %ls", procName, path);
        CreateHighRiskPopupFlag(L"protection", L"protection", procName, path, "Registry tampering attempt", 50);
        char reasonA[512] = {0};
        char procA[256] = {0};
        WideCharToMultiByte(CP_UTF8, 0, reason, -1, reasonA, sizeof(reasonA) - 1, NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, procName, -1, procA, sizeof(procA) - 1, NULL, NULL);
        WriteAiNotification("REGISTRY-TAMPER", L"protection", L"protection", procName, procA, reasonA);
        return;
    }

    if (sys) {
        DaemonLog(L"[ACTION] system-critical registry attacked, terminating pid=%lu proc=%ls reg=%ls", pid, procName, path);
        HANDLE hTerm = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hTerm) { SafeTerminateProcess(hTerm, NULL); CloseHandle(hTerm); }
        AddRepeatedKillByName(s, procName);
        SaveProcs(s);
        wchar_t reason[256];
        swprintf(reason, 256, L"Process %ls modified system-critical registry key: %ls", procName, path);
        CreateHighRiskPopupFlag(L"protection", L"protection", procName, path, "System-critical registry attack", 80);
        char reasonA[512] = {0};
        char procA[256] = {0};
        WideCharToMultiByte(CP_UTF8, 0, reason, -1, reasonA, sizeof(reasonA) - 1, NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, procName, -1, procA, sizeof(procA) - 1, NULL, NULL);
        WriteAiNotification("REGISTRY-SYS-ATTACK", L"protection", L"protection", procName, procA, reasonA);
        /* Actual registry restore is performed by periodic ExecuteSysRegProtection */
    } else if (user || browserHijack || pathScore >= 60 || burst) {
        DaemonLog(L"[ACTION] suspicious registry activity detected, terminating pid=%lu proc=%ls reg=%ls", pid, procName, path);
        HANDLE hTerm = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hTerm) { SafeTerminateProcess(hTerm, NULL); CloseHandle(hTerm); }
        AddRepeatedKillByName(s, procName);
        SaveProcs(s);
        wchar_t reason[256];
        swprintf(reason, 256, L"Process %ls performed suspicious registry activity: %ls", procName, path);
        CreateHighRiskPopupFlag(L"protection", L"protection", procName, path, "Suspicious registry activity", 60);
        char reasonA[512] = {0};
        char procA[256] = {0};
        WideCharToMultiByte(CP_UTF8, 0, reason, -1, reasonA, sizeof(reasonA) - 1, NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, procName, -1, procA, sizeof(procA) - 1, NULL, NULL);
        WriteAiNotification("SUSPICIOUS-REGISTRY", L"protection", L"protection", procName, procA, reasonA);
    }
}

static BOOL IsCriticalFilePath(const wchar_t* path) {
    if (!path || !path[0]) return FALSE;
    /* Only true Windows system directories. Program Files and user apps are
       intentionally excluded from real-time ETW file monitoring to avoid noise. */
    static const wchar_t* criticalDirs[] = {
        L"C:\\Windows\\System32",
        L"C:\\Windows\\SysWOW64",
        L"C:\\Windows\\Boot",
        L"C:\\Windows\\Setup",
        L"C:\\Windows\\security",
        L"C:\\Windows\\WinSxS",
        L"C:\\Windows\\explorer.exe",
        L"C:\\Windows\\regedit.exe",
        L"C:\\Windows\\notepad.exe",
        L"C:\\Windows\\twain.dll",
        L"C:\\Windows\\twain_32.dll",
        L"C:\\Windows\\hh.exe",
        L"C:\\Windows\\help.exe",
        L"C:\\Windows\\winhlp32.exe",
        NULL
    };
    for (int i = 0; criticalDirs[i]; i++) {
        size_t len = wcslen(criticalDirs[i]);
        if (_wcsnicmp(path, criticalDirs[i], len) == 0) return TRUE;
    }
    return FALSE;
}

static void QuarantineDirectory(const wchar_t* dir) {
    if (!dir || !dir[0]) return;
    /* Rename malicious directory so it cannot be executed any more */
    wchar_t quarantine[MAX_PATH];
    swprintf(quarantine, MAX_PATH, L"%ls.quarantined", dir);
    DeleteFileW(quarantine);
    MoveFileW(dir, quarantine);
}

static BOOL IsSensitiveFilePath(const wchar_t* path) {
    if (!path || !path[0]) return FALSE;
    /* Browser credential / cookie stores */
    if (wcsstr(path, L"\\Google\\Chrome\\User Data\\") &&
        (wcsstr(path, L"Login Data") || wcsstr(path, L"Cookies") ||
         wcsstr(path, L"Web Data") || wcsstr(path, L"History"))) return TRUE;
    if (wcsstr(path, L"\\Microsoft\\Edge\\User Data\\") &&
        (wcsstr(path, L"Login Data") || wcsstr(path, L"Cookies") ||
         wcsstr(path, L"Web Data") || wcsstr(path, L"History"))) return TRUE;
    if (wcsstr(path, L"\\Mozilla\\Firefox\\Profiles\\") &&
        (wcsstr(path, L"logins.json") || wcsstr(path, L"key4.db") ||
         wcsstr(path, L"cookies.sqlite") || wcsstr(path, L"places.sqlite"))) return TRUE;
    /* Crypto wallets */
    if (wcsstr(path, L"\\Bitcoin\\wallet.dat") ||
        wcsstr(path, L"\\Ethereum\\") ||
        wcsstr(path, L"\\MetaMask") ||
        wcsstr(path, L"\\Electrum\\") ||
        wcsstr(path, L"\\Exodus\\") ||
        wcsstr(path, L"\\Atomic\\")) return TRUE;
    /* User document archives */
    const wchar_t* ext = wcsrchr(path, L'.');
    if (ext) {
        if (!_wcsicmp(ext, L".doc") || !_wcsicmp(ext, L".docx") ||
            !_wcsicmp(ext, L".xls") || !_wcsicmp(ext, L".xlsx") ||
            !_wcsicmp(ext, L".ppt") || !_wcsicmp(ext, L".pptx") ||
            !_wcsicmp(ext, L".pdf") || !_wcsicmp(ext, L".txt") ||
            !_wcsicmp(ext, L".zip") || !_wcsicmp(ext, L".rar") ||
            !_wcsicmp(ext, L".7z")) {
            if (wcsstr(path, L"\\Documents\\") || wcsstr(path, L"\\Desktop\\") ||
                wcsstr(path, L"\\Downloads\\") || wcsstr(path, L"\\OneDrive\\")) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

typedef struct {
    DWORD pid;
    DWORD tick;
    int writeCount;
} FileOpTrack;

#define MAX_FILE_OP_TRACK 128
static FileOpTrack s_fileOpTrack[MAX_FILE_OP_TRACK];

static void TrackFileOperation(DaemonState* s, DWORD pid, const wchar_t* procName,
                               const wchar_t* filePath, BOOL signedOk) {
    (void)filePath;
    DWORD now = GetTickCount();
    int slot = -1;
    for (int i = 0; i < MAX_FILE_OP_TRACK; i++) {
        if (s_fileOpTrack[i].pid == pid) {
            slot = i;
            break;
        }
        if (slot == -1 && s_fileOpTrack[i].pid == 0) slot = i;
    }
    if (slot == -1) {
        /* evict oldest */
        DWORD oldest = 0xFFFFFFFF;
        for (int i = 0; i < MAX_FILE_OP_TRACK; i++) {
            if (s_fileOpTrack[i].tick < oldest) {
                oldest = s_fileOpTrack[i].tick;
                slot = i;
            }
        }
        s_fileOpTrack[slot].pid = 0;
        s_fileOpTrack[slot].writeCount = 0;
    }

    s_fileOpTrack[slot].pid = pid;
    if (now - s_fileOpTrack[slot].tick > 5000) {
        s_fileOpTrack[slot].tick = now;
        s_fileOpTrack[slot].writeCount = 1;
    } else {
        s_fileOpTrack[slot].writeCount++;
    }

    if (s_fileOpTrack[slot].writeCount >= 30) {
        if (IsCriticalSystemProcess(procName)) {
            DaemonLog(L"[CRITICAL-PROTECT] BLOCKED: Ransomware termination avoided for critical system process: pid=%lu name=%ls", pid, procName);
            s_fileOpTrack[slot].writeCount = 0;
            return;
        }
        DaemonLog(L"[RANSOMWARE-BLOCK] pid=%lu proc=%ls modified %d files in 5 seconds",
                  pid, procName, s_fileOpTrack[slot].writeCount);
        HANDLE hTerm = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hTerm) { SafeTerminateProcess(hTerm, NULL); CloseHandle(hTerm); }
        AddRepeatedKillByName(s, procName);
        SaveProcs(s);
        wchar_t reason[256];
        swprintf(reason, 256, L"Mass file modifications (%d in 5s)", s_fileOpTrack[slot].writeCount);
        CreateHighRiskPopupFlag(L"protection", L"protection", procName, filePath ? filePath : L"-", "Ransomware-like activity", 85);
        char reasonA[256] = {0};
        char procA[256] = {0};
        WideCharToMultiByte(CP_UTF8, 0, reason, -1, reasonA, sizeof(reasonA) - 1, NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, procName, -1, procA, sizeof(procA) - 1, NULL, NULL);
        WriteAiNotification("RANSOMWARE", L"protection", L"protection", procName, procA, reasonA);
        s_fileOpTrack[slot].writeCount = 0;
    }
}

static void OnEtwFileEvent(DWORD pid, const wchar_t* filePath, UCHAR opcode, void* ctx) {
    DaemonState* s = (DaemonState*)ctx;
    if (!s || !filePath || !filePath[0]) return;
    if (pid == 0 || pid == 4 || pid == GetCurrentProcessId()) return;

    wchar_t imgPath[MAX_PATH] = {0};
    wchar_t procName[256] = L"unknown";
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProc) {
        DWORD sz = MAX_PATH;
        QueryFullProcessImageNameW(hProc, 0, imgPath, &sz);
        CloseHandle(hProc);
    }
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = {0}; pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (pe.th32ProcessID == pid) {
                    wcsncpy(procName, pe.szExeFile, 255);
                    procName[255] = L'\0';
                    break;
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    
    if (_wcsicmp(procName, L"unknown") == 0) {
        DaemonLog(L"[SAFETY-GUARD] BLOCKED: FileEvent skipping process with unknown name PID=%lu", pid);
        return;
    }

    /* Never investigate or terminate our own processes - CHECK FIRST */
    if (IsSelfProcessName(procName)) {
        return;
    }

    if (!IsSelfProcessName(procName)) {
        ActionLogManagerGetOrCreate(&s->actionLogManager, pid, procName, imgPath);
        ActionType actionType = ACTION_TYPE_FILE_WRITE;
        if (opcode == 70) actionType = ACTION_TYPE_FILE_DELETE;
        else if (opcode == 71) actionType = ACTION_TYPE_FILE_RENAME;
        else if (opcode == 69) actionType = ACTION_TYPE_FILE_SET_INFO;
        ActionLogManagerAddEntry(&s->actionLogManager, pid, actionType, filePath, NULL, NULL, NULL);
    }

    BOOL critical = IsCriticalFilePath(filePath);
    BOOL sensitive = IsSensitiveFilePath(filePath);
    
    if (!critical && !sensitive) {
        if (opcode == 68 || opcode == 70 || opcode == 71) {
            wchar_t signer[256] = {0};
            BOOL isSigned = imgPath[0] && CheckFileSignatureCached(imgPath, signer, 256);
            TrackFileOperation(s, pid, procName, filePath, isSigned);
        }
        return;
    }

    wchar_t signer[256] = {0};
    BOOL signedOk = FALSE;
    if (imgPath[0] && CheckFileSignatureCached(imgPath, signer, 256)) {
        signedOk = TRUE;
    }

    /* Skip system/antivirus/interactive/Windows/trusted-zone actors.
       Valid third-party signatures are no longer auto-quarantined here;
       they are handled below with lower aggression. */
    if (IsProcessRunningAsSystem(pid) ||
        IsSystemProcessName(procName) || IsAntivirusProcessName(procName) ||
        IsUserInteractiveProcess(procName) || IsProcessUnderWindowsDir(imgPath) ||
        TzShouldSkip(&s->tz, imgPath)) {
        return;
    }

    const wchar_t* opName = (opcode == 70) ? L"delete" :
                            (opcode == 71) ? L"rename" :
                            (opcode == 68) ? L"write" : L"setinfo";

    /* Unsigned critical attacks: boot changes, system32 deletion, self-copy */
    if (!signedOk && imgPath[0]) {
        BOOL isSystem32 = wcsstr(filePath, L"\\System32\\") || wcsstr(filePath, L"\\SysWOW64\\");
        BOOL isBoot = wcsstr(filePath, L"\\Boot\\") || wcsstr(filePath, L"\\Boot\\BCD") ||
                      wcsstr(filePath, L"\\bootmgr") || wcsstr(filePath, L"\\bootsect.bak");
        BOOL isSelfCopy = (opcode == 68 || opcode == 71) && 
                          wcsstr(filePath, imgPath) && 
                          wcsicmp(filePath, imgPath) != 0;

        if (isBoot && (opcode == 68 || opcode == 70 || opcode == 71)) {
            HandleUnsignedCriticalAttack(s, pid, procName, imgPath, L"boot modification");
            return;
        }

        if (isSystem32 && opcode == 70) {
            HandleUnsignedCriticalAttack(s, pid, procName, imgPath, L"system32 file deletion");
            return;
        }

        if (isSelfCopy) {
            UpdateUnsignedScore(s, imgPath, 5);
            if (IsUnsignedRascal(s, imgPath)) {
                MarkUnsignedRascal(s, imgPath, procName);
            }
        }
    }

    /* Sensitive file access: signed processes only warn; unsigned processes are blocked. */
    if (sensitive && (opcode == 68 || opcode == 70 || opcode == 71)) {
        DaemonLog(L"[DATA-THEFT] %ls process accessed sensitive file: pid=%lu proc=%ls file=%ls",
                  signedOk ? L"signed" : L"unsigned", pid, procName, filePath);
        if (!signedOk && !IsSelfProcessName(procName)) {
            DaemonLog(L"[WARNING] unsigned process accessed sensitive file, reporting only");
        }
        wchar_t reason[256];
        swprintf(reason, 256, L"Sensitive file access: %ls", filePath);
        CreateHighRiskPopupFlag(L"protection", L"protection", procName, filePath ? filePath : L"-", "Data theft attempt", 60);
        char reasonA[512] = {0};
        char procA[256] = {0};
        WideCharToMultiByte(CP_UTF8, 0, reason, -1, reasonA, sizeof(reasonA) - 1, NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, procName, -1, procA, sizeof(procA) - 1, NULL, NULL);
        WriteAiNotification("DATA-THEFT", L"protection", L"protection", procName, procA, reasonA);
    }

    if (IsCriticalSystemProcess(procName)) {
        DaemonLog(L"[CRITICAL-PROTECT] BLOCKED: FileEvent termination avoided for critical system process: pid=%lu name=%ls", pid, procName);
        return;
    }

    if (signedOk) {
        DaemonLog(L"[SIGNATURE-PROTECT] BLOCKED: FileEvent termination avoided for signed process: pid=%lu name=%ls signer=%ls file=%ls", pid, procName, signer, filePath);
        return;
    }

    if (!imgPath[0]) {
        DaemonLog(L"[SAFETY-GUARD] BLOCKED: FileEvent termination avoided - cannot get image path for pid=%lu name=%ls", pid, procName);
        return;
    }

    wchar_t parentName[256] = L"unknown";
    DWORD parentPid = 0;
    GetParentProcessInfo(pid, &parentPid, parentName, 256);

    /* Record forensics before the process can self-terminate */
    DaemonLog(L"[SUSPECT] file %ls by unsigned non-system actor: name=%ls pid=%lu path=%ls parent=%ls(%lu) file=%ls",
              opName, procName, pid, imgPath, parentName, parentPid, filePath);

    /* Unsigned attacker: quarantine its directory and repeated-kill the process */
    DaemonLog(L"[ACTION] unsigned attacker, quarantining directory and terminating pid=%lu", pid);
    HANDLE hTerm = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hTerm) { SafeTerminateProcess(hTerm, NULL); CloseHandle(hTerm); }

    wchar_t* p = wcsrchr(imgPath, L'\\');
    if (p) {
        *p = L'\0';
        QuarantineDirectory(imgPath);
    }

    /* Also add to repeated-kill list so it cannot restart */
    AddRepeatedKillByName(s, procName);
}

static void GetProcessNameByPid(DWORD pid, wchar_t* out, DWORD outSz) {
    out[0] = L'\0';
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe = {0}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                wcsncpy(out, pe.szExeFile, outSz - 1);
                out[outSz - 1] = L'\0';
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

static void GetBaseNameFromPath(const wchar_t* path, wchar_t* out, DWORD outSz) {
    out[0] = L'\0';
    if (!path) return;
    const wchar_t* p = wcsrchr(path, L'\\');
    const wchar_t* base = p ? p + 1 : path;
    wcsncpy(out, base, outSz - 1);
    out[outSz - 1] = L'\0';
}

static BOOL IsSuspiciousDllPath(const wchar_t* path) {
    if (!path || !path[0]) return FALSE;
    static const wchar_t* suspiciousPrefixes[] = {
        L"C:\\Users\\",
        L"C:\\Temp\\",
        L"C:\\Windows\\Temp\\",
        L"C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Temp\\",
        L"C:\\Windows\\System32\\config\\systemprofile\\AppData\\Roaming\\",
        L"C:\\Users\\Public\\",
        L"C:\\ProgramData\\",
        NULL
    };
    for (int i = 0; suspiciousPrefixes[i]; i++) {
        if (_wcsnicmp(path, suspiciousPrefixes[i], wcslen(suspiciousPrefixes[i])) == 0) {
            return TRUE;
        }
    }
    if (wcsstr(path, L"\\Temp\\") || wcsstr(path, L"\\temp\\") ||
        wcsstr(path, L"\\AppData\\Local\\") || wcsstr(path, L"\\AppData\\Roaming\\")) {
        return TRUE;
    }
    return FALSE;
}

static BOOL IsKnownTrustedDll(const wchar_t* path) {
    if (!path || !path[0]) return FALSE;
    const wchar_t* dllName = wcsrchr(path, L'\\');
    if (dllName) dllName++; else dllName = path;

    static const wchar_t* trustedDlls[] = {
        L"ntdll.dll", L"kernel32.dll", L"kernelbase.dll", L"advapi32.dll",
        L"user32.dll", L"gdi32.dll", L"gdi32full.dll", L"msvcp_win.dll",
        L"ucrtbase.dll", L"combase.dll", L"rpcrt4.dll", L"ole32.dll",
        L"oleaut32.dll", L"shcore.dll", L"shell32.dll", L"windows.storage.dll",
        L"win32u.dll", L"crypt32.dll", L"bcrypt.dll", L"ws2_32.dll",
        L"iphlpapi.dll", L"mswsock.dll", L"dnsapi.dll", L"ntoskrnl.exe",
        L"hal.dll", L"winhttp.dll", L"wintrust.dll", L"psapi.dll",
        L"tdh.dll", L"evntrace.dll", L"evntprov.dll", L"propsys.dll",
        L"cfgmgr32.dll", L"powrprof.dll", L"kernel.appcore.dll",
        L"mshtml.dll", L"urlmon.dll", L"msxml3.dll", L"msxml6.dll",
        L"iertutil.dll", L"netapi32.dll", L"secur32.dll", L"sspicli.dll",
        L"credui.dll", L"dxgi.dll", L"d3d11.dll", L"d3d9.dll",
        L"opengl32.dll", L"glu32.dll", L"wgl.dll", L"winmm.dll",
        L"mmdevapi.dll", L"wmcodecdsp.dll", L"msvcrt.dll", L"dbghelp.dll",
        L"imagehlp.dll", L"samcli.dll", L"lsasrv.dll", L"services.exe",
        L"svchost.exe", L"csrss.exe", L"smss.exe", L"wininit.exe",
        L"winlogon.exe", L"lsass.exe", L"dwm.dll", L"dwmapi.dll",
        L"explorerframe.dll", L"taskschd.dll", L"msi.dll", L"mshtml.dll",
        L"msxml.dll", L"comctl32.dll", L"uxtheme.dll", L"themeui.dll",
        L"dwmcore.dll", L"input.dll", L"usermgr.dll", L"netcfgx.dll",
        L"devmgr.dll", L"perfmon.dll", L"sysdm.cpl", L"msinfo32.dll",
        L"cryptui.dll", L"clbcatq.dll", L"apphelp.dll", L"sfc.dll",
        L"wscsvc.dll", L"wsqmcons.dll", L"wscui.cpl", L"wudfplatform.dll",
        L"wudfsvc.dll", L"wuapi.dll", L"wuauclt.exe", L"wups2.dll",
        L"wuweb.dll", L"msi.dll", L"msiexec.exe", L"setupapi.dll",
        L"newdev.dll", L"devobj.dll", L"cfg32.dll", L"shlwapi.dll",
        L"imm32.dll", L"msctf.dll", L"ctfmon.exe", L"ctfutil.dll",
        L"atl.dll", L"mfc*.dll", L"vcruntime*.dll", L"msvcr*.dll",
        L"msvcp*.dll", L"ucrtbase.dll", L"vcomp*.dll", L"concrt*.dll",
        NULL
    };
    for (int i = 0; trustedDlls[i]; i++) {
        if (wcsstr(trustedDlls[i], L"*")) {
            const wchar_t* star = wcschr(trustedDlls[i], L'*');
            size_t prefixLen = star - trustedDlls[i];
            if (_wcsnicmp(dllName, trustedDlls[i], prefixLen) == 0 &&
                _wcsnicmp(dllName + wcslen(dllName) - wcslen(star + 1), star + 1, wcslen(star + 1)) == 0) {
                return TRUE;
            }
        } else {
            if (!_wcsicmp(dllName, trustedDlls[i])) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

static const wchar_t* GetFileNameFromPathW(const wchar_t* path);

static void OnEtwImageLoad(DWORD pid, const wchar_t* imagePath, BOOL isLoad, void* ctx) {
    DaemonLog(L"[ETW-IMAGE-LOAD] pid=%lu isLoad=%d path=%ls", pid, isLoad, imagePath ? imagePath : L"NULL");
    if (!isLoad) return;
    DaemonState* s = (DaemonState*)ctx;
    if (!s || !imagePath || !imagePath[0]) return;
    if (pid == 0 || pid == 4 || pid == GetCurrentProcessId()) return;

    const wchar_t* ext = wcsrchr(imagePath, L'.');
    if (!ext) return;

    if (_wcsicmp(ext, L".sys") == 0) return;

    if (_wcsicmp(ext, L".exe") == 0) {
        const wchar_t* procName = GetFileNameFromPathW(imagePath);
        if (procName && procName[0]) {
            DaemonLog(L"[ETW-IMAGE-LOAD-EXE] pid=%lu name=%ls path=%ls", pid, procName, imagePath);
            if (IsSelfProcessName(procName)) return;
            if (s->cm && !IsSelfProcessName(procName)) {
                CoreModulesOnNewProcess(s->cm, pid, procName, imagePath);
            }
        }
        return;
    }

    if (_wcsicmp(ext, L".dll") != 0) return;

    if (wcsstr(imagePath, L"trae_guardian_daemon") ||
        wcsstr(imagePath, L"trae_guardian_service_wrapper")) return;

    wchar_t hostPath[MAX_PATH] = {0};
    wchar_t hostName[256] = L"unknown";
    GetProcessImagePath(pid, hostPath, MAX_PATH);
    GetProcessNameByPid(pid, hostName, 256);

    if (!hostPath[0]) return;

    if (TzShouldSkip(&s->tz, hostPath)) return;
    if (TzShouldSkip(&s->tz, imagePath)) return;

    if (IsKnownTrustedDll(imagePath)) return;

    if (IsProcessUnderWindowsDir(imagePath) && !IsSuspiciousDllPath(imagePath)) {
        return;
    }

    wchar_t hostSigner[256] = {0};
    BOOL hostSigned = FALSE;
    BOOL hostIsMs = FALSE;
    if (CheckFileSignatureCached(hostPath, hostSigner, 256)) {
        hostSigned = TRUE;
        if (wcsstr(hostSigner, L"Microsoft") || wcsstr(hostSigner, L"Windows")) hostIsMs = TRUE;
    }
    BOOL hostIsSystem = IsSystemProcessName(hostName);
    BOOL hostIsSystemPriv = IsProcessRunningAsSystem(pid);

    if (!hostIsMs && !hostIsSystem && !hostIsSystemPriv) {
        if (!IsSuspiciousDllPath(imagePath)) return;
    }

    wchar_t dllSigner[256] = {0};
    BOOL dllSigned = FALSE;
    BOOL dllIsMs = FALSE;
    if (CheckFileSignatureCached(imagePath, dllSigner, 256)) {
        dllSigned = TRUE;
        if (wcsstr(dllSigner, L"Microsoft") || wcsstr(dllSigner, L"Windows")) dllIsMs = TRUE;
    }

    if (dllIsMs) return;

    if (dllSigned) {
        DaemonLog(L"[INJECTION-WARN] non-MS signed DLL loaded into trusted process: host=%ls pid=%lu dll=%ls dllSigner=%ls",
                  hostPath, pid, imagePath, dllSigner);
        if (IsSuspiciousDllPath(imagePath)) {
            wchar_t reason[512];
            swprintf(reason, 512,
                     L"Potential injection: signed DLL from suspicious path %ls loaded into trusted process %ls (PID %lu).",
                     imagePath, hostPath, pid);
            CreateHighRiskPopupFlag(L"protection", L"protection", hostName, hostPath, "Potential DLL injection from suspicious path", 55);
            WriteAiNotification("INJECTION-WARN", L"protection", L"protection", hostName, "-", "Signed DLL from suspicious path");
            DaemonLog(L"[ACTION] terminating process with suspicious DLL injection: pid=%lu", pid);
            HANDLE hTerm = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
            if (hTerm) { SafeTerminateProcess(hTerm, NULL); CloseHandle(hTerm); }
            if (!IsSystemProcessName(hostName) && !IsCriticalSystemProcess(hostName)) {
                AddRepeatedKillByName(s, hostName);
                SaveProcs(s);
            }
        }
        return;
    }

    DaemonLog(L"[INJECTION] unsigned DLL loaded into trusted process: host=%ls pid=%lu dll=%ls",
              hostPath, pid, imagePath);

    wchar_t reason[512];
    swprintf(reason, 512,
             L"Injection detected: unsigned DLL %ls loaded into trusted process %ls (PID %lu). "
             L"This is strong evidence of code injection or memory-resident malware.",
             imagePath, hostPath, pid);
    CreateHighRiskPopupFlag(L"protection", L"protection", hostName, hostPath, "Code injection detected", 80);
    WriteAiNotification("INJECTION", L"protection", L"protection", hostName, "-", "Code injection / unsigned DLL loaded into trusted process");

    if (!dllSigned && imagePath[0]) {
        BOOL injectSystem = hostIsMs || hostIsSystem || hostIsSystemPriv;
        if (injectSystem) {
            HandleUnsignedCriticalAttack(s, pid, hostName, hostPath, L"system process injection");
            return;
        }
        UpdateUnsignedScore(s, imagePath, 4);
        if (IsUnsignedRascal(s, imagePath)) {
            MarkUnsignedRascal(s, imagePath, hostName);
        }
    }

    if (hostIsSystem) {
        DaemonLog(L"[ACTION] injected critical system process, terminating: host=%ls pid=%lu dll=%ls", hostPath, pid, imagePath);
        HANDLE hTerm = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hTerm) { SafeTerminateProcess(hTerm, NULL); CloseHandle(hTerm); }
        if (!IsCriticalSystemProcess(hostName)) {
            AddRepeatedKillByName(s, hostName);
            SaveProcs(s);
        }
    } else {
        DaemonLog(L"[ACTION] terminating injected non-critical process pid=%lu", pid);
        HANDLE hTerm = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hTerm) { SafeTerminateProcess(hTerm, NULL); CloseHandle(hTerm); }
        if (!IsSystemProcessName(hostName) && !IsCriticalSystemProcess(hostName)) {
            AddRepeatedKillByName(s, hostName);
            SaveProcs(s);
        }
    }
}

static void OnEtwThread(DWORD pid, DWORD tid, DWORD startAddr, void* ctx) {
    (void)tid; (void)startAddr; (void)ctx;
    /* Thread start events are currently logged only for future correlation.
       Remote-thread injection detection is better done via IMAGE_LOAD + host signature. */
    if (pid == 0 || pid == 4) return;
}

/* Return non-zero if haystack contains needle (case-insensitive) */
static int WcsContainsI(const wchar_t* haystack, const wchar_t* needle) {
    if (!haystack || !needle || !needle[0]) return 0;
    size_t nlen = wcslen(needle);
    size_t hlen = wcslen(haystack);
    if (hlen < nlen) return 0;
    for (size_t i = 0; i <= hlen - nlen; i++) {
        if (_wcsnicmp(haystack + i, needle, nlen) == 0) return 1;
    }
    return 0;
}

static const wchar_t* GetFileNameFromPathW(const wchar_t* path) {
    if (!path || !path[0]) return L"";
    const wchar_t* slash = wcsrchr(path, L'\\');
    const wchar_t* colon = wcsrchr(path, L':');
    if (slash && colon && colon > slash) slash = colon;
    return slash ? slash + 1 : path;
}

static void TerminateAndLog(DaemonState* s, DWORD pid, const wchar_t* procName, const wchar_t* reason, const wchar_t* commandLine) {
    (void)s;
    if (pid == 0 || pid == 4) return;
    DaemonLog(L"[BEHAVIOR-BLOCK] %ls detected for pid=%lu proc=%ls cmd=%ls", reason, pid, procName, commandLine ? commandLine : L"");
    HANDLE hTerm = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hTerm) { SafeTerminateProcess(hTerm, NULL); CloseHandle(hTerm); }
    AddRepeatedKillByName(s, procName);
    SaveProcs(s);

    char reasonA[256] = {0};
    char pathA[512] = {0};
    WideCharToMultiByte(CP_UTF8, 0, reason ? reason : L"-", -1, reasonA, sizeof(reasonA) - 1, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, commandLine ? commandLine : L"-", -1, pathA, sizeof(pathA) - 1, NULL, NULL);

    CreateHighRiskPopupFlag(L"protection", L"protection", procName, commandLine ? commandLine : L"-", reasonA, 30);
    WriteAiNotification("BEHAVIOR", L"protection", L"protection", procName, pathA, reasonA);
}

static void WarnAndLog(DaemonState* s, DWORD pid, const wchar_t* procName, const wchar_t* reason, const wchar_t* commandLine) {
    (void)s;
    if (pid == 0 || pid == 4) return;
    DaemonLog(L"[BEHAVIOR-WARN] %ls detected for signed pid=%lu proc=%ls cmd=%ls", reason, pid, procName, commandLine ? commandLine : L"");

    char reasonA[256] = {0};
    char pathA[512] = {0};
    WideCharToMultiByte(CP_UTF8, 0, reason ? reason : L"-", -1, reasonA, sizeof(reasonA) - 1, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, commandLine ? commandLine : L"-", -1, pathA, sizeof(pathA) - 1, NULL, NULL);

    CreateHighRiskPopupFlag(L"protection", L"protection", procName, commandLine ? commandLine : L"-", reasonA, 20);
    WriteAiNotification("BEHAVIOR-WARN", L"protection", L"protection", procName, pathA, reasonA);
}

static void OnEtwProcStart(DWORD pid, DWORD parentPid, const wchar_t* imageName, const wchar_t* commandLine, void* ctx) {
    DaemonState* s = (DaemonState*)ctx;
    if (!s) return;
    if (pid == 0 || pid == 4 || pid == GetCurrentProcessId()) return;

    wchar_t imgPath[MAX_PATH] = {0};
    wchar_t resolvedName[260] = {0};
    
    if (imageName && imageName[0]) {
        if (wcschr(imageName, L'\\')) {
            wcsncpy(imgPath, imageName, MAX_PATH - 1);
            imgPath[MAX_PATH - 1] = L'\0';
            const wchar_t* name = GetFileNameFromPathW(imageName);
            wcscpy(resolvedName, name);
        } else {
            wcscpy(resolvedName, imageName);
            GetProcessImagePath(pid, imgPath, MAX_PATH);
        }
    } else {
        GetProcessImagePath(pid, imgPath, MAX_PATH);
        if (imgPath[0]) {
            const wchar_t* name = GetFileNameFromPathW(imgPath);
            wcscpy(resolvedName, name);
        } else {
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe = {0};
                pe.dwSize = sizeof(PROCESSENTRY32W);
                if (Process32FirstW(hSnap, &pe)) {
                    do {
                        if (pe.th32ProcessID == pid) {
                            if (pe.szExeFile && pe.szExeFile[0]) {
                                wcscpy(resolvedName, pe.szExeFile);
                                DaemonLog(L"[ETW-PROC-START] PID=%lu: got name from Toolhelp32: %ls", pid, resolvedName);
                            }
                            break;
                        }
                    } while (Process32NextW(hSnap, &pe));
                }
                CloseHandle(hSnap);
            }
            
            if (!resolvedName[0]) {
                DaemonLog(L"[ETW-PROC-START] PID=%lu: name and path both empty, skipping (will be handled by ImageLoad)", pid);
                return;
            }
        }
    }

    const wchar_t* procName = GetFileNameFromPathW(resolvedName);
    if (!procName || !procName[0]) {
        DaemonLog(L"[ETW-PROC-START] PID=%lu: Cannot resolve process name, skipping (will be handled by ImageLoad)", pid);
        return;
    }
    DaemonLog(L"[ETW-PROC-START] pid=%lu name=%ls path=%ls", pid, procName, imgPath);

    /* Never investigate or terminate our own processes - CHECK FIRST */
    if (IsSelfProcessName(procName)) {
        return;
    }

    if (!IsSelfProcessName(procName)) {
        ActionLogManagerGetOrCreate(&s->actionLogManager, pid, procName, imgPath);
    }

    if (s->cm && imgPath[0] && procName[0]) {
        CoreModulesOnNewProcess(s->cm, pid, procName, imgPath);
    }

    if (IsCommonProcess(s, imageName)) return;

    wchar_t signer[256] = {0};
    BOOL signedOk = FALSE;
    if (imgPath[0] && CheckFileSignatureCached(imgPath, signer, 256)) {
        signedOk = TRUE;
    }
    
    DetectEvent event = {0};
    event.type = DETECT_EVENT_PROCESS_SPAWN;
    event.pid = pid;
    wcsncpy(event.processName, procName, 255);
    wcsncpy(event.imagePath, imgPath, MAX_PATH - 1);
    wcsncpy(event.signer, signer, 255);
    event.isSigned = signedOk;
    swprintf(event.eventDetails, 1024, L"New process spawned: %ls cmd=%ls", procName, commandLine ? commandLine : L"(none)");
    event.timestamp = GetTickCount64();
    
    DispatchDetectEvent(s, &event);

    const wchar_t* ext = wcsrchr(imgPath, L'.');
    if (ext && (_wcsicmp(ext, L".exe") == 0 || _wcsicmp(ext, L".dll") == 0 || _wcsicmp(ext, L".sys") == 0)) {
        PEAnalysisResult peResult = {0};
        PEQuickAnalyze(imgPath, &peResult);

        if (!signedOk) {
            DaemonLog(L"[VIRUS-ANALYZER] Analyzing unsigned process: pid=%lu path=%ls", pid, imgPath);
            BOOL shouldKill = FALSE;
            int virusScore = PEGetVirusScore(&peResult, &shouldKill);
            
            if (shouldKill) {
                DaemonLog(L"[VIRUS-KILL] Direct kill triggered for pid=%lu path=%ls", pid, imgPath);
                KillProcessByPid(pid);
                DaemonLog(L"[VIRUS-KILL] Terminated virus process");
            } else if (virusScore > 0) {
                DaemonLog(L"[VIRUS-SCORE] Virus score=%d for pid=%lu path=%ls", virusScore, pid, imgPath);
                if (s->cm) {
                    ScoreCenter* sc = &s->cm->sc;
                    uint64_t createTime = 0;
                    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                    if (hProc) {
                        FILETIME ftCreate, ftExit, ftKernel, ftUser;
                        if (GetProcessTimes(hProc, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
                            createTime = ((uint64_t)ftCreate.dwHighDateTime << 32) | ftCreate.dwLowDateTime;
                        }
                        CloseHandle(hProc);
                    }
                    if (createTime > 0) {
                        uint64_t key = ScoreCenterMakeKey(pid, createTime);
                        ScoreCenterAddStaticScore(sc, key, virusScore, L"Virus PE analysis");
                    }
                }
            }
        } else {
            DaemonLog(L"[ROGUE-ANALYZER] Analyzing signed process: pid=%lu path=%ls signer=%ls", pid, imgPath, signer);
            int rogueScore = PEGetRogueScore(&peResult);
            
            if (rogueScore > 0) {
                DaemonLog(L"[ROGUE-SCORE] Rogue score=%d for pid=%lu path=%ls", rogueScore, pid, imgPath);
                if (s->cm) {
                    ScoreCenter* sc = &s->cm->sc;
                    uint64_t createTime = 0;
                    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                    if (hProc) {
                        FILETIME ftCreate, ftExit, ftKernel, ftUser;
                        if (GetProcessTimes(hProc, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
                            createTime = ((uint64_t)ftCreate.dwHighDateTime << 32) | ftCreate.dwLowDateTime;
                        }
                        CloseHandle(hProc);
                    }
                    if (createTime > 0) {
                        uint64_t key = ScoreCenterMakeKey(pid, createTime);
                        ScoreCenterAddStaticScore(sc, key, rogueScore, L"Rogue PE analysis");
                    }
                }
            }
            DaemonLog(L"[ROGUE-AI] Signed process %ls entering long-term AI behavior analysis", procName);
        }

        if (peResult.hashComputed) {
            DaemonLog(L"[PE-HASH] SHA256 computed for pid=%lu", pid);
        }

        PEFreeResult(&peResult);
    }

    if (!signedOk && !IsSystemProcessName(procName) && !IsCriticalSystemProcess(procName)) {
        DaemonLog(L"[HOOK-INJECT] Attempting to inject guardian_hook.dll into unsigned process: pid=%lu name=%ls", pid, procName);
        InjectHookDll(pid);
    }

    wchar_t parentName[256] = {0};
    GetProcessNameByPid(parentPid, parentName, 256);

    wchar_t parentPath[MAX_PATH] = {0};
    wchar_t parentSigner[256] = {0};
    BOOL parentSigned = FALSE;
    GetProcessImagePath(parentPid, parentPath, MAX_PATH);
    if (parentPath[0] && CheckFileSignatureCached(parentPath, parentSigner, 256)) {
        parentSigned = TRUE;
    }

    /* Detect same-signer app installation: parent installs another app with same signer */
    if (signedOk && parentSigned && signer[0] && parentSigner[0]) {
        if (_wcsicmp(signer, parentSigner) == 0) {
            if (wcsicmp(imgPath, parentPath) != 0) {
                UpdateSignerScore(s, signer, imgPath, 2);
                if (IsSignerRascal(s, signer)) {
                    MarkRascalSigner(s, signer);
                    AddRepeatedKillByName(s, procName);
                    SaveProcs(s);
                    CreateHighRiskPopupFlag(L"protection", L"protection", procName, signer, "Rascal software detected", 60);
                }
            }
        }
    }

#define BEHAVIOR_ACT(pid, procName, reason, cmd) \
    do { if (signedOk) WarnAndLog(s, pid, procName, reason, cmd); else TerminateAndLog(s, pid, procName, reason, cmd); } while (0)

    /* --- 1. Backup / recovery destruction --- */
    if (_wcsicmp(procName, L"vssadmin.exe") == 0) {
        if (WcsContainsI(commandLine, L"delete") && WcsContainsI(commandLine, L"shadow")) {
            BEHAVIOR_ACT(pid, procName, L"Volume Shadow Copy deletion", commandLine);
            return;
        }
    }
    if (_wcsicmp(procName, L"wbadmin.exe") == 0) {
        if (WcsContainsI(commandLine, L"delete") || WcsContainsI(commandLine, L"catalog")) {
            BEHAVIOR_ACT(pid, procName, L"Backup catalog deletion", commandLine);
            return;
        }
    }
    if (_wcsicmp(procName, L"bcdedit.exe") == 0) {
        if (WcsContainsI(commandLine, L"recoveryenabled") && WcsContainsI(commandLine, L"no")) {
            BEHAVIOR_ACT(pid, procName, L"Recovery mode disabled", commandLine);
            return;
        }
        if (WcsContainsI(commandLine, L"bootstatuspolicy") && WcsContainsI(commandLine, L"ignoreallfailures")) {
            BEHAVIOR_ACT(pid, procName, L"Boot failure reporting disabled", commandLine);
            return;
        }
    }

    /* --- 2. Log / audit clearing --- */
    if (_wcsicmp(procName, L"wevtutil.exe") == 0) {
        if (WcsContainsI(commandLine, L"cl") || WcsContainsI(commandLine, L"clear-log")) {
            BEHAVIOR_ACT(pid, procName, L"Event log clearing", commandLine);
            return;
        }
    }

    /* --- 3. Privilege escalation / account tampering --- */
    if (_wcsicmp(procName, L"net.exe") == 0 || _wcsicmp(procName, L"net1.exe") == 0) {
        if (WcsContainsI(commandLine, L"localgroup") && WcsContainsI(commandLine, L"administrators")) {
            BEHAVIOR_ACT(pid, procName, L"Local administrator group modification", commandLine);
            return;
        }
        if (WcsContainsI(commandLine, L"user") && (WcsContainsI(commandLine, L"/add") || WcsContainsI(commandLine, L"/active:yes"))) {
            BEHAVIOR_ACT(pid, procName, L"User account creation/activation", commandLine);
            return;
        }
    }

    /* --- 4. Persistence via service / scheduled task / registry --- */
    if (_wcsicmp(procName, L"sc.exe") == 0) {
        if (WcsContainsI(commandLine, L"create") || WcsContainsI(commandLine, L"config") || WcsContainsI(commandLine, L"start")) {
            BEHAVIOR_ACT(pid, procName, L"Service creation/configuration", commandLine);
            return;
        }
    }
    if (_wcsicmp(procName, L"schtasks.exe") == 0) {
        if (WcsContainsI(commandLine, L"/create") || WcsContainsI(commandLine, L"/change")) {
            BEHAVIOR_ACT(pid, procName, L"Scheduled task creation/modification", commandLine);
            return;
        }
    }

    /* --- 5. LOLBins: suspicious interpreter/loader usage --- */
    BOOL isLolbin = (_wcsicmp(procName, L"powershell.exe") == 0 ||
                     _wcsicmp(procName, L"powershell_ise.exe") == 0 ||
                     _wcsicmp(procName, L"cmd.exe") == 0 ||
                     _wcsicmp(procName, L"wscript.exe") == 0 ||
                     _wcsicmp(procName, L"cscript.exe") == 0 ||
                     _wcsicmp(procName, L"mshta.exe") == 0 ||
                     _wcsicmp(procName, L"rundll32.exe") == 0 ||
                     _wcsicmp(procName, L"regsvr32.exe") == 0 ||
                     _wcsicmp(procName, L"certutil.exe") == 0 ||
                     _wcsicmp(procName, L"wmic.exe") == 0 ||
                     _wcsicmp(procName, L"bitsadmin.exe") == 0);
    if (isLolbin) {
        int suspicious = 0;
        if (_wcsicmp(procName, L"powershell.exe") == 0 || _wcsicmp(procName, L"powershell_ise.exe") == 0) {
            if (WcsContainsI(commandLine, L"-enc") ||
                WcsContainsI(commandLine, L"-encodedcommand") ||
                WcsContainsI(commandLine, L"-nop") ||
                WcsContainsI(commandLine, L"-windowstyle hidden") ||
                WcsContainsI(commandLine, L"iex") ||
                WcsContainsI(commandLine, L"invoke-expression") ||
                WcsContainsI(commandLine, L"invoke-webrequest") ||
                WcsContainsI(commandLine, L"downloadstring") ||
                WcsContainsI(commandLine, L"downloadfile") ||
                WcsContainsI(commandLine, L"-ep bypass") ||
                WcsContainsI(commandLine, L"executionpolicy bypass")) {
                suspicious = 1;
            }
        }
        if (_wcsicmp(procName, L"cmd.exe") == 0) {
            if (WcsContainsI(commandLine, L"/c") &&
                (WcsContainsI(commandLine, L"powershell") ||
                 WcsContainsI(commandLine, L"certutil") ||
                 WcsContainsI(commandLine, L"mshta") ||
                 WcsContainsI(commandLine, L"rundll32") ||
                 WcsContainsI(commandLine, L"regsvr32") ||
                 WcsContainsI(commandLine, L"bitsadmin"))) {
                suspicious = 1;
            }
        }
        if (_wcsicmp(procName, L"mshta.exe") == 0) {
            if (WcsContainsI(commandLine, L"javascript:") ||
                WcsContainsI(commandLine, L"vbscript:") ||
                WcsContainsI(commandLine, L"http://") ||
                WcsContainsI(commandLine, L"https://")) {
                suspicious = 1;
            }
        }
        if (_wcsicmp(procName, L"rundll32.exe") == 0) {
            if (WcsContainsI(commandLine, L".htm") ||
                WcsContainsI(commandLine, L".html") ||
                WcsContainsI(commandLine, L"javascript") ||
                WcsContainsI(commandLine, L"http://") ||
                WcsContainsI(commandLine, L"https://") ||
                WcsContainsI(commandLine, L"\\")) {
                suspicious = 1;
            }
        }
        if (_wcsicmp(procName, L"regsvr32.exe") == 0) {
            if (WcsContainsI(commandLine, L"/i:") ||
                WcsContainsI(commandLine, L"scrobj") ||
                WcsContainsI(commandLine, L"http://") ||
                WcsContainsI(commandLine, L"https://")) {
                suspicious = 1;
            }
        }
        if (_wcsicmp(procName, L"certutil.exe") == 0) {
            if (WcsContainsI(commandLine, L"-urlcache") ||
                WcsContainsI(commandLine, L"-split") ||
                WcsContainsI(commandLine, L"-decode") ||
                WcsContainsI(commandLine, L"-encode")) {
                suspicious = 1;
            }
        }
        if (_wcsicmp(procName, L"wmic.exe") == 0) {
            if (WcsContainsI(commandLine, L"process create") ||
                WcsContainsI(commandLine, L"/node:") ||
                WcsContainsI(commandLine, L"shadowcopy delete")) {
                suspicious = 1;
            }
        }
        if (_wcsicmp(procName, L"bitsadmin.exe") == 0) {
            if (WcsContainsI(commandLine, L"/transfer") ||
                WcsContainsI(commandLine, L"/download") ||
                WcsContainsI(commandLine, L"/create")) {
                suspicious = 1;
            }
        }
        if (suspicious) {
            BEHAVIOR_ACT(pid, procName, L"Suspicious LOLBin execution", commandLine);
            return;
        }
    }

    /* --- 6. Lateral movement / remote execution --- */
    if (_wcsicmp(procName, L"psexec.exe") == 0 ||
        _wcsicmp(procName, L"psexesvc.exe") == 0 ||
        (_wcsicmp(procName, L"wmic.exe") == 0 && WcsContainsI(commandLine, L"/node:")) ||
        (_wcsicmp(procName, L"mstsc.exe") == 0 && WcsContainsI(commandLine, L"/v:"))) {
        BEHAVIOR_ACT(pid, procName, L"Remote execution / lateral movement tool", commandLine);
        return;
    }

    /* --- 7. Mass process spawning by same parent (fork bomb / rapid execution) --- */
    static volatile DWORD s_lastParent = 0;
    static volatile int s_parentCount = 0;
    static volatile DWORD s_lastTick = 0;
    DWORD now = GetTickCount();
    if (parentPid == s_lastParent && (now - s_lastTick) < 2000) {
        int c = InterlockedIncrement((LONG*)&s_parentCount);
        if (c >= 10) {
            BEHAVIOR_ACT(pid, procName, L"Rapid process spawning", commandLine);
            return;
        }
    } else {
        s_lastParent = parentPid;
        s_parentCount = 1;
        s_lastTick = now;
    }

#undef BEHAVIOR_ACT
    (void)parentName;
}

static void OnEtwProcessStop(DWORD pid, const wchar_t* imageName, void* ctx) {
    DaemonState* s = (DaemonState*)ctx;
    if (!s || !imageName || !imageName[0]) return;

    /* We only know which process ended, not who ended it.
       Treating every background process exit as an attack causes false positives.
       Only log system-critical process termination for now; AI/global scan
       handles active threats separately. */
    if (IsSystemProcessName(imageName)) {
        DaemonLog(L"ETW: system process terminated: %ls pid=%lu", imageName, pid);
    }
}

static void OnEtwProcessTerminate(DWORD sourcePid, DWORD targetPid, void* ctx) {
    DaemonState* s = (DaemonState*)ctx;
    if (!s) return;
    if (sourcePid == 0 || targetPid == 0 || sourcePid == GetCurrentProcessId()) return;

    wchar_t sourceName[256] = L"unknown";
    wchar_t targetName[256] = L"unknown";
    GetProcessNameByPid(sourcePid, sourceName, 256);
    GetProcessNameByPid(targetPid, targetName, 256);

    /* Ignore self-termination and trusted terminators */
    if (IsSystemProcessName(sourceName) || IsAntivirusProcessName(sourceName) ||
        IsUserInteractiveProcess(sourceName)) {
        return;
    }

    wchar_t sourcePath[MAX_PATH] = {0};
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, sourcePid);
    if (hProc) {
        DWORD sz = MAX_PATH;
        QueryFullProcessImageNameW(hProc, 0, sourcePath, &sz);
        CloseHandle(hProc);
    }
    if (sourcePath[0] && (IsProcessUnderWindowsDir(sourcePath) || TzShouldSkip(&s->tz, sourcePath))) {
        return;
    }

    if (sourcePath[0] && IsTrustedPath(sourcePath)) {
        DaemonLog(L"ETW TI: source %ls runs from trusted path %ls, skipping termination",
                  sourceName, sourcePath);
        return;
    }

    /* If we cannot open the source process, at least check its name. Do not
     * treat well-known system processes as unsigned killers just because
     * OpenProcess failed. */
    if (!sourcePath[0] && IsSystemProcessName(sourceName)) {
        DaemonLog(L"ETW TI: system process %ls terminated another process, cannot verify path, skipping",
                  sourceName);
        return;
    }

    wchar_t targetPath[MAX_PATH] = {0};
    HANDLE hTarget = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetPid);
    if (hTarget) {
        DWORD sz = MAX_PATH;
        QueryFullProcessImageNameW(hTarget, 0, targetPath, &sz);
        CloseHandle(hTarget);
    }

    BOOL targetSys = IsSystemProcessName(targetName) || IsProcessUnderWindowsDir(targetPath);
    BOOL targetBack = !ProcessHasVisibleWindow(targetPid);

    if (targetSys || targetBack) {
        const wchar_t* type = targetSys ? L"system/background system" : L"background";
        DaemonLog(L"ETW TI: %ls process terminated by %ls (sourcePid=%lu targetPid=%lu)",
                  type, sourceName, sourcePid, targetPid);

        wchar_t sourceSigner[256] = {0};
        BOOL sourceSigned = FALSE;
        BOOL sourceIsMs = FALSE;
        if (sourcePath[0] && CheckFileSignatureCached(sourcePath, sourceSigner, 256)) {
            sourceSigned = TRUE;
            if (wcsstr(sourceSigner, L"Microsoft") || wcsstr(sourceSigner, L"Windows")) sourceIsMs = TRUE;
        }

        if (sourceIsMs) {
            /* Microsoft-signed terminator of system/background processes is considered normal. */
            return;
        }

        if (IsSystemProcessName(sourceName)) {
            /* Even if signature check failed/was skipped, do not kill known system processes. */
            DaemonLog(L"ETW TI: source %ls looks like a system process, skipping termination", sourceName);
            return;
        }

        if (!sourceSigned || !sourceSigner[0]) {
            /* Unsigned killer: terminate immediately and add to repeated-kill list. No AI needed. */
            DaemonLog(L"[ACTION] terminating unsigned process %ls (pid=%lu) that killed %ls",
                      sourceName, sourcePid, targetName);
            HANDLE hTerm = OpenProcess(PROCESS_TERMINATE, FALSE, sourcePid);
            if (hTerm) { SafeTerminateProcess(hTerm, NULL); CloseHandle(hTerm); }
            AddRepeatedKillByName(s, sourceName);
            SaveProcs(s);
            WriteAiNotification("THREAT", L"protection", L"protection", sourceName, "-",
                                "Unsigned process terminated system/background process");
        } else {
            DaemonLog(L"[ACTION] terminating signed process %ls (pid=%lu) that killed %ls",
                      sourceName, sourcePid, targetName);
            HANDLE hTerm = OpenProcess(PROCESS_TERMINATE, FALSE, sourcePid);
            if (hTerm) { SafeTerminateProcess(hTerm, NULL); CloseHandle(hTerm); }
            AddRepeatedKillByName(s, sourceName);
            SaveProcs(s);
            WriteAiNotification("THREAT", L"protection", L"protection", sourceName, "-",
                                "Signed process terminated system/background process");
        }
    }
}

void StartEtwMonitoring(DaemonState* s) {
    DaemonLog(L"[ETW-START] StartEtwMonitoring called, sysCritical=%d", s->enableSysCriticalProtection);
    if (!s->enableSysCriticalProtection) {
        DaemonLog(L"[ETW-START] ETW monitoring disabled by config");
        return;
    }
    BOOL ok = EtwStart(&g_etwMonitor, OnEtwRegEvent, OnEtwProcStart, OnEtwProcessStop,
                       OnEtwProcessTerminate, OnEtwFileEvent, OnEtwImageLoad, OnEtwThread, s, &s->tz);
    DaemonLog(L"[ETW-START] EtwStart returned %d", ok);
}

void StopEtwMonitoring(void) {
    EtwStop(&g_etwMonitor);
}

DaemonState g_state;

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

int wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    (void)hInstance; (void)hPrevInstance; (void)lpCmdLine; (void)nCmdShow;

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

    memset(&g_state, 0, sizeof(DaemonState));
    g_state.running = TRUE;
    g_state.hStopEvent = g_hStopEvent;

    DaemonLoadSettings(&g_state);

    DaemonLog(L"=== Trae Guardian Daemon starting ===");
    DaemonLog(L"Base path: %ls", basePath);
    DaemonLog(L"Settings loaded: checkInterval=%dms", g_state.checkInterval);

    CoreModules* cm = (CoreModules*)malloc(sizeof(CoreModules));
    if (!cm) {
        DaemonLog(L"FATAL: Cannot allocate CoreModules");
        return 1;
    }
    memset(cm, 0, sizeof(CoreModules));
    if (!CoreModulesInit(cm, basePath)) {
        DaemonLog(L"FATAL: CoreModulesInit failed");
        free(cm);
        return 1;
    }
    g_state.cm = cm;
    cm->ds = &g_state;

    DaemonLoadAll(&g_state);
    DaemonLoadDlls(&g_state);

    CoreModulesStartThreads(cm);
    StartEtwMonitoring(&g_state);
    DaemonStartAiTaskThread(&g_state);
    StartAiActionPipeServer(&g_state);

    DaemonLog(L"=== Daemon started successfully ===");

    while (WaitForSingleObject(g_hStopEvent, g_state.checkInterval > 0 ? g_state.checkInterval : 500) == WAIT_TIMEOUT) {
        DaemonTick(&g_state);
    }

    DaemonLog(L"=== Daemon shutting down ===");
    g_state.running = FALSE;

    StopEtwMonitoring();
    CoreModulesStopThreads(cm);
    CoreModulesCleanup(cm);
    free(cm);

    if (g_hMutex) {
        ReleaseMutex(g_hMutex);
        CloseHandle(g_hMutex);
    }
    if (g_hStopEvent) CloseHandle(g_hStopEvent);
    if (g_hStopExternal) CloseHandle(g_hStopExternal);

    DaemonLog(L"=== Daemon stopped ===");
    return 0;
}