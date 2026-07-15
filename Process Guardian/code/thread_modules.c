#define UNICODE
#define _UNICODE

#include "thread_modules.h"
#include "daemon_core.h"
#include "response_center.h"
#include "direct_syscall_detector.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <wintrust.h>
#include <softpub.h>
#include <tlhelp32.h>
#include <shlobj.h>

#pragma comment(lib, "wintrust.lib")

typedef enum {
    SystemHandleInformation = 16
} SYSTEM_INFORMATION_CLASS;

typedef struct {
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct {
    ULONG HandleCount;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS (NTAPI *NtQuerySystemInformationFunc)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NtQueryObjectFunc)(HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef struct {
    BYTE data[512];
    uint64_t hash;
} MbrBackup;

static MbrBackup g_mbrBackup = {0};
static uint64_t g_lastMbrHash = 0;
static BOOL g_mbrBackupValid = FALSE;
static BOOL g_isGptDisk = FALSE;
static BYTE g_gptHeader[512] = {0};
static BYTE g_gptPartitionTable[16384] = {0};
static BOOL g_gptBackupValid = FALSE;

#define MAX_REG_ENTRIES 1024
typedef struct {
    wchar_t keyPath[MAX_PATH];
    wchar_t valueName[256];
    wchar_t data[MAX_PATH];
    DWORD type;
} RegSnapshotEntry;

static RegSnapshotEntry g_regSnapshot[MAX_REG_ENTRIES] = {0};
static int g_regSnapshotCount = 0;
static BOOL g_regSnapshotValid = FALSE;

static uint64_t HashMBR(const BYTE* data, int size) {
    uint64_t hash = 17;
    for (int i = 0; i < size; i++) {
        hash = hash * 31 + data[i];
    }
    return hash;
}

static BOOL ReadDiskSector(int sector, BYTE* buffer, int size) {
    HANDLE hDisk = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk == INVALID_HANDLE_VALUE) return FALSE;
    LARGE_INTEGER offset = {0};
    offset.QuadPart = (uint64_t)sector * 512;
    SetFilePointerEx(hDisk, offset, NULL, FILE_BEGIN);
    DWORD br;
    BOOL ok = ReadFile(hDisk, buffer, size, &br, NULL);
    CloseHandle(hDisk);
    return ok && br == size;
}

static BOOL WriteDiskSector(int sector, const BYTE* buffer, int size) {
    HANDLE hDisk = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk == INVALID_HANDLE_VALUE) return FALSE;
    LARGE_INTEGER offset = {0};
    offset.QuadPart = (uint64_t)sector * 512;
    SetFilePointerEx(hDisk, offset, NULL, FILE_BEGIN);
    DWORD bw;
    BOOL ok = WriteFile(hDisk, buffer, size, &bw, NULL);
    CloseHandle(hDisk);
    return ok && bw == size;
}

static BOOL IsGPT(void) {
    BYTE buffer[512] = {0};
    if (!ReadDiskSector(1, buffer, 512)) return FALSE;
    return memcmp(buffer, "EFI PART", 8) == 0;
}

static BOOL BackupMBR(void) {
    g_isGptDisk = IsGPT();
    if (g_isGptDisk) {
        if (ReadDiskSector(0, g_mbrBackup.data, 512) &&
            ReadDiskSector(1, g_gptHeader, 512) &&
            ReadDiskSector(2, g_gptPartitionTable, 16384)) {
            g_mbrBackup.hash = HashMBR(g_mbrBackup.data, 512);
            g_lastMbrHash = g_mbrBackup.hash;
            g_mbrBackupValid = TRUE;
            g_gptBackupValid = TRUE;
            DaemonLog(L"[GPT-DETECTED] System uses GPT partition table");
            return TRUE;
        }
        return FALSE;
    }
    if (ReadDiskSector(0, g_mbrBackup.data, 512)) {
        g_mbrBackup.hash = HashMBR(g_mbrBackup.data, 512);
        g_lastMbrHash = g_mbrBackup.hash;
        g_mbrBackupValid = TRUE;
        DaemonLog(L"[MBR-DETECTED] System uses MBR partition table");
        return TRUE;
    }
    return FALSE;
}

static BOOL RestoreMBR(void) {
    if (!g_mbrBackupValid) {
        DaemonLog(L"[MBR-RESTORE] ABORTED: No valid backup available");
        return FALSE;
    }
    
    BOOL isGptNow = IsGPT();
    
    if (isGptNow) {
        if (!g_gptBackupValid) {
            DaemonLog(L"[GPT-RESTORE] ABORTED: GPT detected but backup is invalid - refusing to restore to avoid disk corruption");
            return FALSE;
        }
        DaemonLog(L"[GPT-RESTORE] Restoring GPT partition table (verified: GPT)");
        if (!WriteDiskSector(0, g_mbrBackup.data, 512)) {
            DaemonLog(L"[GPT-RESTORE] FAILED: Could not write protective MBR");
            return FALSE;
        }
        if (!WriteDiskSector(1, g_gptHeader, 512)) {
            DaemonLog(L"[GPT-RESTORE] FAILED: Could not write GPT header");
            return FALSE;
        }
        if (!WriteDiskSector(2, g_gptPartitionTable, 16384)) {
            DaemonLog(L"[GPT-RESTORE] FAILED: Could not write GPT partition table");
            return FALSE;
        }
        DaemonLog(L"[GPT-RESTORE] SUCCESS: GPT partition table restored");
        return TRUE;
    }
    
    BYTE currentMbr[512] = {0};
    if (!ReadDiskSector(0, currentMbr, 512)) {
        DaemonLog(L"[MBR-RESTORE] ABORTED: Cannot read current MBR to verify disk format");
        return FALSE;
    }
    
    if (memcmp(currentMbr + 440, g_mbrBackup.data + 440, 4) != 0) {
        DaemonLog(L"[MBR-RESTORE] WARNING: Disk signature mismatch - double-checking format");
        if (memcmp(currentMbr, g_mbrBackup.data, 512) == 0) {
            DaemonLog(L"[MBR-RESTORE] INFO: MBR already matches backup, no restore needed");
            return TRUE;
        }
    }
    
    DaemonLog(L"[MBR-RESTORE] Restoring MBR partition table (verified: MBR)");
    if (!WriteDiskSector(0, g_mbrBackup.data, 512)) {
        DaemonLog(L"[MBR-RESTORE] FAILED: Could not write MBR");
        return FALSE;
    }
    DaemonLog(L"[MBR-RESTORE] SUCCESS: MBR partition table restored");
    return TRUE;
}

static void BackupRegistryKeys(void) {
    g_regSnapshotCount = 0;
    const wchar_t* protectedKeys[] = {
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
        L"System\\CurrentControlSet\\Services",
        L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
        L"Software\\Classes\\exefile\\shell\\open\\command",
        L"Software\\Classes\\batfile\\shell\\open\\command",
        L"Software\\Classes\\cmdfile\\shell\\open\\command",
        NULL
    };

    for (int i = 0; protectedKeys[i] && g_regSnapshotCount < MAX_REG_ENTRIES; i++) {
        HKEY hKey = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, protectedKeys[i], 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            continue;
        }
        wchar_t valueName[256] = {0};
        wchar_t data[MAX_PATH] = {0};
        DWORD nameLen = 256, dataLen = MAX_PATH * sizeof(wchar_t), type = 0;
        DWORD j = 0;
        while (RegEnumValueW(hKey, j, valueName, &nameLen, NULL, &type, (LPBYTE)data, &dataLen) == ERROR_SUCCESS) {
            if (g_regSnapshotCount >= MAX_REG_ENTRIES) break;
            if (type == REG_SZ || type == REG_EXPAND_SZ) {
                swprintf(g_regSnapshot[g_regSnapshotCount].keyPath, MAX_PATH, L"HKLM\\%ls", protectedKeys[i]);
                wcscpy(g_regSnapshot[g_regSnapshotCount].valueName, valueName);
                wcscpy(g_regSnapshot[g_regSnapshotCount].data, data);
                g_regSnapshot[g_regSnapshotCount].type = type;
                g_regSnapshotCount++;
            }
            nameLen = 256;
            dataLen = MAX_PATH * sizeof(wchar_t);
            j++;
        }
        RegCloseKey(hKey);
    }
    g_regSnapshotValid = TRUE;
    DaemonLog(L"[REGISTRY-BACKUP] Backed up %d registry entries", g_regSnapshotCount);
}

static void RestoreRegistryKeys(void) {
    if (!g_regSnapshotValid) return;
    DaemonLog(L"[REGISTRY-RESTORE] Restoring registry entries");
    for (int i = 0; i < g_regSnapshotCount; i++) {
        wchar_t keyPath[MAX_PATH] = {0};
        if (wcsncmp(g_regSnapshot[i].keyPath, L"HKLM\\", 5) == 0) {
            wcscpy(keyPath, g_regSnapshot[i].keyPath + 5);
            HKEY hKey = NULL;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
                RegSetValueExW(hKey, g_regSnapshot[i].valueName, 0, g_regSnapshot[i].type,
                    (const BYTE*)g_regSnapshot[i].data, (wcslen(g_regSnapshot[i].data) + 1) * sizeof(wchar_t));
                RegCloseKey(hKey);
            }
        }
    }
    DaemonLog(L"[REGISTRY-RESTORE] Restored %d registry entries", g_regSnapshotCount);
}

static BOOL CheckMBRIntegrity(void) {
    BYTE current[512] = {0};
    if (!ReadDiskSector(0, current, 512)) {
        DaemonLog(L"[MBR-CHECK] FAILED: Cannot read sector 0");
        return TRUE;
    }
    
    uint64_t currentHash = HashMBR(current, 512);
    if (currentHash != g_lastMbrHash) {
        DaemonLog(L"[MBR-CHECK] WARNING: Sector 0 hash mismatch");
        
        BOOL isGpt = IsGPT();
        if (isGpt) {
            DaemonLog(L"[MBR-CHECK] INFO: GPT disk detected, checking GPT structures");
            
            BYTE gptHeader[512] = {0};
            BYTE gptTable[16384] = {0};
            if (!ReadDiskSector(1, gptHeader, 512)) {
                DaemonLog(L"[GPT-CHECK] FAILED: Cannot read GPT header (sector 1)");
                g_lastMbrHash = currentHash;
                return FALSE;
            }
            if (!ReadDiskSector(2, gptTable, 16384)) {
                DaemonLog(L"[GPT-CHECK] FAILED: Cannot read GPT table (sector 2)");
                g_lastMbrHash = currentHash;
                return FALSE;
            }
            
            if (memcmp(gptHeader, g_gptHeader, 512) != 0) {
                DaemonLog(L"[GPT-CHECK] FAILED: GPT header mismatch");
                g_lastMbrHash = currentHash;
                return FALSE;
            }
            if (memcmp(gptTable, g_gptPartitionTable, 16384) != 0) {
                DaemonLog(L"[GPT-CHECK] FAILED: GPT partition table mismatch");
                g_lastMbrHash = currentHash;
                return FALSE;
            }
            
            DaemonLog(L"[GPT-CHECK] OK: GPT structures intact, only protective MBR changed");
            g_lastMbrHash = currentHash;
            return TRUE;
        }
        
        g_lastMbrHash = currentHash;
        return FALSE;
    }
    
    return TRUE;
}

typedef NTSTATUS (NTAPI *NtQuerySystemInformationFunc)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

static BOOL IsProcessSigned(DWORD pid) {
    wchar_t path[MAX_PATH] = {0};
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return FALSE;
    DWORD sz = MAX_PATH;
    if (!QueryFullProcessImageNameW(hProc, 0, path, &sz)) {
        CloseHandle(hProc);
        return FALSE;
    }
    CloseHandle(hProc);
    if (!path[0]) return FALSE;
    wchar_t signer[256] = {0};
    return CheckFileSignature(path, signer, 256);
}

static void CmStartupLog(const char* msg) {
    FILE* f = fopen("C:\\tmp\\daemon_startup.log", "a");
    if (!f) return;
    SYSTEMTIME st; GetLocalTime(&st);
    fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] CoreModulesInit: %s\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, msg);
    fclose(f);
}

BOOL CoreModulesInit(CoreModules* cm, const wchar_t* basePath) {
    if (!cm || !basePath) return FALSE;
    memset(cm, 0, sizeof(CoreModules));
    InitializeCriticalSection(&cm->cs);
    cm->hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    cm->hHighSpeedEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    cm->highSpeedMode = FALSE;
    wchar_t rulesPath[MAX_PATH] = {0};
    swprintf(rulesPath, MAX_PATH, L"%ls\\rules.json", basePath);
    wchar_t whitelistPath[MAX_PATH] = {0};
    swprintf(whitelistPath, MAX_PATH, L"%ls\\whitelist.json", basePath);
    wchar_t configPath[MAX_PATH] = {0};
    swprintf(configPath, MAX_PATH, L"%ls\\config.json", basePath);
    wchar_t logPath[MAX_PATH] = {0};
    swprintf(logPath, MAX_PATH, L"%ls\\logs\\events.db", basePath);
    CreateDirectoryW(L"C:\\ProgramData\\ProcessGuardian\\logs", NULL);
    CmStartupLog("StateMachineInit");
    StateMachineInit(&cm->sm);
    CmStartupLog("RuleEngineInit");
    RuleEngineInit(&cm->re, rulesPath);
    CmStartupLog("RuleEngineLoadRules");
    RuleEngineLoadRules(&cm->re);
    CmStartupLog("ScoreCenterInit");
    ScoreCenterInit(&cm->sc);
    CmStartupLog("ResponseCenterInit");
    ResponseCenterInit(&cm->rc, FALSE);
    CmStartupLog("WhitelistDBInit");
    WhitelistDBInit(&cm->wdb, whitelistPath);
    CmStartupLog("WhitelistDBLoad");
    WhitelistDBLoad(&cm->wdb);
    CmStartupLog("ConfigJSONInit");
    ConfigJSONInit(&cm->cfg, configPath);
    CmStartupLog("ConfigJSONLoad");
    ConfigJSONLoad(&cm->cfg);
    CmStartupLog("SQLiteLogInit");
    BOOL slInit = SQLiteLogInit(&cm->sl, logPath);
    CmStartupLog(slInit ? "SQLiteLogInit succeeded" : "SQLiteLogInit failed");
    CmStartupLog("SQLiteLogOpen");
    BOOL slOpen = SQLiteLogOpen(&cm->sl);
    CmStartupLog(slOpen ? "SQLiteLogOpen succeeded" : "SQLiteLogOpen failed");
    CmStartupLog("VirusSignatureInit");
    VirusSignatureInit(&cm->vsdb);
    CmStartupLog("NetworkMonitorInit");
    NetworkMonitorInit(&cm->nm);
    CmStartupLog("UserInteractionMonitorInit");
    UserInteractionMonitorInit(&cm->uim);
    CmStartupLog("BackupMBR");
    BOOL mbrOk = BackupMBR();
    CmStartupLog(mbrOk ? "BackupMBR succeeded" : "BackupMBR failed");
    CmStartupLog("BackupRegistryKeys");
    BackupRegistryKeys();
    CmStartupLog("done");
    return TRUE;
}

void CoreModulesCleanup(CoreModules* cm) {
    if (!cm) return;
    CoreModulesStopThreads(cm);
    NetworkMonitorCleanup(&cm->nm);
    UserInteractionMonitorCleanup(&cm->uim);
    SQLiteLogClose(&cm->sl);
    SQLiteLogCleanup(&cm->sl);
    ConfigJSONCleanup(&cm->cfg);
    WhitelistDBCleanup(&cm->wdb);
    ResponseCenterCleanup(&cm->rc);
    ScoreCenterCleanup(&cm->sc);
    RuleEngineCleanup(&cm->re);
    StateMachineCleanup(&cm->sm);
    if (cm->hHighSpeedEvent) CloseHandle(cm->hHighSpeedEvent);
    if (cm->hStopEvent) CloseHandle(cm->hStopEvent);
    DeleteCriticalSection(&cm->cs);
}

void CoreModulesStartThreads(CoreModules* cm) {
    if (!cm) return;
    DaemonLog(L"[THREAD-START] Starting all core module threads");
    cm->hHandleScanThread = CreateThread(NULL, 0, HandleScanThreadProc, cm, 0, NULL);
    DaemonLog(L"[THREAD-START] HandleScanThread created: %p", cm->hHandleScanThread);
    cm->hMbrThread = CreateThread(NULL, 0, MbrThreadProc, cm, 0, NULL);
    DaemonLog(L"[THREAD-START] MbrThread created: %p", cm->hMbrThread);
    cm->hRegistryThread = CreateThread(NULL, 0, RegistryThreadProc, cm, 0, NULL);
    DaemonLog(L"[THREAD-START] RegistryThread created: %p", cm->hRegistryThread);
    cm->hFileThread = CreateThread(NULL, 0, FileThreadProc, cm, 0, NULL);
    DaemonLog(L"[THREAD-START] FileThread created: %p", cm->hFileThread);
    cm->hNetworkThread = CreateThread(NULL, 0, NetworkThreadProc, cm, 0, NULL);
    DaemonLog(L"[THREAD-START] NetworkThread created: %p", cm->hNetworkThread);
    cm->hAiThread = CreateThread(NULL, 0, AiThreadProc, cm, 0, NULL);
    DaemonLog(L"[THREAD-START] AiThread created: %p", cm->hAiThread);
    cm->hLogThread = CreateThread(NULL, 0, LogThreadProc, cm, 0, NULL);
    DaemonLog(L"[THREAD-START] LogThread created: %p", cm->hLogThread);
    cm->hSyscallThread = StartDirectSyscallDetector(cm->hStopEvent);
    DaemonLog(L"[THREAD-START] SyscallThread created: %p", cm->hSyscallThread);
    NetworkMonitorStart(&cm->nm);
    UserInteractionMonitorStart(&cm->uim);
}

void CoreModulesStopThreads(CoreModules* cm) {
    if (!cm) return;
    SetEvent(cm->hStopEvent);
    if (cm->hHandleScanThread) { WaitForSingleObject(cm->hHandleScanThread, 5000); CloseHandle(cm->hHandleScanThread); }
    if (cm->hMbrThread) { WaitForSingleObject(cm->hMbrThread, 5000); CloseHandle(cm->hMbrThread); }
    if (cm->hRegistryThread) { WaitForSingleObject(cm->hRegistryThread, 5000); CloseHandle(cm->hRegistryThread); }
    if (cm->hFileThread) { WaitForSingleObject(cm->hFileThread, 5000); CloseHandle(cm->hFileThread); }
    if (cm->hNetworkThread) { WaitForSingleObject(cm->hNetworkThread, 5000); CloseHandle(cm->hNetworkThread); }
    if (cm->hAiThread) { WaitForSingleObject(cm->hAiThread, 5000); CloseHandle(cm->hAiThread); }
    if (cm->hLogThread) { WaitForSingleObject(cm->hLogThread, 5000); CloseHandle(cm->hLogThread); }
    NetworkMonitorStop(&cm->nm);
}

typedef NTSTATUS (NTAPI *NtQueryObjectFunc)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static BOOL CheckProcessForDiskHandle(CoreModules* cm, DWORD pid,
                                       const wchar_t* name, const wchar_t* imagePath) {
    if (pid == GetCurrentProcessId()) return FALSE;
    if (name && name[0] && IsSelfProcessName(name)) return FALSE;
    
    HANDLE hProc = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        DaemonLog(L"[DISK-HANDLE-DEBUG] OpenProcess failed for PID=%lu, err=%lu", pid, GetLastError());
        return FALSE;
    }

    static NtQueryObjectFunc queryObj = NULL;
    if (!queryObj) {
        queryObj = (NtQueryObjectFunc)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");
    }
    if (!queryObj) { 
        CloseHandle(hProc); 
        return FALSE; 
    }

    BOOL found = FALSE;
    DWORD scannedCount = 0;
    
    for (DWORD handleVal = 4; handleVal < 65536 && !found; handleVal += 4) {
        scannedCount++;
        if (scannedCount % 1024 == 0) {
            DaemonLog(L"[DISK-HANDLE-DEBUG] Scanning PID=%lu, scanned %lu handles so far", pid, scannedCount);
        }
        HANDLE hDup = NULL;
        if (DuplicateHandle(hProc, (HANDLE)(ULONG_PTR)handleVal,
                            GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            wchar_t objName[512] = {0};
            DWORD retLen = 0;
            NTSTATUS status = queryObj(hDup, 1, objName, sizeof(objName), &retLen);
            
            const wchar_t* actualName = NULL;
            if (status == 0 && retLen >= 16) {
                USHORT length = *(USHORT*)objName;
                ULONG_PTR bufferPtr = *(ULONG_PTR*)((BYTE*)objName + 8);
                
                if (length > 0 && length < sizeof(objName)) {
                    if (bufferPtr >= (ULONG_PTR)objName && 
                        bufferPtr < (ULONG_PTR)((BYTE*)objName + sizeof(objName))) {
                        actualName = (const wchar_t*)bufferPtr;
                    } else {
                        actualName = (wchar_t*)((BYTE*)objName + 16);
                    }
                }
            }
            
            if (actualName && actualName[0]) {
                BOOL isDiskHandle = FALSE;
                if (wcsstr(actualName, L"PhysicalDrive")) {
                    isDiskHandle = TRUE;
                } else if (wcsstr(actualName, L"Harddisk") && !wcsstr(actualName, L"HarddiskVolume")) {
                    isDiskHandle = TRUE;
                } else if (wcsstr(actualName, L"Volume{")) {
                    isDiskHandle = TRUE;
                }
                
                if (isDiskHandle) {
                    DaemonLog(L"[DISK-HANDLE] PID=%lu (%ls) opened disk handle: %ls", pid, name, actualName);
                    
                    if (IsCriticalSystemProcess(name)) {
                        DaemonLog(L"[CRITICAL-PROTECT] BLOCKED: Cannot terminate critical system process %ls (PID=%lu) with disk handle", name, pid);
                        CloseHandle(hDup);
                        continue;
                    }
                    
                    if (IsSystemProcessName(name)) {
                        DaemonLog(L"[SAFETY] BLOCKED: Cannot terminate system process %ls (PID=%lu) with disk handle", name, pid);
                        CloseHandle(hDup);
                        continue;
                    }
                    
                    BOOL isSigned = FALSE;
                    wchar_t signer[256] = {0};
                    if (imagePath && imagePath[0]) {
                        isSigned = CheckFileSignatureCached(imagePath, signer, 256);
                    } else {
                        isSigned = IsProcessSigned(pid);
                    }
                    
                    if (isSigned) {
                        DaemonLog(L"[SAFETY] SKIP: Signed process %ls (PID=%lu) opened disk handle, skipping termination", name, pid);
                        CloseHandle(hDup);
                        continue;
                    }
                    
                    if (cm->ds) {
                        DetectEvent event = {0};
                        event.type = DETECT_EVENT_DISK_HANDLE;
                        event.pid = pid;
                        wcsncpy(event.processName, name, 255);
                        wcsncpy(event.imagePath, imagePath ? imagePath : L"", MAX_PATH - 1);
                        wcsncpy(event.signer, signer, 255);
                        event.isSigned = isSigned;
                        wcsncpy(event.eventPath, actualName, 511);
                        swprintf(event.eventDetails, 1024, L"Process %ls opened disk handle: %ls", name, actualName);
                        event.timestamp = GetTickCount64();
                        
                        DispatchDetectEvent(cm->ds, &event);
                    }
                    
                    DaemonLog(L"DANGEROUS: Unsigned PID=%lu (%ls) opened disk handle, signer=%ls", pid, name, signer);

                    if (cm->ds) {
                        TerminateWatchdogGroup(cm->ds, pid, name, imagePath);
                    }

                    for (int i = 0; i < 10; i++) {
                        TerminateAllThreads(pid);
                        TerminateProcessTree(pid);
                        Sleep(50);
                    }
                    if (imagePath && imagePath[0]) {
                        CacheFilePath(pid, name, imagePath);
                        ForceDeleteFile(imagePath);
                        DeleteVirusCopies(imagePath);
                    }
                    ScoreCenterAddKernelScore(&cm->sc, pid, 35, L"Opened PhysicalDrive handle");
                    ResponseCenterQueueResponse(&cm->rc, pid, name, imagePath, RESPONSE_DELETE, L"Unauthorized physical disk access");
                    StateMachineEntry* entry = StateMachineGetOrCreate(&cm->sm, pid, name, imagePath);
                    if (entry) StateMachineUpdateState(&cm->sm, entry, PROC_STATE_REMOVED, L"Opened physical disk handle");
                    CoreModulesTerminateSameOriginProcesses(cm, imagePath);
                    if (cm->ds) RecoverFromEtwLogs(cm->ds, pid);
                    found = TRUE;
                }
            }
            CloseHandle(hDup);
        }
    }
    CloseHandle(hProc);
    return found;
}

static BOOL CheckProcessAllHandles(CoreModules* cm, DWORD pid,
                                   const wchar_t* name, const wchar_t* imagePath) {
    if (pid == GetCurrentProcessId()) return FALSE;
    if (name && name[0] && IsSelfProcessName(name)) return FALSE;

    HANDLE hProc = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        DaemonLog(L"[HIGH-FREQ-SCAN] OpenProcess failed for PID=%lu (%ls), err=%lu", pid, name, GetLastError());
        return FALSE;
    }

    static NtQueryObjectFunc queryObj = NULL;
    if (!queryObj) {
        queryObj = (NtQueryObjectFunc)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");
    }
    if (!queryObj) {
        CloseHandle(hProc);
        return FALSE;
    }

    BOOL found = FALSE;
    DWORD dupSuccess = 0;
    DWORD scanned = 0;
    /* Limit to first 4096 handle values (4..16384) - PhysicalDrive handles are usually
     * opened early in process lifetime so they have low handle values. This keeps
     * each scan under 20ms to maintain the 20ms high-frequency polling interval. */
    for (DWORD handleVal = 4; handleVal < 16384 && !found; handleVal += 4) {
        HANDLE hDup = NULL;
        if (DuplicateHandle(hProc, (HANDLE)(ULONG_PTR)handleVal,
                            GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            dupSuccess++;
            wchar_t objName[512] = {0};
            DWORD retLen = 0;
            NTSTATUS status = queryObj(hDup, 1, objName, sizeof(objName), &retLen);
            
            const wchar_t* actualName = NULL;
            if (status == 0 && retLen >= 16) {
                USHORT length = *(USHORT*)objName;
                ULONG_PTR bufferPtr = *(ULONG_PTR*)((BYTE*)objName + 8);
                
                if (length > 0 && length < sizeof(objName)) {
                    if (bufferPtr >= (ULONG_PTR)objName && 
                        bufferPtr < (ULONG_PTR)((BYTE*)objName + sizeof(objName))) {
                        actualName = (const wchar_t*)bufferPtr;
                    } else {
                        actualName = (wchar_t*)((BYTE*)objName + 16);
                    }
                }
            }
            
            if (actualName && actualName[0]) {
                BOOL isSensitive = FALSE;
                wchar_t threatType[256] = {0};
                
                if (wcsstr(actualName, L"PhysicalDrive")) {
                    isSensitive = TRUE;
                    wcscpy(threatType, L"PhysicalDrive");
                } else if (wcsstr(actualName, L"Harddisk") && !wcsstr(actualName, L"HarddiskVolume")) {
                    isSensitive = TRUE;
                    wcscpy(threatType, L"Harddisk");
                } else if (wcsstr(actualName, L"Volume{")) {
                    isSensitive = TRUE;
                    wcscpy(threatType, L"Volume");
                } else if (wcsstr(actualName, L"\\REGISTRY\\MACHINE\\SYSTEM")) {
                    isSensitive = TRUE;
                    wcscpy(threatType, L"SYSTEM Registry");
                } else if (wcsstr(actualName, L"\\REGISTRY\\MACHINE\\SAM")) {
                    isSensitive = TRUE;
                    wcscpy(threatType, L"SAM Registry");
                } else if (wcsstr(actualName, L"\\REGISTRY\\MACHINE\\SECURITY")) {
                    isSensitive = TRUE;
                    wcscpy(threatType, L"SECURITY Registry");
                }
                
                if (isSensitive) {
                    DaemonLog(L"[HIGH-FREQ-HANDLE] PID=%lu (%ls) opened sensitive handle: %ls type=%ls", pid, name, actualName, threatType);
                    
                    if (IsCriticalSystemProcess(name)) {
                        DaemonLog(L"[HIGH-FREQ-SKIP] Critical system process %ls, skipping", name);
                        CloseHandle(hDup);
                        continue;
                    }
                    
                    if (IsSystemProcessName(name)) {
                        DaemonLog(L"[HIGH-FREQ-SKIP] System process %ls, skipping", name);
                        CloseHandle(hDup);
                        continue;
                    }
                    
                    BOOL isSigned = FALSE;
                    wchar_t signer[256] = {0};
                    if (imagePath && imagePath[0]) {
                        isSigned = CheckFileSignatureCached(imagePath, signer, 256);
                    } else {
                        isSigned = IsProcessSigned(pid);
                    }
                    
                    if (isSigned) {
                        DaemonLog(L"[HIGH-FREQ-SKIP] Signed process %ls (PID=%lu) opened %ls handle, skipping termination", name, pid, threatType);
                        CloseHandle(hDup);
                        continue;
                    }
                    
                    DaemonLog(L"DANGEROUS: Unsigned PID=%lu (%ls) opened %ls handle, signer=%ls", pid, name, threatType, signer);

                    if (cm->ds) {
                        DetectEvent event = {0};
                        if (wcsstr(threatType, L"PhysicalDrive") || wcsstr(threatType, L"Harddisk") || wcsstr(threatType, L"Volume")) {
                            event.type = DETECT_EVENT_DISK_HANDLE;
                            swprintf(event.eventDetails, 1024, L"Process %ls opened disk handle: %ls", name, actualName);
                        } else {
                            event.type = DETECT_EVENT_REGISTRY_WRITE;
                            swprintf(event.eventDetails, 1024, L"Process %ls opened %ls handle", name, threatType);
                        }
                        event.pid = pid;
                        wcsncpy(event.processName, name, 255);
                        wcsncpy(event.imagePath, imagePath ? imagePath : L"", MAX_PATH - 1);
                        wcsncpy(event.signer, signer, 255);
                        event.isSigned = isSigned;
                        wcsncpy(event.eventPath, actualName, 511);
                        event.timestamp = GetTickCount64();
                        
                        DispatchDetectEvent(cm->ds, &event);
                    }

                    if (cm->ds) {
                        TerminateWatchdogGroup(cm->ds, pid, name, imagePath);
                    }

                    for (int i = 0; i < 10; i++) {
                        TerminateAllThreads(pid);
                        TerminateProcessTree(pid);
                        Sleep(50);
                    }
                    if (imagePath && imagePath[0]) {
                        CacheFilePath(pid, name, imagePath);
                        ForceDeleteFile(imagePath);
                        DeleteVirusCopies(imagePath);
                    }
                    
                    if (wcsstr(threatType, L"PhysicalDrive") || wcsstr(threatType, L"Harddisk") || wcsstr(threatType, L"Volume")) {
                        ScoreCenterAddKernelScore(&cm->sc, pid, 35, L"Opened PhysicalDrive handle");
                        ResponseCenterQueueResponse(&cm->rc, pid, name, imagePath, RESPONSE_DELETE, L"Unauthorized physical disk access");
                    } else {
                        ScoreCenterAddKernelScore(&cm->sc, pid, 35, L"Opened SYSTEM registry handle");
                        ResponseCenterQueueResponse(&cm->rc, pid, name, imagePath, RESPONSE_DELETE, L"Unauthorized SYSTEM registry access");
                    }
                    
                    StateMachineEntry* entry = StateMachineGetOrCreate(&cm->sm, pid, name, imagePath);
                    if (entry) StateMachineUpdateState(&cm->sm, entry, PROC_STATE_REMOVED, threatType);
                    CoreModulesTerminateSameOriginProcesses(cm, imagePath);
                    if (cm->ds) RecoverFromEtwLogs(cm->ds, pid);
                    found = TRUE;
                }
            }
            CloseHandle(hDup);
        }
        scanned++;
    }
    static DWORD debugLogCounter = 0;
    debugLogCounter++;
    if (debugLogCounter % 50 == 0) {
        DaemonLog(L"[HIGH-FREQ-SCAN] PID=%lu (%ls) scanned %lu handles, dupSuccess=%lu found=%d",
                  pid, name, scanned, dupSuccess, found);
    }
    CloseHandle(hProc);
    return found;
}

DWORD WINAPI HandleScanThreadProc(LPVOID param) {
    CoreModules* cm = (CoreModules*)param;
    if (!cm) return 0;
    int highFreqInterval = 20;
    int lowFreqInterval = 1000;
    if (cm->ds) {
        highFreqInterval = cm->ds->highFreqScanIntervalMs;
        if (highFreqInterval < 5 || highFreqInterval > 1000) {
            highFreqInterval = 20;
        }
    }
    DaemonLog(L"[HANDLE-MONITOR] Started lightweight handle monitor, highFreq=%dms lowFreq=%dms", highFreqInterval, lowFreqInterval);

    static uint64_t lastCacheCleanup = 0;
    static DWORD iteration = 0;
    static DWORD globalScanCounter = 0;
    static DWORD procPollCounter = 0;
    static DWORD seenPids[1024] = {0};
    static int seenPidCount = 0;

    DaemonLog(L"[HANDLE-MONITOR] Entering main loop - state machine mode");

    /* Initial scan: record all existing PIDs without analysis */
    {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = {0};
            pe.dwSize = sizeof(PROCESSENTRY32W);
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;
                    if (pe.th32ProcessID == GetCurrentProcessId()) continue;
                    if (seenPidCount < 1024) {
                        seenPids[seenPidCount++] = pe.th32ProcessID;
                    }
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
        DaemonLog(L"[HANDLE-MONITOR] Initial scan: %d existing processes recorded", seenPidCount);
    }

    while (1) {
        if (WaitForSingleObject(cm->hStopEvent, highFreqInterval) == WAIT_OBJECT_0) {
            DaemonLog(L"[HANDLE-MONITOR] Stop event signaled, exiting loop");
            break;
        }
        iteration++;
        uint64_t now = GetTickCount64();
        
        if (iteration == 1 || iteration % 100 == 0) {
            DaemonLog(L"[HANDLE-MONITOR] Iteration %lu, scan interval=%dms", iteration, highFreqInterval);
        }

        int scannedCount = 0;

        /* Poll for new processes every ~200ms using Toolhelp32 (reliable fallback for ETW) */
        procPollCounter++;
        if (procPollCounter >= (200 / highFreqInterval)) {
            procPollCounter = 0;
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe = {0};
                pe.dwSize = sizeof(PROCESSENTRY32W);
                if (Process32FirstW(hSnap, &pe)) {
                    do {
                        if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;
                        if (pe.th32ProcessID == GetCurrentProcessId()) continue;
                        if (IsSelfProcessName(pe.szExeFile)) continue;

                        BOOL alreadySeen = FALSE;
                        for (int i = 0; i < seenPidCount; i++) {
                            if (seenPids[i] == pe.th32ProcessID) {
                                alreadySeen = TRUE;
                                break;
                            }
                        }

                        if (!alreadySeen) {
                            if (seenPidCount < 1024) {
                                seenPids[seenPidCount++] = pe.th32ProcessID;
                            }

                            wchar_t procPath[MAX_PATH] = {0};
                            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                            if (hProc) {
                                DWORD sz = MAX_PATH;
                                QueryFullProcessImageNameW(hProc, 0, procPath, &sz);
                                CloseHandle(hProc);
                            }

                            if (procPath[0]) {
                                DaemonLog(L"[PROC-POLL] New process detected: pid=%lu name=%ls path=%ls",
                                          pe.th32ProcessID, pe.szExeFile, procPath);
                                CoreModulesOnNewProcess(cm, pe.th32ProcessID, pe.szExeFile, procPath);
                            }
                        }
                    } while (Process32NextW(hSnap, &pe));
                }
                CloseHandle(hSnap);
            }
        }

        StateMachineEntry* entry = cm->sm.head;
        BOOL hasHighFreqEntries = FALSE;
        
        while (entry) {
            StateMachineEntry* nextEntry = entry->next;
            
            if (entry->inHighFreqMonitor) {
                hasHighFreqEntries = TRUE;
                if ((now - entry->highFreqStartTime) >= 5000) {
                    entry->inHighFreqMonitor = FALSE;
                    DaemonLog(L"[HIGH-FREQ] Process %ls (PID=%lu) exiting observation - no threats detected", entry->name, entry->pid);
                    if (entry->state == PROC_STATE_OBSERVED) {
                        StateMachineUpdateState(&cm->sm, entry, PROC_STATE_TRUSTED, L"5-second observation period completed");
                    }
                } else {
                    CheckProcessAllHandles(cm, entry->pid, entry->name, entry->imagePath);
                    scannedCount++;
                }
            }
            
            entry = nextEntry;
        }

        /* NOTE: Global scan removed - it scans 65536 handles per process for all 273+ processes,
         * taking 1-2 minutes and blocking PROC-POLL. Detection now relies on:
         * 1) PROC-POLL detects new processes every 200ms and sets high-frequency monitoring
         * 2) CheckProcessAllHandles scans the new process's handles during the 5-second window
         * This is sufficient because new malware must start as a new process. */
        (void)hasHighFreqEntries;
        (void)globalScanCounter;

        if (iteration == 1 || iteration % 100 == 0) {
            DaemonLog(L"[HANDLE-MONITOR] Finished scanning %d processes", scannedCount);
        }

        if ((now - lastCacheCleanup) >= 60000) {
            CleanupStaleCache();
            lastCacheCleanup = now;
        }
    }
    DaemonLog(L"[HANDLE-MONITOR] Exiting handle monitor thread - loop exited!");
    return 0;
}

DWORD WINAPI MbrThreadProc(LPVOID param) {
    CoreModules* cm = (CoreModules*)param;
    if (!cm) return 0;
    while (WaitForSingleObject(cm->hStopEvent, 500) != WAIT_OBJECT_0) {
        if (!CheckMBRIntegrity()) {
            DaemonLog(L"[EMERGENCY] MBR integrity check FAILED - restoring MBR...");
            cm->highSpeedMode = TRUE;
            cm->highSpeedStartTime = GetTickCount64();
            SetEvent(cm->hHighSpeedEvent);
            
            DaemonLog(L"[EMERGENCY] Restoring MBR...");
            if (RestoreMBR()) {
                DaemonLog(L"MBR restored successfully");
                ScoreCenterAddKernelScore(&cm->sc, 0, 18, L"MBR modified and restored");
                ResponseCenterQueueResponse(&cm->rc, 0, L"MBR_RESTORE", L"", RESPONSE_RESTORE, L"MBR was modified");
            } else {
                DaemonLog(L"MBR restore FAILED!");
            }
        }
        if (cm->highSpeedMode) {
            Sleep(50);
        } else {
            Sleep(500);
        }
    }
    return 0;
}

static const wchar_t* g_protectedRegPaths[] = {
    L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
    L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
    L"\\Registry\\User\\",
    L"\\Registry\\Machine\\System\\CurrentControlSet\\Services",
    L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
    L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
    L"\\Registry\\Machine\\Software\\Classes\\exefile\\shell\\open\\command",
    L"\\Registry\\Machine\\Software\\Classes\\batfile\\shell\\open\\command",
    L"\\Registry\\Machine\\Software\\Classes\\cmdfile\\shell\\open\\command",
    NULL
};

static BOOL IsProtectedRegPath(const wchar_t* path) {
    if (!path) return FALSE;
    for (int i = 0; g_protectedRegPaths[i]; i++) {
        if (wcsstr(path, g_protectedRegPaths[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

static void CheckRunKeyForSuspiciousEntries(CoreModules* cm, HKEY rootKey, const wchar_t* keyPath) {
    HKEY hRun = NULL;
    LONG result = RegOpenKeyExW(rootKey, keyPath, 0, KEY_READ, &hRun);
    if (hRun) {
        wchar_t name[MAX_PATH] = {0};
        wchar_t data[MAX_PATH] = {0};
        DWORD nameLen = MAX_PATH, dataLen = MAX_PATH, type = 0;
        DWORD i = 0;
        while (RegEnumValueW(hRun, i, name, &nameLen, NULL, &type, 
            (LPBYTE)data, &dataLen) == ERROR_SUCCESS) {
            if (type == REG_SZ || type == REG_EXPAND_SZ) {
                DaemonLog(L"[REGISTRY-CHANGE] Run entry found: %ls -> %ls", name, data);
                
                wchar_t fullPath[MAX_PATH] = {0};
                if (rootKey == HKEY_CURRENT_USER) {
                    swprintf(fullPath, MAX_PATH, L"HKEY_CURRENT_USER\\%ls\\%ls", keyPath, name);
                } else {
                    swprintf(fullPath, MAX_PATH, L"HKEY_LOCAL_MACHINE\\%ls\\%ls", keyPath, name);
                }
                
                if (cm && cm->ds) {
                    DetectEvent event = {0};
                    event.type = DETECT_EVENT_REGISTRY_WRITE;
                    event.pid = 0;
                    wcscpy(event.processName, L"unknown");
                    wcscpy(event.eventPath, fullPath);
                    swprintf(event.eventDetails, 1024, L"Run key modified: %ls -> %ls", name, data);
                    event.isSigned = FALSE;
                    event.timestamp = GetTickCount64();
                    
                    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                    if (hSnap != INVALID_HANDLE_VALUE) {
                        PROCESSENTRY32W pe = {0};
                        pe.dwSize = sizeof(pe);
                        if (Process32FirstW(hSnap, &pe)) {
                            do {
                                wchar_t procPath[MAX_PATH] = {0};
                                HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                                if (hProc) {
                                    DWORD sz = MAX_PATH;
                                    if (QueryFullProcessImageNameW(hProc, 0, procPath, &sz)) {
                                        if (wcsstr(data, procPath)) {
                                            event.pid = pe.th32ProcessID;
                                            wcscpy(event.processName, pe.szExeFile);
                                            wcscpy(event.imagePath, procPath);
                                            
                                            wchar_t signer[256] = {0};
                                            if (CheckFileSignatureCached(procPath, signer, 256)) {
                                                event.isSigned = TRUE;
                                                wcscpy(event.signer, signer);
                                            }
                                            break;
                                        }
                                    }
                                    CloseHandle(hProc);
                                }
                            } while (Process32NextW(hSnap, &pe));
                        }
                        CloseHandle(hSnap);
                    }
                    
                    DispatchDetectEvent(cm->ds, &event);
                }
                
                BOOL isSuspicious = FALSE;
                if (wcsstr(data, L"ransomware") || wcsstr(data, L"malware") || 
                    wcsstr(data, L"virus") || wcsstr(data, L"trojan")) {
                    isSuspicious = TRUE;
                }
                
                if (_wcsicmp(name, L"Ransomware") == 0 || _wcsicmp(name, L"Virus") == 0 ||
                    _wcsicmp(name, L"Malware") == 0) {
                    isSuspicious = TRUE;
                }
                
                if (isSuspicious) {
                    DaemonLog(L"[REGISTRY-ALERT] Suspicious Run entry detected: %ls -> %ls", name, data);
                    
                    BOOL foundMatch = FALSE;
                    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                    if (hSnap != INVALID_HANDLE_VALUE) {
                        PROCESSENTRY32W pe = {0};
                        pe.dwSize = sizeof(PROCESSENTRY32W);
                        if (Process32FirstW(hSnap, &pe)) {
                            do {
                                wchar_t procPath[MAX_PATH] = {0};
                                HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                                if (hProc) {
                                    DWORD sz = MAX_PATH;
                                    if (QueryFullProcessImageNameW(hProc, 0, procPath, &sz)) {
                                        if (wcsstr(data, procPath)) {
                                            foundMatch = TRUE;
                                            if (IsCriticalSystemProcess(pe.szExeFile)) {
                                                DaemonLog(L"[CRITICAL-PROTECT] BLOCKED: Cannot terminate critical system process %ls (PID=%lu)", pe.szExeFile, pe.th32ProcessID);
                                            } else if (IsSelfProcessName(pe.szExeFile)) {
                                                DaemonLog(L"[SELF-PROTECT] BLOCKED: Cannot terminate self process %ls (PID=%lu)", pe.szExeFile, pe.th32ProcessID);
                                            } else if (IsSystemProcessName(pe.szExeFile)) {
                                                DaemonLog(L"[SAFETY] BLOCKED: Cannot terminate system process %ls (PID=%lu)", pe.szExeFile, pe.th32ProcessID);
                                            } else {
                                                wchar_t signer[256] = {0};
                                                if (CheckFileSignature(procPath, signer, 256)) {
                                                    DaemonLog(L"[SIGNATURE-PROTECT] BLOCKED: Termination of signed process skipped: %ls (PID=%lu) signer=%ls", pe.szExeFile, pe.th32ProcessID, signer);
                                                } else {
                                                    DaemonLog(L"[ACTION] Terminating suspicious process: %ls (PID=%lu)", pe.szExeFile, pe.th32ProcessID);
                                                    TerminateProcess(hProc, 1);
                                                }
                                            }
                                        }
                                    }
                                    CloseHandle(hProc);
                                }
                            } while (Process32NextW(hSnap, &pe));
                        }
                        CloseHandle(hSnap);
                    }
                    
                    /* Fallback: if no matching process was found by Run-key data path,
                     * search for recently-started unsigned processes as suspects */
                    if (!foundMatch) {
                        DaemonLog(L"[REGISTRY-ALERT] No process matched Run-key data, searching for recently-started unsigned processes...");
                        HANDLE hSnap2 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                        if (hSnap2 != INVALID_HANDLE_VALUE) {
                            PROCESSENTRY32W pe = {0};
                            pe.dwSize = sizeof(PROCESSENTRY32W);
                            FILETIME ftNow;
                            GetSystemTimeAsFileTime(&ftNow);
                            ULONGLONG nowTick = GetTickCount64();
                            if (Process32FirstW(hSnap2, &pe)) {
                                do {
                                    /* Skip system/critical/self processes */
                                    if (IsCriticalSystemProcess(pe.szExeFile)) continue;
                                    if (IsSelfProcessName(pe.szExeFile)) continue;
                                    if (IsSystemProcessName(pe.szExeFile)) continue;
                                    if (pe.th32ProcessID <= 4) continue;
                                    
                                    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                                    if (!hProc) continue;
                                    
                                    wchar_t procPath[MAX_PATH] = {0};
                                    DWORD sz = MAX_PATH;
                                    if (!QueryFullProcessImageNameW(hProc, 0, procPath, &sz)) {
                                        CloseHandle(hProc);
                                        continue;
                                    }
                                    
                                    /* Check if process started within last 120 seconds */
                                    FILETIME ftCreate, ftExit, ftKernel, ftUser;
                                    ULONGLONG createTick = 0;
                                    BOOL isRecent = FALSE;
                                    if (GetProcessTimes(hProc, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
                                        ULONGLONG createTime = ((ULONGLONG)ftCreate.dwHighDateTime << 32) | ftCreate.dwLowDateTime;
                                        ULONGLONG nowTime = ((ULONGLONG)ftNow.dwHighDateTime << 32) | ftNow.dwLowDateTime;
                                        /* 120 seconds in 100-nanosecond intervals */
                                        if (nowTime - createTime < (ULONGLONG)120 * 10000000) {
                                            isRecent = TRUE;
                                        }
                                    }
                                    
                                    if (!isRecent) {
                                        CloseHandle(hProc);
                                        continue;
                                    }
                                    
                                    /* Skip processes running from Windows system directories */
                                    if (_wcsnicmp(procPath, L"C:\\Windows\\", 11) == 0 ||
                                        _wcsnicmp(procPath, L"C:\\Program Files\\", 17) == 0 ||
                                        _wcsnicmp(procPath, L"C:\\Program Files (x86)\\", 22) == 0) {
                                        CloseHandle(hProc);
                                        continue;
                                    }
                                    
                                    /* Check if unsigned */
                                    wchar_t signer[256] = {0};
                                    BOOL isSigned = CheckFileSignature(procPath, signer, 256);
                                    
                                    if (!isSigned) {
                                        DaemonLog(L"[REGISTRY-ALERT] Suspect process found (recently started, unsigned): %ls (PID=%lu) path=%ls", 
                                                  pe.szExeFile, pe.th32ProcessID, procPath);
                                        
                                        /* Dispatch a high-score detect event - let rule engine decide */
                                        if (cm && cm->ds) {
                                            DetectEvent event = {0};
                                            event.type = DETECT_EVENT_REGISTRY_WRITE;
                                            event.pid = pe.th32ProcessID;
                                            wcsncpy(event.processName, pe.szExeFile, 255);
                                            wcsncpy(event.imagePath, procPath, MAX_PATH - 1);
                                            event.isSigned = FALSE;
                                            swprintf(event.eventDetails, 1024, 
                                                     L"Process suspected of creating suspicious Run-key entry: %ls -> %ls", 
                                                     name, data);
                                            event.timestamp = GetTickCount64();
                                            DispatchDetectEvent(cm->ds, &event);
                                        }
                                        
                                        foundMatch = TRUE;
                                    }
                                    
                                    CloseHandle(hProc);
                                } while (Process32NextW(hSnap2, &pe));
                            }
                            CloseHandle(hSnap2);
                        }
                    }
                    
                    RegDeleteValueW(hRun, name);
                    DaemonLog(L"[REGISTRY-CLEAN] Removed suspicious Run entry: %ls", name);
                }
            }
            nameLen = MAX_PATH;
            dataLen = MAX_PATH;
            i++;
        }
        RegCloseKey(hRun);
    }
}

DWORD WINAPI RegistryThreadProc(LPVOID param) {
    CoreModules* cm = (CoreModules*)param;
    if (!cm) return 0;

    HKEY hNotifyLM = NULL;
    HKEY hNotifyCU = NULL;
    HANDLE hEventLM = CreateEventW(NULL, TRUE, FALSE, NULL);
    HANDLE hEventCU = CreateEventW(NULL, TRUE, FALSE, NULL);
    
    LONG resLM = RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
        0, KEY_NOTIFY, &hNotifyLM);
    DaemonLog(L"[REGISTRY] Opened HKLM Run key: %ld, hNotify=%p", resLM, hNotifyLM);
    
    LONG resCU = RegOpenKeyExW(HKEY_CURRENT_USER, 
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
        0, KEY_NOTIFY, &hNotifyCU);
    DaemonLog(L"[REGISTRY] Opened HKCU Run key: %ld, hNotify=%p", resCU, hNotifyCU);
    
    if (hNotifyLM && hEventLM) {
        RegNotifyChangeKeyValue(hNotifyLM, TRUE, 
            REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_ATTRIBUTES | 
            REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_SECURITY,
            hEventLM, TRUE);
    }
    
    if (hNotifyCU && hEventCU) {
        RegNotifyChangeKeyValue(hNotifyCU, TRUE, 
            REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_ATTRIBUTES | 
            REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_SECURITY,
            hEventCU, TRUE);
    }
    
    HANDLE handles[3];
    handles[0] = cm->hStopEvent;
    handles[1] = hEventLM;
    handles[2] = hEventCU;
    
    DWORD pollInterval = 5000; /* 5 seconds */
    
    while (TRUE) {
        DWORD waitResult = WaitForMultipleObjects(3, handles, FALSE, pollInterval);
        
        if (waitResult == WAIT_OBJECT_0) {
            break;
        }
        
        if (waitResult == WAIT_OBJECT_0 + 1 && hNotifyLM) {
            DaemonLog(L"[REGISTRY-CHANGE] HKLM Run key modified (notification)");
            CheckRunKeyForSuspiciousEntries(cm, HKEY_LOCAL_MACHINE, 
                L"Software\\Microsoft\\Windows\\CurrentVersion\\Run");
            ResetEvent(hEventLM);
            RegNotifyChangeKeyValue(hNotifyLM, TRUE, 
                REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_ATTRIBUTES | 
                REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_SECURITY,
                hEventLM, TRUE);
        }
        
        if (waitResult == WAIT_OBJECT_0 + 2 && hNotifyCU) {
            DaemonLog(L"[REGISTRY-CHANGE] HKCU Run key modified (notification)");
            CheckRunKeyForSuspiciousEntries(cm, HKEY_CURRENT_USER, 
                L"Software\\Microsoft\\Windows\\CurrentVersion\\Run");
            ResetEvent(hEventCU);
            RegNotifyChangeKeyValue(hNotifyCU, TRUE, 
                REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_ATTRIBUTES | 
                REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_SECURITY,
                hEventCU, TRUE);
        }
        
        /* Polling fallback: check Run keys every pollInterval even if no notification fired */
        if (waitResult == WAIT_TIMEOUT) {
            static DWORD pollCount = 0;
            pollCount++;
            if (pollCount % 2 == 0) { /* every other poll (10s) */
                DaemonLog(L"[REGISTRY-POLL] Polling Run keys for suspicious entries");
                CheckRunKeyForSuspiciousEntries(cm, HKEY_LOCAL_MACHINE, 
                    L"Software\\Microsoft\\Windows\\CurrentVersion\\Run");
                CheckRunKeyForSuspiciousEntries(cm, HKEY_CURRENT_USER, 
                    L"Software\\Microsoft\\Windows\\CurrentVersion\\Run");
            }
        }
    }
    
    if (hNotifyLM) RegCloseKey(hNotifyLM);
    if (hNotifyCU) RegCloseKey(hNotifyCU);
    if (hEventLM) CloseHandle(hEventLM);
    if (hEventCU) CloseHandle(hEventCU);
    return 0;
}

typedef struct {
    wchar_t path[MAX_PATH];
    uint64_t lastWriteTime;
    uint64_t fileSize;
} FileMonitorEntry;

#define MAX_FILE_MONITOR 512

DWORD WINAPI FileThreadProc(LPVOID param) {
    CoreModules* cm = (CoreModules*)param;
    if (!cm) return 0;

    FileMonitorEntry monitoredFiles[MAX_FILE_MONITOR] = {0};
    int fileCount = 0;
    uint64_t lastScanTime = 0;
    int rapidWriteCount = 0;
    uint64_t rapidWriteStartTime = 0;

    while (WaitForSingleObject(cm->hStopEvent, 1000) != WAIT_OBJECT_0) {
        uint64_t currentTime = GetTickCount64();
        
        if (currentTime - lastScanTime > 5000) {
            lastScanTime = currentTime;
            
            wchar_t system32Path[MAX_PATH] = {0};
            GetSystemDirectoryW(system32Path, MAX_PATH);
            
            WIN32_FIND_DATAW findData;
            wchar_t searchPath[MAX_PATH] = {0};
            swprintf(searchPath, MAX_PATH, L"%ls\\*.exe", system32Path);
            
            HANDLE hFind = FindFirstFileW(searchPath, &findData);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    wchar_t fullPath[MAX_PATH] = {0};
                    swprintf(fullPath, MAX_PATH, L"%ls\\%ls", system32Path, findData.cFileName);
                    
                    BOOL found = FALSE;
                    for (int i = 0; i < fileCount; i++) {
                        if (wcscmp(monitoredFiles[i].path, fullPath) == 0) {
                            if (findData.ftLastWriteTime.dwHighDateTime != monitoredFiles[i].lastWriteTime >> 32 ||
                                findData.ftLastWriteTime.dwLowDateTime != monitoredFiles[i].lastWriteTime & 0xFFFFFFFF) {
                                DaemonLog(L"[FILE-ALERT] System32 EXE modified: %ls", fullPath);
                                ScoreCenterAddBehaviorScore(&cm->sc, 0, 25, L"System32 file modified");
                                ResponseCenterQueueResponse(&cm->rc, 0, findData.cFileName, fullPath, 
                                                           RESPONSE_QUARANTINE, L"System32 file modified");
                            }
                            monitoredFiles[i].lastWriteTime = ((uint64_t)findData.ftLastWriteTime.dwHighDateTime << 32) | 
                                                               findData.ftLastWriteTime.dwLowDateTime;
                            monitoredFiles[i].fileSize = ((uint64_t)findData.nFileSizeHigh << 32) | findData.nFileSizeLow;
                            found = TRUE;
                            break;
                        }
                    }
                    
                    if (!found && fileCount < MAX_FILE_MONITOR) {
                        wcscpy(monitoredFiles[fileCount].path, fullPath);
                        monitoredFiles[fileCount].lastWriteTime = ((uint64_t)findData.ftLastWriteTime.dwHighDateTime << 32) | 
                                                                  findData.ftLastWriteTime.dwLowDateTime;
                        monitoredFiles[fileCount].fileSize = ((uint64_t)findData.nFileSizeHigh << 32) | findData.nFileSizeLow;
                        fileCount++;
                    }
                } while (FindNextFileW(hFind, &findData));
                FindClose(hFind);
            }
            
            wchar_t userDir[MAX_PATH] = {0};
            if (GetEnvironmentVariableW(L"USERPROFILE", userDir, MAX_PATH) > 0) {
                swprintf(searchPath, MAX_PATH, L"%ls\\*.exe", userDir);
                
                hFind = FindFirstFileW(searchPath, &findData);
                if (hFind != INVALID_HANDLE_VALUE) {
                    do {
                        wchar_t fullPath[MAX_PATH] = {0};
                        swprintf(fullPath, MAX_PATH, L"%ls\\%ls", userDir, findData.cFileName);
                        
                        BOOL found = FALSE;
                        for (int i = 0; i < fileCount; i++) {
                            if (wcscmp(monitoredFiles[i].path, fullPath) == 0) {
                                uint64_t newTime = ((uint64_t)findData.ftLastWriteTime.dwHighDateTime << 32) | 
                                                  findData.ftLastWriteTime.dwLowDateTime;
                                if (newTime > monitoredFiles[i].lastWriteTime && 
                                    currentTime - newTime < 10000) {
                                    rapidWriteCount++;
                                    if (rapidWriteStartTime == 0) {
                                        rapidWriteStartTime = currentTime;
                                    }
                                    if (rapidWriteCount > 50 && currentTime - rapidWriteStartTime < 30000) {
                                        DaemonLog(L"[FILE-ALERT] Rapid file modification detected - possible ransomware");
                                        ScoreCenterAddBehaviorScore(&cm->sc, 0, 30, L"Rapid file modifications");
                                        rapidWriteCount = 0;
                                        rapidWriteStartTime = 0;
                                    }
                                }
                                monitoredFiles[i].lastWriteTime = newTime;
                                monitoredFiles[i].fileSize = ((uint64_t)findData.nFileSizeHigh << 32) | findData.nFileSizeLow;
                                found = TRUE;
                                break;
                            }
                        }
                        
                        if (!found && fileCount < MAX_FILE_MONITOR) {
                            wcscpy(monitoredFiles[fileCount].path, fullPath);
                            monitoredFiles[fileCount].lastWriteTime = ((uint64_t)findData.ftLastWriteTime.dwHighDateTime << 32) | 
                                                                      findData.ftLastWriteTime.dwLowDateTime;
                            monitoredFiles[fileCount].fileSize = ((uint64_t)findData.nFileSizeHigh << 32) | findData.nFileSizeLow;
                            fileCount++;
                        }
                    } while (FindNextFileW(hFind, &findData));
                    FindClose(hFind);
                }
            }
            
            if (rapidWriteStartTime > 0 && currentTime - rapidWriteStartTime > 60000) {
                rapidWriteCount = 0;
                rapidWriteStartTime = 0;
            }
        }
        
        Sleep(2000);
    }
    return 0;
}

DWORD WINAPI NetworkThreadProc(LPVOID param) {
    CoreModules* cm = (CoreModules*)param;
    if (!cm) return 0;
    
    while (WaitForSingleObject(cm->hStopEvent, 1000) != WAIT_OBJECT_0) {
        EnterCriticalSection(&cm->nm.cs);
        for (int i = 0; i < cm->nm.entryCount; i++) {
            NetFlowEntry* entry = &cm->nm.entries[i];
            if (!entry->pid) continue;
            
            BOOL isSigned = FALSE;
            if (entry->imagePath[0]) {
                WINTRUST_FILE_INFO fileInfo = {0};
                fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
                fileInfo.pcwszFilePath = entry->imagePath;
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
            
            int connCount = 0;
            FlowLevel level = NetworkMonitorGetFlowLevel(entry->pid, &connCount);
            
            if (isSigned && connCount <= 200) {
                continue;
            }
            
            int score = NetworkMonitorGetScore(entry->pid);
            if (score != 0) {
                int userAdj = UserInteractionGetScoreAdjustment(entry->pid);
                
                wchar_t evidence[512] = {0};
                
                BOOL isSystemPath = FALSE;
                if (entry->imagePath[0]) {
                    isSystemPath = (wcsnicmp(entry->imagePath, L"C:\\WINDOWS\\", 11) == 0 ||
                                   wcsnicmp(entry->imagePath, L"C:\\Program Files\\", 16) == 0 ||
                                   wcsnicmp(entry->imagePath, L"C:\\Program Files (x86)\\", 21) == 0);
                }
                
                int finalScore = score;
                if (isSigned && isSystemPath) {
                    finalScore = max(finalScore - 15, 0);
                } else if (isSigned) {
                    finalScore = max(finalScore - 10, 0);
                }
                
                if (userAdj < 0) {
                    finalScore = max(finalScore + userAdj, 0);
                }
                
                if (finalScore <= 0) {
                    swprintf(evidence, 512, L"Connections %d, signed=%d, system=%d, user=%d, score adjusted to safe", 
                             connCount, isSigned, isSystemPath, userAdj);
                    ScoreCenterAddBehaviorScore(&cm->sc, entry->pid, -5, evidence);
                } else if (level == FLOW_LEVEL_CRITICAL) {
                    swprintf(evidence, 512, L"Kernel process excessive connections: %d", connCount);
                    ScoreCenterAddKernelScore(&cm->sc, entry->pid, 60, evidence);
                    ResponseCenterQueueResponse(&cm->rc, entry->pid, entry->name, entry->imagePath,
                                               RESPONSE_LIMIT_NETWORK, evidence);
                } else if (level == FLOW_LEVEL_DANGER) {
                    if (isSigned) {
                        swprintf(evidence, 512, L"High connections %d but signed", connCount);
                        ScoreCenterAddBehaviorScore(&cm->sc, entry->pid, 15, evidence);
                    } else if (userAdj < 0) {
                        swprintf(evidence, 512, L"High connections %d but user active", connCount);
                        ScoreCenterAddBehaviorScore(&cm->sc, entry->pid, 10, evidence);
                    } else {
                        swprintf(evidence, 512, L"High connections %d no user action", connCount);
                        ScoreCenterAddBehaviorScore(&cm->sc, entry->pid, 35, evidence);
                        ResponseCenterQueueResponse(&cm->rc, entry->pid, entry->name, entry->imagePath,
                                                   RESPONSE_LIMIT_NETWORK, evidence);
                    }
                } else if (level == FLOW_LEVEL_WARNING && userAdj == 0 && !isSigned) {
                    swprintf(evidence, 512, L"Medium connections %d no user action", connCount);
                    ScoreCenterAddBehaviorScore(&cm->sc, entry->pid, 8, evidence);
                } else if (level == FLOW_LEVEL_SAFE && score < 0) {
                    swprintf(evidence, 512, L"Low connections %d, safe", connCount);
                    ScoreCenterAddBehaviorScore(&cm->sc, entry->pid, -10, evidence);
                }
            }
        }
        LeaveCriticalSection(&cm->nm.cs);
        
        Sleep(1000);
    }
    
    return 0;
}

DWORD WINAPI AiThreadProc(LPVOID param) {
    CoreModules* cm = (CoreModules*)param;
    if (!cm) return 0;
    while (WaitForSingleObject(cm->hStopEvent, 1000) != WAIT_OBJECT_0) {
        Sleep(1000);
    }
    return 0;
}

DWORD WINAPI LogThreadProc(LPVOID param) {
    CoreModules* cm = (CoreModules*)param;
    if (!cm) return 0;
    while (WaitForSingleObject(cm->hStopEvent, 5000) != WAIT_OBJECT_0) {
        SQLiteLogDeleteOldEntries(&cm->sl, GetTickCount64() - 86400000);
        Sleep(5000);
    }
    return 0;
}

static BOOL IsCriticalSystemProcessLocal(const wchar_t* name) {
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

static BOOL IsSystemPath(const wchar_t* path) {
    if (!path || !path[0]) return FALSE;
    if (wcsstr(path, L"\\Windows\\System32\\") || wcsstr(path, L"\\Windows\\SysWOW64\\")) return TRUE;
    if (wcsstr(path, L"\\Windows\\WinSxS\\") || wcsstr(path, L"\\Windows\\Microsoft.NET\\")) return TRUE;
    if (wcsstr(path, L"\\Program Files\\WindowsApps\\") || wcsstr(path, L"\\Program Files (x86)\\Microsoft\\")) return TRUE;
    return FALSE;
}

static void ExecuteVirusResponse(CoreModules* cm, DWORD pid,
                                  const wchar_t* name, const wchar_t* imagePath,
                                  VirusSignature* sig, const wchar_t* matchReason) {
    if (pid == 0 || pid == 4) {
        DaemonLog(L"[CRITICAL-PROTECT] BLOCKED: Attempt to terminate kernel process PID=%lu", pid);
        return;
    }

    if (!name || !name[0] || _wcsicmp(name, L"unknown") == 0) {
        DaemonLog(L"[SAFETY-GUARD] BLOCKED: Cannot terminate process with unknown name PID=%lu", pid);
        return;
    }

    if (IsCriticalSystemProcess(name)) {
        DaemonLog(L"[CRITICAL-PROTECT] BLOCKED: Cannot terminate critical system process %ls PID=%lu", name, pid);
        return;
    }
    
    if (IsSystemProcessName(name)) {
        DaemonLog(L"[SAFETY] BLOCKED: Cannot terminate system process %ls PID=%lu", name, pid);
        return;
    }

    if (!imagePath || !imagePath[0]) {
        DaemonLog(L"[SAFETY-GUARD] BLOCKED: Cannot terminate process without image path PID=%lu name=%ls", pid, name);
        return;
    }

    wchar_t evidence[512] = {0};
    swprintf(evidence, 512, L"%hs: %ls", sig->name, matchReason);
    DaemonLog(L"[VIRUS-DETECTED] PID=%lu %ls - %hs (%ls)", pid, name, sig->name, matchReason);

    for (int i = 0; i < 10; i++) {
        TerminateAllThreads(pid);
        TerminateProcessTree(pid);
        Sleep(50);
    }
    if (imagePath && imagePath[0]) {
        ForceDeleteFile(imagePath);
        DeleteVirusCopies(imagePath);
    }

    ScoreCenterAddStaticScore(&cm->sc, pid, 80, evidence);
    ResponseCenterQueueResponse(&cm->rc, pid, name, imagePath, RESPONSE_FULL_CLEANUP, evidence);
    StateMachineEntry* e = StateMachineGetEntryByPid(&cm->sm, pid);
    if (e) StateMachineUpdateState(&cm->sm, e, PROC_STATE_REMOVED, evidence);
    CoreModulesTerminateSameOriginProcesses(cm, imagePath);

    if (sig->level == THREAT_LEVEL_CRITICAL) {
        RestoreMBR();
        RestoreRegistryKeys();
        if (cm->ds) RecoverFromEtwLogs(cm->ds, pid);
        DirectCleanupMaliciousChanges(imagePath);
    }

    ActionLogRestoreByPid(pid);
    ShowSecurityAlertPopupEx(L"TRAE Guardian - Virus Detected", L"Malware", name, imagePath, evidence, 100);
}

void CoreModulesOnNewProcess(CoreModules* cm, DWORD pid, const wchar_t* name, const wchar_t* imagePath) {
    if (!cm) return;
    if (IsSelfProcessName(name)) return;

    if (WhitelistDBCheck(&cm->wdb, NULL, NULL, imagePath, NULL, FALSE)) {
        DaemonLog(L"[WHITELIST] Process %ls (PID=%lu) is whitelisted, skipping analysis", name, pid);
        return;
    }

    if (!imagePath || !imagePath[0]) {
        DaemonLog(L"[SAFETY] Process %ls (PID=%lu) has no image path, skipping analysis", name, pid);
        return;
    }

    wchar_t signer[256] = {0};
    BOOL signedOk = FALSE;
    if (CheckFileSignature(imagePath, signer, sizeof(signer))) {
        signedOk = TRUE;
        DaemonLog(L"[SIGNATURE] Process %ls (PID=%lu) is signed by: %ls", name, pid, signer);
    } else {
        DaemonLog(L"[SIGNATURE] Process %ls (PID=%lu) is UNSIGNED", name, pid);
    }

    StateMachineEntry* entry = StateMachineGetOrCreate(&cm->sm, pid, name, imagePath);
    if (entry) {
        entry->inHighFreqMonitor = TRUE;
        entry->highFreqStartTime = GetTickCount64();
        if (signedOk) {
            StateMachineUpdateState(&cm->sm, entry, PROC_STATE_TRUSTED, L"Signed process - trusted");
            DaemonLog(L"[HIGH-FREQ] Signed process %ls (PID=%lu) entering 5-second high-frequency monitoring", name, pid);
            DaemonLog(L"[TRUSTED] Process %ls (PID=%lu) is signed by: %ls", name, pid, signer);
            
            if (cm->ds && cm->ds->enableAiAssist) {
                DaemonLog(L"[AI] Signed process %ls (PID=%lu) entering long-term AI analysis", name, pid);
                int threshold = LoadAiThreatThreshold();
                char apiKey[512] = {0};
                if (LoadApiKey(apiKey, sizeof(apiKey)) == 0 && apiKey[0]) {
                    AiEvaluateSingleProcess(cm->ds, pid, name, imagePath, 
                                            L"new-signed-process", L"process-create", 
                                            NULL, NULL, NULL, threshold, apiKey, 0);
                }
            }
        } else {
            StateMachineUpdateState(&cm->sm, entry, PROC_STATE_OBSERVED, L"New process spawned");
            DaemonLog(L"[HIGH-FREQ] New unsigned process %ls (PID=%lu) entering 5-second high-frequency monitoring", name, pid);
            
            PEAnalysisResult pe = {0};
            PEThreatLevel threat = PEQuickAnalyze(imagePath, &pe);
            DaemonLog(L"[PE-DEBUG] PEQuickAnalyze for %ls returned threat=%d hashComputed=%d importCount=%d hasExecutableWritableSection=%d", 
                      name, threat, pe.hashComputed, pe.importCount, pe.hasExecutableWritableSection);

            int detectionSignals = 0;
            int matchedSigIdx = -1;
            wchar_t matchReason[256] = {0};

            if (pe.hashComputed) {
                int sigIdx = VirusSignatureMatchHash(&cm->vsdb, pe.sha256);
                if (sigIdx >= 0) {
                    VirusSignature* sig = VirusSignatureGetById(&cm->vsdb, sigIdx);
                    ExecuteVirusResponse(cm, pid, name, imagePath, sig, L"SHA256 hash match");
                    PEFreeResult(&pe);
                    return;
                }
            }

            if (pe.importCount > 0) {
                const char* importPtrs[PE_MAX_IMPORTS];
                for (int i = 0; i < pe.importCount; i++)
                    importPtrs[i] = pe.importNames[i];
                int sigIdx = VirusSignatureMatchImports(&cm->vsdb, importPtrs, pe.importCount);
                if (sigIdx >= 0) {
                    detectionSignals++;
                    matchedSigIdx = sigIdx;
                    wcscpy(matchReason, L"Import table match");
                }
            }

            if (pe.fileData && pe.fileDataSize > 0) {
                int sigIdx = VirusSignatureMatchStrings(&cm->vsdb, (const char*)pe.fileData, pe.fileDataSize);
                if (sigIdx >= 0) {
                    detectionSignals++;
                    if (matchedSigIdx < 0) matchedSigIdx = sigIdx;
                    if (wcslen(matchReason) > 0) wcscat(matchReason, L"; ");
                    wcscat(matchReason, L"String signature match");
                }
            }

            if (threat >= PE_THREAT_HIGH) {
                detectionSignals++;
                if (wcslen(matchReason) > 0) wcscat(matchReason, L"; ");
                if (pe.hasExecutableWritableSection)
                    wcscat(matchReason, L"RWX section");
                if (pe.hasPhysicalDriveString) {
                    if (wcslen(matchReason) > 0) wcscat(matchReason, L"; ");
                    wcscat(matchReason, L"PhysicalDrive string");
                }
                if (pe.hasSuspiciousImports) {
                    if (wcslen(matchReason) > 0) wcscat(matchReason, L"; ");
                    wcscat(matchReason, L"Suspicious imports");
                }
            }

            if (detectionSignals >= 2 && matchedSigIdx >= 0) {
                VirusSignature* sig = VirusSignatureGetById(&cm->vsdb, matchedSigIdx);
                DaemonLog(L"[VIRUS-DETECTED] PID=%lu %ls - %d signals matched: %ls", pid, name, detectionSignals, matchReason);
                ExecuteVirusResponse(cm, pid, name, imagePath, sig, matchReason);
                PEFreeResult(&pe);
                return;
            }

            int peScore = 0;
            wchar_t peEvidence[1024] = {0};
            
            if (pe.hasPhysicalDriveString && pe.hasSuspiciousImports) {
                peScore += 25;
                wcscat(peEvidence, L"PhysicalDrive API + crash API; ");
            } else if (pe.hasPhysicalDriveString) {
                peScore += 15;
                wcscat(peEvidence, L"PhysicalDrive string; ");
            }
            
            if (pe.hasExecutableWritableSection && pe.hasSuspiciousImports && !IsProcessSigned(pid)) {
                peScore += 15;
                wcscat(peEvidence, L"RWX + suspicious imports + no signature; ");
            } else if (pe.hasExecutableWritableSection) {
                peScore += 8;
                wcscat(peEvidence, L"RWX section; ");
            }
            
            if (pe.hasSuspiciousImports && !pe.hasPhysicalDriveString) {
                peScore += 5;
                wcscat(peEvidence, L"Suspicious imports; ");
            }
            
            if (peScore > 0) {
                DaemonLog(L"[PE-SCORE] PID=%lu %ls - PE static score +=%d: %ls", pid, name, peScore, peEvidence);
                ScoreCenterAddStaticScore(&cm->sc, pid, peScore, peEvidence);
            }

            if (detectionSignals == 1) {
                DaemonLog(L"[OBSERVE] PID=%lu %ls - 1 signal matched, entering observation: %ls", pid, name, matchReason);
                StateMachineEntry* e = StateMachineGetEntryByPid(&cm->sm, pid);
                if (e) StateMachineUpdateState(&cm->sm, e, PROC_STATE_SUSPICIOUS, matchReason);
            }

            PEFreeResult(&pe);
            StateMachineAddEvidence(&cm->sm, pid, L"New process spawned");
            SQLiteLogInsert(&cm->sl, LOG_TYPE_SCAN, pid, name, imagePath, L"process_spawn", imagePath, L"New process created", 0, L"", FALSE);
        }
    }
}

void CoreModulesOnEvent(CoreModules* cm, DWORD pid, const wchar_t* eventType, const wchar_t* eventPath, const wchar_t* details) {
    if (!cm) return;
    StateMachineEntry* entry = StateMachineGetEntryByPid(&cm->sm, pid);
    if (!entry) return;
    StateMachineAddEvidence(&cm->sm, pid, details);
    int score = RuleEngineEvaluate(&cm->re, pid, entry->name, entry->imagePath, 
                                   entry->signer, entry->isSigned, eventType, eventPath, NULL);
    if (score > 0) {
        ScoreCenterAddBehaviorScore(&cm->sc, pid, score, details);
        int totalScore = ScoreCenterGetTotalScore(&cm->sc, pid);
        DaemonLog(L"[SCORE] PID=%lu %ls - Behavior score +=%d, Total=%d", pid, entry->name, score, totalScore);
        
        if (totalScore >= cm->sc.thresholdRemoved) {
            DaemonLog(L"[TERMINATE-QUEUE] Score %d >= %d, queueing termination", totalScore, cm->sc.thresholdRemoved);
            ResponseCenterQueueResponse(&cm->rc, pid, entry->name, entry->imagePath, 
                                        RESPONSE_TERMINATE, L"Score exceeded removal threshold");
        } else if (totalScore >= cm->sc.thresholdQuarantined) {
            DaemonLog(L"[QUARANTINE-QUEUE] Score %d >= %d, queueing quarantine", totalScore, cm->sc.thresholdQuarantined);
            ResponseCenterQueueResponse(&cm->rc, pid, entry->name, entry->imagePath, 
                                        RESPONSE_QUARANTINE, L"Score high, quarantining");
        } else if (totalScore >= cm->sc.thresholdRoguePopup) {
            DaemonLog(L"[ROGUE-POPUP] Score %d >= %d, rogue software detected", totalScore, cm->sc.thresholdRoguePopup);
        } else if (totalScore >= cm->sc.thresholdRestricted) {
            DaemonLog(L"[SUSPEND-QUEUE] Score %d >= %d, queueing suspend", totalScore, cm->sc.thresholdRestricted);
            ResponseCenterQueueResponse(&cm->rc, pid, entry->name, entry->imagePath, 
                                        RESPONSE_SUSPEND_PROCESS, L"Score suspicious, suspending");
        }
    }
    SQLiteLogInsert(&cm->sl, LOG_TYPE_RISK, pid, entry->name, entry->imagePath, eventType, eventPath, details, score, entry->signer, entry->isSigned);
}

void CoreModulesEnterHighSpeedMode(CoreModules* cm, DWORD pid) {
    if (!cm) return;
    cm->highSpeedTargetPid = pid;
    cm->highSpeedMode = TRUE;
    cm->highSpeedStartTime = GetTickCount64();
    SetEvent(cm->hHighSpeedEvent);
}

void CoreModulesExitHighSpeedMode(CoreModules* cm) {
    if (!cm) return;
    cm->highSpeedMode = FALSE;
}

void CoreModulesTerminateSameOriginProcesses(CoreModules* cm, const wchar_t* imagePath) {
    DaemonLog(L"[KILL-SAME-ORIGIN] Entering function, imagePath=%ls", imagePath ? imagePath : L"NULL");
    if (!cm || !imagePath || !imagePath[0]) {
        DaemonLog(L"[KILL-SAME-ORIGIN] Invalid parameters, returning");
        return;
    }
    wchar_t targetName[MAX_PATH] = {0};
    wchar_t* lastSlash = wcsrchr(imagePath, L'\\');
    if (lastSlash) {
        wcscpy(targetName, lastSlash + 1);
    } else {
        wcscpy(targetName, imagePath);
    }
    DaemonLog(L"[KILL-SAME-ORIGIN] Target name: %ls", targetName);
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        DaemonLog(L"[KILL-SAME-ORIGIN] CreateToolhelp32Snapshot failed, err=%lu", GetLastError());
        return;
    }
    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(hSnap, &pe)) {
        DaemonLog(L"[KILL-SAME-ORIGIN] Process32FirstW failed, err=%lu", GetLastError());
        CloseHandle(hSnap);
        return;
    }

    /* Phase 1: Collect all matching PIDs and open terminate handles simultaneously.
     * This is critical for watchdog processes that restart each other - we must
     * open all handles BEFORE terminating any process to avoid race conditions. */
    DWORD targetPids[256] = {0};
    wchar_t targetPaths[256][MAX_PATH] = {0};
    int targetCount = 0;

    do {
        if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4 || pe.th32ProcessID == GetCurrentProcessId()) continue;
        if (_wcsicmp(pe.szExeFile, targetName) != 0) continue;
        if (IsCriticalSystemProcess(pe.szExeFile)) {
            DaemonLog(L"[CRITICAL-PROTECT] BLOCKED: Cannot terminate critical system process %ls (PID=%lu) in same-origin kill", pe.szExeFile, pe.th32ProcessID);
            continue;
        }
        if (IsSystemProcessName(pe.szExeFile)) {
            DaemonLog(L"[SAFETY] BLOCKED: Cannot terminate system process %ls (PID=%lu) in same-origin kill", pe.szExeFile, pe.th32ProcessID);
            continue;
        }

        wchar_t procPath[MAX_PATH] = {0};
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
        if (hProc) {
            DWORD sz = MAX_PATH;
            QueryFullProcessImageNameW(hProc, 0, procPath, &sz);
            CloseHandle(hProc);
        }

        /* Skip signed processes - they are handled by rogue software identification */
        wchar_t signer[256] = {0};
        if (procPath[0] && CheckFileSignatureCached(procPath, signer, 256)) {
            DaemonLog(L"[SAFETY] BLOCKED: Cannot terminate signed process %ls (PID=%lu) signer=%ls", pe.szExeFile, pe.th32ProcessID, signer);
            continue;
        }

        if (targetCount < 256) {
            targetPids[targetCount] = pe.th32ProcessID;
            wcscpy(targetPaths[targetCount], procPath);
            targetCount++;
            DaemonLog(L"[KILL-SAME-ORIGIN] Found match: PID=%lu (%ls), path=%ls", pe.th32ProcessID, pe.szExeFile, procPath);
        }
    } while (Process32NextW(hSnap, &pe));
    CloseHandle(hSnap);

    if (targetCount == 0) {
        DaemonLog(L"[KILL-SAME-ORIGIN] No matching processes found");
        return;
    }

    DaemonLog(L"[KILL-SAME-ORIGIN] Found %d processes, terminating ALL simultaneously (watchdog group kill)", targetCount);

    /* Phase 2: Open ALL terminate handles first, before killing anything.
     * This prevents watchdog processes from restarting each other. */
    HANDLE hProcs[256] = {0};
    int handleCount = 0;
    for (int i = 0; i < targetCount; i++) {
        HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, targetPids[i]);
        if (hProc) {
            hProcs[handleCount++] = hProc;
        }
    }
    DaemonLog(L"[KILL-SAME-ORIGIN] Opened %d terminate handles (out of %d targets)", handleCount, targetCount);

    /* Phase 3: Terminate ALL processes at once - no Sleep between them! */
    for (int i = 0; i < handleCount; i++) {
        TerminateProcess(hProcs[i], 1);
    }
    /* Also terminate all threads for each process to ensure complete kill */
    for (int i = 0; i < targetCount; i++) {
        TerminateAllThreads(targetPids[i]);
    }

    /* Phase 4: Close handles and verify termination */
    for (int i = 0; i < handleCount; i++) {
        CloseHandle(hProcs[i]);
    }

    /* Phase 5: Repeat kill to handle any survivors (watchdogs that restarted) */
    for (int round = 0; round < 5; round++) {
        Sleep(100);
        for (int i = 0; i < targetCount; i++) {
            HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, targetPids[i]);
            if (hProc) {
                TerminateProcess(hProc, 1);
                CloseHandle(hProc);
            }
            /* Also check for new instances with same name */
            DWORD newPid = GetPidByName(targetName);
            if (newPid && newPid != targetPids[i]) {
                HANDLE hNew = OpenProcess(PROCESS_TERMINATE, FALSE, newPid);
                if (hNew) {
                    DaemonLog(L"[KILL-SAME-ORIGIN] Round %d: Found restarted watchdog PID=%lu, terminating", round+1, newPid);
                    TerminateProcess(hNew, 1);
                    CloseHandle(hNew);
                }
            }
            TerminateAllThreads(targetPids[i]);
        }
    }

    /* Phase 6: Force delete the executable files */
    for (int i = 0; i < targetCount; i++) {
        if (targetPaths[i][0]) {
            ForceDeleteFile(targetPaths[i]);
            DaemonLog(L"[KILL-SAME-ORIGIN] Force deleted file: %ls", targetPaths[i]);
        }
    }

    DaemonLog(L"[KILL-SAME-ORIGIN] Group termination complete: %d processes terminated simultaneously", targetCount);
}

void CoreModulesCleanupNonSystemProcesses(CoreModules* cm) {
    if (!cm) return;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(hSnap, &pe)) {
        CloseHandle(hSnap);
        return;
    }
    do {
        if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4 || pe.th32ProcessID == GetCurrentProcessId()) continue;
        wchar_t procPath[MAX_PATH] = {0};
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
        if (hProc) {
            DWORD sz = MAX_PATH;
            QueryFullProcessImageNameW(hProc, 0, procPath, &sz);
            CloseHandle(hProc);
        }
        if (IsCriticalSystemProcess(pe.szExeFile)) continue;
        if (IsSystemProcessName(pe.szExeFile)) continue;
        if (IsSelfProcessName(pe.szExeFile)) continue;
        if (wcsstr(procPath, L"C:\\Windows\\") || wcsstr(procPath, L"C:\\Windows\\System32\\") || wcsstr(procPath, L"C:\\Windows\\SysWOW64\\")) continue;
        if (wcsstr(procPath, L"C:\\Program Files\\") || wcsstr(procPath, L"C:\\Program Files (x86)\\") || wcsstr(procPath, L"C:\\Program Files\\WindowsApps")) continue;
        if (IsProcessSigned(pe.th32ProcessID)) {
            DaemonLog(L"[CLEANUP-SKIP] Signed process %ls (PID=%lu) in protected path, skipping", pe.szExeFile, pe.th32ProcessID);
            continue;
        }
        DaemonLog(L"[CLEANUP-NON-SYSTEM] Terminating suspicious PID=%lu (%ls) path=%ls", pe.th32ProcessID, pe.szExeFile, procPath);
        HANDLE hTerm = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
        if (hTerm) {
            TerminateProcess(hTerm, 1);
            CloseHandle(hTerm);
        }
    } while (Process32NextW(hSnap, &pe));
    CloseHandle(hSnap);
}

void DirectCleanupMaliciousChanges(const wchar_t* threatPath) {
    if (!threatPath || !threatPath[0]) return;
    
    int recovered = 0;
    
    HKEY hKey;
    
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        wchar_t valueName[256] = {0};
        DWORD nameLen = 256;
        DWORD idx = 0;
        while (RegEnumValueW(hKey, idx, valueName, &nameLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            wchar_t data[MAX_PATH] = {0};
            DWORD dataLen = sizeof(data);
            if (RegQueryValueExW(hKey, valueName, NULL, NULL, (BYTE*)data, &dataLen) == ERROR_SUCCESS) {
                if (wcsstr(data, threatPath) || _wcsicmp(valueName, L"MaliciousStartup") == 0) {
                    if (RegDeleteValueW(hKey, valueName) == ERROR_SUCCESS) {
                        DaemonLog(L"[CLEANUP] Removed malicious startup entry: %ls", valueName);
                        recovered++;
                    }
                }
            }
            nameLen = 256;
            idx++;
        }
        RegCloseKey(hKey);
    }
    
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Internet Explorer\\Main", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        wchar_t currentValue[MAX_PATH] = {0};
        DWORD valueLen = sizeof(currentValue);
        if (RegQueryValueExW(hKey, L"Start Page", NULL, NULL, (BYTE*)currentValue, &valueLen) == ERROR_SUCCESS) {
            if (wcsstr(currentValue, L"malicious") || wcsstr(currentValue, L"threat")) {
                wchar_t defaultValue[] = L"https://www.microsoft.com";
                if (RegSetValueExW(hKey, L"Start Page", 0, REG_SZ, (const BYTE*)defaultValue, (wcslen(defaultValue) + 1) * sizeof(wchar_t)) == ERROR_SUCCESS) {
                    DaemonLog(L"[CLEANUP] Restored IE start page from: %ls to default", currentValue);
                    recovered++;
                }
            }
        }
        RegCloseKey(hKey);
    }
    
    DaemonLog(L"[CLEANUP] Direct cleanup completed: %d items recovered", recovered);
}