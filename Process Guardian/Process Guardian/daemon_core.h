#ifndef DAEMON_CORE_H
#define DAEMON_CORE_H

#include <windows.h>

#define DAEMON_MUTEX L"Global\\TRAE_Guardian_Daemon_Mutex"
#define SERVICE_WRAPPER_EXE L"trae_guardian_service_wrapper.exe"
#define STOP_DAEMON_EVENT L"Global\\TRAE_Guardian_Stop_Event"
#define MAX_PROC 256
#define MAX_SVC 128
#define MAX_REG 256
#define MAX_PART 64
#define MAX_REG_PROTECTED 128
#define MAX_SYS_REG_PROTECTED 128
#define MAX_PART_PROTECTED 32
#define MAX_PROC_SNAPSHOT 256

#define MAX_COMMON_PROCS 256
#define MAX_PROC_RECORDS 1024
#define MAX_MANUAL_COMMON 64
#define MAX_RASCAL_SIGNERS 64
#define MAX_UNSIGNED_SCORES 128

#include "trust_zone.h"
#include "thread_modules.h"
#include "rule_engine.h"
#include "score_center.h"
#include "state_machine.h"
#include "response_center.h"

#pragma pack(push, 8)
typedef struct {
    wchar_t name[260];
    DWORD pid;
    BOOL isTree;
    BOOL isRepeated;
} ProtectedEntry;
#pragma pack(pop)

typedef struct {
    wchar_t name[256];
} SvcRepeatedEntry;

typedef struct {
    wchar_t fullPath[512];
} RegRepeatedEntry;

typedef struct {
    int diskNumber;
    int partitionNumber;
    wchar_t location[512];
} PartRepeatedEntry;

typedef struct {
    wchar_t fullPath[512];
    wchar_t snapshotFile[512];
} RegProtectedEntry;

typedef struct {
    wchar_t fullPath[512];
    wchar_t snapshotFile[512];
    BOOL isKey;
} SysRegProtectedEntry;

typedef struct {
    DWORD pid;
    wchar_t name[260];
    wchar_t imagePath[MAX_PATH];
} ProcSnapshotEntry;

typedef struct {
    wchar_t imagePath[MAX_PATH];
} CommonProcEntry;

typedef struct {
    wchar_t imagePath[MAX_PATH];
    ULONGLONG totalRuntimeMs;
    ULONGLONG lastSeenTick;
    ULONGLONG firstSeenTick;
} ProcRecordEntry;

typedef struct {
    wchar_t signer[256];
    float score;
    int regWriteCount;
    int installedAppCount;
    int blockOtherCount;
    float aiReputation;
    ULONGLONG lastUpdateTick;
} SignerScoreEntry;

typedef struct {
    wchar_t imagePath[MAX_PATH];
    float score;
    int regWriteCount;
    int regDeleteCount;
    int sysRegDeleteCount;
    int injectCount;
    int selfCopyCount;
    ULONGLONG lastUpdateTick;
} UnsignedScoreEntry;

#define MAX_PROC_ACTIONS 512
#define MAX_ACTION_ENTRIES 2048

typedef enum {
    ACTION_TYPE_REG_SET = 1,
    ACTION_TYPE_REG_DELETE_VALUE = 2,
    ACTION_TYPE_REG_DELETE_KEY = 3,
    ACTION_TYPE_REG_RENAME = 4,
    ACTION_TYPE_FILE_WRITE = 5,
    ACTION_TYPE_FILE_DELETE = 6,
    ACTION_TYPE_FILE_RENAME = 7,
    ACTION_TYPE_FILE_SET_INFO = 8
} ActionType;

typedef enum {
    DETECT_EVENT_NONE = 0,
    DETECT_EVENT_PROCESS_SPAWN = 1,
    DETECT_EVENT_PROCESS_TERMINATE = 2,
    DETECT_EVENT_REGISTRY_WRITE = 3,
    DETECT_EVENT_REGISTRY_DELETE = 4,
    DETECT_EVENT_FILE_WRITE = 5,
    DETECT_EVENT_FILE_DELETE = 6,
    DETECT_EVENT_DISK_HANDLE = 7,
    DETECT_EVENT_INJECTION = 8,
    DETECT_EVENT_MBR_ACCESS = 9,
    DETECT_EVENT_BOOT_CHANGE = 10,
    DETECT_EVENT_NETWORK = 11,
    DETECT_EVENT_SELF_COPY = 12,
    DETECT_EVENT_MASS_FILE_MODIFY = 13,
    DETECT_EVENT_VSS_DELETE = 14,
    DETECT_EVENT_LOG_CLEAR = 15,
    DETECT_EVENT_DEFENDER_DISABLE = 16,
    DETECT_EVENT_MINIMAL_IMPORTS = 17
} DetectEventType;

typedef struct {
    DetectEventType type;
    DWORD pid;
    wchar_t processName[256];
    wchar_t imagePath[MAX_PATH];
    wchar_t signer[256];
    BOOL isSigned;
    wchar_t eventPath[512];
    wchar_t eventDetails[1024];
    uint64_t timestamp;
} DetectEvent;

typedef struct {
    DWORD pid;
    wchar_t procName[260];
    wchar_t imagePath[MAX_PATH];
    ULONGLONG startTime;
    ULONGLONG endTime;
    int actionCount;
    int actions[MAX_PROC_ACTIONS];
    CRITICAL_SECTION cs;
} ProcActionLog;

typedef struct {
    int id;
    DWORD pid;
    ActionType type;
    wchar_t targetPath[512];
    wchar_t valueName[256];
    wchar_t newValue[1024];
    wchar_t oldValue[1024];
    ULONGLONG timestamp;
} ActionEntry;

typedef struct {
    ProcActionLog procs[MAX_PROC_ACTIONS];
    int procCount;
    ActionEntry entries[MAX_ACTION_ENTRIES];
    int entryCount;
    CRITICAL_SECTION cs;
} ActionLogManager;

typedef struct {
    int diskNumber;
    wchar_t snapshotFile[512];
} PartProtectedEntry;

#define MAX_AI_TARGETS 16
#define MAX_AI_TASKS 64

typedef struct {
    int  type;          /* 1=process 2=service 3=registry 4=partition */
    wchar_t name[260];
    DWORD pid;
    BOOL tree;
} AiTarget;

typedef struct {
    wchar_t id[64];
    wchar_t name[256];
    wchar_t startTime[32];
    wchar_t endTime[32];
    int readIntervalSec;
    int readBytes;
    wchar_t memoryFile[MAX_PATH];
    wchar_t soulFile[MAX_PATH];
    BOOL enabled;
    AiTarget targets[MAX_AI_TARGETS];
    int targetCount;
    DWORD lastCheckTick;
} AiTask;

typedef struct DaemonState {
    ProtectedEntry procs[MAX_PROC];
    int procCount;
    SvcRepeatedEntry svcs[MAX_SVC];
    int svcCount;
    RegRepeatedEntry regs[MAX_REG];
    int regCount;
    PartRepeatedEntry parts[MAX_PART];
    int partCount;
    RegProtectedEntry regProt[MAX_REG_PROTECTED];
    int regProtCount;
    SysRegProtectedEntry sysRegProt[MAX_SYS_REG_PROTECTED];
    int sysRegProtCount;
    PartProtectedEntry partProt[MAX_PART_PROTECTED];
    int partProtCount;
    int checkInterval;
    int reloadInterval;
    BOOL enableRegProtection;
    BOOL enablePartProtection;
    BOOL enableSysCriticalProtection;
    BOOL enableAiAssist;
    TrustZoneList tz;
    CommonProcEntry commonProcs[MAX_COMMON_PROCS];
    int commonProcCount;
    BOOL wasModifiedThisTick;
    AiTask aiTasks[MAX_AI_TASKS];
    int aiTaskCount;
    BOOL running;
    int currentCommonMonth; /* YYYYMM format */
    int lastReportDay;      /* YYYYMMDD; 0 means not yet reported */

    /* Process census / runtime-based common process tracking */
    ProcRecordEntry procRecords[MAX_PROC_RECORDS];
    int procRecordCount;
    int censusIntervalMs;
    int maxProcRecordCount;
    ULONGLONG lastCensusTick;
    int censusCount;
    int avgProcCount;
    CommonProcEntry manualCommonProcs[MAX_MANUAL_COMMON];
    int manualCommonProcCount;

    SignerScoreEntry signerScores[MAX_RASCAL_SIGNERS];
    int signerScoreCount;

    UnsignedScoreEntry unsignedScores[MAX_UNSIGNED_SCORES];
    int unsignedScoreCount;
    ULONGLONG scoreResetIntervalMs;
    ULONGLONG lastScoreResetTick;

    ActionLogManager actionLogManager;

    CoreModules* cm;

    HANDLE hStopEvent;
    DWORD serviceWrapperPid;
    BOOL stopRequested;
    
    int highFreqScanIntervalMs;
    int lowFreqScanIntervalMs;

    RuleEngine ruleEngine;
    ScoreCenter scoreCenter;
    StateMachine stateMachine;
    ResponseCenter responseCenter;
} DaemonState;

#ifdef __cplusplus
extern "C" {
#endif

void DaemonLog(const wchar_t* fmt, ...);
void DaemonGetBasePath(wchar_t* out, DWORD len);
BOOL IsSelfProcessName(const wchar_t* name);
BOOL IsCriticalSystemProcess(const wchar_t* name);
BOOL IsSystemProcessName(const wchar_t* name);
BOOL CheckFileSignature(const wchar_t* path, wchar_t* signer, DWORD signerSz);
BOOL CheckFileSignatureCached(const wchar_t* path, wchar_t* signer, DWORD signerSz);
void DaemonLoadAll(DaemonState* s);
void DaemonLoadSettings(DaemonState* s);
void DaemonLoadDlls(DaemonState* s);
void DaemonTick(DaemonState* s);
void DaemonStartAiTaskThread(DaemonState* s);
DWORD GetPidByName(const wchar_t* name);
void StartAiActionPipeServer(DaemonState* s);
void StartEtwMonitoring(DaemonState* s);
void StartHookPipeServer(DaemonState* s);
void StopHookPipeServer(DaemonState* s);
BOOL InjectHookDll(DWORD pid);
void CacheFilePath(DWORD pid, const wchar_t* procName, const wchar_t* filePath);
BOOL DeleteCachedFile(DWORD pid, const wchar_t* procName);
void CleanupStaleCache(void);
void StopEtwMonitoring(void);
void DispatchDetectEvent(DaemonState* s, const DetectEvent* event);
const wchar_t* DetectEventTypeToString(DetectEventType type);

void ShowSecurityAlertPopupEx(const wchar_t* title, const wchar_t* threatType, const wchar_t* procName, 
                               const wchar_t* imagePath, const wchar_t* evidence, int score);

void ActionLogRestoreByPid(DWORD pid);
void AddRepeatedKillByName(DaemonState* s, const wchar_t* name);
void TerminateWatchdogGroup(DaemonState* s, DWORD pid, const wchar_t* procName, const wchar_t* procPath);
void RecoverFromEtwLogs(DaemonState* s, DWORD pid);
void AiEvaluateSingleProcess(DaemonState* s, DWORD pid, const wchar_t* procName,
                             const wchar_t* imgPath, const wchar_t* modifiedObject,
                             const wchar_t* objectType, const wchar_t* regValueName,
                             const wchar_t* regData, const wchar_t* regOldData,
                             int threshold, const char* apiKey, int pathScore);
int LoadAiThreatThreshold(void);
int LoadApiKey(char* out, int outSz);

#ifdef __cplusplus
}
#endif

#endif