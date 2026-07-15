#ifndef STATE_MACHINE_H
#define STATE_MACHINE_H

#include <windows.h>
#include <stdint.h>

typedef enum {
    PROC_STATE_UNKNOWN = 0,
    PROC_STATE_OBSERVED = 1,
    PROC_STATE_SUSPICIOUS = 2,
    PROC_STATE_RESTRICTED = 3,
    PROC_STATE_QUARANTINED = 4,
    PROC_STATE_REMOVED = 5,
    PROC_STATE_WHITELISTED = 6,
    PROC_STATE_TRUSTED = 7
} ProcessState;

typedef struct StateMachineEntry {
    DWORD pid;
    wchar_t name[256];
    wchar_t imagePath[MAX_PATH];
    wchar_t signer[256];
    BOOL isSigned;
    ProcessState state;
    uint64_t stateEnterTime;
    uint32_t observedDuration;
    uint32_t suspiciousDuration;
    BOOL inHighFreqMonitor;
    uint64_t highFreqStartTime;
    struct {
        int staticScore;
        int behaviorScore;
        int kernelScore;
        int aiScore;
    } scores;
    int totalScore;
    uint32_t evidenceCount;
    wchar_t lastEvidence[1024];
    uint64_t createTime;
    DWORD parentPid;
    uint32_t handleScanCount;
    uint32_t networkConnectionCount;
    uint32_t registryOperationCount;
    uint32_t fileOperationCount;
    uint32_t processSpawnCount;
    BOOL isSystemProcess;
    BOOL isService;
    BOOL isAiAnalyzed;
    wchar_t aiAnalysis[2048];
    struct StateMachineEntry* next;
} StateMachineEntry;

typedef struct {
    StateMachineEntry* head;
    CRITICAL_SECTION cs;
    HANDLE hChangeEvent;
    uint32_t entryCount;
} StateMachine;

BOOL StateMachineInit(StateMachine* sm);
void StateMachineCleanup(StateMachine* sm);
StateMachineEntry* StateMachineGetOrCreate(StateMachine* sm, DWORD pid, const wchar_t* name, const wchar_t* imagePath);
void StateMachineUpdateState(StateMachine* sm, StateMachineEntry* entry, ProcessState newState, const wchar_t* reason);
ProcessState StateMachineGetState(StateMachine* sm, DWORD pid);
void StateMachineRemove(StateMachine* sm, DWORD pid);
void StateMachinePurgeOldEntries(StateMachine* sm, uint64_t maxAgeMs);
void StateMachineTick(StateMachine* sm);
StateMachineEntry* StateMachineGetEntryByPid(StateMachine* sm, DWORD pid);
void StateMachineAddEvidence(StateMachine* sm, DWORD pid, const wchar_t* evidence);
const wchar_t* StateMachineGetStateName(ProcessState state);
BOOL StateMachineTransition(StateMachineEntry* entry, ProcessState newState, const wchar_t* reason);
void StateMachineDump(StateMachine* sm);

#endif