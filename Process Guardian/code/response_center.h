#ifndef RESPONSE_CENTER_H
#define RESPONSE_CENTER_H

#include <windows.h>
#include <stdint.h>

typedef enum {
    RESPONSE_NONE = 0,
    RESPONSE_OBSERVE = 1,
    RESPONSE_NOTIFY = 2,
    RESPONSE_LIMIT_NETWORK = 3,
    RESPONSE_SUSPEND_THREADS = 4,
    RESPONSE_SUSPEND_PROCESS = 5,
    RESPONSE_TERMINATE = 6,
    RESPONSE_QUARANTINE = 7,
    RESPONSE_DELETE = 8,
    RESPONSE_BLACKLIST = 9,
    RESPONSE_RESTORE = 10,
    RESPONSE_FULL_CLEANUP = 11,
    RESPONSE_REPEATED_KILL = 12,
    RESPONSE_WATCHDOG_KILL = 13
} ResponseAction;

typedef struct ResponseEntry {
    DWORD pid;
    wchar_t name[256];
    wchar_t imagePath[MAX_PATH];
    ResponseAction action;
    const wchar_t* reason;
    uint64_t timestamp;
    BOOL executed;
    BOOL userConfirmed;
    struct ResponseEntry* next;
} ResponseEntry;

typedef struct {
    ResponseEntry* head;
    CRITICAL_SECTION cs;
    HANDLE hResponseEvent;
    uint32_t entryCount;
    BOOL requireUserConfirm;
} ResponseCenter;

BOOL ResponseCenterInit(ResponseCenter* rc, BOOL requireUserConfirm);
void ResponseCenterCleanup(ResponseCenter* rc);
BOOL ResponseCenterQueueResponse(ResponseCenter* rc, DWORD pid, const wchar_t* name, 
                                 const wchar_t* imagePath, ResponseAction action, 
                                 const wchar_t* reason);
BOOL ResponseCenterExecuteResponse(ResponseCenter* rc, ResponseEntry* entry);
BOOL ResponseCenterExecuteByPid(ResponseCenter* rc, DWORD pid, ResponseAction action, 
                                 const wchar_t* reason);
void ResponseCenterProcessQueue(ResponseCenter* rc);
void ResponseCenterRemove(ResponseCenter* rc, DWORD pid);
void ResponseCenterPurgeOldEntries(ResponseCenter* rc, uint64_t maxAgeMs);
void ResponseCenterDump(ResponseCenter* rc);
const wchar_t* ResponseCenterGetActionName(ResponseAction action);
BOOL ResponseLimitNetwork(DWORD pid);
BOOL ResponseSuspendProcess(DWORD pid);
BOOL ResponseResumeProcess(DWORD pid);
BOOL ResponseTerminateProcess(DWORD pid);
BOOL ResponseQuarantine(DWORD pid, const wchar_t* imagePath);
BOOL ResponseDelete(DWORD pid, const wchar_t* imagePath);
void TerminateAllThreads(DWORD pid);
void TerminateProcessTree(DWORD pid);
void ForceDeleteFile(const wchar_t* path);
void DeleteVirusCopies(const wchar_t* originalPath);

#endif