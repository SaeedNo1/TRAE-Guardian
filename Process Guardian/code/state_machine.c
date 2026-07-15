#define UNICODE
#define _UNICODE

#include "state_machine.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

static const wchar_t* g_stateNames[] = {
    L"Unknown",
    L"Observed",
    L"Suspicious",
    L"Restricted",
    L"Quarantined",
    L"Removed",
    L"Whitelisted",
    L"Trusted"
};

const wchar_t* StateMachineGetStateName(ProcessState state) {
    if (state >= PROC_STATE_UNKNOWN && state <= PROC_STATE_TRUSTED) {
        return g_stateNames[state];
    }
    return L"Unknown";
}

BOOL StateMachineInit(StateMachine* sm) {
    if (!sm) return FALSE;
    memset(sm, 0, sizeof(StateMachine));
    InitializeCriticalSection(&sm->cs);
    sm->hChangeEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    return sm->hChangeEvent != NULL;
}

void StateMachineCleanup(StateMachine* sm) {
    if (!sm) return;
    EnterCriticalSection(&sm->cs);
    StateMachineEntry* entry = sm->head;
    while (entry) {
        StateMachineEntry* next = entry->next;
        free(entry);
        entry = next;
    }
    sm->head = NULL;
    sm->entryCount = 0;
    LeaveCriticalSection(&sm->cs);
    DeleteCriticalSection(&sm->cs);
    if (sm->hChangeEvent) {
        CloseHandle(sm->hChangeEvent);
        sm->hChangeEvent = NULL;
    }
}

StateMachineEntry* StateMachineGetEntryByPid(StateMachine* sm, DWORD pid) {
    if (!sm || pid == 0) return NULL;
    EnterCriticalSection(&sm->cs);
    StateMachineEntry* entry = sm->head;
    while (entry) {
        if (entry->pid == pid) {
            LeaveCriticalSection(&sm->cs);
            return entry;
        }
        entry = entry->next;
    }
    LeaveCriticalSection(&sm->cs);
    return NULL;
}

StateMachineEntry* StateMachineGetOrCreate(StateMachine* sm, DWORD pid, const wchar_t* name, const wchar_t* imagePath) {
    if (!sm || pid == 0) return NULL;
    EnterCriticalSection(&sm->cs);
    StateMachineEntry* entry = sm->head;
    while (entry) {
        if (entry->pid == pid) {
            if (name && name[0]) {
                wcsncpy(entry->name, name, sizeof(entry->name) / sizeof(wchar_t) - 1);
                entry->name[sizeof(entry->name) / sizeof(wchar_t) - 1] = L'\0';
            }
            if (imagePath && imagePath[0]) {
                wcsncpy(entry->imagePath, imagePath, sizeof(entry->imagePath) / sizeof(wchar_t) - 1);
                entry->imagePath[sizeof(entry->imagePath) / sizeof(wchar_t) - 1] = L'\0';
            }
            LeaveCriticalSection(&sm->cs);
            return entry;
        }
        entry = entry->next;
    }
    entry = (StateMachineEntry*)malloc(sizeof(StateMachineEntry));
    if (!entry) {
        LeaveCriticalSection(&sm->cs);
        return NULL;
    }
    memset(entry, 0, sizeof(StateMachineEntry));
    entry->pid = pid;
    if (name && name[0]) {
        wcsncpy(entry->name, name, sizeof(entry->name) / sizeof(wchar_t) - 1);
        entry->name[sizeof(entry->name) / sizeof(wchar_t) - 1] = L'\0';
    } else {
        wcscpy(entry->name, L"unknown");
    }
    if (imagePath && imagePath[0]) {
        wcsncpy(entry->imagePath, imagePath, sizeof(entry->imagePath) / sizeof(wchar_t) - 1);
        entry->imagePath[sizeof(entry->imagePath) / sizeof(wchar_t) - 1] = L'\0';
    }
    entry->state = PROC_STATE_UNKNOWN;
    entry->createTime = GetTickCount64();
    entry->stateEnterTime = entry->createTime;
    entry->next = sm->head;
    sm->head = entry;
    sm->entryCount++;
    LeaveCriticalSection(&sm->cs);
    return entry;
}

BOOL StateMachineTransition(StateMachineEntry* entry, ProcessState newState, const wchar_t* reason) {
    if (!entry) return FALSE;
    if (entry->state == newState) return FALSE;
    
    entry->state = newState;
    entry->stateEnterTime = GetTickCount64();
    if (reason && reason[0]) {
        wcsncpy(entry->lastEvidence, reason, sizeof(entry->lastEvidence) / sizeof(wchar_t) - 1);
        entry->lastEvidence[sizeof(entry->lastEvidence) / sizeof(wchar_t) - 1] = L'\0';
    }
    if (newState == PROC_STATE_OBSERVED) {
        entry->observedDuration = 0;
    } else if (newState == PROC_STATE_SUSPICIOUS) {
        entry->suspiciousDuration = 0;
    }
    return TRUE;
}

BOOL StateMachineCanTransition(StateMachineEntry* entry, ProcessState newState) {
    if (!entry) return FALSE;
    if (entry->state == newState) return FALSE;
    if (entry->state == PROC_STATE_REMOVED) return FALSE;
    return TRUE;
}

void StateMachineUpdateState(StateMachine* sm, StateMachineEntry* entry, ProcessState newState, const wchar_t* reason) {
    if (!sm || !entry) return;
    EnterCriticalSection(&sm->cs);
    if (StateMachineTransition(entry, newState, reason)) {
        SetEvent(sm->hChangeEvent);
    }
    LeaveCriticalSection(&sm->cs);
}

ProcessState StateMachineGetState(StateMachine* sm, DWORD pid) {
    StateMachineEntry* entry = StateMachineGetEntryByPid(sm, pid);
    return entry ? entry->state : PROC_STATE_UNKNOWN;
}

void StateMachineRemove(StateMachine* sm, DWORD pid) {
    if (!sm || pid == 0) return;
    EnterCriticalSection(&sm->cs);
    StateMachineEntry** pp = &sm->head;
    while (*pp) {
        StateMachineEntry* entry = *pp;
        if (entry->pid == pid) {
            *pp = entry->next;
            free(entry);
            sm->entryCount--;
            SetEvent(sm->hChangeEvent);
            break;
        }
        pp = &entry->next;
    }
    LeaveCriticalSection(&sm->cs);
}

void StateMachinePurgeOldEntries(StateMachine* sm, uint64_t maxAgeMs) {
    if (!sm) return;
    uint64_t now = GetTickCount64();
    EnterCriticalSection(&sm->cs);
    StateMachineEntry** pp = &sm->head;
    while (*pp) {
        StateMachineEntry* entry = *pp;
        if (entry->state == PROC_STATE_REMOVED && (now - entry->stateEnterTime) > maxAgeMs) {
            *pp = entry->next;
            free(entry);
            sm->entryCount--;
            continue;
        }
        pp = &entry->next;
    }
    LeaveCriticalSection(&sm->cs);
}

void StateMachineAddEvidence(StateMachine* sm, DWORD pid, const wchar_t* evidence) {
    if (!sm || !evidence || !evidence[0]) return;
    StateMachineEntry* entry = StateMachineGetEntryByPid(sm, pid);
    if (!entry) return;
    EnterCriticalSection(&sm->cs);
    entry->evidenceCount++;
    wcsncpy(entry->lastEvidence, evidence, sizeof(entry->lastEvidence) / sizeof(wchar_t) - 1);
    entry->lastEvidence[sizeof(entry->lastEvidence) / sizeof(wchar_t) - 1] = L'\0';
    LeaveCriticalSection(&sm->cs);
}

void StateMachineTick(StateMachine* sm) {
    if (!sm) return;
    uint64_t now = GetTickCount64();
    EnterCriticalSection(&sm->cs);
    StateMachineEntry* entry = sm->head;
    while (entry) {
        if (entry->state == PROC_STATE_OBSERVED) {
            entry->observedDuration = (uint32_t)(now - entry->stateEnterTime);
        } else if (entry->state == PROC_STATE_SUSPICIOUS) {
            entry->suspiciousDuration = (uint32_t)(now - entry->stateEnterTime);
        }
        entry->totalScore = entry->scores.staticScore + entry->scores.behaviorScore + 
                            entry->scores.kernelScore + entry->scores.aiScore;
        
        uint64_t timeInState = now - entry->stateEnterTime;
        
        if (entry->state == PROC_STATE_RESTRICTED && entry->totalScore < 30 && timeInState > 600000) {
            StateMachineTransition(entry, PROC_STATE_SUSPICIOUS, L"Score dropped, downgraded");
        } else if (entry->state == PROC_STATE_SUSPICIOUS && entry->totalScore < 10 && timeInState > 300000) {
            StateMachineTransition(entry, PROC_STATE_OBSERVED, L"Score dropped, downgraded");
        } else if (entry->state == PROC_STATE_OBSERVED && entry->totalScore == 0 && timeInState > 600000) {
            StateMachineTransition(entry, PROC_STATE_TRUSTED, L"Long time clean, promoted to trusted");
        }
        
        entry = entry->next;
    }
    LeaveCriticalSection(&sm->cs);
    StateMachinePurgeOldEntries(sm, 300000);
}

void StateMachineDump(StateMachine* sm) {
    if (!sm) return;
    EnterCriticalSection(&sm->cs);
    StateMachineEntry* entry = sm->head;
    while (entry) {
        wprintf(L"[SM] PID=%lu Name=%ls State=%ls Score=%d (S=%d B=%d K=%d AI=%d) Evidences=%u\n",
                entry->pid, entry->name, StateMachineGetStateName(entry->state),
                entry->totalScore, entry->scores.staticScore, entry->scores.behaviorScore,
                entry->scores.kernelScore, entry->scores.aiScore, entry->evidenceCount);
        entry = entry->next;
    }
    LeaveCriticalSection(&sm->cs);
}