#define UNICODE
#define _UNICODE

#include "score_center.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const wchar_t* g_levelNames[] = {
    L"Unknown",
    L"Observed",
    L"Suspicious",
    L"Restricted",
    L"Quarantined",
    L"Removed"
};

const wchar_t* ScoreCenterGetLevelName(int level) {
    if (level >= 0 && level <= 5) {
        return g_levelNames[level];
    }
    return L"Unknown";
}

static void FreeScoreEntry(void* value) {
    if (value) {
        free(value);
    }
}

uint64_t ScoreCenterMakeKey(DWORD pid, uint64_t createTime) {
    return ((uint64_t)pid << 32) | (createTime & 0xFFFFFFFFULL);
}

BOOL ScoreCenterInit(ScoreCenter* sc) {
    if (!sc) return FALSE;
    memset(sc, 0, sizeof(ScoreCenter));
    if (!HashTableInit(&sc->entries, FreeScoreEntry)) {
        return FALSE;
    }
    sc->hChangeEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    sc->thresholdObserved = THRESHOLD_OBSERVED;
    sc->thresholdSuspicious = THRESHOLD_SUSPICIOUS;
    sc->thresholdRestricted = THRESHOLD_RESTRICTED;
    sc->thresholdRoguePopup = THRESHOLD_ROGUE_POPUP;
    sc->thresholdQuarantined = THRESHOLD_QUARANTINED;
    sc->thresholdRemoved = THRESHOLD_REMOVED;
    sc->behaviorDecayRate = 2;
    sc->kernelDecayRate = 1;
    return sc->hChangeEvent != NULL;
}

void ScoreCenterCleanup(ScoreCenter* sc) {
    if (!sc) return;
    HashTableCleanup(&sc->entries);
    if (sc->hChangeEvent) {
        CloseHandle(sc->hChangeEvent);
        sc->hChangeEvent = NULL;
    }
}

ScoreEntry* ScoreCenterGetByKey(ScoreCenter* sc, uint64_t key) {
    if (!sc) return NULL;
    return (ScoreEntry*)HashTableGet(&sc->entries, key);
}

typedef struct {
    DWORD pid;
    uint64_t now;
    ScoreEntry* found;
} FindByPidContext;

static void FindByPidCallback(uint64_t key, void* value, void* context) {
    ScoreEntry* entry = (ScoreEntry*)value;
    FindByPidContext* ctx = (FindByPidContext*)context;
    if (entry->pid == ctx->pid && (ctx->now - entry->lastUpdateTime) < 300000) {
        ctx->found = entry;
    }
}

ScoreEntry* ScoreCenterGetByPid(ScoreCenter* sc, DWORD pid) {
    if (!sc) return NULL;
    
    FindByPidContext ctx = {0};
    ctx.pid = pid;
    ctx.now = GetTickCount64();
    ctx.found = NULL;
    
    HashTableIterate(&sc->entries, FindByPidCallback, &ctx);
    return ctx.found;
}

BOOL ScoreCenterCopyEntry(ScoreCenter* sc, uint64_t key, ScoreEntry* out) {
    if (!sc || !out) return FALSE;
    
    EnterCriticalSection(&sc->entries.cs);
    ScoreEntry* entry = (ScoreEntry*)HashTableGet(&sc->entries, key);
    if (entry) {
        *out = *entry;
        LeaveCriticalSection(&sc->entries.cs);
        return TRUE;
    }
    LeaveCriticalSection(&sc->entries.cs);
    return FALSE;
}

ScoreEntry* ScoreCenterGetOrCreate(ScoreCenter* sc, DWORD pid, uint64_t createTime, const wchar_t* name, const wchar_t* imagePath) {
    if (!sc || pid == 0) return NULL;
    
    uint64_t key = ScoreCenterMakeKey(pid, createTime);
    
    EnterCriticalSection(&sc->entries.cs);
    
    ScoreEntry* entry = (ScoreEntry*)HashTableGet(&sc->entries, key);
    if (entry) {
        if (name && name[0]) {
            wcsncpy(entry->name, name, sizeof(entry->name) / sizeof(wchar_t) - 1);
            entry->name[sizeof(entry->name) / sizeof(wchar_t) - 1] = L'\0';
        }
        if (imagePath && imagePath[0]) {
            wcsncpy(entry->imagePath, imagePath, sizeof(entry->imagePath) / sizeof(wchar_t) - 1);
            entry->imagePath[sizeof(entry->imagePath) / sizeof(wchar_t) - 1] = L'\0';
        }
        entry->lastUpdateTime = GetTickCount64();
        LeaveCriticalSection(&sc->entries.cs);
        return entry;
    }
    
    entry = (ScoreEntry*)malloc(sizeof(ScoreEntry));
    if (!entry) {
        LeaveCriticalSection(&sc->entries.cs);
        return NULL;
    }
    memset(entry, 0, sizeof(ScoreEntry));
    entry->pid = pid;
    entry->createTime = createTime;
    entry->entryKey = key;
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
    entry->lastUpdateTime = GetTickCount64();
    entry->behaviorDecayBaseTime = entry->lastUpdateTime;
    entry->kernelDecayBaseTime = entry->lastUpdateTime;
    
    HashTableInsert(&sc->entries, key, entry);
    
    LeaveCriticalSection(&sc->entries.cs);
    return entry;
}

static void AppendEvidence(wchar_t* buffer, DWORD bufferSize, const wchar_t* evidence) {
    if (!buffer || !evidence || !evidence[0]) return;
    size_t len = wcslen(buffer);
    if (len + wcslen(evidence) + 4 < bufferSize) {
        if (len > 0) wcscat(buffer, L"; ");
        wcscat(buffer, evidence);
    }
}

void ScoreCenterAddStaticScore(ScoreCenter* sc, uint64_t key, int score, const wchar_t* evidence) {
    if (!sc) return;
    
    EnterCriticalSection(&sc->entries.cs);
    
    ScoreEntry* entry = (ScoreEntry*)HashTableGet(&sc->entries, key);
    if (!entry) {
        LeaveCriticalSection(&sc->entries.cs);
        return;
    }
    
    entry->staticScore = min(entry->staticScore + score, MAX_STATIC_SCORE);
    if (entry->staticEvidenceCount < MAX_EVIDENCE_TAGS) {
        uint32_t idx = entry->staticEvidenceCount;
        entry->staticEvidenceTags[idx] = (EvidenceTag)(score * 1000 + idx);
        entry->staticEvidenceCount++;
    }
    AppendEvidence(entry->staticEvidence, sizeof(entry->staticEvidence) / sizeof(wchar_t), evidence);
    entry->lastUpdateTime = GetTickCount64();
    entry->totalScore = entry->staticScore + entry->behaviorScore + entry->kernelScore + entry->aiScore;
    
    LeaveCriticalSection(&sc->entries.cs);
    SetEvent(sc->hChangeEvent);
}

void ScoreCenterAddBehaviorScore(ScoreCenter* sc, uint64_t key, int score, const wchar_t* evidence) {
    if (!sc) return;
    
    EnterCriticalSection(&sc->entries.cs);
    
    ScoreEntry* entry = (ScoreEntry*)HashTableGet(&sc->entries, key);
    if (!entry) {
        LeaveCriticalSection(&sc->entries.cs);
        return;
    }
    
    entry->behaviorScore = min(entry->behaviorScore + score, MAX_BEHAVIOR_SCORE);
    if (entry->behaviorEvidenceCount < MAX_EVIDENCE_TAGS) {
        uint32_t idx = entry->behaviorEvidenceCount;
        entry->behaviorEvidenceTags[idx] = (EvidenceTag)(score * 1000 + idx);
        entry->behaviorEvidenceCount++;
    }
    AppendEvidence(entry->behaviorEvidence, sizeof(entry->behaviorEvidence) / sizeof(wchar_t), evidence);
    entry->lastUpdateTime = GetTickCount64();
    entry->behaviorDecayBaseTime = entry->lastUpdateTime;
    entry->totalScore = entry->staticScore + entry->behaviorScore + entry->kernelScore + entry->aiScore;
    
    LeaveCriticalSection(&sc->entries.cs);
    SetEvent(sc->hChangeEvent);
}

void ScoreCenterAddKernelScore(ScoreCenter* sc, uint64_t key, int score, const wchar_t* evidence) {
    if (!sc) return;
    
    EnterCriticalSection(&sc->entries.cs);
    
    ScoreEntry* entry = (ScoreEntry*)HashTableGet(&sc->entries, key);
    if (!entry) {
        LeaveCriticalSection(&sc->entries.cs);
        return;
    }
    
    entry->kernelScore = min(entry->kernelScore + score, MAX_KERNEL_SCORE);
    if (entry->kernelEvidenceCount < MAX_EVIDENCE_TAGS) {
        uint32_t idx = entry->kernelEvidenceCount;
        entry->kernelEvidenceTags[idx] = (EvidenceTag)(score * 1000 + idx);
        entry->kernelEvidenceCount++;
    }
    AppendEvidence(entry->kernelEvidence, sizeof(entry->kernelEvidence) / sizeof(wchar_t), evidence);
    entry->lastUpdateTime = GetTickCount64();
    entry->kernelDecayBaseTime = entry->lastUpdateTime;
    entry->totalScore = entry->staticScore + entry->behaviorScore + entry->kernelScore + entry->aiScore;
    
    LeaveCriticalSection(&sc->entries.cs);
    SetEvent(sc->hChangeEvent);
}

void ScoreCenterAddAiScore(ScoreCenter* sc, uint64_t key, int score, const wchar_t* evidence) {
    if (!sc) return;
    
    EnterCriticalSection(&sc->entries.cs);
    
    ScoreEntry* entry = (ScoreEntry*)HashTableGet(&sc->entries, key);
    if (!entry) {
        LeaveCriticalSection(&sc->entries.cs);
        return;
    }
    
    entry->aiScore = entry->aiScore + score;
    if (entry->aiScore > MAX_AI_SCORE) entry->aiScore = MAX_AI_SCORE;
    if (entry->aiScore < -MAX_AI_SCORE) entry->aiScore = -MAX_AI_SCORE;
    if (entry->aiEvidenceCount < MAX_EVIDENCE_TAGS) {
        uint32_t idx = entry->aiEvidenceCount;
        entry->aiEvidenceTags[idx] = (EvidenceTag)(score * 1000 + idx);
        entry->aiEvidenceCount++;
    }
    AppendEvidence(entry->aiEvidence, sizeof(entry->aiEvidence) / sizeof(wchar_t), evidence);
    entry->lastUpdateTime = GetTickCount64();
    entry->totalScore = entry->staticScore + entry->behaviorScore + entry->kernelScore + entry->aiScore;
    
    LeaveCriticalSection(&sc->entries.cs);
    SetEvent(sc->hChangeEvent);
}

int ScoreCenterGetTotalScore(ScoreCenter* sc, uint64_t key) {
    if (!sc) return 0;
    
    EnterCriticalSection(&sc->entries.cs);
    
    ScoreEntry* entry = (ScoreEntry*)HashTableGet(&sc->entries, key);
    int score = entry ? entry->totalScore : 0;
    
    LeaveCriticalSection(&sc->entries.cs);
    return score;
}

void ScoreCenterGetScoreBreakdown(ScoreCenter* sc, uint64_t key, int* staticScore, int* behaviorScore, int* kernelScore, int* aiScore) {
    if (!sc) {
        if (staticScore) *staticScore = 0;
        if (behaviorScore) *behaviorScore = 0;
        if (kernelScore) *kernelScore = 0;
        if (aiScore) *aiScore = 0;
        return;
    }
    
    EnterCriticalSection(&sc->entries.cs);
    
    ScoreEntry* entry = (ScoreEntry*)HashTableGet(&sc->entries, key);
    if (entry) {
        if (staticScore) *staticScore = entry->staticScore;
        if (behaviorScore) *behaviorScore = entry->behaviorScore;
        if (kernelScore) *kernelScore = entry->kernelScore;
        if (aiScore) *aiScore = entry->aiScore;
    } else {
        if (staticScore) *staticScore = 0;
        if (behaviorScore) *behaviorScore = 0;
        if (kernelScore) *kernelScore = 0;
        if (aiScore) *aiScore = 0;
    }
    
    LeaveCriticalSection(&sc->entries.cs);
}

void ScoreCenterRemove(ScoreCenter* sc, uint64_t key) {
    if (!sc) return;
    HashTableRemove(&sc->entries, key);
    SetEvent(sc->hChangeEvent);
}

typedef struct {
    DWORD pid;
    uint64_t removeKey;
} RemoveByPidContext;

static void RemoveByPidCallback(uint64_t key, void* value, void* context) {
    ScoreEntry* entry = (ScoreEntry*)value;
    RemoveByPidContext* ctx = (RemoveByPidContext*)context;
    if (entry->pid == ctx->pid) {
        ctx->removeKey = key;
    }
}

void ScoreCenterRemoveByPid(ScoreCenter* sc, DWORD pid) {
    if (!sc) return;
    
    EnterCriticalSection(&sc->entries.cs);
    
    RemoveByPidContext ctx = {0};
    ctx.pid = pid;
    ctx.removeKey = 0;
    
    HashTableIterate(&sc->entries, RemoveByPidCallback, &ctx);
    
    if (ctx.removeKey != 0) {
        HashTableRemove(&sc->entries, ctx.removeKey);
        SetEvent(sc->hChangeEvent);
    }
    
    LeaveCriticalSection(&sc->entries.cs);
}

typedef struct {
    uint64_t now;
    uint64_t toRemove[128];
    int removeCount;
} PurgeContext;

static void PurgeCallback(uint64_t key, void* value, void* context) {
    ScoreEntry* entry = (ScoreEntry*)value;
    PurgeContext* ctx = (PurgeContext*)context;
    if ((ctx->now - entry->lastUpdateTime) > 300000) {
        if (ctx->removeCount < 128) {
            ctx->toRemove[ctx->removeCount++] = key;
        }
    }
}

void ScoreCenterPurgeOldEntries(ScoreCenter* sc, uint64_t maxAgeMs) {
    if (!sc) return;
    
    PurgeContext ctx = {0};
    ctx.now = GetTickCount64();
    ctx.removeCount = 0;
    
    EnterCriticalSection(&sc->entries.cs);
    
    HashTableIterate(&sc->entries, PurgeCallback, &ctx);
    
    for (int i = 0; i < ctx.removeCount; i++) {
        HashTableRemove(&sc->entries, ctx.toRemove[i]);
    }
    
    LeaveCriticalSection(&sc->entries.cs);
}

typedef struct {
    uint64_t now;
    BOOL changed;
} DecayContext;

static void DecayCallback(uint64_t key, void* value, void* context) {
    ScoreEntry* entry = (ScoreEntry*)value;
    DecayContext* ctx = (DecayContext*)context;
    
    uint64_t behaviorTimeDiff = ctx->now - entry->behaviorDecayBaseTime;
    if (behaviorTimeDiff > 300000) {
        int decayAmount = (int)(behaviorTimeDiff / 300000) * 5;
        entry->behaviorScore = max(entry->behaviorScore - decayAmount, 0);
        entry->behaviorDecayBaseTime = ctx->now;
        ctx->changed = TRUE;
    }
    
    uint64_t kernelTimeDiff = ctx->now - entry->kernelDecayBaseTime;
    if (kernelTimeDiff > 300000) {
        int decayAmount = (int)(kernelTimeDiff / 300000) * 3;
        entry->kernelScore = max(entry->kernelScore - decayAmount, 0);
        entry->kernelDecayBaseTime = ctx->now;
        ctx->changed = TRUE;
    }
    
    entry->totalScore = entry->staticScore + entry->behaviorScore + entry->kernelScore + entry->aiScore;
}

void ScoreCenterTick(ScoreCenter* sc) {
    if (!sc) return;
    
    DecayContext ctx = {0};
    ctx.now = GetTickCount64();
    ctx.changed = FALSE;
    
    EnterCriticalSection(&sc->entries.cs);
    
    HashTableIterate(&sc->entries, DecayCallback, &ctx);
    
    LeaveCriticalSection(&sc->entries.cs);
    
    if (ctx.changed) {
        SetEvent(sc->hChangeEvent);
    }
    
    ScoreCenterPurgeOldEntries(sc, 300000);
}

typedef struct {
    ScoreCenter* sc;
} DumpContext;

static void DumpCallback(uint64_t key, void* value, void* context) {
    ScoreEntry* entry = (ScoreEntry*)value;
    DumpContext* ctx = (DumpContext*)context;
    wprintf(L"[ScoreCenter] Key=0x%llX PID=%lu Name=%ls Score=%d (Static=%d Behavior=%d Kernel=%d AI=%d) Level=%ls\n",
            entry->entryKey, entry->pid, entry->name, entry->totalScore,
            entry->staticScore, entry->behaviorScore,
            entry->kernelScore, entry->aiScore,
            ScoreCenterGetLevelName(ScoreCenterGetLevelByScore(ctx->sc, entry->totalScore)));
}

int ScoreCenterGetLevel(ScoreCenter* sc, DWORD pid) {
    ScoreEntry* entry = ScoreCenterGetByPid(sc, pid);
    if (!entry) return -1;
    return ScoreCenterGetLevelByScore(sc, entry->totalScore);
}

int ScoreCenterGetLevelByScore(ScoreCenter* sc, int score) {
    if (!sc) return -1;
    if (score >= sc->thresholdRemoved) return 5;
    if (score >= sc->thresholdQuarantined) return 4;
    if (score >= sc->thresholdRoguePopup) return 3;
    if (score >= sc->thresholdRestricted) return 2;
    if (score >= sc->thresholdSuspicious) return 1;
    if (score >= sc->thresholdObserved) return 0;
    return -1;
}

void ScoreCenterDump(ScoreCenter* sc) {
    if (!sc) return;
    
    DumpContext ctx = {0};
    ctx.sc = sc;
    
    EnterCriticalSection(&sc->entries.cs);
    
    HashTableIterate(&sc->entries, DumpCallback, &ctx);
    
    LeaveCriticalSection(&sc->entries.cs);
}