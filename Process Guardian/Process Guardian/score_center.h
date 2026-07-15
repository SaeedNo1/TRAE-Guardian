#ifndef SCORE_CENTER_H
#define SCORE_CENTER_H

#include <windows.h>
#include <stdint.h>
#include "hash_table.h"

#define MAX_STATIC_SCORE 100
#define MAX_BEHAVIOR_SCORE 100
#define MAX_KERNEL_SCORE 50
#define MAX_AI_SCORE 20
#define THRESHOLD_OBSERVED 0
#define THRESHOLD_SUSPICIOUS 30
#define THRESHOLD_RESTRICTED 50
#define THRESHOLD_ROGUE_POPUP 60
#define THRESHOLD_QUARANTINED 70
#define THRESHOLD_REMOVED 80

#define MAX_EVIDENCE_TAGS 64
typedef uint16_t EvidenceTag;

typedef struct ScoreEntry {
    DWORD pid;
    uint64_t createTime;
    uint64_t entryKey;
    wchar_t name[256];
    wchar_t imagePath[MAX_PATH];
    int staticScore;
    int behaviorScore;
    int kernelScore;
    int aiScore;
    int totalScore;
    EvidenceTag staticEvidenceTags[MAX_EVIDENCE_TAGS];
    EvidenceTag behaviorEvidenceTags[MAX_EVIDENCE_TAGS];
    EvidenceTag kernelEvidenceTags[MAX_EVIDENCE_TAGS];
    EvidenceTag aiEvidenceTags[MAX_EVIDENCE_TAGS];
    uint32_t staticEvidenceCount;
    uint32_t behaviorEvidenceCount;
    uint32_t kernelEvidenceCount;
    uint32_t aiEvidenceCount;
    wchar_t staticEvidence[2048];
    wchar_t behaviorEvidence[2048];
    wchar_t kernelEvidence[2048];
    wchar_t aiEvidence[2048];
    uint64_t lastUpdateTime;
    uint64_t behaviorDecayBaseTime;
    uint64_t kernelDecayBaseTime;
} ScoreEntry;

typedef struct {
    HashTable entries;
    HANDLE hChangeEvent;
    int thresholdObserved;
    int thresholdSuspicious;
    int thresholdRestricted;
    int thresholdRoguePopup;
    int thresholdQuarantined;
    int thresholdRemoved;
    int behaviorDecayRate;
    int kernelDecayRate;
} ScoreCenter;

BOOL ScoreCenterInit(ScoreCenter* sc);
void ScoreCenterCleanup(ScoreCenter* sc);
uint64_t ScoreCenterMakeKey(DWORD pid, uint64_t createTime);
ScoreEntry* ScoreCenterGetOrCreate(ScoreCenter* sc, DWORD pid, uint64_t createTime, const wchar_t* name, const wchar_t* imagePath);
ScoreEntry* ScoreCenterGetByKey(ScoreCenter* sc, uint64_t key);
ScoreEntry* ScoreCenterGetByPid(ScoreCenter* sc, DWORD pid);
BOOL ScoreCenterCopyEntry(ScoreCenter* sc, uint64_t key, ScoreEntry* out);
void ScoreCenterAddStaticScore(ScoreCenter* sc, uint64_t key, int score, const wchar_t* evidence);
void ScoreCenterAddBehaviorScore(ScoreCenter* sc, uint64_t key, int score, const wchar_t* evidence);
void ScoreCenterAddKernelScore(ScoreCenter* sc, uint64_t key, int score, const wchar_t* evidence);
void ScoreCenterAddAiScore(ScoreCenter* sc, uint64_t key, int score, const wchar_t* evidence);
int ScoreCenterGetTotalScore(ScoreCenter* sc, uint64_t key);
void ScoreCenterGetScoreBreakdown(ScoreCenter* sc, uint64_t key, int* staticScore, int* behaviorScore, int* kernelScore, int* aiScore);
void ScoreCenterRemove(ScoreCenter* sc, uint64_t key);
void ScoreCenterRemoveByPid(ScoreCenter* sc, DWORD pid);
void ScoreCenterPurgeOldEntries(ScoreCenter* sc, uint64_t maxAgeMs);
void ScoreCenterTick(ScoreCenter* sc);
void ScoreCenterDump(ScoreCenter* sc);
int ScoreCenterGetLevel(ScoreCenter* sc, DWORD pid);
int ScoreCenterGetLevelByScore(ScoreCenter* sc, int score);
const wchar_t* ScoreCenterGetLevelName(int level);

#endif