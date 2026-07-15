#ifndef RULE_ENGINE_V2_H
#define RULE_ENGINE_V2_H

#include <windows.h>
#include <stdint.h>

#define MAX_RULE_ID 256
#define MAX_RULE_NAME 64
#define MAX_RULE_DESC 256
#define MAX_RULE_CONDITIONS 8

typedef enum {
    RULE_TYPE_STATIC = 1,
    RULE_TYPE_BEHAVIOR = 2,
    RULE_TYPE_KERNEL = 4,
    RULE_TYPE_AI = 8
} RuleType;

typedef enum {
    RULE_COND_ALWAYS = 0,
    RULE_COND_NO_SIGNATURE = 1,
    RULE_COND_HAS_SIGNATURE = 2,
    RULE_COND_IS_SYSTEM = 4,
    RULE_COND_IS_SERVICE = 8,
    RULE_COND_RECENTLY_STARTED = 16,
    RULE_COND_HIGH_RISK = 32,
    RULE_COND_LOW_RISK = 64
} RuleCondition;

typedef struct {
    uint16_t id;
    wchar_t name[MAX_RULE_NAME];
    wchar_t description[MAX_RULE_DESC];
    RuleType type;
    int weight;
    uint32_t conditions;
    uint64_t expireTimeMs;
    float aiWeight;
    BOOL recoverable;
    int repeatPenalty;
    uint32_t cooldownMs;
} RuleDefinition;

typedef struct {
    RuleDefinition rules[MAX_RULE_ID];
    uint16_t ruleCount;
    CRITICAL_SECTION cs;
} RuleEngineV2;

typedef struct {
    uint16_t ruleId;
    uint64_t timestamp;
    uint32_t repeatCount;
    int appliedScore;
} RuleInstance;

BOOL RuleEngineV2Init(RuleEngineV2* re);
void RuleEngineV2Cleanup(RuleEngineV2* re);
BOOL RuleEngineV2AddRule(RuleEngineV2* re, const RuleDefinition* rule);
BOOL RuleEngineV2RemoveRule(RuleEngineV2* re, uint16_t ruleId);
const RuleDefinition* RuleEngineV2GetRule(RuleEngineV2* re, uint16_t ruleId);

int RuleEngineV2Evaluate(RuleEngineV2* re, uint16_t ruleId, DWORD pid, BOOL isSigned, 
                         BOOL isSystem, BOOL isService, uint64_t createTime, 
                         int currentScore, int* outFinalScore, wchar_t* outReason);

void RuleEngineV2LoadFromConfig(RuleEngineV2* re, const wchar_t* configPath);
void RuleEngineV2SaveToConfig(RuleEngineV2* re, const wchar_t* configPath);

#endif