#ifndef RULE_ENGINE_H
#define RULE_ENGINE_H

#include <windows.h>
#include <stdint.h>

typedef enum {
    RULE_COND_TYPE_SIGNED = 0,
    RULE_COND_TYPE_UNSIGNED = 1,
    RULE_COND_TYPE_PATH = 2,
    RULE_COND_TYPE_NAME = 3,
    RULE_COND_TYPE_SIGNER = 4,
    RULE_COND_TYPE_REGISTRY_PATH = 5,
    RULE_COND_TYPE_FILE_PATH = 6,
    RULE_COND_TYPE_NETWORK = 7,
    RULE_COND_TYPE_HANDLE = 8,
    RULE_COND_TYPE_PROCESS_SPAWN = 9,
    RULE_COND_TYPE_MBR = 10,
    RULE_COND_TYPE_INJECTION = 11,
    RULE_COND_TYPE_SELF_COPY = 12,
    RULE_COND_TYPE_DELETE_SYSTEM = 13,
    RULE_COND_TYPE_BOOT_CHANGE = 14,
    RULE_COND_TYPE_CRITICAL_ATTACK = 15
} RuleConditionType;

typedef enum {
    RULE_SEVERITY_LOW = 0,
    RULE_SEVERITY_MEDIUM = 1,
    RULE_SEVERITY_HIGH = 2,
    RULE_SEVERITY_CRITICAL = 3
} RuleSeverity;

typedef enum {
    RULE_MODULE_STATIC = 0,
    RULE_MODULE_BEHAVIOR = 1,
    RULE_MODULE_KERNEL = 2,
    RULE_MODULE_AI = 3
} RuleModule;

typedef struct {
    RuleConditionType type;
    wchar_t pattern[512];
    BOOL matchAny;
} RuleCondition;

typedef struct {
    wchar_t id[32];
    wchar_t description[512];
    RuleCondition conditions[8];
    int conditionCount;
    int score;
    RuleSeverity severity;
    RuleModule module;
    wchar_t response[256];
    BOOL enabled;
} Rule;

typedef struct {
    Rule rules[64];
    int ruleCount;
    CRITICAL_SECTION cs;
    wchar_t configPath[MAX_PATH];
} RuleEngine;

BOOL RuleEngineInit(RuleEngine* re, const wchar_t* configPath);
void RuleEngineCleanup(RuleEngine* re);
BOOL RuleEngineLoadRules(RuleEngine* re);
BOOL RuleEngineSaveRules(RuleEngine* re);
int RuleEngineEvaluate(RuleEngine* re, DWORD pid, const wchar_t* processName, 
                       const wchar_t* imagePath, const wchar_t* signer, BOOL isSigned,
                       const wchar_t* eventType, const wchar_t* eventPath, Rule* matchedRule);
void RuleEngineAddRule(RuleEngine* re, const Rule* rule);
void RuleEngineRemoveRule(RuleEngine* re, const wchar_t* ruleId);
void RuleEngineDumpRules(RuleEngine* re);
const wchar_t* RuleEngineGetSeverityName(RuleSeverity severity);
const wchar_t* RuleEngineGetModuleName(RuleModule module);

#endif