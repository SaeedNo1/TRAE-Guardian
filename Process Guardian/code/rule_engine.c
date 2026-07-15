#define UNICODE
#define _UNICODE

#include "rule_engine.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const wchar_t* g_severityNames[] = {L"Low", L"Medium", L"High", L"Critical"};
static const wchar_t* g_moduleNames[] = {L"Static", L"Behavior", L"Kernel", L"AI"};

const wchar_t* RuleEngineGetSeverityName(RuleSeverity severity) {
    if (severity >= RULE_SEVERITY_LOW && severity <= RULE_SEVERITY_CRITICAL) {
        return g_severityNames[severity];
    }
    return L"Unknown";
}

const wchar_t* RuleEngineGetModuleName(RuleModule module) {
    if (module >= RULE_MODULE_STATIC && module <= RULE_MODULE_AI) {
        return g_moduleNames[module];
    }
    return L"Unknown";
}

static BOOL MatchPattern(const wchar_t* input, const wchar_t* pattern) {
    if (!input || !pattern) return FALSE;
    if (!input[0] && pattern[0]) return FALSE;
    if (!pattern[0]) return TRUE;
    
    const wchar_t* p = pattern;
    const wchar_t* i = input;
    
    while (*p && *i) {
        if (*p == L'*') {
            p++;
            if (!*p) return TRUE;
            while (*i) {
                if (MatchPattern(i, p)) return TRUE;
                i++;
            }
            return FALSE;
        }
        if (_wcsicmp(p, i) != 0) {
            if (*p != *i) return FALSE;
        }
        p++;
        i++;
    }
    
    while (*p == L'*') p++;
    return !*p && !*i;
}

static BOOL EvaluateCondition(const RuleCondition* cond, const wchar_t* processName,
                             const wchar_t* imagePath, const wchar_t* signer, 
                             BOOL isSigned, const wchar_t* eventType, const wchar_t* eventPath) {
    if (!cond) return FALSE;
    switch (cond->type) {
        case RULE_COND_TYPE_SIGNED:
            return isSigned;
        case RULE_COND_TYPE_UNSIGNED:
            return !isSigned;
        case RULE_COND_TYPE_PATH:
            return imagePath ? MatchPattern(imagePath, cond->pattern) : FALSE;
        case RULE_COND_TYPE_NAME:
            return processName ? MatchPattern(processName, cond->pattern) : FALSE;
        case RULE_COND_TYPE_SIGNER:
            return signer ? MatchPattern(signer, cond->pattern) : FALSE;
        case RULE_COND_TYPE_REGISTRY_PATH:
            if (!(eventType && _wcsicmp(eventType, L"registry_write") == 0)) {
                return FALSE;
            }
            return eventPath ? MatchPattern(eventPath, cond->pattern) : FALSE;
        case RULE_COND_TYPE_FILE_PATH:
            return eventPath ? MatchPattern(eventPath, cond->pattern) : FALSE;
        case RULE_COND_TYPE_NETWORK:
            return eventType && _wcsicmp(eventType, L"network") == 0;
        case RULE_COND_TYPE_HANDLE:
            if (!(eventType && (_wcsicmp(eventType, L"handle") == 0 || _wcsicmp(eventType, L"disk_handle") == 0))) {
                return FALSE;
            }
            if (cond->pattern && cond->pattern[0]) {
                return eventPath ? MatchPattern(eventPath, cond->pattern) : FALSE;
            }
            return TRUE;
        case RULE_COND_TYPE_PROCESS_SPAWN:
            return eventType && _wcsicmp(eventType, L"process_spawn") == 0;
        case RULE_COND_TYPE_MBR:
            return eventType && _wcsicmp(eventType, L"mbr") == 0;
        case RULE_COND_TYPE_INJECTION:
            return eventType && _wcsicmp(eventType, L"injection") == 0;
        case RULE_COND_TYPE_SELF_COPY:
            return eventType && _wcsicmp(eventType, L"self_copy") == 0;
        case RULE_COND_TYPE_DELETE_SYSTEM:
            return eventType && _wcsicmp(eventType, L"delete_system") == 0;
        case RULE_COND_TYPE_BOOT_CHANGE:
            return eventType && _wcsicmp(eventType, L"boot_change") == 0;
        case RULE_COND_TYPE_CRITICAL_ATTACK:
            return eventType && _wcsicmp(eventType, L"critical_attack") == 0;
        default:
            return FALSE;
    }
}

BOOL RuleEngineInit(RuleEngine* re, const wchar_t* configPath) {
    if (!re) return FALSE;
    memset(re, 0, sizeof(RuleEngine));
    InitializeCriticalSection(&re->cs);
    if (configPath && configPath[0]) {
        wcsncpy(re->configPath, configPath, sizeof(re->configPath) / sizeof(wchar_t) - 1);
        re->configPath[sizeof(re->configPath) / sizeof(wchar_t) - 1] = L'\0';
    }
    return TRUE;
}

void RuleEngineCleanup(RuleEngine* re) {
    if (!re) return;
    DeleteCriticalSection(&re->cs);
}

static void AddDefaultRules(RuleEngine* re) {
    if (!re) return;
    memset(re->rules, 0, sizeof(re->rules));
    re->ruleCount = 0;

    Rule r001 = {0};
    wcscpy(r001.id, L"R001");
    wcscpy(r001.description, L"Unsigned process opens disk handle (PhysicalDrive/Harddisk/Volume)");
    r001.conditions[0].type = RULE_COND_TYPE_UNSIGNED;
    r001.conditions[1].type = RULE_COND_TYPE_HANDLE;
    wcscpy(r001.conditions[1].pattern, L"*");
    r001.conditionCount = 2;
    r001.score = 35;
    r001.severity = RULE_SEVERITY_CRITICAL;
    r001.module = RULE_MODULE_KERNEL;
    wcscpy(r001.response, L"terminate");
    r001.enabled = TRUE;
    re->rules[re->ruleCount++] = r001;

    Rule r002 = {0};
    wcscpy(r002.id, L"R002");
    wcscpy(r002.description, L"Unsigned process modifies boot configuration");
    r002.conditions[0].type = RULE_COND_TYPE_UNSIGNED;
    r002.conditions[1].type = RULE_COND_TYPE_BOOT_CHANGE;
    r002.conditionCount = 2;
    r002.score = 30;
    r002.severity = RULE_SEVERITY_CRITICAL;
    r002.module = RULE_MODULE_KERNEL;
    wcscpy(r002.response, L"terminate");
    r002.enabled = TRUE;
    re->rules[re->ruleCount++] = r002;

    Rule r003 = {0};
    wcscpy(r003.id, L"R003");
    wcscpy(r003.description, L"Unsigned process deletes system32 files");
    r003.conditions[0].type = RULE_COND_TYPE_UNSIGNED;
    r003.conditions[1].type = RULE_COND_TYPE_FILE_PATH;
    wcscpy(r003.conditions[1].pattern, L"*\\System32\\*");
    r003.conditionCount = 2;
    r003.score = 25;
    r003.severity = RULE_SEVERITY_CRITICAL;
    r003.module = RULE_MODULE_KERNEL;
    wcscpy(r003.response, L"terminate");
    r003.enabled = TRUE;
    re->rules[re->ruleCount++] = r003;

    Rule r004 = {0};
    wcscpy(r004.id, L"R004");
    wcscpy(r004.description, L"Unsigned process injects into other process");
    r004.conditions[0].type = RULE_COND_TYPE_UNSIGNED;
    r004.conditions[1].type = RULE_COND_TYPE_INJECTION;
    r004.conditionCount = 2;
    r004.score = 15;
    r004.severity = RULE_SEVERITY_HIGH;
    r004.module = RULE_MODULE_BEHAVIOR;
    wcscpy(r004.response, L"terminate");
    r004.enabled = TRUE;
    re->rules[re->ruleCount++] = r004;

    Rule r005 = {0};
    wcscpy(r005.id, L"R005");
    wcscpy(r005.description, L"Process copies itself");
    r005.conditions[0].type = RULE_COND_TYPE_SELF_COPY;
    r005.conditionCount = 1;
    r005.score = 5;
    r005.severity = RULE_SEVERITY_MEDIUM;
    r005.module = RULE_MODULE_BEHAVIOR;
    wcscpy(r005.response, L"observe");
    r005.enabled = TRUE;
    re->rules[re->ruleCount++] = r005;

    Rule r006 = {0};
    wcscpy(r006.id, L"R006");
    wcscpy(r006.description, L"Unsigned process writes to system registry");
    r006.conditions[0].type = RULE_COND_TYPE_UNSIGNED;
    r006.conditions[1].type = RULE_COND_TYPE_REGISTRY_PATH;
    wcscpy(r006.conditions[1].pattern, L"HKEY_LOCAL_MACHINE\\SYSTEM\\*");
    r006.conditionCount = 2;
    r006.score = 10;
    r006.severity = RULE_SEVERITY_HIGH;
    r006.module = RULE_MODULE_BEHAVIOR;
    wcscpy(r006.response, L"observe");
    r006.enabled = TRUE;
    re->rules[re->ruleCount++] = r006;

    Rule r007 = {0};
    wcscpy(r007.id, L"R007");
    wcscpy(r007.description, L"Unsigned process deletes registry");
    r007.conditions[0].type = RULE_COND_TYPE_UNSIGNED;
    r007.conditions[1].type = RULE_COND_TYPE_REGISTRY_PATH;
    wcscpy(r007.conditions[1].pattern, L"*");
    r007.conditionCount = 2;
    r007.score = 5;
    r007.severity = RULE_SEVERITY_MEDIUM;
    r007.module = RULE_MODULE_BEHAVIOR;
    wcscpy(r007.response, L"observe");
    r007.enabled = TRUE;
    re->rules[re->ruleCount++] = r007;

    Rule r007a = {0};
    wcscpy(r007a.id, L"R007a");
    wcscpy(r007a.description, L"Unsigned process writes to Run key");
    r007a.conditions[0].type = RULE_COND_TYPE_UNSIGNED;
    r007a.conditions[1].type = RULE_COND_TYPE_REGISTRY_PATH;
    wcscpy(r007a.conditions[1].pattern, L"*\\Run\\*");
    r007a.conditionCount = 2;
    r007a.score = 35;
    r007a.severity = RULE_SEVERITY_CRITICAL;
    r007a.module = RULE_MODULE_BEHAVIOR;
    wcscpy(r007a.response, L"terminate");
    r007a.enabled = TRUE;
    re->rules[re->ruleCount++] = r007a;

    Rule r008 = {0};
    wcscpy(r008.id, L"R008");
    wcscpy(r008.description, L"Signed process rapid network connections (whitelist friendly)");
    r008.conditions[0].type = RULE_COND_TYPE_SIGNED;
    r008.conditions[1].type = RULE_COND_TYPE_NETWORK;
    r008.conditionCount = 2;
    r008.score = 0;
    r008.severity = RULE_SEVERITY_LOW;
    r008.module = RULE_MODULE_BEHAVIOR;
    wcscpy(r008.response, L"none");
    r008.enabled = TRUE;
    re->rules[re->ruleCount++] = r008;

    Rule r009 = {0};
    wcscpy(r009.id, L"R009");
    wcscpy(r009.description, L"Microsoft signed process - trusted");
    r009.conditions[0].type = RULE_COND_TYPE_SIGNER;
    wcscpy(r009.conditions[0].pattern, L"*Microsoft*");
    r009.conditionCount = 1;
    r009.score = 0;
    r009.severity = RULE_SEVERITY_LOW;
    r009.module = RULE_MODULE_STATIC;
    wcscpy(r009.response, L"trust");
    r009.enabled = TRUE;
    re->rules[re->ruleCount++] = r009;

    Rule r010 = {0};
    wcscpy(r010.id, L"R010");
    wcscpy(r010.description, L"New process spawned - observe");
    r010.conditions[0].type = RULE_COND_TYPE_PROCESS_SPAWN;
    r010.conditionCount = 1;
    r010.score = 0;
    r010.severity = RULE_SEVERITY_LOW;
    r010.module = RULE_MODULE_STATIC;
    wcscpy(r010.response, L"observe");
    r010.enabled = TRUE;
    re->rules[re->ruleCount++] = r010;
}

BOOL RuleEngineLoadRules(RuleEngine* re) {
    if (!re) return FALSE;
    EnterCriticalSection(&re->cs);
    AddDefaultRules(re);
    if (re->configPath[0]) {
        FILE* f = _wfopen(re->configPath, L"rb");
        if (f) {
            fclose(f);
        }
    }
    LeaveCriticalSection(&re->cs);
    return TRUE;
}

BOOL RuleEngineSaveRules(RuleEngine* re) {
    if (!re || !re->configPath[0]) return FALSE;
    EnterCriticalSection(&re->cs);
    FILE* f = _wfopen(re->configPath, L"wb");
    if (!f) {
        LeaveCriticalSection(&re->cs);
        return FALSE;
    }
    fprintf(f, "{\n");
    fprintf(f, "  \"rules\": [\n");
    for (int i = 0; i < re->ruleCount; i++) {
        const Rule* r = &re->rules[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"id\": \"%ls\",\n", r->id);
        fprintf(f, "      \"description\": \"%ls\",\n", r->description);
        fprintf(f, "      \"conditions\": [\n");
        for (int j = 0; j < r->conditionCount; j++) {
            fprintf(f, "        {\n");
            fprintf(f, "          \"type\": %d,\n", r->conditions[j].type);
            fprintf(f, "          \"pattern\": \"%ls\"\n", r->conditions[j].pattern);
            fprintf(f, "        }%s\n", (j < r->conditionCount - 1) ? "," : "");
        }
        fprintf(f, "      ],\n");
        fprintf(f, "      \"score\": %d,\n", r->score);
        fprintf(f, "      \"severity\": %d,\n", r->severity);
        fprintf(f, "      \"module\": %d,\n", r->module);
        fprintf(f, "      \"response\": \"%ls\",\n", r->response);
        fprintf(f, "      \"enabled\": %s\n", r->enabled ? "true" : "false");
        fprintf(f, "    }%s\n", (i < re->ruleCount - 1) ? "," : "");
    }
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    fclose(f);
    LeaveCriticalSection(&re->cs);
    return TRUE;
}

int RuleEngineEvaluate(RuleEngine* re, DWORD pid, const wchar_t* processName,
                       const wchar_t* imagePath, const wchar_t* signer, BOOL isSigned,
                       const wchar_t* eventType, const wchar_t* eventPath, Rule* matchedRule) {
    if (!re) return 0;
    int totalScore = 0;
    EnterCriticalSection(&re->cs);
    for (int i = 0; i < re->ruleCount; i++) {
        const Rule* r = &re->rules[i];
        if (!r->enabled) continue;
        BOOL allMatched = TRUE;
        for (int j = 0; j < r->conditionCount; j++) {
            BOOL condResult = EvaluateCondition(&r->conditions[j], processName, imagePath, signer, 
                                               isSigned, eventType, eventPath);
            if (!condResult) {
                allMatched = FALSE;
                break;
            }
        }
        if (allMatched) {
            totalScore += r->score;
            if (matchedRule) {
                *matchedRule = *r;
            }
        }
    }
    LeaveCriticalSection(&re->cs);
    return totalScore;
}

void RuleEngineAddRule(RuleEngine* re, const Rule* rule) {
    if (!re || !rule) return;
    EnterCriticalSection(&re->cs);
    if (re->ruleCount < 64) {
        re->rules[re->ruleCount++] = *rule;
    }
    LeaveCriticalSection(&re->cs);
}

void RuleEngineRemoveRule(RuleEngine* re, const wchar_t* ruleId) {
    if (!re || !ruleId) return;
    EnterCriticalSection(&re->cs);
    for (int i = 0; i < re->ruleCount; i++) {
        if (_wcsicmp(re->rules[i].id, ruleId) == 0) {
            for (int j = i; j < re->ruleCount - 1; j++) {
                re->rules[j] = re->rules[j + 1];
            }
            re->ruleCount--;
            break;
        }
    }
    LeaveCriticalSection(&re->cs);
}

void RuleEngineDumpRules(RuleEngine* re) {
    if (!re) return;
    EnterCriticalSection(&re->cs);
    for (int i = 0; i < re->ruleCount; i++) {
        const Rule* r = &re->rules[i];
        wprintf(L"[RuleEngine] %ls: %ls Score=%d Severity=%ls Module=%ls Enabled=%s\n",
                r->id, r->description, r->score, 
                RuleEngineGetSeverityName(r->severity),
                RuleEngineGetModuleName(r->module),
                r->enabled ? L"true" : L"false");
    }
    LeaveCriticalSection(&re->cs);
}