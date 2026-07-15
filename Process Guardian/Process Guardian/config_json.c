#define UNICODE
#define _UNICODE

#include "config_json.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void SetDefaultConfig(ConfigJSON* cfg) {
    if (!cfg) return;
    cfg->modules.etwEnabled = 1;
    cfg->modules.handleScanEnabled = 1;
    cfg->modules.mbrProtectionEnabled = 1;
    cfg->modules.registryMonitorEnabled = 1;
    cfg->modules.networkMonitorEnabled = 1;
    cfg->modules.aiAnalysisEnabled = 1;
    cfg->modules.autoUpdateEnabled = 0;
    cfg->modules.selfProtectionEnabled = 1;
    cfg->scans.globalScanIntervalMs = 1000;
    cfg->scans.newProcessScanIntervalMs = 20;
    cfg->scans.newProcessMonitorDurationMs = 5000;
    cfg->scans.highSpeedScanIntervalMs = 10;
    cfg->scans.highSpeedScanDurationMs = 10000;
    cfg->scans.mbrCheckIntervalMs = 5000;
    cfg->scans.mbrHighSpeedIntervalMs = 50;
    cfg->scans.registryCheckIntervalMs = 1000;
    cfg->scans.networkCheckIntervalMs = 1000;
    cfg->scores.thresholdObserved = 0;
    cfg->scores.thresholdSuspicious = 30;
    cfg->scores.thresholdRestricted = 50;
    cfg->scores.thresholdQuarantined = 70;
    cfg->scores.thresholdRemoved = 80;
    cfg->scores.maxStaticScore = 25;
    cfg->scores.maxBehaviorScore = 40;
    cfg->scores.maxKernelScore = 18;
    cfg->scores.maxAiScore = 8;
    cfg->logs.logEnabled = 1;
    cfg->logs.logLevel = 3;
    wcscpy(cfg->logs.logPath, L"C:\\ProgramData\\ProcessGuardian\\logs");
    cfg->logs.logMaxSizeMb = 10;
    cfg->logs.logMaxFiles = 5;
    cfg->ai.aiEnabled = 1;
    wcscpy(cfg->ai.aiEndpoint, L"");
    cfg->ai.aiTimeoutMs = 30000;
    cfg->ai.aiMaxConcurrent = 3;
}

BOOL ConfigJSONInit(ConfigJSON* cfg, const wchar_t* configPath) {
    if (!cfg) return FALSE;
    memset(cfg, 0, sizeof(ConfigJSON));
    InitializeCriticalSection(&cfg->cs);
    if (configPath && configPath[0]) {
        wcsncpy(cfg->configPath, configPath, sizeof(cfg->configPath) / sizeof(wchar_t) - 1);
        cfg->configPath[sizeof(cfg->configPath) / sizeof(wchar_t) - 1] = L'\0';
    }
    SetDefaultConfig(cfg);
    return TRUE;
}

void ConfigJSONCleanup(ConfigJSON* cfg) {
    if (!cfg) return;
    DeleteCriticalSection(&cfg->cs);
}

BOOL ConfigJSONLoad(ConfigJSON* cfg) {
    if (!cfg) return FALSE;
    EnterCriticalSection(&cfg->cs);
    if (cfg->configPath[0]) {
        FILE* f = _wfopen(cfg->configPath, L"rb");
        if (f) {
            fclose(f);
        } else {
            ConfigJSONSave(cfg);
        }
    }
    LeaveCriticalSection(&cfg->cs);
    return TRUE;
}

BOOL ConfigJSONSave(ConfigJSON* cfg) {
    if (!cfg || !cfg->configPath[0]) return FALSE;
    EnterCriticalSection(&cfg->cs);
    FILE* f = _wfopen(cfg->configPath, L"wb");
    if (!f) {
        LeaveCriticalSection(&cfg->cs);
        return FALSE;
    }
    fprintf(f, "{\n");
    fprintf(f, "  \"modules\": {\n");
    fprintf(f, "    \"etwEnabled\": %d,\n", cfg->modules.etwEnabled);
    fprintf(f, "    \"handleScanEnabled\": %d,\n", cfg->modules.handleScanEnabled);
    fprintf(f, "    \"mbrProtectionEnabled\": %d,\n", cfg->modules.mbrProtectionEnabled);
    fprintf(f, "    \"registryMonitorEnabled\": %d,\n", cfg->modules.registryMonitorEnabled);
    fprintf(f, "    \"networkMonitorEnabled\": %d,\n", cfg->modules.networkMonitorEnabled);
    fprintf(f, "    \"aiAnalysisEnabled\": %d,\n", cfg->modules.aiAnalysisEnabled);
    fprintf(f, "    \"autoUpdateEnabled\": %d,\n", cfg->modules.autoUpdateEnabled);
    fprintf(f, "    \"selfProtectionEnabled\": %d\n", cfg->modules.selfProtectionEnabled);
    fprintf(f, "  },\n");
    fprintf(f, "  \"scans\": {\n");
    fprintf(f, "    \"globalScanIntervalMs\": %d,\n", cfg->scans.globalScanIntervalMs);
    fprintf(f, "    \"newProcessScanIntervalMs\": %d,\n", cfg->scans.newProcessScanIntervalMs);
    fprintf(f, "    \"newProcessMonitorDurationMs\": %d,\n", cfg->scans.newProcessMonitorDurationMs);
    fprintf(f, "    \"highSpeedScanIntervalMs\": %d,\n", cfg->scans.highSpeedScanIntervalMs);
    fprintf(f, "    \"highSpeedScanDurationMs\": %d,\n", cfg->scans.highSpeedScanDurationMs);
    fprintf(f, "    \"mbrCheckIntervalMs\": %d,\n", cfg->scans.mbrCheckIntervalMs);
    fprintf(f, "    \"mbrHighSpeedIntervalMs\": %d,\n", cfg->scans.mbrHighSpeedIntervalMs);
    fprintf(f, "    \"registryCheckIntervalMs\": %d,\n", cfg->scans.registryCheckIntervalMs);
    fprintf(f, "    \"networkCheckIntervalMs\": %d\n", cfg->scans.networkCheckIntervalMs);
    fprintf(f, "  },\n");
    fprintf(f, "  \"scores\": {\n");
    fprintf(f, "    \"thresholdObserved\": %d,\n", cfg->scores.thresholdObserved);
    fprintf(f, "    \"thresholdSuspicious\": %d,\n", cfg->scores.thresholdSuspicious);
    fprintf(f, "    \"thresholdRestricted\": %d,\n", cfg->scores.thresholdRestricted);
    fprintf(f, "    \"thresholdQuarantined\": %d,\n", cfg->scores.thresholdQuarantined);
    fprintf(f, "    \"thresholdRemoved\": %d,\n", cfg->scores.thresholdRemoved);
    fprintf(f, "    \"maxStaticScore\": %d,\n", cfg->scores.maxStaticScore);
    fprintf(f, "    \"maxBehaviorScore\": %d,\n", cfg->scores.maxBehaviorScore);
    fprintf(f, "    \"maxKernelScore\": %d,\n", cfg->scores.maxKernelScore);
    fprintf(f, "    \"maxAiScore\": %d\n", cfg->scores.maxAiScore);
    fprintf(f, "  },\n");
    fprintf(f, "  \"logs\": {\n");
    fprintf(f, "    \"logEnabled\": %d,\n", cfg->logs.logEnabled);
    fprintf(f, "    \"logLevel\": %d,\n", cfg->logs.logLevel);
    fprintf(f, "    \"logPath\": \"%ls\",\n", cfg->logs.logPath);
    fprintf(f, "    \"logMaxSizeMb\": %d,\n", cfg->logs.logMaxSizeMb);
    fprintf(f, "    \"logMaxFiles\": %d\n", cfg->logs.logMaxFiles);
    fprintf(f, "  },\n");
    fprintf(f, "  \"ai\": {\n");
    fprintf(f, "    \"aiEnabled\": %d,\n", cfg->ai.aiEnabled);
    fprintf(f, "    \"aiEndpoint\": \"%ls\",\n", cfg->ai.aiEndpoint);
    fprintf(f, "    \"aiTimeoutMs\": %d,\n", cfg->ai.aiTimeoutMs);
    fprintf(f, "    \"aiMaxConcurrent\": %d\n", cfg->ai.aiMaxConcurrent);
    fprintf(f, "  }\n");
    fprintf(f, "}\n");
    fclose(f);
    LeaveCriticalSection(&cfg->cs);
    return TRUE;
}

BOOL ConfigJSONGetInt(ConfigJSON* cfg, const wchar_t* key, int defaultValue) {
    if (!cfg || !key) return defaultValue;
    if (_wcsicmp(key, L"etwEnabled") == 0) return cfg->modules.etwEnabled;
    if (_wcsicmp(key, L"handleScanEnabled") == 0) return cfg->modules.handleScanEnabled;
    if (_wcsicmp(key, L"mbrProtectionEnabled") == 0) return cfg->modules.mbrProtectionEnabled;
    if (_wcsicmp(key, L"globalScanIntervalMs") == 0) return cfg->scans.globalScanIntervalMs;
    if (_wcsicmp(key, L"thresholdSuspicious") == 0) return cfg->scores.thresholdSuspicious;
    if (_wcsicmp(key, L"thresholdRestricted") == 0) return cfg->scores.thresholdRestricted;
    if (_wcsicmp(key, L"thresholdQuarantined") == 0) return cfg->scores.thresholdQuarantined;
    if (_wcsicmp(key, L"thresholdRemoved") == 0) return cfg->scores.thresholdRemoved;
    return defaultValue;
}

BOOL ConfigJSONSetInt(ConfigJSON* cfg, const wchar_t* key, int value) {
    if (!cfg || !key) return FALSE;
    if (_wcsicmp(key, L"etwEnabled") == 0) { cfg->modules.etwEnabled = value; return TRUE; }
    if (_wcsicmp(key, L"handleScanEnabled") == 0) { cfg->modules.handleScanEnabled = value; return TRUE; }
    if (_wcsicmp(key, L"mbrProtectionEnabled") == 0) { cfg->modules.mbrProtectionEnabled = value; return TRUE; }
    if (_wcsicmp(key, L"globalScanIntervalMs") == 0) { cfg->scans.globalScanIntervalMs = value; return TRUE; }
    if (_wcsicmp(key, L"thresholdSuspicious") == 0) { cfg->scores.thresholdSuspicious = value; return TRUE; }
    if (_wcsicmp(key, L"thresholdRestricted") == 0) { cfg->scores.thresholdRestricted = value; return TRUE; }
    if (_wcsicmp(key, L"thresholdQuarantined") == 0) { cfg->scores.thresholdQuarantined = value; return TRUE; }
    if (_wcsicmp(key, L"thresholdRemoved") == 0) { cfg->scores.thresholdRemoved = value; return TRUE; }
    return FALSE;
}

BOOL ConfigJSONGetString(ConfigJSON* cfg, const wchar_t* key, wchar_t* buffer, int bufferSize, const wchar_t* defaultValue) {
    if (!cfg || !key || !buffer) return FALSE;
    if (_wcsicmp(key, L"logPath") == 0) { wcsncpy(buffer, cfg->logs.logPath, bufferSize - 1); buffer[bufferSize - 1] = L'\0'; return TRUE; }
    if (_wcsicmp(key, L"aiEndpoint") == 0) { wcsncpy(buffer, cfg->ai.aiEndpoint, bufferSize - 1); buffer[bufferSize - 1] = L'\0'; return TRUE; }
    if (defaultValue) { wcsncpy(buffer, defaultValue, bufferSize - 1); buffer[bufferSize - 1] = L'\0'; }
    return defaultValue != NULL;
}

BOOL ConfigJSONSetString(ConfigJSON* cfg, const wchar_t* key, const wchar_t* value) {
    if (!cfg || !key || !value) return FALSE;
    if (_wcsicmp(key, L"logPath") == 0) { wcsncpy(cfg->logs.logPath, value, sizeof(cfg->logs.logPath) / sizeof(wchar_t) - 1); cfg->logs.logPath[sizeof(cfg->logs.logPath) / sizeof(wchar_t) - 1] = L'\0'; return TRUE; }
    if (_wcsicmp(key, L"aiEndpoint") == 0) { wcsncpy(cfg->ai.aiEndpoint, value, sizeof(cfg->ai.aiEndpoint) / sizeof(wchar_t) - 1); cfg->ai.aiEndpoint[sizeof(cfg->ai.aiEndpoint) / sizeof(wchar_t) - 1] = L'\0'; return TRUE; }
    return FALSE;
}

void ConfigJSONDump(ConfigJSON* cfg) {
    if (!cfg) return;
    EnterCriticalSection(&cfg->cs);
    wprintf(L"[Config] ETW=%d HandleScan=%d MBR=%d Registry=%d Network=%d AI=%d\n",
            cfg->modules.etwEnabled, cfg->modules.handleScanEnabled,
            cfg->modules.mbrProtectionEnabled, cfg->modules.registryMonitorEnabled,
            cfg->modules.networkMonitorEnabled, cfg->modules.aiAnalysisEnabled);
    wprintf(L"[Config] Thresholds: Observed=%d Suspicious=%d Restricted=%d Quarantined=%d Removed=%d\n",
            cfg->scores.thresholdObserved, cfg->scores.thresholdSuspicious,
            cfg->scores.thresholdRestricted, cfg->scores.thresholdQuarantined,
            cfg->scores.thresholdRemoved);
    LeaveCriticalSection(&cfg->cs);
}