#ifndef CONFIG_JSON_H
#define CONFIG_JSON_H

#include <windows.h>
#include <stdint.h>

typedef struct {
    int etwEnabled;
    int handleScanEnabled;
    int mbrProtectionEnabled;
    int registryMonitorEnabled;
    int networkMonitorEnabled;
    int aiAnalysisEnabled;
    int autoUpdateEnabled;
    int selfProtectionEnabled;
} ModuleConfig;

typedef struct {
    int globalScanIntervalMs;
    int newProcessScanIntervalMs;
    int newProcessMonitorDurationMs;
    int highSpeedScanIntervalMs;
    int highSpeedScanDurationMs;
    int mbrCheckIntervalMs;
    int mbrHighSpeedIntervalMs;
    int registryCheckIntervalMs;
    int networkCheckIntervalMs;
} ScanConfig;

typedef struct {
    int thresholdObserved;
    int thresholdSuspicious;
    int thresholdRestricted;
    int thresholdQuarantined;
    int thresholdRemoved;
    int maxStaticScore;
    int maxBehaviorScore;
    int maxKernelScore;
    int maxAiScore;
} ScoreConfig;

typedef struct {
    int logEnabled;
    int logLevel;
    wchar_t logPath[MAX_PATH];
    int logMaxSizeMb;
    int logMaxFiles;
} LogConfig;

typedef struct {
    int aiEnabled;
    wchar_t aiEndpoint[MAX_PATH];
    int aiTimeoutMs;
    int aiMaxConcurrent;
} AIConfig;

typedef struct {
    wchar_t configPath[MAX_PATH];
    ModuleConfig modules;
    ScanConfig scans;
    ScoreConfig scores;
    LogConfig logs;
    AIConfig ai;
    CRITICAL_SECTION cs;
} ConfigJSON;

BOOL ConfigJSONInit(ConfigJSON* cfg, const wchar_t* configPath);
void ConfigJSONCleanup(ConfigJSON* cfg);
BOOL ConfigJSONLoad(ConfigJSON* cfg);
BOOL ConfigJSONSave(ConfigJSON* cfg);
BOOL ConfigJSONGetInt(ConfigJSON* cfg, const wchar_t* key, int defaultValue);
BOOL ConfigJSONSetInt(ConfigJSON* cfg, const wchar_t* key, int value);
BOOL ConfigJSONGetString(ConfigJSON* cfg, const wchar_t* key, wchar_t* buffer, int bufferSize, const wchar_t* defaultValue);
BOOL ConfigJSONSetString(ConfigJSON* cfg, const wchar_t* key, const wchar_t* value);
void ConfigJSONDump(ConfigJSON* cfg);

#endif