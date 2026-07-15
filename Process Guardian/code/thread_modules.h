#ifndef THREAD_MODULES_H
#define THREAD_MODULES_H

#include <windows.h>
#include "state_machine.h"
#include "rule_engine.h"
#include "score_center.h"
#include "response_center.h"
#include "whitelist_db.h"
#include "config_json.h"
#include "sqlite_log.h"
#include "virus_signature.h"
#include "pe_analysis.h"
#include "network_monitor.h"
#include "user_interaction.h"

typedef struct DaemonState DaemonState;

typedef struct {
    StateMachine sm;
    RuleEngine re;
    ScoreCenter sc;
    ResponseCenter rc;
    WhitelistDB wdb;
    ConfigJSON cfg;
    SQLiteLog sl;
    VirusSignatureDatabase vsdb;
    NetworkMonitor nm;
    UserInteractionMonitor uim;
    HANDLE hHandleScanThread;
    HANDLE hMbrThread;
    HANDLE hRegistryThread;
    HANDLE hFileThread;
    HANDLE hNetworkThread;
    HANDLE hAiThread;
    HANDLE hLogThread;
    HANDLE hSyscallThread;
    HANDLE hDaemonThread;
    HANDLE hStopEvent;
    HANDLE hHighSpeedEvent;
    BOOL highSpeedMode;
    DWORD highSpeedTargetPid;
    uint64_t highSpeedStartTime;
    CRITICAL_SECTION cs;
    DaemonState* ds;
} CoreModules;

BOOL CoreModulesInit(CoreModules* cm, const wchar_t* basePath);
void CoreModulesCleanup(CoreModules* cm);
void CoreModulesStartThreads(CoreModules* cm);
void CoreModulesStopThreads(CoreModules* cm);
DWORD WINAPI HandleScanThreadProc(LPVOID param);
DWORD WINAPI MbrThreadProc(LPVOID param);
DWORD WINAPI RegistryThreadProc(LPVOID param);
DWORD WINAPI FileThreadProc(LPVOID param);
DWORD WINAPI NetworkThreadProc(LPVOID param);
DWORD WINAPI AiThreadProc(LPVOID param);
DWORD WINAPI LogThreadProc(LPVOID param);
void CoreModulesOnNewProcess(CoreModules* cm, DWORD pid, const wchar_t* name, const wchar_t* imagePath);
void CoreModulesOnEvent(CoreModules* cm, DWORD pid, const wchar_t* eventType, const wchar_t* eventPath, const wchar_t* details);
void CoreModulesEnterHighSpeedMode(CoreModules* cm, DWORD pid);
void CoreModulesExitHighSpeedMode(CoreModules* cm);
void DirectCleanupMaliciousChanges(const wchar_t* threatPath);
void CoreModulesTerminateSameOriginProcesses(CoreModules* cm, const wchar_t* imagePath);
void CoreModulesCleanupNonSystemProcesses(CoreModules* cm);

#endif