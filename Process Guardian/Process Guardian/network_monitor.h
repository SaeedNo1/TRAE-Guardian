#ifndef NETWORK_MONITOR_H
#define NETWORK_MONITOR_H

#include <windows.h>
#include <stdint.h>

#define MAX_FLOW_ENTRIES 1024
#define FLOW_HISTORY_SIZE 10

#define SAFE_CONNECTIONS 10
#define WARNING_CONNECTIONS 50
#define DANGER_CONNECTIONS 100
#define KERNEL_MAX_CONNECTIONS 3

#define SAFE_DURATION_MS 0
#define WARNING_DURATION_MS 10000
#define DANGER_DURATION_MS 5000

typedef struct {
    int connectionCount[FLOW_HISTORY_SIZE];
    uint64_t timestamps[FLOW_HISTORY_SIZE];
    int historyIndex;
    int historyCount;
} FlowHistory;

typedef struct {
    DWORD pid;
    wchar_t name[256];
    wchar_t imagePath[MAX_PATH];
    FlowHistory flowHistory;
    uint64_t lastUserActionTime;
    uint64_t lastFocusTime;
    BOOL hasFocus;
    BOOL isKernel;
    DWORD parentPid;
    wchar_t parentName[256];
    uint64_t highFlowStartTime;
    int highFlowLevel;
    BOOL isWhitelisted;
    int whitelistThreshold;
    uint64_t lastCheckTime;
} NetFlowEntry;

typedef struct {
    NetFlowEntry entries[MAX_FLOW_ENTRIES];
    int entryCount;
    CRITICAL_SECTION cs;
    HANDLE hUpdateEvent;
    BOOL running;
} NetworkMonitor;

typedef enum {
    FLOW_LEVEL_SAFE = 0,
    FLOW_LEVEL_WARNING = 1,
    FLOW_LEVEL_DANGER = 2,
    FLOW_LEVEL_CRITICAL = 3
} FlowLevel;

BOOL NetworkMonitorInit(NetworkMonitor* nm);
void NetworkMonitorCleanup(NetworkMonitor* nm);
void NetworkMonitorStart(NetworkMonitor* nm);
void NetworkMonitorStop(NetworkMonitor* nm);
DWORD WINAPI NetworkMonitorThreadProc(LPVOID param);
void NetworkMonitorUpdateConnections(DWORD pid, const wchar_t* name, const wchar_t* imagePath, int connCount);
void NetworkMonitorMarkUserAction(DWORD pid);
void NetworkMonitorUpdateFocus(DWORD pid, BOOL hasFocus);
FlowLevel NetworkMonitorGetFlowLevel(DWORD pid, int* connCount);
void NetworkMonitorAddWhitelist(DWORD pid, int threshold);
void NetworkMonitorRemoveWhitelist(DWORD pid);
int NetworkMonitorGetScore(DWORD pid);
void NetworkMonitorPurgeStaleEntries(NetworkMonitor* nm);

#endif
