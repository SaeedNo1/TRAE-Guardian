#pragma once

#ifdef OBSERVER_DLL_EXPORTS
#define OBSERVER_API __declspec(dllexport)
#else
#define OBSERVER_API __declspec(dllimport)
#endif

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OBSERVER_MAX_NAME 260
#define OBSERVER_MAX_HISTORY 900 /* 30 minutes at 2 sec interval */

typedef struct _ObserverProcessInfo {
    DWORD pid;
    WCHAR processName[OBSERVER_MAX_NAME];
    WCHAR filePath[MAX_PATH];
    WCHAR userName[OBSERVER_MAX_NAME];
    WCHAR signerName[OBSERVER_MAX_NAME];
    BOOL hasValidSignature;
    LARGE_INTEGER timestamp;
} ObserverProcessInfo;

typedef struct _ObserverStatsPoint {
    double cpuPercent;
    double gpuPercent;
    double memMB;
    double vramMB;
    LARGE_INTEGER timestamp;
} ObserverStatsPoint;

typedef struct _ObserverStatsEx {
    ObserverProcessInfo info;
    ObserverStatsPoint current;
    ObserverStatsPoint history[OBSERVER_MAX_HISTORY];
    int historyCount;
} ObserverStatsEx;

/* Legacy-compatible single-shot API */
OBSERVER_API BOOL __stdcall GetProcessStatsEx(DWORD pid, ObserverStatsEx* out, DWORD size);
typedef BOOL (__stdcall *FnObserverGetStatsEx)(DWORD pid, ObserverStatsEx* out, DWORD size);

/* Start / stop continuous observation of a process */
OBSERVER_API BOOL __stdcall ObserveProcess(DWORD pid);
OBSERVER_API BOOL __stdcall StopObservation(DWORD pid);
OBSERVER_API BOOL __stdcall StopAllObservations(void);

/* Query current info and full history */
OBSERVER_API BOOL __stdcall GetObserverStats(DWORD pid, ObserverStatsEx* out, DWORD size);

#ifdef __cplusplus
}
#endif
