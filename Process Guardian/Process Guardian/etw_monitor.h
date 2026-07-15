#ifndef ETW_MONITOR_H
#define ETW_MONITOR_H

#include <windows.h>
#include <evntcons.h>
#include <evntrace.h>
#include "trust_zone.h"

typedef void (*EtwRegCallback)(DWORD pid, UCHAR eventId, const wchar_t* path, const wchar_t* valueName, const wchar_t* data, const wchar_t* oldData, BOOL isSysReg, void* ctx);
typedef void (*EtwProcStartCallback)(DWORD pid, DWORD parentPid, const wchar_t* imageName, const wchar_t* commandLine, void* ctx);
typedef void (*EtwProcStopCallback)(DWORD pid, const wchar_t* imageName, void* ctx);
typedef void (*EtwProcTerminateCallback)(DWORD sourcePid, DWORD targetPid, void* ctx);
typedef void (*EtwFileCallback)(DWORD pid, const wchar_t* filePath, UCHAR opcode, void* ctx);
typedef void (*EtwImageLoadCallback)(DWORD pid, const wchar_t* imagePath, BOOL isLoad, void* ctx);
typedef void (*EtwThreadCallback)(DWORD pid, DWORD tid, DWORD startAddr, void* ctx);

typedef struct {
    EtwRegCallback regCb;
    EtwProcStartCallback procStartCb;
    EtwProcStopCallback procStopCb;
    EtwProcTerminateCallback procTermCb;
    EtwFileCallback fileCb;
    EtwImageLoadCallback imageLoadCb;
    EtwThreadCallback threadCb;
    void* ctx;
    TrustZoneList* tz;
    HANDLE hThread;
    BOOL running;
    TRACEHANDLE hSession;
    TRACEHANDLE hConsumer;
    wchar_t sessionName[64];
    wchar_t lastRegPath[MAX_PATH];
    DWORD lastRegPid;
} EtwMonitor;

BOOL EtwStart(EtwMonitor* m, EtwRegCallback regCb, EtwProcStartCallback procStartCb,
              EtwProcStopCallback procStopCb, EtwProcTerminateCallback procTermCb,
              EtwFileCallback fileCb, EtwImageLoadCallback imageLoadCb,
              EtwThreadCallback threadCb, void* ctx, TrustZoneList* tz);
void EtwStop(EtwMonitor* m);

#endif