#ifndef GUARDIAN_HOOK_H
#define GUARDIAN_HOOK_H

#include <stdint.h>
#include <windows.h>

#define HOOK_PIPE_NAME L"\\\\.\\pipe\\GuardianHookPipe"
#define HOOK_TIMEOUT_MS 5000

typedef enum {
    HOOK_MSG_FIRST_CALL = 1,
    HOOK_MSG_API_CALL = 2,
    HOOK_MSG_BLOCKED = 3
} HookMessageType;

typedef struct {
    HookMessageType type;
    DWORD pid;
    wchar_t procName[256];
    wchar_t apiName[128];
    wchar_t imagePath[MAX_PATH];
    uint64_t timestamp;
} HookMessage;

BOOL HookInitialize(HMODULE hModule);
void HookCleanup(void);
BOOL SendHookMessage(HookMessageType type, const wchar_t* apiName);

#endif