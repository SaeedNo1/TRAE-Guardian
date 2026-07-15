#ifndef MINHOOK_H
#define MINHOOK_H

#if !(defined _M_IX86) && !(defined _M_X64) && !(defined __i386__) && !(defined __x86_64__)
#error MinHook supports only x86 and x64 systems.
#endif

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum MH_STATUS
{
    MH_OK = 0,
    MH_ERROR_ALREADY_INITIALIZED = -1,
    MH_ERROR_NOT_INITIALIZED = -2,
    MH_ERROR_ALREADY_CREATED = -3,
    MH_ERROR_NOT_CREATED = -4,
    MH_ERROR_ENABLED = -5,
    MH_ERROR_DISABLED = -6,
    MH_ERROR_NOT_EXECUTABLE = -7,
    MH_ERROR_UNSUPPORTED_FUNCTION = -8,
    MH_ERROR_MEMORY_ALLOC = -9,
    MH_ERROR_MEMORY_PROTECT = -10,
    MH_ERROR_MODULE_NOT_FOUND = -11,
    MH_ERROR_FUNCTION_NOT_FOUND = -12
} MH_STATUS;

typedef void *MH_CPU_CTX;

typedef struct MH_PAIR
{
    LPVOID pTarget;
    LPVOID pDetour;
    LPVOID pOriginal;
} MH_PAIR;

MH_STATUS WINAPI MH_Initialize(VOID);
MH_STATUS WINAPI MH_Uninitialize(VOID);
MH_STATUS WINAPI MH_CreateHook(LPVOID pTarget, LPVOID pDetour, LPVOID *ppOriginal);
MH_STATUS WINAPI MH_CreateHookApi(LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, LPVOID *ppOriginal);
MH_STATUS WINAPI MH_CreateHookApiEx(LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, LPVOID *ppOriginal, LPVOID *ppTarget);
MH_STATUS WINAPI MH_RemoveHook(LPVOID pTarget);
MH_STATUS WINAPI MH_EnableHook(LPVOID pTarget);
MH_STATUS WINAPI MH_DisableHook(LPVOID pTarget);
MH_STATUS WINAPI MH_EnableHookEx(LPVOID pTarget, DWORD dwThreadId);
MH_STATUS WINAPI MH_DisableHookEx(LPVOID pTarget, DWORD dwThreadId);
MH_STATUS WINAPI MH_QueueEnableHook(LPVOID pTarget);
MH_STATUS WINAPI MH_QueueDisableHook(LPVOID pTarget);
MH_STATUS WINAPI MH_ApplyQueued(VOID);
MH_STATUS WINAPI MH_GetHookInfo(LPVOID pTarget, MH_PAIR *ppPair);

#ifdef __cplusplus
}
#endif

#endif