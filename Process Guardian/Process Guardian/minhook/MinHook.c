#include "MinHook.h"

#ifdef _M_X64
#include "hde64.h"
#define hde_disasm hde64_disasm
#define hde_s hde64s
#else
#include "hde32.h"
#define hde_disasm hde32_disasm
#define hde_s hde32s
#endif

typedef struct {
    LPVOID pTarget;
    LPVOID pDetour;
    LPVOID pOriginal;
    BYTE originalBytes[32];
    BYTE trampoline[32];
    BOOL enabled;
} HOOK_ENTRY;

#define MAX_HOOKS 64
static HOOK_ENTRY g_hooks[MAX_HOOKS] = {0};
static int g_hookCount = 0;
static BOOL g_initialized = FALSE;

static BOOL IsCodePage(LPVOID p)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0)
        return FALSE;
    return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

static BOOL WriteProtectedMemory(LPVOID p, const void *data, SIZE_T size)
{
    DWORD oldProtect;
    if (!VirtualProtect(p, size, PAGE_EXECUTE_READWRITE, &oldProtect))
        return FALSE;
    memcpy(p, data, size);
    VirtualProtect(p, size, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), p, size);
    return TRUE;
}

static int FindHookIndex(LPVOID pTarget)
{
    for (int i = 0; i < g_hookCount; i++) {
        if (g_hooks[i].pTarget == pTarget)
            return i;
    }
    return -1;
}

MH_STATUS WINAPI MH_Initialize(VOID)
{
    if (g_initialized)
        return MH_ERROR_ALREADY_INITIALIZED;
    g_hookCount = 0;
    g_initialized = TRUE;
    return MH_OK;
}

MH_STATUS WINAPI MH_Uninitialize(VOID)
{
    if (!g_initialized)
        return MH_ERROR_NOT_INITIALIZED;
    for (int i = 0; i < g_hookCount; i++) {
        if (g_hooks[i].enabled)
            MH_DisableHook(g_hooks[i].pTarget);
    }
    g_hookCount = 0;
    g_initialized = FALSE;
    return MH_OK;
}

MH_STATUS WINAPI MH_CreateHook(LPVOID pTarget, LPVOID pDetour, LPVOID *ppOriginal)
{
    if (!g_initialized)
        return MH_ERROR_NOT_INITIALIZED;
    if (!pTarget || !pDetour)
        return MH_ERROR_UNSUPPORTED_FUNCTION;
    if (!IsCodePage(pTarget))
        return MH_ERROR_NOT_EXECUTABLE;
    if (FindHookIndex(pTarget) >= 0)
        return MH_ERROR_ALREADY_CREATED;
    if (g_hookCount >= MAX_HOOKS)
        return MH_ERROR_MEMORY_ALLOC;

    hde_s hs;
    unsigned int len = hde_disasm(pTarget, &hs);
    if (len < 5)
        return MH_ERROR_UNSUPPORTED_FUNCTION;

    HOOK_ENTRY *pEntry = &g_hooks[g_hookCount++];
    pEntry->pTarget = pTarget;
    pEntry->pDetour = pDetour;
    pEntry->enabled = FALSE;

    memcpy(pEntry->originalBytes, pTarget, len);

    BYTE *trampoline = pEntry->trampoline;
    *trampoline++ = 0xFF;
    *trampoline++ = 0x25;
    *(DWORD *)trampoline = 0;
    trampoline += 4;
    *(DWORD *)trampoline = (DWORD)pTarget + len;
    trampoline += 4;

    if (len > 12) {
        memcpy(trampoline, pTarget + 12, len - 12);
        trampoline += len - 12;
    }

    pEntry->pOriginal = pEntry->trampoline;
    if (ppOriginal)
        *ppOriginal = pEntry->pOriginal;

    return MH_OK;
}

MH_STATUS WINAPI MH_CreateHookApi(LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, LPVOID *ppOriginal)
{
    if (!pszModule || !pszProcName)
        return MH_ERROR_UNSUPPORTED_FUNCTION;
    HMODULE hModule = GetModuleHandleW(pszModule);
    if (!hModule)
        return MH_ERROR_MODULE_NOT_FOUND;
    LPVOID pTarget = (LPVOID)GetProcAddress(hModule, pszProcName);
    if (!pTarget)
        return MH_ERROR_FUNCTION_NOT_FOUND;
    return MH_CreateHook(pTarget, pDetour, ppOriginal);
}

MH_STATUS WINAPI MH_CreateHookApiEx(LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, LPVOID *ppOriginal, LPVOID *ppTarget)
{
    if (!pszModule || !pszProcName)
        return MH_ERROR_UNSUPPORTED_FUNCTION;
    HMODULE hModule = GetModuleHandleW(pszModule);
    if (!hModule)
        return MH_ERROR_MODULE_NOT_FOUND;
    LPVOID pTarget = (LPVOID)GetProcAddress(hModule, pszProcName);
    if (!pTarget)
        return MH_ERROR_FUNCTION_NOT_FOUND;
    if (ppTarget)
        *ppTarget = pTarget;
    return MH_CreateHook(pTarget, pDetour, ppOriginal);
}

MH_STATUS WINAPI MH_RemoveHook(LPVOID pTarget)
{
    if (!g_initialized)
        return MH_ERROR_NOT_INITIALIZED;
    int idx = FindHookIndex(pTarget);
    if (idx < 0)
        return MH_ERROR_NOT_CREATED;
    if (g_hooks[idx].enabled)
        return MH_ERROR_ENABLED;

    for (int i = idx; i < g_hookCount - 1; i++) {
        g_hooks[i] = g_hooks[i + 1];
    }
    g_hookCount--;
    return MH_OK;
}

MH_STATUS WINAPI MH_EnableHook(LPVOID pTarget)
{
    if (!g_initialized)
        return MH_ERROR_NOT_INITIALIZED;
    int idx = FindHookIndex(pTarget);
    if (idx < 0)
        return MH_ERROR_NOT_CREATED;
    if (g_hooks[idx].enabled)
        return MH_ERROR_ENABLED;

    hde_s hs;
    unsigned int len = hde_disasm(pTarget, &hs);
    if (len < 5)
        return MH_ERROR_UNSUPPORTED_FUNCTION;

    BYTE jump[32] = {0};
    BYTE *pJump = jump;
    *pJump++ = 0xE9;
    *(DWORD *)pJump = (DWORD)g_hooks[idx].pDetour - (DWORD)pTarget - 5;
    pJump += 4;

    if (len > 5) {
        memcpy(pJump, pTarget + 5, len - 5);
    }

    if (!WriteProtectedMemory(pTarget, jump, len))
        return MH_ERROR_MEMORY_PROTECT;

    g_hooks[idx].enabled = TRUE;
    return MH_OK;
}

MH_STATUS WINAPI MH_DisableHook(LPVOID pTarget)
{
    if (!g_initialized)
        return MH_ERROR_NOT_INITIALIZED;
    int idx = FindHookIndex(pTarget);
    if (idx < 0)
        return MH_ERROR_NOT_CREATED;
    if (!g_hooks[idx].enabled)
        return MH_ERROR_DISABLED;

    hde_s hs;
    unsigned int len = hde_disasm(pTarget, &hs);
    if (len < 5)
        return MH_ERROR_UNSUPPORTED_FUNCTION;

    if (!WriteProtectedMemory(pTarget, g_hooks[idx].originalBytes, len))
        return MH_ERROR_MEMORY_PROTECT;

    g_hooks[idx].enabled = FALSE;
    return MH_OK;
}

MH_STATUS WINAPI MH_EnableHookEx(LPVOID pTarget, DWORD dwThreadId)
{
    return MH_EnableHook(pTarget);
}

MH_STATUS WINAPI MH_DisableHookEx(LPVOID pTarget, DWORD dwThreadId)
{
    return MH_DisableHook(pTarget);
}

MH_STATUS WINAPI MH_QueueEnableHook(LPVOID pTarget)
{
    return MH_ERROR_UNSUPPORTED_FUNCTION;
}

MH_STATUS WINAPI MH_QueueDisableHook(LPVOID pTarget)
{
    return MH_ERROR_UNSUPPORTED_FUNCTION;
}

MH_STATUS WINAPI MH_ApplyQueued(VOID)
{
    return MH_ERROR_UNSUPPORTED_FUNCTION;
}

MH_STATUS WINAPI MH_GetHookInfo(LPVOID pTarget, MH_PAIR *ppPair)
{
    if (!g_initialized)
        return MH_ERROR_NOT_INITIALIZED;
    int idx = FindHookIndex(pTarget);
    if (idx < 0)
        return MH_ERROR_NOT_CREATED;
    if (!ppPair)
        return MH_ERROR_UNSUPPORTED_FUNCTION;

    ppPair->pTarget = g_hooks[idx].pTarget;
    ppPair->pDetour = g_hooks[idx].pDetour;
    ppPair->pOriginal = g_hooks[idx].pOriginal;
    return MH_OK;
}