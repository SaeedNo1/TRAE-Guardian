#define UNICODE
#define _UNICODE

#include "guardian_hook.h"
#include "minhook/MinHook.h"
#include <windows.h>
#include <wintrust.h>
#include <stdio.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#define WINTRUST_ACTION_GENERIC_VERIFY_V2 {0xaac56b, 0xcd44, 0x11d0, {0x8c, 0xc2, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee}}

typedef LONG NTSTATUS;
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    NTSTATUS Status;
    ULONG Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef VOID (NTAPI *PIO_APC_ROUTINE)(PVOID, PIO_STATUS_BLOCK, ULONG);

#define InitializeObjectAttributes(p, n, a, r, s) \
    { (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
      (p)->RootDirectory = r; \
      (p)->ObjectName = n; \
      (p)->Attributes = a; \
      (p)->SecurityDescriptor = s; \
      (p)->SecurityQualityOfService = NULL; }

#define MH_ALL_HOOKS NULL

static BOOL g_hookInitialized = FALSE;
static BOOL g_isSigned = FALSE;
static wchar_t g_procName[256] = {0};
static wchar_t g_imagePath[MAX_PATH] = {0};
static DWORD g_pid = 0;
static BOOL g_firstCallReported = FALSE;

static const wchar_t* SYSTEM_PROCESSES[] = {
    L"svchost.exe",
    L"lsass.exe",
    L"smss.exe",
    L"csrss.exe",
    L"wininit.exe",
    L"winlogon.exe",
    L"services.exe",
    L"dwm.exe",
    L"explorer.exe",
    L"taskhostw.exe",
    L"conhost.exe",
    L"trae_guardian_daemon.exe",
    L"trae_guardian_qt.exe",
    L"trae_guardian_service_wrapper.exe",
    L"observer.exe",
    NULL
};

static BOOL IsSystemProcess(const wchar_t* name) {
    for (int i = 0; SYSTEM_PROCESSES[i]; i++) {
        if (_wcsicmp(name, SYSTEM_PROCESSES[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

static BOOL CheckFileSignature(const wchar_t* path) {
    if (!path || !path[0]) return FALSE;
    
    WINTRUST_FILE_INFO fileInfo = {0};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = path;
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;
    
    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wd = {0};
    wd.cbStruct = sizeof(WINTRUST_DATA);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fileInfo;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.hWVTStateData = NULL;
    wd.pwszURLReference = NULL;
    wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    wd.dwUIContext = 0;
    
    LONG result = WinVerifyTrust(NULL, &policyGuid, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGuid, &wd);
    
    return (result == ERROR_SUCCESS);
}

static void InitProcessInfo(void) {
    g_pid = GetCurrentProcessId();
    
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, g_pid);
    if (hProc) {
        DWORD sz = MAX_PATH;
        QueryFullProcessImageNameW(hProc, 0, g_imagePath, &sz);
        CloseHandle(hProc);
    }
    
    const wchar_t* name = wcsrchr(g_imagePath, L'\\');
    if (name) {
        wcsncpy(g_procName, name + 1, 255);
        g_procName[255] = L'\0';
    } else {
        wcsncpy(g_procName, g_imagePath, 255);
        g_procName[255] = L'\0';
    }
    
    if (!IsSystemProcess(g_procName)) {
        g_isSigned = CheckFileSignature(g_imagePath);
    } else {
        g_isSigned = TRUE;
    }
}

BOOL SendHookMessage(HookMessageType type, const wchar_t* apiName) {
    if (!g_pid || !g_procName[0])
        return FALSE;
    
    HANDLE hPipe = CreateFileW(HOOK_PIPE_NAME, GENERIC_WRITE, 0, NULL, 
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hPipe == INVALID_HANDLE_VALUE)
        return FALSE;
    
    HookMessage msg = {0};
    msg.type = type;
    msg.pid = g_pid;
    wcsncpy(msg.procName, g_procName, 255);
    if (apiName)
        wcsncpy(msg.apiName, apiName, 127);
    wcsncpy(msg.imagePath, g_imagePath, MAX_PATH - 1);
    msg.timestamp = GetTickCount64();
    
    DWORD bytesWritten = 0;
    BOOL success = WriteFile(hPipe, &msg, sizeof(HookMessage), &bytesWritten, NULL);
    
    CloseHandle(hPipe);
    return success;
}

static NTSTATUS (NTAPI *pNtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
static NTSTATUS (NTAPI *pNtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
static NTSTATUS (NTAPI *pNtDeviceIoControlFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
static NTSTATUS (NTAPI *pNtSetValueKey)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
static NTSTATUS (NTAPI *pNtDeleteKey)(HANDLE);
static NTSTATUS (NTAPI *pNtRaiseHardError)(NTSTATUS, ULONG, ULONG, PULONG_PTR, ULONG, PULONG);
static NTSTATUS (NTAPI *pNtTerminateProcess)(HANDLE, NTSTATUS);
static NTSTATUS (NTAPI *pNtLoadDriver)(PUNICODE_STRING);

static NTSTATUS NTAPI Hook_NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, 
                                          POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    if (!g_isSigned && !IsSystemProcess(g_procName)) {
        if (!g_firstCallReported) {
            g_firstCallReported = TRUE;
            SendHookMessage(HOOK_MSG_FIRST_CALL, L"NtOpenProcess");
        }
        SendHookMessage(HOOK_MSG_BLOCKED, L"NtOpenProcess");
        return STATUS_ACCESS_DENIED;
    }
    return pNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

static NTSTATUS NTAPI Hook_NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, 
                                         POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, 
                                         PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, 
                                         ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {
    if (!g_isSigned && !IsSystemProcess(g_procName)) {
        if (!g_firstCallReported) {
            g_firstCallReported = TRUE;
            SendHookMessage(HOOK_MSG_FIRST_CALL, L"NtCreateFile");
        }
    }
    return pNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, 
                         AllocationSize, FileAttributes, ShareAccess, CreateDisposition, 
                         CreateOptions, EaBuffer, EaLength);
}

static NTSTATUS NTAPI Hook_NtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, 
                                                  PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, 
                                                  PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, 
                                                  PVOID InputBuffer, ULONG InputBufferLength, 
                                                  PVOID OutputBuffer, ULONG OutputBufferLength) {
    if (!g_isSigned && !IsSystemProcess(g_procName)) {
        if (!g_firstCallReported) {
            g_firstCallReported = TRUE;
            SendHookMessage(HOOK_MSG_FIRST_CALL, L"NtDeviceIoControlFile");
        }
        SendHookMessage(HOOK_MSG_BLOCKED, L"NtDeviceIoControlFile");
        return STATUS_ACCESS_DENIED;
    }
    return pNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, 
                                   IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, 
                                   OutputBuffer, OutputBufferLength);
}

static NTSTATUS NTAPI Hook_NtSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, 
                                          ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize) {
    if (!g_isSigned && !IsSystemProcess(g_procName)) {
        if (!g_firstCallReported) {
            g_firstCallReported = TRUE;
            SendHookMessage(HOOK_MSG_FIRST_CALL, L"NtSetValueKey");
        }
        SendHookMessage(HOOK_MSG_BLOCKED, L"NtSetValueKey");
        return STATUS_ACCESS_DENIED;
    }
    return pNtSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);
}

static NTSTATUS NTAPI Hook_NtDeleteKey(HANDLE KeyHandle) {
    if (!g_isSigned && !IsSystemProcess(g_procName)) {
        if (!g_firstCallReported) {
            g_firstCallReported = TRUE;
            SendHookMessage(HOOK_MSG_FIRST_CALL, L"NtDeleteKey");
        }
        SendHookMessage(HOOK_MSG_BLOCKED, L"NtDeleteKey");
        return STATUS_ACCESS_DENIED;
    }
    return pNtDeleteKey(KeyHandle);
}

static NTSTATUS NTAPI Hook_NtRaiseHardError(NTSTATUS ErrorStatus, ULONG NumberOfParameters, 
                                             ULONG UnicodeStringParameterMask, PULONG_PTR Parameters, 
                                             ULONG ResponseOption, PULONG Response) {
    if (!g_isSigned && !IsSystemProcess(g_procName)) {
        if (!g_firstCallReported) {
            g_firstCallReported = TRUE;
            SendHookMessage(HOOK_MSG_FIRST_CALL, L"NtRaiseHardError");
        }
        SendHookMessage(HOOK_MSG_BLOCKED, L"NtRaiseHardError");
        return STATUS_ACCESS_DENIED;
    }
    return pNtRaiseHardError(ErrorStatus, NumberOfParameters, UnicodeStringParameterMask, 
                              Parameters, ResponseOption, Response);
}

static NTSTATUS NTAPI Hook_NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus) {
    if (!g_isSigned && !IsSystemProcess(g_procName)) {
        if (!g_firstCallReported) {
            g_firstCallReported = TRUE;
            SendHookMessage(HOOK_MSG_FIRST_CALL, L"NtTerminateProcess");
        }
        SendHookMessage(HOOK_MSG_BLOCKED, L"NtTerminateProcess");
        return STATUS_ACCESS_DENIED;
    }
    return pNtTerminateProcess(ProcessHandle, ExitStatus);
}

static NTSTATUS NTAPI Hook_NtLoadDriver(PUNICODE_STRING DriverServiceName) {
    if (!g_isSigned && !IsSystemProcess(g_procName)) {
        if (!g_firstCallReported) {
            g_firstCallReported = TRUE;
            SendHookMessage(HOOK_MSG_FIRST_CALL, L"NtLoadDriver");
        }
        SendHookMessage(HOOK_MSG_BLOCKED, L"NtLoadDriver");
        return STATUS_ACCESS_DENIED;
    }
    return pNtLoadDriver(DriverServiceName);
}

BOOL HookInitialize(HMODULE hModule) {
    if (g_hookInitialized)
        return TRUE;
    
    InitProcessInfo();
    
    if (IsSystemProcess(g_procName)) {
        g_hookInitialized = TRUE;
        return TRUE;
    }
    
    if (MH_Initialize() != MH_OK) {
        g_hookInitialized = TRUE;
        return TRUE;
    }
    
    MH_CreateHookApi(L"ntdll.dll", "NtOpenProcess", Hook_NtOpenProcess, (LPVOID*)&pNtOpenProcess);
    MH_CreateHookApi(L"ntdll.dll", "NtCreateFile", Hook_NtCreateFile, (LPVOID*)&pNtCreateFile);
    MH_CreateHookApi(L"ntdll.dll", "NtDeviceIoControlFile", Hook_NtDeviceIoControlFile, (LPVOID*)&pNtDeviceIoControlFile);
    MH_CreateHookApi(L"ntdll.dll", "NtSetValueKey", Hook_NtSetValueKey, (LPVOID*)&pNtSetValueKey);
    MH_CreateHookApi(L"ntdll.dll", "NtDeleteKey", Hook_NtDeleteKey, (LPVOID*)&pNtDeleteKey);
    MH_CreateHookApi(L"ntdll.dll", "NtRaiseHardError", Hook_NtRaiseHardError, (LPVOID*)&pNtRaiseHardError);
    MH_CreateHookApi(L"ntdll.dll", "NtTerminateProcess", Hook_NtTerminateProcess, (LPVOID*)&pNtTerminateProcess);
    MH_CreateHookApi(L"ntdll.dll", "NtLoadDriver", Hook_NtLoadDriver, (LPVOID*)&pNtLoadDriver);
    
    MH_EnableHook(MH_ALL_HOOKS);
    
    g_hookInitialized = TRUE;
    return TRUE;
}

void HookCleanup(void) {
    if (!g_hookInitialized)
        return;
    
    if (!IsSystemProcess(g_procName)) {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
    }
    
    g_hookInitialized = FALSE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            HookInitialize(hModule);
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            HookCleanup();
            break;
    }
    return TRUE;
}