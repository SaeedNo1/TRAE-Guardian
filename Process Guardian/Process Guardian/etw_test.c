#define UNICODE
#define _UNICODE
#include <windows.h>
#include <evntcons.h>
#include <evntrace.h>
#include <evntprov.h>
#include <tdh.h>
#include <stdio.h>

#pragma comment(lib, "tdh.lib")

static const GUID RegProviderGuid =
    {0x70EB4F03, 0xC1DE, 0x4F73, {0xA0, 0x51, 0x33, 0xD1, 0x3D, 0x54, 0x13, 0xBD}};

static DWORD GetPropertyString(PEVENT_RECORD ev, LPCWSTR propName, LPWSTR out, DWORD outSz) {
    PROPERTY_DATA_DESCRIPTOR desc = {0};
    desc.PropertyName = (ULONGLONG)propName;
    desc.ArrayIndex = (ULONG)-1;
    DWORD sz = 0;
    DWORD s = TdhGetPropertySize(ev, 0, NULL, 1, &desc, &sz);
    if (s != ERROR_SUCCESS) return s;
    if (sz == 0 || sz > outSz) return ERROR_INSUFFICIENT_BUFFER;
    return TdhGetProperty(ev, 0, NULL, 1, &desc, sz, (PBYTE)out);
}

static void WINAPI EventRecordCallback(PEVENT_RECORD ev) {
    wprintf(L"EVENT received\n");
    DWORD pid = ev->EventHeader.ProcessId;
    UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;
    GUID provider = ev->EventHeader.ProviderId;
    wchar_t path[1024] = {0};
    DWORD s = GetPropertyString(ev, L"KeyName", path, sizeof(path));
    wprintf(L"ETW pid=%lu opcode=%u guid={%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X} path=%s status=%lu\n",
        pid, opcode,
        provider.Data1, provider.Data2, provider.Data3,
        provider.Data4[0], provider.Data4[1], provider.Data4[2], provider.Data4[3],
        provider.Data4[4], provider.Data4[5], provider.Data4[6], provider.Data4[7],
        path, s);
}

static DWORD WINAPI Thread(LPVOID p) {
    (void)p;
    wchar_t name[64]; swprintf(name, 64, L"TestRegSession_%lu", GetCurrentProcessId());
    EVENT_TRACE_PROPERTIES* prop = (EVENT_TRACE_PROPERTIES*)malloc(sizeof(EVENT_TRACE_PROPERTIES) + 128);
    ZeroMemory(prop, sizeof(EVENT_TRACE_PROPERTIES) + 128);
    prop->Wnode.BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 128;
    prop->Wnode.ClientContext = 1;
    prop->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    prop->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    ControlTraceW(0, name, prop, EVENT_TRACE_CONTROL_STOP);
    TRACEHANDLE hSession = 0;
    ULONG st = StartTraceW(&hSession, name, prop);
    wprintf(L"StartTrace=%lu\n", st);
    if (st == 0) {
        st = EnableTraceEx2(hSession, &RegProviderGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0xFFFFFFFFFFFFFFFFULL, 0, 0, NULL);
        wprintf(L"EnableTraceEx2=%lu\n", st);
        EVENT_TRACE_LOGFILEW log = {0};
        log.LoggerName = name;
        log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        log.EventRecordCallback = EventRecordCallback;
        TRACEHANDLE hConsumer = OpenTraceW(&log);
        wprintf(L"OpenTrace=%p\n", (void*)hConsumer);
        ProcessTrace(&hConsumer, 1, 0, 0);
    }
    return 0;
}

int main(void) {
    CreateThread(NULL, 0, Thread, NULL, 0, NULL);
    Sleep(2000);
    wprintf(L"Modifying registry...\n");
    HKEY hKey;
    RegOpenKeyExW(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey);
    if (hKey) {
        const wchar_t* val = L"notepad.exe";
        RegSetValueExW(hKey, L"ETWTest", 0, REG_SZ, (const BYTE*)val, (DWORD)((wcslen(val)+1)*sizeof(wchar_t)));
        RegCloseKey(hKey);
        wprintf(L"Registry modified\n");
    } else {
        wprintf(L"Failed to open registry key\n");
    }
    Sleep(15000);
    return 0;
}
