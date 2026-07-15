#define INITGUID
#include "etw_monitor.h"
#include "daemon_core.h"
#include <evntcons.h>
#include <evntrace.h>
#include <evntprov.h>
#include <tdh.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "tdh.lib")

static DWORD GetPropertyString(PEVENT_RECORD ev, LPCWSTR propName, LPWSTR out, DWORD outSz) {
    PROPERTY_DATA_DESCRIPTOR desc;
    ZeroMemory(&desc, sizeof(desc));
    desc.PropertyName = (ULONGLONG)(ULONG_PTR)propName;
    desc.ArrayIndex = (ULONG)-1;

    DWORD sz = 0;
    DWORD status = TdhGetPropertySize(ev, 0, NULL, 1, &desc, &sz);
    if (status != ERROR_SUCCESS) return status;
    if (sz == 0 || sz > outSz) return ERROR_INSUFFICIENT_BUFFER;
    return TdhGetProperty(ev, 0, NULL, 1, &desc, sz, (PBYTE)out);
}

static void NormalizeRegPath(const wchar_t* raw, wchar_t* out, DWORD outSz) {
    out[0] = L'\0';
    if (!raw || !raw[0]) {
        DaemonLog(L"[ETW-DEBUG] NormalizeRegPath: raw is NULL or empty");
        return;
    }
    
    DaemonLog(L"[ETW-DEBUG] NormalizeRegPath: raw='%ls' (len=%lu)", raw, wcslen(raw));

    if (_wcsnicmp(raw, L"\\REGISTRY\\MACHINE\\", 18) == 0) {
        swprintf(out, outSz, L"HKEY_LOCAL_MACHINE\\%ls", raw + 18);
        DaemonLog(L"[ETW-DEBUG] NormalizeRegPath: matched MACHINE -> '%ls'", out);
    } else if (_wcsnicmp(raw, L"\\REGISTRY\\USER\\", 16) == 0) {
        swprintf(out, outSz, L"HKEY_USERS\\%ls", raw + 16);
        DaemonLog(L"[ETW-DEBUG] NormalizeRegPath: matched USER -> '%ls'", out);
    } else if (_wcsnicmp(raw, L"\\REGISTRY\\", 10) == 0) {
        swprintf(out, outSz, L"HKEY_LOCAL_MACHINE\\%ls", raw + 10);
        DaemonLog(L"[ETW-DEBUG] NormalizeRegPath: matched REGISTRY -> '%ls'", out);
    } else if (raw[0] == L'\\') {
        swprintf(out, outSz, L"HKEY_CURRENT_USER%ls", raw);
        DaemonLog(L"[ETW-DEBUG] NormalizeRegPath: matched leading backslash -> '%ls'", out);
    } else {
        swprintf(out, outSz, L"HKEY_CURRENT_USER\\%ls", raw);
        DaemonLog(L"[ETW-DEBUG] NormalizeRegPath: matched else -> '%ls'", out);
    }
}

static void DumpAllProperties(PEVENT_RECORD ev) {
    DaemonLog(L"[ETW-DEBUG] EventDescriptor: Id=%lu Version=%lu Channel=%lu Level=%lu Opcode=%lu",
              ev->EventHeader.EventDescriptor.Id,
              ev->EventHeader.EventDescriptor.Version,
              ev->EventHeader.EventDescriptor.Channel,
              ev->EventHeader.EventDescriptor.Level,
              ev->EventHeader.EventDescriptor.Opcode);
    
    DaemonLog(L"[ETW-DEBUG] Event data size=%lu", ev->UserDataLength);
    
    DaemonLog(L"[ETW-DEBUG] Raw UserData (first 128 bytes):");
    if (ev->UserData && ev->UserDataLength > 0) {
        char hexStr[1024] = {0};
        int len = (int)(ev->UserDataLength < 128 ? ev->UserDataLength : 128);
        for (int i = 0; i < len; i++) {
            sprintf(hexStr + i * 3, "%02X ", ((BYTE*)ev->UserData)[i]);
        }
        DaemonLog(L"[ETW-DEBUG] %hs", hexStr);
        
        wchar_t textStr[64] = {0};
        for (int i = 0; i < len && i < 63; i++) {
            BYTE b = ((BYTE*)ev->UserData)[i];
            textStr[i] = (b >= 0x20 && b <= 0x7E) ? (wchar_t)b : L'.';
        }
        DaemonLog(L"[ETW-DEBUG] Text: %ls", textStr);
    }
    
    const wchar_t* propNames[] = {L"KeyName", L"Path", L"ObjectName", L"ValueName", L"Data", L"OldValue",
                                  L"KeyPath", L"RegistryPath", L"Value", L"NewValue", L"ProcessId", L"ThreadId",
                                  L"ImageFileName", L"ProcessName", L"ImageName", L"ParentProcessId", L"CommandLine"};
    int numProps = sizeof(propNames) / sizeof(propNames[0]);
    
    for (int i = 0; i < numProps; i++) {
        wchar_t buffer[1024] = {0};
        DWORD sz = 0;
        PROPERTY_DATA_DESCRIPTOR desc;
        ZeroMemory(&desc, sizeof(desc));
        desc.PropertyName = (ULONGLONG)(ULONG_PTR)propNames[i];
        desc.ArrayIndex = (ULONG)-1;
        
        DWORD status = TdhGetPropertySize(ev, 0, NULL, 1, &desc, &sz);
        if (status == ERROR_SUCCESS && sz > 0 && sz <= sizeof(buffer)) {
            status = TdhGetProperty(ev, 0, NULL, 1, &desc, sz, (PBYTE)buffer);
            if (status == ERROR_SUCCESS && buffer[0]) {
                DaemonLog(L"[ETW-DEBUG] Property '%ls' found: %ls", propNames[i], buffer);
            }
        }
    }
}

static BOOL ExtractPathFromRawData(PEVENT_RECORD ev, wchar_t* outPath, DWORD outSz) {
    if (!ev->UserData || ev->UserDataLength == 0) return FALSE;
    
    BYTE* data = (BYTE*)ev->UserData;
    DWORD len = ev->UserDataLength;
    
    for (DWORD i = 0; i < len - 1; i += 2) {
        wchar_t w = *(wchar_t*)(data + i);
        if (w == L'\\') {
            DWORD j = i;
            int charCount = 0;
            while (j < len - 1) {
                wchar_t c = *(wchar_t*)(data + j);
                if (c == 0 || c == L'\r' || c == L'\n') break;
                j += 2;
                charCount++;
            }
            
            if (charCount > 3) {
                int pathLen = charCount;
                if (pathLen > (int)outSz - 1) pathLen = (int)outSz - 1;
                
                for (int k = 0; k < pathLen; k++) {
                    outPath[k] = *(wchar_t*)(data + i + k * 2);
                }
                outPath[pathLen] = L'\0';
                
                DaemonLog(L"[ETW-DEBUG] ExtractPathFromRawData: found UTF-16 path: %ls", outPath);
                
                if (wcsstr(outPath, L"Run") || wcsstr(outPath, L"Software") || 
                    wcsstr(outPath, L"Microsoft") || wcsstr(outPath, L"Windows") ||
                    wcsstr(outPath, L"SYSTEM") || wcsstr(outPath, L"System") ||
                    wcsstr(outPath, L"ControlSet") || wcsstr(outPath, L"Services")) {
                    return TRUE;
                }
            }
        }
    }
    
    for (DWORD i = 0; i < len - 1; i += 2) {
        wchar_t w = *(wchar_t*)(data + i);
        if ((w == L'S' || w == L's') && i + 16 < len) {
            wchar_t software[9] = {0};
            for (int k = 0; k < 8; k++) {
                software[k] = *(wchar_t*)(data + i + k * 2);
            }
            
            if (_wcsicmp(software, L"Software") == 0) {
                DWORD j = i;
                int charCount = 0;
                while (j < len - 1) {
                    wchar_t c = *(wchar_t*)(data + j);
                    if (c == 0 || c == L'\r' || c == L'\n') break;
                    j += 2;
                    charCount++;
                }
                
                int pathLen = charCount;
                if (pathLen > (int)outSz - 1) pathLen = (int)outSz - 1;
                
                for (int k = 0; k < pathLen; k++) {
                    outPath[k] = *(wchar_t*)(data + i + k * 2);
                }
                outPath[pathLen] = L'\0';
                
                DaemonLog(L"[ETW-DEBUG] ExtractPathFromRawData: found Software path: %ls", outPath);
                return TRUE;
            }
        }
    }
    
    return FALSE;
}

static void HandleRegEvent(EtwMonitor* m, PEVENT_RECORD ev, DWORD pid, UCHAR opcode) {
    (void)opcode;
    if (!m->regCb) return;

    UCHAR eventId = ev->EventHeader.EventDescriptor.Id;
    DaemonLog(L"[ETW-DEBUG] HandleRegEvent: pid=%lu eventId=%u opcode=%u dataLen=%lu", 
              pid, eventId, ev->EventHeader.EventDescriptor.Opcode, ev->UserDataLength);

    wchar_t rawPath[1024] = {0};
    BOOL pathFromCache = FALSE;
    const wchar_t* pathProps[] = {
        L"Object_Name", L"KeyName", L"Path", L"ObjectName", 
        L"KeyPath", L"RegistryPath", L"FullPath", L"Value",
        L"ObjectNameW", L"KeyNameW", L"PathName", L"PathW",
        L"RegistryKey", L"Hive", L"SubKey", L"FullKeyPath"
    };
    int numPathProps = sizeof(pathProps) / sizeof(pathProps[0]);
    
    DWORD status = ERROR_NOT_FOUND;
    for (int i = 0; i < numPathProps; i++) {
        DWORD sz = 0;
        PROPERTY_DATA_DESCRIPTOR desc;
        ZeroMemory(&desc, sizeof(desc));
        desc.PropertyName = (ULONGLONG)(ULONG_PTR)pathProps[i];
        desc.ArrayIndex = (ULONG)-1;
        
        DWORD sizeStatus = TdhGetPropertySize(ev, 0, NULL, 1, &desc, &sz);
        if (sizeStatus == ERROR_SUCCESS && sz > 0) {
            status = TdhGetProperty(ev, 0, NULL, 1, &desc, sz, (PBYTE)rawPath);
            if (status == ERROR_SUCCESS && rawPath[0]) {
                DaemonLog(L"[ETW-DEBUG] HandleRegEvent: found path via '%ls': %ls", pathProps[i], rawPath);
                break;
            }
        }
        rawPath[0] = L'\0';
    }
    
    if (status != ERROR_SUCCESS || !rawPath[0]) {
        DaemonLog(L"[ETW-DEBUG] HandleRegEvent: TdhGetProperty failed, trying raw data extraction...");
        if (ExtractPathFromRawData(ev, rawPath, sizeof(rawPath) / sizeof(wchar_t))) {
            DaemonLog(L"[ETW-DEBUG] HandleRegEvent: extracted path from raw data: %ls", rawPath);
        } else {
            if (eventId == 9 && m->lastRegPid == pid && m->lastRegPath[0]) {
                DaemonLog(L"[ETW-DEBUG] HandleRegEvent: using cached path for SetValue: %ls", m->lastRegPath);
                wcscpy(rawPath, m->lastRegPath);
                pathFromCache = TRUE;
            } else {
                DaemonLog(L"[ETW-DEBUG] HandleRegEvent: failed to extract path from raw data");
                DaemonLog(L"[ETW-DEBUG] Dumping all properties for this registry event:");
                DumpAllProperties(ev);
                return;
            }
        }
    }
    
    if (eventId == 2 && !pathFromCache) {
        wcscpy(m->lastRegPath, rawPath);
        m->lastRegPid = pid;
        DaemonLog(L"[ETW-DEBUG] HandleRegEvent: cached path for pid=%lu: %ls", pid, rawPath);
    }

    wchar_t valueName[512] = {0};
    GetPropertyString(ev, L"ValueName", valueName, sizeof(valueName));

    wchar_t data[1024] = {0};
    GetPropertyString(ev, L"Data", data, sizeof(data));
    if (!data[0]) {
        GetPropertyString(ev, L"NewData", data, sizeof(data));
    }

    wchar_t oldData[1024] = {0};
    GetPropertyString(ev, L"OldValue", oldData, sizeof(oldData));
    if (!oldData[0]) {
        GetPropertyString(ev, L"OldData", oldData, sizeof(oldData));
    }

    if (wcschr(rawPath, L'\\')) {
        wchar_t fullPath[1024] = {0};
        NormalizeRegPath(rawPath, fullPath, 1024);
        if (!fullPath[0]) return;
        m->regCb(pid, eventId, fullPath, valueName[0] ? valueName : NULL, data[0] ? data : NULL, oldData[0] ? oldData : NULL, FALSE, m->ctx);
    } else {
        m->regCb(pid, eventId, rawPath, valueName[0] ? valueName : NULL, data[0] ? data : NULL, oldData[0] ? oldData : NULL, FALSE, m->ctx);
    }
}

static void GetProcessInfoByPid(DWORD pid, wchar_t* outPath, DWORD pathSz, wchar_t* outName, DWORD nameSz) {
    if (outPath && pathSz > 0) *outPath = L'\0';
    if (outName && nameSz > 0) *outName = L'\0';
    
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProc == NULL) return;
    
    if (outPath && pathSz > 0) {
        DWORD sz = pathSz;
        if (QueryFullProcessImageNameW(hProc, 0, outPath, &sz)) {
            const wchar_t* name = wcsrchr(outPath, L'\\');
            if (outName && nameSz > 0) {
                if (name) {
                    wcsncpy(outName, name + 1, nameSz - 1);
                    outName[nameSz - 1] = L'\0';
                } else {
                    wcsncpy(outName, outPath, nameSz - 1);
                    outName[nameSz - 1] = L'\0';
                }
            }
        }
    } else if (outName && nameSz > 0) {
        wchar_t tempPath[MAX_PATH] = {0};
        DWORD sz = MAX_PATH;
        if (QueryFullProcessImageNameW(hProc, 0, tempPath, &sz)) {
            const wchar_t* name = wcsrchr(tempPath, L'\\');
            if (name) {
                wcsncpy(outName, name + 1, nameSz - 1);
                outName[nameSz - 1] = L'\0';
            } else {
                wcsncpy(outName, tempPath, nameSz - 1);
                outName[nameSz - 1] = L'\0';
            }
        }
    }
    CloseHandle(hProc);
}

static void HandleProcStartEvent(EtwMonitor* m, PEVENT_RECORD ev, DWORD pid) {
    if (!m->procStartCb) return;

    /* NT Kernel Logger sends pid=0xFFFFFFFF in the event header.
     * The real PID is in the event data. Try to extract it. */
    DWORD realPid = pid;
    if (pid == 0xFFFFFFFF && ev->UserDataLength >= 4) {
        memcpy(&realPid, ev->UserData, 4);
        DaemonLog(L"[ETW-PROC-START-DEBUG] Header pid=%lu, extracted real pid=%lu from event data", pid, realPid);
    }

    if (realPid == 0 || realPid == 4) return;
    if (realPid == 0xFFFFFFFF) return;

    pid = realPid;
    DaemonLog(L"[ETW-PROC-START-DEBUG] Received process start event pid=%lu", pid);

    DWORD parentPid = 0;
    wchar_t parentPidStr[32] = {0};
    const wchar_t* parentPidNames[] = {L"ParentProcessId", L"ParentId", L"PPID", NULL};
    for (int i = 0; parentPidNames[i]; i++) {
        DWORD status = GetPropertyString(ev, parentPidNames[i], parentPidStr, sizeof(parentPidStr));
        if (status == ERROR_SUCCESS && parentPidStr[0]) {
            parentPid = wcstoul(parentPidStr, NULL, 10);
            break;
        }
    }

    wchar_t imageName[1024] = {0};
    const wchar_t* imageNameProps[] = {L"ImageFileName", L"ProcessName", L"ImageName", 
                                       L"FileName", L"Name", L"Path", NULL};
    BOOL imageNameFound = FALSE;
    for (int i = 0; imageNameProps[i]; i++) {
        DWORD status = GetPropertyString(ev, imageNameProps[i], imageName, sizeof(imageName));
        if (status == ERROR_SUCCESS && imageName[0]) {
            imageNameFound = TRUE;
            DaemonLog(L"[ETW-DEBUG] ProcStart found image name via '%ls': %ls", imageNameProps[i], imageName);
            break;
        }
    }

    if (!imageNameFound) {
        DaemonLog(L"[ETW-DEBUG] ProcStart pid=%lu: Property lookup failed, trying direct data parse", pid);
        
        /* Try to parse ImageFileName directly from event data.
         * NT Kernel Logger Process_V2 format: ProcessId(4) + ImageFileName(WCHAR, null-terminated) */
        if (ev->UserDataLength > 4) {
            const wchar_t* dataStr = (const wchar_t*)((BYTE*)ev->UserData + 4);
            int maxChars = (ev->UserDataLength - 4) / 2;
            BOOL valid = TRUE;
            for (int i = 0; i < maxChars && dataStr[i]; i++) {
                if (dataStr[i] > 0x7F || (dataStr[i] < 0x20 && dataStr[i] != 0)) {
                    valid = FALSE;
                    break;
                }
            }
            if (valid && dataStr[0] >= 0x20) {
                wcsncpy(imageName, dataStr, maxChars);
                imageName[maxChars] = 0;
                imageNameFound = TRUE;
                DaemonLog(L"[ETW-DEBUG] ProcStart parsed image name from data: %ls", imageName);
            }
        }
        
        if (!imageNameFound) {
            DaemonLog(L"[ETW-DEBUG] ProcStart pid=%lu: Falling back to PID lookup", pid);
            wchar_t fallbackPath[1024] = {0};
            wchar_t fallbackName[1024] = {0};
            GetProcessInfoByPid(pid, fallbackPath, sizeof(fallbackPath), fallbackName, sizeof(fallbackName));
            if (fallbackName[0]) {
                wcscpy(imageName, fallbackName);
                imageNameFound = TRUE;
                DaemonLog(L"[ETW-DEBUG] ProcStart pid=%lu: Got name from PID lookup: %ls path=%ls", pid, fallbackName, fallbackPath);
            } else {
                DaemonLog(L"[ETW-DEBUG] ProcStart pid=%lu: PID lookup also failed, skipping", pid);
                return;
            }
        }
    }

    wchar_t commandLine[2048] = {0};
    const wchar_t* cmdLineProps[] = {L"CommandLine", L"Command Line", L"CmdLine", NULL};
    for (int i = 0; cmdLineProps[i]; i++) {
        DWORD status = GetPropertyString(ev, cmdLineProps[i], commandLine, sizeof(commandLine));
        if (status == ERROR_SUCCESS && commandLine[0]) {
            break;
        }
    }

    DaemonLog(L"[ETW-DEBUG] ProcStart pid=%lu name=%ls", pid, imageName);
    
    m->procStartCb(pid, parentPid, imageName[0] ? imageName : NULL,
                   commandLine[0] ? commandLine : L"", m->ctx);
}

static void HandleProcStopEvent(EtwMonitor* m, PEVENT_RECORD ev, DWORD pid) {
    if (!m->procStopCb) return;

    wchar_t imageName[1024] = {0};
    DWORD status = GetPropertyString(ev, L"ImageName", imageName, sizeof(imageName));
    if (status != ERROR_SUCCESS) imageName[0] = L'\0';
    m->procStopCb(pid, imageName[0] ? imageName : L"unknown", m->ctx);
}

static void HandleProcTerminateEvent(EtwMonitor* m, PEVENT_RECORD ev, DWORD sourcePid) {
    if (!m->procTermCb) return;

    DWORD targetPid = 0;
    DWORD status = GetPropertyString(ev, L"ProcessID", (LPWSTR)&targetPid, sizeof(targetPid));
    if (status != ERROR_SUCCESS) targetPid = 0;

    if (sourcePid == targetPid || targetPid == 0) {
        return;
    }

    m->procTermCb(sourcePid, targetPid, m->ctx);
}

static void HandleImageLoadEvent(EtwMonitor* m, PEVENT_RECORD ev, DWORD pid, BOOL isLoad) {
    DaemonLog(L"[ETW-DEBUG] HandleImageLoadEvent called pid=%lu isLoad=%d", pid, isLoad);
    if (!m->imageLoadCb) return;
    if (pid == 0 || pid == 4) return;

    wchar_t imageName[1024] = {0};
    DWORD status = GetPropertyString(ev, L"ImageName", imageName, sizeof(imageName));
    if (status != ERROR_SUCCESS) imageName[0] = L'\0';
    if (!imageName[0]) return;
    DaemonLog(L"[ETW-DEBUG] HandleImageLoadEvent image=%ls", imageName);
    m->imageLoadCb(pid, imageName, isLoad, m->ctx);
}

static void HandleThreadEvent(EtwMonitor* m, PEVENT_RECORD ev, DWORD pid) {
    if (!m->threadCb) return;
    if (pid == 0 || pid == 4) return;

    DWORD tid = 0;
    ULONGLONG startAddr = 0;
    DWORD status = GetPropertyString(ev, L"TThreadId", (LPWSTR)&tid, sizeof(tid));
    if (status != ERROR_SUCCESS) {
        TdhGetProperty(ev, 0, NULL, 1,
                &(PROPERTY_DATA_DESCRIPTOR){(ULONGLONG)(ULONG_PTR)L"ThreadId", (ULONG)-1},
                sizeof(tid), (PBYTE)&tid);
    }
    TdhGetProperty(ev, 0, NULL, 1,
        &(PROPERTY_DATA_DESCRIPTOR){(ULONGLONG)(ULONG_PTR)L"StartAddr", (ULONG)-1},
        sizeof(startAddr), (PBYTE)&startAddr);
    m->threadCb(pid, tid, (DWORD)startAddr, m->ctx);
}

static BOOL IsProtectedFileExtension(const wchar_t* path) {
    if (!path) return FALSE;
    const wchar_t* ext = wcsrchr(path, L'.');
    if (!ext) return FALSE;
    return !_wcsicmp(ext, L".exe") || !_wcsicmp(ext, L".dll") ||
           !_wcsicmp(ext, L".sys") || !_wcsicmp(ext, L".drv") ||
           !_wcsicmp(ext, L".bat") || !_wcsicmp(ext, L".cmd") ||
           !_wcsicmp(ext, L".ps1") || !_wcsicmp(ext, L".vbs") ||
           !_wcsicmp(ext, L".js")  || !_wcsicmp(ext, L".wsf");
}

static BOOL IsPhysicalDrivePath(const wchar_t* path) {
    if (!path) return FALSE;
    return _wcsnicmp(path, L"\\\\.\\PhysicalDrive", 16) == 0 ||
           _wcsnicmp(path, L"\\\\.\\Harddisk", 14) == 0;
}

static BOOL IsRansomNoteFile(const wchar_t* path) {
    if (!path) return FALSE;
    const wchar_t* ransomNames[] = {
        L"ransom_note", L"readme", L"how_to_decrypt",
        L"decrypt_instructions", L"pay_ransom", L"bitcoin",
        L"your_files_encrypted", L"warning", L"notice",
        NULL
    };
    const wchar_t* ext = wcsrchr(path, L'.');
    const wchar_t* nameStart = wcsrchr(path, L'\\');
    if (!nameStart) nameStart = path;
    else nameStart++;
    
    for (int i = 0; ransomNames[i]; i++) {
        if (_wcsicmp(nameStart, ransomNames[i]) == 0 ||
            wcsstr(nameStart, ransomNames[i]) != NULL) {
            return TRUE;
        }
    }
    if (ext && (_wcsicmp(ext, L".txt") == 0 || _wcsicmp(ext, L".html") == 0 ||
                _wcsicmp(ext, L".htm") == 0 || _wcsicmp(ext, L".jpg") == 0)) {
        return wcsstr(nameStart, L"ransom") != NULL || wcsstr(nameStart, L"decrypt") != NULL ||
               wcsstr(nameStart, L"pay") != NULL || wcsstr(nameStart, L"bitcoin") != NULL;
    }
    return FALSE;
}

static BOOL IsEncryptedFileExtension(const wchar_t* path) {
    if (!path) return FALSE;
    const wchar_t* encryptedExts[] = {
        L".encrypted", L".locky", L".cerber", L".cryptolocker",
        L".ctb-locker", L".crypto", L".crysis", L".wannacry",
        L".petya", L".notpetya", L".maze", L".conti",
        L".darkside", L".blackcat", L".lockbit", L".rhysida",
        NULL
    };
    for (int i = 0; encryptedExts[i]; i++) {
        if (wcsstr(path, encryptedExts[i]) != NULL) {
            return TRUE;
        }
    }
    return FALSE;
}

static void HandleFileEvent(EtwMonitor* m, PEVENT_RECORD ev, DWORD pid, UCHAR opcode) {
    if (!m->fileCb) return;
    if (pid == 0 || pid == 4) return;

    if (opcode != 68 && opcode != 69 && opcode != 70 && opcode != 71) return;

    wchar_t filePath[1024] = {0};
    DWORD status = GetPropertyString(ev, L"FileName", filePath, sizeof(filePath));
    if (status != ERROR_SUCCESS) {
        status = GetPropertyString(ev, L"Path", filePath, sizeof(filePath));
    }
    if (status != ERROR_SUCCESS) {
        status = GetPropertyString(ev, L"FilePath", filePath, sizeof(filePath));
    }
    if (status != ERROR_SUCCESS) {
        status = GetPropertyString(ev, L"Object_Name", filePath, sizeof(filePath));
    }

    if (status != ERROR_SUCCESS || !filePath[0]) {
        PBYTE data = (PBYTE)ev->UserData;
        USHORT dataLen = ev->UserDataLength;
        if (data && dataLen >= 4) {
            for (int offset = 0; offset <= dataLen - 4; offset += 2) {
                wchar_t ch = *(wchar_t*)(data + offset);
                if (ch == L'\\') {
                    int copyLen = (dataLen - offset) / 2;
                    if (copyLen > 1023) copyLen = 1023;
                    wcsncpy(filePath, (wchar_t*)(data + offset), copyLen);
                    filePath[copyLen] = L'\0';
                    for (int j = 0; j < copyLen; j++) {
                        if (filePath[j] == L'\0') break;
                    }
                    status = ERROR_SUCCESS;
                    break;
                }
            }
        }
    }

    if (status != ERROR_SUCCESS || !filePath[0]) {
        return;
    }

    if (IsPhysicalDrivePath(filePath)) {
        DaemonLog(L"[ETW-ALERT] PhysicalDrive access detected: pid=%lu path=%ls", pid, filePath);
        m->fileCb(pid, filePath, opcode, m->ctx);
        return;
    }

    if (IsRansomNoteFile(filePath)) {
        DaemonLog(L"[ETW-ALERT] Ransom note file detected: pid=%lu path=%ls", pid, filePath);
        m->fileCb(pid, filePath, opcode, m->ctx);
        return;
    }

    if (IsEncryptedFileExtension(filePath)) {
        DaemonLog(L"[ETW-ALERT] Encrypted file extension detected: pid=%lu path=%ls", pid, filePath);
        m->fileCb(pid, filePath, opcode, m->ctx);
        return;
    }

    m->fileCb(pid, filePath, opcode, m->ctx);
}

static const GUID KernelProcessProviderGuid =
    {0x3D6FA8D0, 0xFE05, 0x11D0, {0x9D, 0xDA, 0x00, 0xC0, 0x4F, 0xD7, 0xBA, 0x7C}};

/* SystemTraceControlGuid is defined by Windows headers with INITGUID */

static const GUID KernelProcessProviderGuid2 =
    {0x22FB2CD6, 0x0E7B, 0x422B, {0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}};

static const GUID KernelImageProviderGuid =
    {0x2CB15D1D, 0x5FC1, 0x11D2, {0xAB, 0xE1, 0x00, 0xA0, 0xC9, 0x11, 0xF5, 0x18}};

static const GUID KernelThreadProviderGuid =
    {0x3D6FA8D1, 0xFE05, 0x11D0, {0x9D, 0xDA, 0x00, 0xC0, 0x4F, 0xD7, 0xBA, 0x7C}};

static const GUID KernelRegistryProviderGuid =
    {0xAE53722E, 0xC863, 0x11D2, {0x8B, 0xFC, 0x00, 0xC0, 0x4F, 0x8F, 0x1F, 0x6C}};

static const GUID KernelRegistryProviderGuidAlt =
    {0x6A399AE0, 0x4BC6, 0x4DE9, {0x87, 0x0B, 0x36, 0x57, 0xF8, 0x94, 0x7E, 0x7E}};

static const GUID KernelFileProviderGuid =
    {0x90CBDC39, 0x4A3E, 0x11D1, {0x84, 0xF4, 0x00, 0x00, 0xF8, 0x04, 0x64, 0xE3}};

static inline BOOL IsEqualGuid(const GUID* a, const GUID* b) {
    return a->Data1 == b->Data1 && a->Data2 == b->Data2 && a->Data3 == b->Data3 &&
           a->Data4[0] == b->Data4[0] && a->Data4[1] == b->Data4[1] &&
           a->Data4[2] == b->Data4[2] && a->Data4[3] == b->Data4[3] &&
           a->Data4[4] == b->Data4[4] && a->Data4[5] == b->Data4[5] &&
           a->Data4[6] == b->Data4[6] && a->Data4[7] == b->Data4[7];
}

static void WINAPI EventRecordCallback(PEVENT_RECORD ev) {
    EtwMonitor* m = (EtwMonitor*)ev->UserContext;
    if (!m || !m->running) return;

    UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;
    USHORT id = ev->EventHeader.EventDescriptor.Id;
    DWORD pid = ev->EventHeader.ProcessId;

    static DWORD totalEvents = 0;
    static DWORD procEvents = 0, imageEvents = 0, threadEvents = 0, regEvents = 0, fileEvents = 0, unknownEvents2 = 0;
    totalEvents++;
    if (IsEqualGuid(&ev->EventHeader.ProviderId, &KernelProcessProviderGuid)) procEvents++;
    else if (IsEqualGuid(&ev->EventHeader.ProviderId, &KernelImageProviderGuid)) imageEvents++;
    else if (IsEqualGuid(&ev->EventHeader.ProviderId, &KernelThreadProviderGuid)) threadEvents++;
    else if (IsEqualGuid(&ev->EventHeader.ProviderId, &KernelRegistryProviderGuid) ||
             IsEqualGuid(&ev->EventHeader.ProviderId, &KernelRegistryProviderGuidAlt)) regEvents++;
    else if (IsEqualGuid(&ev->EventHeader.ProviderId, &KernelFileProviderGuid)) fileEvents++;
    else unknownEvents2++;

    /* Debug: log events for non-system processes (limited to first 100) */
    if (pid != 0 && pid != 4 && pid != GetCurrentProcessId()) {
        static DWORD debugEvtCount = 0;
        if (debugEvtCount < 100) {
            DaemonLog(L"[ETW-DEBUG] PID=%lu EVENT: provider=%08X id=%u opcode=%u dataLen=%lu",
                      pid, ev->EventHeader.ProviderId.Data1,
                      id, opcode, ev->UserDataLength);
            debugEvtCount++;
        }
    }

    if (IsEqualGuid(&ev->EventHeader.ProviderId, &KernelProcessProviderGuid)) {
        DaemonLog(L"[ETW-KERNEL-PROC] id=%u opcode=%u pid=%lu", id, opcode, pid);
        
        if (pid != 0 && pid != 4) {
            wchar_t procName[260] = {0};
            GetProcessInfoByPid(pid, NULL, 0, procName, 260);
            if (procName[0]) {
                DaemonLog(L"[ETW-KERNEL-PROC-DEBUG] pid=%lu name=%ls", pid, procName);
            }
        }
        
        if ((id == 1 && opcode == 1) || (id == 8 && opcode == 0) || (id == 21 && opcode == 0) || 
            (id == 7 && opcode == 0) || (id == 5 && opcode == 0) || (id == 6 && opcode == 0)) {
            DaemonLog(L"[ETW-DEBUG] Handling PROCESS START event");
            HandleProcStartEvent(m, ev, pid);
        } else if ((id == 2 && opcode == 2) || (id == 9 && opcode == 1)) {
            if (pid != 0 && pid != 4) HandleProcStopEvent(m, ev, pid);
        } else if (id == 3) {
            HandleProcTerminateEvent(m, ev, pid);
        } else {
            DaemonLog(L"[ETW-DEBUG] Unhandled PROCESS event: id=%u opcode=%u pid=%lu", id, opcode, pid);
            if (pid != 0 && pid != 4) {
                DaemonLog(L"[ETW-DEBUG] Trying to handle as PROCESS START for pid=%lu", pid);
                HandleProcStartEvent(m, ev, pid);
            }
        }
        return;
    }

    if (IsEqualGuid(&ev->EventHeader.ProviderId, &KernelImageProviderGuid)) {
        if (opcode == 10) {
            HandleImageLoadEvent(m, ev, pid, TRUE);
        } else if (opcode == 11) {
            HandleImageLoadEvent(m, ev, pid, FALSE);
        }
        return;
    }

    if (IsEqualGuid(&ev->EventHeader.ProviderId, &KernelThreadProviderGuid)) {
        if (opcode == 3) {
            HandleThreadEvent(m, ev, pid);
        }
        return;
    }

    if (IsEqualGuid(&ev->EventHeader.ProviderId, &KernelRegistryProviderGuid) ||
        IsEqualGuid(&ev->EventHeader.ProviderId, &KernelRegistryProviderGuidAlt)) {
        DaemonLog(L"[ETW-KERNEL-REG] id=%u opcode=%u pid=%lu", id, opcode, pid);
        if (pid == 4) return;
        HandleRegEvent(m, ev, pid, id);
        return;
    }

    if (IsEqualGuid(&ev->EventHeader.ProviderId, &KernelFileProviderGuid)) {
        static DWORD fileEvtLogCount = 0;
        if (fileEvtLogCount < 50) {
            DaemonLog(L"[ETW-FILE-EVT] id=%u opcode=%u pid=%lu dataLen=%u", id, opcode, pid, ev->UserDataLength);
            fileEvtLogCount++;
        }
        UCHAR fileOpcode = opcode;
        if (fileOpcode == 0) {
            switch (id) {
                case 12: case 15: case 25: case 64: fileOpcode = 64; break;
                case 13: case 16: case 27: case 34: case 37: case 65: case 70: fileOpcode = 70; break;
                case 22: fileOpcode = 68; break;
                case 14: case 17: case 26: case 33: case 43: case 52: case 53: case 54: case 55: case 56:
                case 57: case 58: case 59: case 60: case 61: case 62: case 63: case 68: case 69:
                case 75: case 76: case 77: fileOpcode = 69; break;
                case 28: case 71: fileOpcode = 71; break;
                default: break;
            }
        }
        if (fileOpcode >= 64 && fileOpcode <= 77) {
            HandleFileEvent(m, ev, pid, fileOpcode);
        }
        return;
    }

    /* Handle NT Kernel Logger events delivered via SystemTraceControlGuid */
    if (IsEqualGuid(&ev->EventHeader.ProviderId, &SystemTraceControlGuid)) {
        static DWORD sysLoggerEvtCount = 0;
        sysLoggerEvtCount++;
        
        /* Process events: opcode 1=Start, 2=End */
        if (opcode == 1 || opcode == 2) {
            if (sysLoggerEvtCount <= 20) {
                DaemonLog(L"[ETW-SYSLOGGER] PROCESS event: id=%u opcode=%u pid=%lu", id, opcode, pid);
            }
            if (opcode == 1 && pid != 0 && pid != 4) {
                HandleProcStartEvent(m, ev, pid);
            } else if (opcode == 2 && pid != 0 && pid != 4) {
                HandleProcStopEvent(m, ev, pid);
            }
            return;
        }
        /* Thread events: opcode 3=Start, 4=End */
        if (opcode == 3 || opcode == 4) {
            if (opcode == 3) {
                HandleThreadEvent(m, ev, pid);
            }
            return;
        }
        /* Image load events: opcode 10=Load, 11=Unload */
        if (opcode == 10 || opcode == 11) {
            HandleImageLoadEvent(m, ev, pid, opcode == 10);
            return;
        }
        /* Registry events: event IDs 1-18 */
        if (id >= 1 && id <= 18 && opcode >= 1 && opcode <= 25) {
            if (sysLoggerEvtCount <= 20) {
                DaemonLog(L"[ETW-SYSLOGGER] REGISTRY event: id=%u opcode=%u pid=%lu", id, opcode, pid);
            }
            if (pid != 0 && pid != 4) {
                HandleRegEvent(m, ev, pid, id);
            }
            return;
        }
        /* File events: event IDs 12-77 */
        if (id >= 12 && id <= 77) {
            static DWORD fileEvtLogCount2 = 0;
            if (fileEvtLogCount2 < 20) {
                DaemonLog(L"[ETW-SYSLOGGER] FILE event: id=%u opcode=%u pid=%lu", id, opcode, pid);
                fileEvtLogCount2++;
            }
            UCHAR fileOpcode = opcode;
            if (fileOpcode == 0) {
                switch (id) {
                    case 12: case 15: case 25: case 64: fileOpcode = 64; break;
                    case 13: case 16: case 27: case 34: case 37: case 65: case 70: fileOpcode = 70; break;
                    case 22: fileOpcode = 68; break;
                    default: fileOpcode = 69; break;
                }
            }
            if (fileOpcode >= 64 && fileOpcode <= 77) {
                HandleFileEvent(m, ev, pid, fileOpcode);
            }
            return;
        }
        
        /* Log unknown SystemTraceControlGuid events (limited) */
        if (sysLoggerEvtCount <= 10) {
            DaemonLog(L"[ETW-SYSLOGGER] Unknown event: id=%u opcode=%u pid=%lu dataLen=%lu",
                      id, opcode, pid, ev->UserDataLength);
        }
        return;
    }

    static DWORD unknownEvents = 0;
    unknownEvents++;
    if (unknownEvents <= 50) {
        DaemonLog(L"[ETW-DEBUG] Unknown provider GUID: Data1=%08X Data2=%04X Data3=%04X pid=%lu id=%u opcode=%u",
                  ev->EventHeader.ProviderId.Data1,
                  ev->EventHeader.ProviderId.Data2,
                  ev->EventHeader.ProviderId.Data3,
                  pid, id, opcode);

        if (ev->EventHeader.ProviderId.Data1 == 0x6A399AE0 &&
            ev->EventHeader.ProviderId.Data2 == 0x4BC6 &&
            ev->EventHeader.ProviderId.Data3 == 0x4DE9) {
            DaemonLog(L"[ETW-DEBUG] Expected registry provider - Data4: %02X%02X%02X%02X%02X%02X%02X%02X",
                      ev->EventHeader.ProviderId.Data4[0],
                      ev->EventHeader.ProviderId.Data4[1],
                      ev->EventHeader.ProviderId.Data4[2],
                      ev->EventHeader.ProviderId.Data4[3],
                      ev->EventHeader.ProviderId.Data4[4],
                      ev->EventHeader.ProviderId.Data4[5],
                      ev->EventHeader.ProviderId.Data4[6],
                      ev->EventHeader.ProviderId.Data4[7]);
            DaemonLog(L"[ETW-DEBUG] KernelRegistryProviderGuid - Data4: %02X%02X%02X%02X%02X%02X%02X%02X",
                      KernelRegistryProviderGuid.Data4[0],
                      KernelRegistryProviderGuid.Data4[1],
                      KernelRegistryProviderGuid.Data4[2],
                      KernelRegistryProviderGuid.Data4[3],
                      KernelRegistryProviderGuid.Data4[4],
                      KernelRegistryProviderGuid.Data4[5],
                      KernelRegistryProviderGuid.Data4[6],
                      KernelRegistryProviderGuid.Data4[7]);
            
            if (pid != 0 && pid != 4) {
                DaemonLog(L"[ETW-KERNEL-REG] FORCED id=%u opcode=%u pid=%lu", id, opcode, pid);
                HandleRegEvent(m, ev, pid, id);
            }
            return;
        }
    }
}

static DWORD WINAPI EtwThreadProc(LPVOID param) {
    EtwMonitor* m = (EtwMonitor*)param;
    if (!m) return 1;

    BOOL isSystemLogger = FALSE;

    size_t propSize = sizeof(EVENT_TRACE_PROPERTIES) + 128;
    EVENT_TRACE_PROPERTIES* p = (EVENT_TRACE_PROPERTIES*)malloc(propSize);

    /* Step 1: Stop any leftover "TRAE_Guardian_EtwSession" */
    ZeroMemory(p, propSize);
    p->Wnode.BufferSize = (ULONG)propSize;
    p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    wcscpy(m->sessionName, L"TRAE_Guardian_EtwSession");
    ControlTraceW(0, m->sessionName, p, EVENT_TRACE_CONTROL_STOP);

    /* Step 2: Stop any leftover "NT Kernel Logger" */
    ZeroMemory(p, propSize);
    p->Wnode.BufferSize = (ULONG)propSize;
    p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    ControlTraceW(0, KERNEL_LOGGER_NAMEW, p, EVENT_TRACE_CONTROL_STOP);

    /* Step 3: Try system logger mode (required for kernel providers) */
    ZeroMemory(p, propSize);
    p->Wnode.BufferSize = (ULONG)propSize;
    p->Wnode.Guid = SystemTraceControlGuid;
    p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    p->Wnode.ClientContext = 1;
    p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    p->LogFileNameOffset = 0;
    p->FlushTimer = 1;
    p->EnableFlags = EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_THREAD |
                     EVENT_TRACE_FLAG_IMAGE_LOAD | EVENT_TRACE_FLAG_REGISTRY |
                     EVENT_TRACE_FLAG_DISK_FILE_IO;

    wcscpy(m->sessionName, KERNEL_LOGGER_NAMEW);

    TRACEHANDLE hSession = 0;
    ULONG status = StartTraceW(&hSession, m->sessionName, p);
    if (status == ERROR_SUCCESS) {
        DaemonLog(L"ETW StartTrace succeeded as system logger (NT Kernel Logger)");
        isSystemLogger = TRUE;
    } else {
        DaemonLog(L"ETW StartTrace system logger failed: %lu, trying regular session", status);

        /* Fallback: regular session (kernel providers may not work) */
        ZeroMemory(p, propSize);
        p->Wnode.BufferSize = (ULONG)propSize;
        p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        p->Wnode.ClientContext = 1;
        p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        p->LogFileNameOffset = 0;
        p->FlushTimer = 1;
        p->EnableFlags = 0;

        wcscpy(m->sessionName, L"TRAE_Guardian_EtwSession");
        status = StartTraceW(&hSession, m->sessionName, p);
        if (status != ERROR_SUCCESS) {
            DaemonLog(L"ETW StartTrace regular also failed: %lu — ETW monitoring disabled", status);
            free(p);
            return 1;
        }
        DaemonLog(L"ETW StartTrace succeeded as regular session (fallback, kernel events may be limited)");
    }
    m->hSession = hSession;
    free(p);

    /* In system logger mode, EnableFlags already enables kernel providers.
     * EnableTraceEx2 is only needed in fallback (regular session) mode. */
    if (!isSystemLogger) {
        status = EnableTraceEx2(hSession, &KernelProcessProviderGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                TRACE_LEVEL_INFORMATION, 0xFFFFFFFFFFFFFFFFULL, 0, 0, NULL);
        DaemonLog(L"ETW EnableTraceEx2 Kernel-Process: status=%lu", status);

        status = EnableTraceEx2(hSession, &KernelImageProviderGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                TRACE_LEVEL_INFORMATION, 0xFFFFFFFFFFFFFFFFULL, 0, 0, NULL);
        DaemonLog(L"ETW EnableTraceEx2 Kernel-Image: status=%lu", status);

        status = EnableTraceEx2(hSession, &KernelThreadProviderGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);
        DaemonLog(L"ETW EnableTraceEx2 Kernel-Thread: status=%lu", status);

        status = EnableTraceEx2(hSession, &KernelRegistryProviderGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                TRACE_LEVEL_INFORMATION, 0xFFFFFFFFFFFFFFFFULL, 0, 0, NULL);
        DaemonLog(L"ETW EnableTraceEx2 Kernel-Registry: status=%lu", status);

        status = EnableTraceEx2(hSession, &KernelRegistryProviderGuidAlt, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                TRACE_LEVEL_INFORMATION, 0xFFFFFFFFFFFFFFFFULL, 0, 0, NULL);
        DaemonLog(L"ETW EnableTraceEx2 Kernel-Registry-Alt: status=%lu", status);

        status = EnableTraceEx2(hSession, &KernelFileProviderGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                TRACE_LEVEL_VERBOSE, 0xFFFFFFFFFFFFFFFFULL, 0, 0, NULL);
        DaemonLog(L"ETW EnableTraceEx2 Kernel-File: status=%lu", status);
    } else {
        DaemonLog(L"ETW system logger mode: kernel providers enabled via EnableFlags, skipping EnableTraceEx2");
    }

    EVENT_TRACE_LOGFILEW log = {0};
    log.LoggerName = m->sessionName;
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = EventRecordCallback;
    log.Context = m;

    TRACEHANDLE hConsumer = OpenTraceW(&log);
    if (hConsumer == (TRACEHANDLE)INVALID_HANDLE_VALUE) {
        DaemonLog(L"ETW OpenTrace failed");
        ControlTraceW(hSession, m->sessionName, NULL, EVENT_TRACE_CONTROL_STOP);
        return 1;
    }
    m->hConsumer = hConsumer;

    DaemonLog(L"ETW monitor started (process + image + thread + registry + file)");
    ProcessTrace(&hConsumer, 1, 0, 0);
    DaemonLog(L"ETW monitor stopped");

    CloseTrace(hConsumer);

    /* Allocate a fresh properties struct for the stop call (p was freed earlier) */
    EVENT_TRACE_PROPERTIES* pStop = (EVENT_TRACE_PROPERTIES*)malloc(propSize);
    if (pStop) {
        ZeroMemory(pStop, propSize);
        pStop->Wnode.BufferSize = (ULONG)propSize;
        pStop->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        ControlTraceW(hSession, m->sessionName, pStop, EVENT_TRACE_CONTROL_STOP);
        free(pStop);
    }
    m->hConsumer = 0;
    m->hSession = 0;
    return 0;
}

BOOL EtwStart(EtwMonitor* m, EtwRegCallback regCb, EtwProcStartCallback procStartCb,
              EtwProcStopCallback procStopCb, EtwProcTerminateCallback procTermCb,
              EtwFileCallback fileCb, EtwImageLoadCallback imageLoadCb,
              EtwThreadCallback threadCb, void* ctx, TrustZoneList* tz) {
    if (!m) return FALSE;
    ZeroMemory(m, sizeof(EtwMonitor));
    m->regCb = regCb;
    m->procStartCb = procStartCb;
    m->procStopCb = procStopCb;
    m->procTermCb = procTermCb;
    m->fileCb = fileCb;
    m->imageLoadCb = imageLoadCb;
    m->threadCb = threadCb;
    m->ctx = ctx;
    m->tz = tz;
    m->running = TRUE;
    m->hThread = CreateThread(NULL, 0, EtwThreadProc, m, 0, NULL);
    return m->hThread != NULL;
}

void EtwStop(EtwMonitor* m) {
    if (!m) return;
    m->running = FALSE;
    if (m->hConsumer) CloseTrace(m->hConsumer);
    if (m->hThread) {
        WaitForSingleObject(m->hThread, 3000);
        CloseHandle(m->hThread);
        m->hThread = NULL;
    }
}
