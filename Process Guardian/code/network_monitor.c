#define UNICODE
#define _UNICODE

#include "network_monitor.h"
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <stdio.h>

#ifndef TCP_TABLE_OWNER_PID
#define TCP_TABLE_OWNER_PID 5
#endif
#ifndef UDP_TABLE_OWNER_PID
#define UDP_TABLE_OWNER_PID 1
#endif

#pragma comment(lib, "iphlpapi.lib")

NetworkMonitor g_networkMonitor = {0};

BOOL NetworkMonitorInit(NetworkMonitor* nm) {
    if (!nm) return FALSE;
    InitializeCriticalSection(&nm->cs);
    nm->entryCount = 0;
    nm->hUpdateEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    nm->running = FALSE;
    return TRUE;
}

void NetworkMonitorCleanup(NetworkMonitor* nm) {
    if (!nm) return;
    DeleteCriticalSection(&nm->cs);
    if (nm->hUpdateEvent) CloseHandle(nm->hUpdateEvent);
}

NetFlowEntry* NetworkMonitorGetEntry(NetworkMonitor* nm, DWORD pid) {
    if (!nm || !pid) return NULL;
    for (int i = 0; i < nm->entryCount; i++) {
        if (nm->entries[i].pid == pid) return &nm->entries[i];
    }
    return NULL;
}

NetFlowEntry* NetworkMonitorCreateEntry(NetworkMonitor* nm, DWORD pid, const wchar_t* name, const wchar_t* imagePath) {
    if (!nm || nm->entryCount >= MAX_FLOW_ENTRIES) return NULL;
    NetFlowEntry* entry = &nm->entries[nm->entryCount++];
    memset(entry, 0, sizeof(NetFlowEntry));
    entry->pid = pid;
    if (name) wcsncpy(entry->name, name, 255);
    if (imagePath) wcsncpy(entry->imagePath, imagePath, MAX_PATH - 1);
    entry->lastUserActionTime = GetTickCount64();
    entry->lastFocusTime = 0;
    entry->hasFocus = FALSE;
    entry->isKernel = (pid == 0 || pid == 4);
    entry->highFlowLevel = FLOW_LEVEL_SAFE;
    entry->isWhitelisted = FALSE;
    entry->whitelistThreshold = 100;
    entry->lastCheckTime = GetTickCount64();
    
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = {0};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (pe.th32ProcessID == pid) {
                    entry->parentPid = pe.th32ParentProcessID;
                    if (pe.th32ParentProcessID != 0) {
                        PROCESSENTRY32W ppe = {0};
                        ppe.dwSize = sizeof(ppe);
                        if (Process32FirstW(hSnap, &ppe)) {
                            do {
                                if (ppe.th32ProcessID == pe.th32ParentProcessID) {
                                    wcsncpy(entry->parentName, ppe.szExeFile, 255);
                                    break;
                                }
                            } while (Process32NextW(hSnap, &ppe));
                        }
                    }
                    break;
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    
    return entry;
}

void NetworkMonitorUpdateConnections(DWORD pid, const wchar_t* name, const wchar_t* imagePath, int connCount) {
    if (!pid) return;
    EnterCriticalSection(&g_networkMonitor.cs);
    
    NetFlowEntry* entry = NetworkMonitorGetEntry(&g_networkMonitor, pid);
    if (!entry) {
        entry = NetworkMonitorCreateEntry(&g_networkMonitor, pid, name, imagePath);
    }
    
    if (entry) {
        uint64_t now = GetTickCount64();
        entry->flowHistory.connectionCount[entry->flowHistory.historyIndex] = connCount;
        entry->flowHistory.timestamps[entry->flowHistory.historyIndex] = now;
        entry->flowHistory.historyIndex = (entry->flowHistory.historyIndex + 1) % FLOW_HISTORY_SIZE;
        if (entry->flowHistory.historyCount < FLOW_HISTORY_SIZE) {
            entry->flowHistory.historyCount++;
        }
        entry->lastCheckTime = now;
    }
    
    LeaveCriticalSection(&g_networkMonitor.cs);
}

void NetworkMonitorMarkUserAction(DWORD pid) {
    if (!pid) return;
    EnterCriticalSection(&g_networkMonitor.cs);
    NetFlowEntry* entry = NetworkMonitorGetEntry(&g_networkMonitor, pid);
    if (entry) {
        entry->lastUserActionTime = GetTickCount64();
    }
    LeaveCriticalSection(&g_networkMonitor.cs);
}

void NetworkMonitorUpdateFocus(DWORD pid, BOOL hasFocus) {
    if (!pid) return;
    EnterCriticalSection(&g_networkMonitor.cs);
    NetFlowEntry* entry = NetworkMonitorGetEntry(&g_networkMonitor, pid);
    if (entry) {
        entry->hasFocus = hasFocus;
        if (hasFocus) {
            entry->lastFocusTime = GetTickCount64();
            entry->lastUserActionTime = GetTickCount64();
        }
    }
    LeaveCriticalSection(&g_networkMonitor.cs);
}

FlowLevel NetworkMonitorGetFlowLevel(DWORD pid, int* connCount) {
    if (!pid) return FLOW_LEVEL_SAFE;
    
    EnterCriticalSection(&g_networkMonitor.cs);
    NetFlowEntry* entry = NetworkMonitorGetEntry(&g_networkMonitor, pid);
    if (!entry) {
        LeaveCriticalSection(&g_networkMonitor.cs);
        return FLOW_LEVEL_SAFE;
    }
    
    if (entry->flowHistory.historyCount < 1) {
        LeaveCriticalSection(&g_networkMonitor.cs);
        return FLOW_LEVEL_SAFE;
    }
    
    int idx = (entry->flowHistory.historyIndex - 1 + FLOW_HISTORY_SIZE) % FLOW_HISTORY_SIZE;
    int count = entry->flowHistory.connectionCount[idx];
    
    LeaveCriticalSection(&g_networkMonitor.cs);
    
    if (connCount) *connCount = count;
    
    if (entry->isWhitelisted) {
        if (count < entry->whitelistThreshold) return FLOW_LEVEL_SAFE;
        return FLOW_LEVEL_WARNING;
    }
    
    if (entry->isKernel) {
        if (count > KERNEL_MAX_CONNECTIONS) return FLOW_LEVEL_CRITICAL;
        return FLOW_LEVEL_SAFE;
    }
    
    if (count > DANGER_CONNECTIONS) return FLOW_LEVEL_DANGER;
    if (count > WARNING_CONNECTIONS) return FLOW_LEVEL_WARNING;
    if (count > SAFE_CONNECTIONS) return FLOW_LEVEL_WARNING;
    return FLOW_LEVEL_SAFE;
}

void NetworkMonitorAddWhitelist(DWORD pid, int threshold) {
    EnterCriticalSection(&g_networkMonitor.cs);
    NetFlowEntry* entry = NetworkMonitorGetEntry(&g_networkMonitor, pid);
    if (entry) {
        entry->isWhitelisted = TRUE;
        entry->whitelistThreshold = threshold;
    }
    LeaveCriticalSection(&g_networkMonitor.cs);
}

void NetworkMonitorRemoveWhitelist(DWORD pid) {
    EnterCriticalSection(&g_networkMonitor.cs);
    NetFlowEntry* entry = NetworkMonitorGetEntry(&g_networkMonitor, pid);
    if (entry) {
        entry->isWhitelisted = FALSE;
    }
    LeaveCriticalSection(&g_networkMonitor.cs);
}

int NetworkMonitorGetScore(DWORD pid) {
    int connCount = 0;
    FlowLevel level = NetworkMonitorGetFlowLevel(pid, &connCount);
    
    EnterCriticalSection(&g_networkMonitor.cs);
    NetFlowEntry* entry = NetworkMonitorGetEntry(&g_networkMonitor, pid);
    if (!entry) {
        LeaveCriticalSection(&g_networkMonitor.cs);
        return 0;
    }
    
    uint64_t now = GetTickCount64();
    uint64_t timeSinceUserAction = now - entry->lastUserActionTime;
    BOOL hasRecentUserAction = (timeSinceUserAction <= 5000);
    BOOL hasFocus = entry->hasFocus;
    
    LeaveCriticalSection(&g_networkMonitor.cs);
    
    int score = 0;
    
    switch (level) {
        case FLOW_LEVEL_SAFE:
            if (connCount <= SAFE_CONNECTIONS) {
                score = -10;
            }
            break;
        case FLOW_LEVEL_WARNING:
            if (hasRecentUserAction || hasFocus) {
                score = 5;
            } else {
                score = 15;
            }
            break;
        case FLOW_LEVEL_DANGER:
            if (hasRecentUserAction || hasFocus) {
                score = 20;
            } else {
                score = 40;
            }
            break;
        case FLOW_LEVEL_CRITICAL:
            score = 60;
            break;
    }
    
    return score;
}

void NetworkMonitorPurgeStaleEntries(NetworkMonitor* nm) {
    if (!nm) return;
    EnterCriticalSection(&nm->cs);
    uint64_t now = GetTickCount64();
    for (int i = nm->entryCount - 1; i >= 0; i--) {
        if (now - nm->entries[i].lastCheckTime > 60000) {
            for (int j = i; j < nm->entryCount - 1; j++) {
                nm->entries[j] = nm->entries[j + 1];
            }
            nm->entryCount--;
        }
    }
    LeaveCriticalSection(&nm->cs);
}

DWORD WINAPI NetworkMonitorThreadProc(LPVOID param) {
    NetworkMonitor* nm = &g_networkMonitor;
    if (!nm) return 0;
    
    MIB_TCPTABLE_OWNER_PID* tcpTable = NULL;
    MIB_UDPTABLE_OWNER_PID* udpTable = NULL;
    DWORD tcpSize = 0, udpSize = 0;
    
    while (nm->running) {
        int pidConnCounts[MAX_FLOW_ENTRIES] = {0};
        DWORD pidList[MAX_FLOW_ENTRIES] = {0};
        int pidCount = 0;
        
        GetExtendedTcpTable(NULL, &tcpSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID, 0);
        tcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(tcpSize);
        if (tcpTable && GetExtendedTcpTable(tcpTable, &tcpSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
                DWORD pid = tcpTable->table[i].dwOwningPid;
                if (pid == 0) continue;
                
                int found = FALSE;
                for (int j = 0; j < pidCount; j++) {
                    if (pidList[j] == pid) {
                        pidConnCounts[j]++;
                        found = TRUE;
                        break;
                    }
                }
                if (!found && pidCount < MAX_FLOW_ENTRIES) {
                    pidList[pidCount] = pid;
                    pidConnCounts[pidCount] = 1;
                    pidCount++;
                }
            }
        }
        free(tcpTable);
        
        GetExtendedUdpTable(NULL, &udpSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        udpTable = (MIB_UDPTABLE_OWNER_PID*)malloc(udpSize);
        if (udpTable && GetExtendedUdpTable(udpTable, &udpSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            for (DWORD i = 0; i < udpTable->dwNumEntries; i++) {
                DWORD pid = udpTable->table[i].dwOwningPid;
                if (pid == 0) continue;
                
                int found = FALSE;
                for (int j = 0; j < pidCount; j++) {
                    if (pidList[j] == pid) {
                        pidConnCounts[j]++;
                        found = TRUE;
                        break;
                    }
                }
                if (!found && pidCount < MAX_FLOW_ENTRIES) {
                    pidList[pidCount] = pid;
                    pidConnCounts[pidCount] = 1;
                    pidCount++;
                }
            }
        }
        free(udpTable);
        
        for (int i = 0; i < pidCount; i++) {
            DWORD pid = pidList[i];
            int connCount = pidConnCounts[i];
            
            wchar_t name[MAX_PATH] = {0};
            wchar_t path[MAX_PATH] = {0};
            
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (hProc) {
                DWORD sz = MAX_PATH;
                QueryFullProcessImageNameW(hProc, 0, path, &sz);
                CloseHandle(hProc);
                wchar_t* lastSlash = wcsrchr(path, L'\\');
                if (lastSlash) wcscpy(name, lastSlash + 1);
            }
            
            NetworkMonitorUpdateConnections(pid, name[0] ? name : L"unknown", path[0] ? path : L"", connCount);
        }
        
        HWND foreground = GetForegroundWindow();
        if (foreground) {
            DWORD foregroundPid = 0;
            GetWindowThreadProcessId(foreground, &foregroundPid);
            if (foregroundPid != 0) {
                NetworkMonitorUpdateFocus(foregroundPid, TRUE);
            }
        }
        
        NetworkMonitorPurgeStaleEntries(nm);
        
        Sleep(1000);
    }
    
    return 0;
}

void NetworkMonitorStart(NetworkMonitor* nm) {
    if (!nm) return;
    nm->running = TRUE;
    CreateThread(NULL, 0, NetworkMonitorThreadProc, nm, 0, NULL);
}

void NetworkMonitorStop(NetworkMonitor* nm) {
    if (!nm) return;
    nm->running = FALSE;
}
