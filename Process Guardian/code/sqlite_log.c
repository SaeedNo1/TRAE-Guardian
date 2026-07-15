#define UNICODE
#define _UNICODE

#include "sqlite_log.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_LOG_ENTRIES 100

typedef struct {
    LogEntry entries[MAX_LOG_ENTRIES];
    int count;
    int head;
} LogBuffer;

BOOL SQLiteLogInit(SQLiteLog* sl, const wchar_t* dbPath) {
    if (!sl) return FALSE;
    memset(sl, 0, sizeof(SQLiteLog));
    InitializeCriticalSection(&sl->cs);
    if (dbPath && dbPath[0]) {
        wcsncpy(sl->dbPath, dbPath, MAX_PATH - 1);
        sl->dbPath[MAX_PATH - 1] = L'\0';
    }
    sl->maxEntries = MAX_LOG_ENTRIES;
    sl->db = (LogBuffer*)malloc(sizeof(LogBuffer));
    if (!sl->db) return FALSE;
    memset(sl->db, 0, sizeof(LogBuffer));
    return TRUE;
}

void SQLiteLogCleanup(SQLiteLog* sl) {
    if (!sl) return;
    if (sl->db) {
        free(sl->db);
        sl->db = NULL;
    }
    DeleteCriticalSection(&sl->cs);
}

BOOL SQLiteLogOpen(SQLiteLog* sl) {
    if (!sl || !sl->db) return FALSE;
    EnterCriticalSection(&sl->cs);
    LogBuffer* lb = (LogBuffer*)sl->db;
    lb->count = 0;
    lb->head = 0;
    LeaveCriticalSection(&sl->cs);
    return TRUE;
}

void SQLiteLogClose(SQLiteLog* sl) {
    if (!sl || !sl->db) return;
    EnterCriticalSection(&sl->cs);
    LogBuffer* lb = (LogBuffer*)sl->db;
    lb->count = 0;
    lb->head = 0;
    LeaveCriticalSection(&sl->cs);
}

BOOL SQLiteLogInsert(SQLiteLog* sl, int logType, DWORD pid, const wchar_t* processName,
                     const wchar_t* imagePath, const wchar_t* eventType, const wchar_t* eventPath,
                     const wchar_t* details, int score, const wchar_t* signer, BOOL isSigned) {
    if (!sl || !sl->db) return FALSE;
    EnterCriticalSection(&sl->cs);
    LogBuffer* lb = (LogBuffer*)sl->db;
    int idx = (lb->head + lb->count) % MAX_LOG_ENTRIES;
    LogEntry* entry = &lb->entries[idx];
    entry->id = GetTickCount64();
    entry->timestamp = GetTickCount64();
    entry->logType = logType;
    entry->pid = pid;
    if (processName) wcsncpy(entry->processName, processName, 255);
    else wcscpy(entry->processName, L"");
    if (imagePath) wcsncpy(entry->imagePath, imagePath, MAX_PATH - 1);
    else wcscpy(entry->imagePath, L"");
    if (eventType) wcsncpy(entry->eventType, eventType, 127);
    else wcscpy(entry->eventType, L"");
    if (eventPath) wcsncpy(entry->eventPath, eventPath, MAX_PATH - 1);
    else wcscpy(entry->eventPath, L"");
    if (details) wcsncpy(entry->details, details, 2047);
    else wcscpy(entry->details, L"");
    entry->score = score;
    if (signer) wcsncpy(entry->signer, signer, 511);
    else wcscpy(entry->signer, L"");
    entry->isSigned = isSigned;
    if (lb->count < MAX_LOG_ENTRIES) lb->count++;
    else lb->head = (lb->head + 1) % MAX_LOG_ENTRIES;
    LeaveCriticalSection(&sl->cs);
    return TRUE;
}

BOOL SQLiteLogQueryByPid(SQLiteLog* sl, DWORD pid, LogEntry* entries, int maxEntries, int* count) {
    if (!sl || !sl->db || !entries || !count) return FALSE;
    *count = 0;
    EnterCriticalSection(&sl->cs);
    LogBuffer* lb = (LogBuffer*)sl->db;
    for (int i = 0; i < lb->count && *count < maxEntries; i++) {
        int idx = (lb->head + i) % MAX_LOG_ENTRIES;
        if (lb->entries[idx].pid == pid) {
            entries[*count] = lb->entries[idx];
            (*count)++;
        }
    }
    LeaveCriticalSection(&sl->cs);
    return TRUE;
}

BOOL SQLiteLogQueryByType(SQLiteLog* sl, int logType, LogEntry* entries, int maxEntries, int* count) {
    if (!sl || !sl->db || !entries || !count) return FALSE;
    *count = 0;
    EnterCriticalSection(&sl->cs);
    LogBuffer* lb = (LogBuffer*)sl->db;
    for (int i = 0; i < lb->count && *count < maxEntries; i++) {
        int idx = (lb->head + i) % MAX_LOG_ENTRIES;
        if (lb->entries[idx].logType == logType) {
            entries[*count] = lb->entries[idx];
            (*count)++;
        }
    }
    LeaveCriticalSection(&sl->cs);
    return TRUE;
}

BOOL SQLiteLogQueryRecent(SQLiteLog* sl, uint64_t sinceTime, LogEntry* entries, int maxEntries, int* count) {
    if (!sl || !sl->db || !entries || !count) return FALSE;
    *count = 0;
    EnterCriticalSection(&sl->cs);
    LogBuffer* lb = (LogBuffer*)sl->db;
    for (int i = 0; i < lb->count && *count < maxEntries; i++) {
        int idx = (lb->head + i) % MAX_LOG_ENTRIES;
        if (lb->entries[idx].timestamp >= sinceTime) {
            entries[*count] = lb->entries[idx];
            (*count)++;
        }
    }
    LeaveCriticalSection(&sl->cs);
    return TRUE;
}

BOOL SQLiteLogDeleteOldEntries(SQLiteLog* sl, uint64_t beforeTime) {
    if (!sl || !sl->db) return FALSE;
    EnterCriticalSection(&sl->cs);
    LogBuffer* lb = (LogBuffer*)sl->db;
    while (lb->count > 0) {
        if (lb->entries[lb->head].timestamp < beforeTime) {
            lb->head = (lb->head + 1) % MAX_LOG_ENTRIES;
            lb->count--;
        } else {
            break;
        }
    }
    LeaveCriticalSection(&sl->cs);
    return TRUE;
}

int SQLiteLogGetEntryCount(SQLiteLog* sl) {
    if (!sl || !sl->db) return 0;
    EnterCriticalSection(&sl->cs);
    LogBuffer* lb = (LogBuffer*)sl->db;
    int count = lb->count;
    LeaveCriticalSection(&sl->cs);
    return count;
}

void SQLiteLogDump(SQLiteLog* sl, int count) {
    if (!sl || !sl->db) return;
    EnterCriticalSection(&sl->cs);
    LogBuffer* lb = (LogBuffer*)sl->db;
    int showCount = min(count, lb->count);
    for (int i = lb->count - showCount; i < lb->count; i++) {
        int idx = (lb->head + i) % MAX_LOG_ENTRIES;
        LogEntry* e = &lb->entries[idx];
        wprintf(L"[SQLiteLog] ID=%llu Type=%d PID=%lu Name=%ls Event=%ls Score=%d\n",
                e->id, e->logType, e->pid, e->processName, e->eventType, e->score);
    }
    LeaveCriticalSection(&sl->cs);
}