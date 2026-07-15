#ifndef SQLITE_LOG_H
#define SQLITE_LOG_H

#include <windows.h>
#include <stdint.h>

#define LOG_TYPE_ETW 1
#define LOG_TYPE_RISK 2
#define LOG_TYPE_AI 3
#define LOG_TYPE_RESTORE 4
#define LOG_TYPE_DELETE 5
#define LOG_TYPE_NETWORK 6
#define LOG_TYPE_SCAN 7
#define LOG_TYPE_THREAT 8

typedef struct {
    uint64_t id;
    uint64_t timestamp;
    int logType;
    DWORD pid;
    wchar_t processName[256];
    wchar_t imagePath[MAX_PATH];
    wchar_t eventType[128];
    wchar_t eventPath[MAX_PATH];
    wchar_t details[2048];
    int score;
    wchar_t signer[512];
    BOOL isSigned;
} LogEntry;

typedef struct {
    void* db;
    wchar_t dbPath[MAX_PATH];
    CRITICAL_SECTION cs;
    int maxEntries;
} SQLiteLog;

BOOL SQLiteLogInit(SQLiteLog* sl, const wchar_t* dbPath);
void SQLiteLogCleanup(SQLiteLog* sl);
BOOL SQLiteLogOpen(SQLiteLog* sl);
void SQLiteLogClose(SQLiteLog* sl);
BOOL SQLiteLogInsert(SQLiteLog* sl, int logType, DWORD pid, const wchar_t* processName,
                     const wchar_t* imagePath, const wchar_t* eventType, const wchar_t* eventPath,
                     const wchar_t* details, int score, const wchar_t* signer, BOOL isSigned);
BOOL SQLiteLogQueryByPid(SQLiteLog* sl, DWORD pid, LogEntry* entries, int maxEntries, int* count);
BOOL SQLiteLogQueryByType(SQLiteLog* sl, int logType, LogEntry* entries, int maxEntries, int* count);
BOOL SQLiteLogQueryRecent(SQLiteLog* sl, uint64_t sinceTime, LogEntry* entries, int maxEntries, int* count);
BOOL SQLiteLogDeleteOldEntries(SQLiteLog* sl, uint64_t beforeTime);
int SQLiteLogGetEntryCount(SQLiteLog* sl);
void SQLiteLogDump(SQLiteLog* sl, int count);

#endif