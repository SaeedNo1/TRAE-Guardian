#pragma once

#include <windows.h>

#define MAX_PATH_W 512
#define MAX_PROCESSES 512

typedef struct {
    wchar_t name[MAX_PATH_W];
    DWORD pid;
    BOOL isTree;
    BOOL isRepeated;
} ProcessEntry;

BOOL KillProcessByName(const wchar_t* name, BOOL killTree);
BOOL KillProcessById(DWORD pid, BOOL killTree);
DWORD GetProcessIdByName(const wchar_t* name);
void EnumerateProcesses(ProcessEntry* entries, int* count);