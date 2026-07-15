#define UNICODE
#define _UNICODE

#include "whitelist_db.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void AddDefaultWhitelist(WhitelistDB* wdb) {
    if (!wdb) return;
    WhitelistDBAdd(wdb, L"", L"Microsoft Corporation", L"C:\\Windows\\*", L"", L"", WHITELIST_TYPE_PUBLISHER | WHITELIST_TYPE_PATH | WHITELIST_TYPE_TRUSTED);
    WhitelistDBAdd(wdb, L"", L"Microsoft Windows", L"", L"", L"", WHITELIST_TYPE_PUBLISHER | WHITELIST_TYPE_TRUSTED);
    WhitelistDBAdd(wdb, L"", L"Google LLC", L"", L"", L"", WHITELIST_TYPE_PUBLISHER);
    WhitelistDBAdd(wdb, L"", L"Apple Inc.", L"", L"", L"", WHITELIST_TYPE_PUBLISHER);
    WhitelistDBAdd(wdb, L"", L"Oracle Corporation", L"", L"", L"", WHITELIST_TYPE_PUBLISHER);
    WhitelistDBAdd(wdb, L"", L"Intel Corporation", L"", L"", L"", WHITELIST_TYPE_PUBLISHER);
    WhitelistDBAdd(wdb, L"", L"NVIDIA Corporation", L"", L"", L"", WHITELIST_TYPE_PUBLISHER);
    WhitelistDBAdd(wdb, L"", L"AMD", L"", L"", L"", WHITELIST_TYPE_PUBLISHER);
}

BOOL WhitelistDBInit(WhitelistDB* wdb, const wchar_t* dbPath) {
    if (!wdb) return FALSE;
    memset(wdb, 0, sizeof(WhitelistDB));
    InitializeCriticalSection(&wdb->cs);
    if (dbPath && dbPath[0]) {
        wcsncpy(wdb->dbPath, dbPath, sizeof(wdb->dbPath) / sizeof(wchar_t) - 1);
        wdb->dbPath[sizeof(wdb->dbPath) / sizeof(wchar_t) - 1] = L'\0';
    }
    return TRUE;
}

void WhitelistDBCleanup(WhitelistDB* wdb) {
    if (!wdb) return;
    EnterCriticalSection(&wdb->cs);
    WhitelistEntry* entry = wdb->head;
    while (entry) {
        WhitelistEntry* next = entry->next;
        free(entry);
        entry = next;
    }
    wdb->head = NULL;
    wdb->entryCount = 0;
    LeaveCriticalSection(&wdb->cs);
    DeleteCriticalSection(&wdb->cs);
}

BOOL WhitelistDBLoad(WhitelistDB* wdb) {
    if (!wdb) return FALSE;
    EnterCriticalSection(&wdb->cs);
    if (wdb->dbPath[0]) {
        FILE* f = _wfopen(wdb->dbPath, L"rb");
        if (f) {
            fclose(f);
        } else {
            AddDefaultWhitelist(wdb);
            WhitelistDBSave(wdb);
        }
    } else {
        AddDefaultWhitelist(wdb);
    }
    LeaveCriticalSection(&wdb->cs);
    return TRUE;
}

BOOL WhitelistDBSave(WhitelistDB* wdb) {
    if (!wdb || !wdb->dbPath[0]) return FALSE;
    EnterCriticalSection(&wdb->cs);
    FILE* f = _wfopen(wdb->dbPath, L"wb");
    if (!f) {
        LeaveCriticalSection(&wdb->cs);
        return FALSE;
    }
    fprintf(f, "{\n");
    fprintf(f, "  \"whitelist\": [\n");
    WhitelistEntry* entry = wdb->head;
    while (entry) {
        fprintf(f, "    {\n");
        fprintf(f, "      \"hash\": \"%ls\",\n", entry->hash);
        fprintf(f, "      \"publisher\": \"%ls\",\n", entry->publisher);
        fprintf(f, "      \"path\": \"%ls\",\n", entry->path);
        fprintf(f, "      \"version\": \"%ls\",\n", entry->version);
        fprintf(f, "      \"name\": \"%ls\",\n", entry->name);
        fprintf(f, "      \"flags\": %d,\n", entry->flags);
        fprintf(f, "      \"addedTime\": %llu,\n", entry->addedTime);
        fprintf(f, "      \"lastUsedTime\": %llu,\n", entry->lastUsedTime);
        fprintf(f, "      \"hitCount\": %u\n", entry->hitCount);
        fprintf(f, "    }%s\n", (entry->next) ? "," : "");
        entry = entry->next;
    }
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    fclose(f);
    LeaveCriticalSection(&wdb->cs);
    return TRUE;
}

BOOL WhitelistDBAdd(WhitelistDB* wdb, const wchar_t* hash, const wchar_t* publisher,
                    const wchar_t* path, const wchar_t* version, const wchar_t* name,
                    WhitelistFlags flags) {
    if (!wdb) return FALSE;
    EnterCriticalSection(&wdb->cs);
    WhitelistEntry* entry = (WhitelistEntry*)malloc(sizeof(WhitelistEntry));
    if (!entry) {
        LeaveCriticalSection(&wdb->cs);
        return FALSE;
    }
    memset(entry, 0, sizeof(WhitelistEntry));
    if (hash && hash[0]) wcsncpy(entry->hash, hash, WHITELIST_HASH_SIZE);
    if (publisher && publisher[0]) wcsncpy(entry->publisher, publisher, WHITELIST_PUBLISHER_SIZE);
    if (path && path[0]) wcsncpy(entry->path, path, WHITELIST_PATH_SIZE);
    if (version && version[0]) wcsncpy(entry->version, version, WHITELIST_VERSION_SIZE);
    if (name && name[0]) wcsncpy(entry->name, name, 255);
    entry->flags = flags;
    entry->addedTime = GetTickCount64();
    entry->lastUsedTime = GetTickCount64();
    entry->hitCount = 0;
    entry->next = wdb->head;
    wdb->head = entry;
    wdb->entryCount++;
    LeaveCriticalSection(&wdb->cs);
    return TRUE;
}

BOOL WhitelistDBRemove(WhitelistDB* wdb, const wchar_t* hash) {
    if (!wdb || !hash || !hash[0]) return FALSE;
    EnterCriticalSection(&wdb->cs);
    WhitelistEntry** pp = &wdb->head;
    while (*pp) {
        if (_wcsicmp((*pp)->hash, hash) == 0) {
            WhitelistEntry* entry = *pp;
            *pp = entry->next;
            free(entry);
            wdb->entryCount--;
            LeaveCriticalSection(&wdb->cs);
            return TRUE;
        }
        pp = &(*pp)->next;
    }
    LeaveCriticalSection(&wdb->cs);
    return FALSE;
}

BOOL WhitelistDBRemoveByPath(WhitelistDB* wdb, const wchar_t* path) {
    if (!wdb || !path || !path[0]) return FALSE;
    EnterCriticalSection(&wdb->cs);
    WhitelistEntry** pp = &wdb->head;
    while (*pp) {
        if (_wcsicmp((*pp)->path, path) == 0) {
            WhitelistEntry* entry = *pp;
            *pp = entry->next;
            free(entry);
            wdb->entryCount--;
            LeaveCriticalSection(&wdb->cs);
            return TRUE;
        }
        pp = &(*pp)->next;
    }
    LeaveCriticalSection(&wdb->cs);
    return FALSE;
}

BOOL WhitelistDBContains(WhitelistDB* wdb, const wchar_t* hash) {
    if (!wdb || !hash || !hash[0]) return FALSE;
    EnterCriticalSection(&wdb->cs);
    WhitelistEntry* entry = wdb->head;
    while (entry) {
        if (_wcsicmp(entry->hash, hash) == 0) {
            LeaveCriticalSection(&wdb->cs);
            return TRUE;
        }
        entry = entry->next;
    }
    LeaveCriticalSection(&wdb->cs);
    return FALSE;
}

static BOOL MatchPattern(const wchar_t* input, const wchar_t* pattern) {
    if (!input || !pattern) return FALSE;
    if (!pattern[0]) return TRUE;
    if (wcsstr(pattern, L"*")) {
        wchar_t* star = wcsstr(pattern, L"*");
        wchar_t prefix[512] = {0};
        wchar_t suffix[512] = {0};
        wcsncpy(prefix, pattern, star - pattern);
        wcscpy(suffix, star + 1);
        if (wcslen(prefix) > 0 && wcsnicmp(input, prefix, wcslen(prefix)) != 0) return FALSE;
        if (wcslen(suffix) > 0) {
            size_t inputLen = wcslen(input);
            size_t suffixLen = wcslen(suffix);
            if (inputLen < suffixLen) return FALSE;
            if (_wcsicmp(input + inputLen - suffixLen, suffix) != 0) return FALSE;
        }
        return TRUE;
    }
    return _wcsicmp(input, pattern) == 0;
}

int WhitelistDBGetMatchLevel(WhitelistDB* wdb, const wchar_t* hash, const wchar_t* publisher,
                             const wchar_t* path, const wchar_t* version, BOOL isSigned) {
    if (!wdb) return 0;
    EnterCriticalSection(&wdb->cs);
    int maxLevel = 0;
    WhitelistEntry* entry = wdb->head;
    while (entry) {
        int level = 0;
        if (entry->flags & WHITELIST_TYPE_TRUSTED) level += 100;
        if (hash && hash[0] && _wcsicmp(entry->hash, hash) == 0) level += 50;
        if (publisher && publisher[0] && MatchPattern(publisher, entry->publisher)) level += 30;
        if (isSigned && (entry->flags & WHITELIST_TYPE_SIGNED)) level += 20;
        if (path && path[0] && MatchPattern(path, entry->path)) level += 10;
        if (version && version[0] && _wcsicmp(entry->version, version) == 0) level += 5;
        if (entry->flags & WHITELIST_TYPE_USER_CONFIRMED) level += 50;
        if (level > maxLevel) maxLevel = level;
        entry = entry->next;
    }
    LeaveCriticalSection(&wdb->cs);
    return maxLevel;
}

BOOL WhitelistDBCheck(WhitelistDB* wdb, const wchar_t* hash, const wchar_t* publisher,
                      const wchar_t* path, const wchar_t* version, BOOL isSigned) {
    int level = WhitelistDBGetMatchLevel(wdb, hash, publisher, path, version, isSigned);
    return level >= 30;
}

void WhitelistDBUpdateUsage(WhitelistDB* wdb, const wchar_t* hash) {
    if (!wdb || !hash || !hash[0]) return;
    EnterCriticalSection(&wdb->cs);
    WhitelistEntry* entry = wdb->head;
    while (entry) {
        if (_wcsicmp(entry->hash, hash) == 0) {
            entry->lastUsedTime = GetTickCount64();
            entry->hitCount++;
            break;
        }
        entry = entry->next;
    }
    LeaveCriticalSection(&wdb->cs);
}

void WhitelistDBPurgeOldEntries(WhitelistDB* wdb, uint64_t maxAgeMs) {
    if (!wdb) return;
    uint64_t now = GetTickCount64();
    EnterCriticalSection(&wdb->cs);
    WhitelistEntry** pp = &wdb->head;
    while (*pp) {
        WhitelistEntry* entry = *pp;
        if (!(entry->flags & WHITELIST_TYPE_TRUSTED) && (now - entry->lastUsedTime) > maxAgeMs) {
            *pp = entry->next;
            free(entry);
            wdb->entryCount--;
            continue;
        }
        pp = &entry->next;
    }
    LeaveCriticalSection(&wdb->cs);
}

void WhitelistDBDump(WhitelistDB* wdb) {
    if (!wdb) return;
    EnterCriticalSection(&wdb->cs);
    WhitelistEntry* entry = wdb->head;
    while (entry) {
        wprintf(L"[Whitelist] Hash=%ls Publisher=%ls Path=%ls Flags=%d Hits=%u\n",
                entry->hash, entry->publisher, entry->path, entry->flags, entry->hitCount);
        entry = entry->next;
    }
    LeaveCriticalSection(&wdb->cs);
}