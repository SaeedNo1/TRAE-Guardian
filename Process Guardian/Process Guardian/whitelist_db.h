#ifndef WHITELIST_DB_H
#define WHITELIST_DB_H

#include <windows.h>
#include <stdint.h>

#define WHITELIST_HASH_SIZE 64
#define WHITELIST_PUBLISHER_SIZE 512
#define WHITELIST_PATH_SIZE 512
#define WHITELIST_VERSION_SIZE 64

typedef enum {
    WHITELIST_TYPE_SHA256 = 1,
    WHITELIST_TYPE_PUBLISHER = 2,
    WHITELIST_TYPE_SIGNED = 4,
    WHITELIST_TYPE_PATH = 8,
    WHITELIST_TYPE_VERSION = 16,
    WHITELIST_TYPE_USER_CONFIRMED = 32,
    WHITELIST_TYPE_TRUSTED = 64
} WhitelistFlags;

typedef struct WhitelistEntry {
    wchar_t hash[WHITELIST_HASH_SIZE + 1];
    wchar_t publisher[WHITELIST_PUBLISHER_SIZE + 1];
    wchar_t path[WHITELIST_PATH_SIZE + 1];
    wchar_t version[WHITELIST_VERSION_SIZE + 1];
    wchar_t name[256];
    WhitelistFlags flags;
    uint64_t addedTime;
    uint64_t lastUsedTime;
    uint32_t hitCount;
    struct WhitelistEntry* next;
} WhitelistEntry;

typedef struct {
    WhitelistEntry* head;
    CRITICAL_SECTION cs;
    wchar_t dbPath[MAX_PATH];
    uint32_t entryCount;
} WhitelistDB;

BOOL WhitelistDBInit(WhitelistDB* wdb, const wchar_t* dbPath);
void WhitelistDBCleanup(WhitelistDB* wdb);
BOOL WhitelistDBLoad(WhitelistDB* wdb);
BOOL WhitelistDBSave(WhitelistDB* wdb);
BOOL WhitelistDBAdd(WhitelistDB* wdb, const wchar_t* hash, const wchar_t* publisher,
                    const wchar_t* path, const wchar_t* version, const wchar_t* name,
                    WhitelistFlags flags);
BOOL WhitelistDBRemove(WhitelistDB* wdb, const wchar_t* hash);
BOOL WhitelistDBRemoveByPath(WhitelistDB* wdb, const wchar_t* path);
BOOL WhitelistDBContains(WhitelistDB* wdb, const wchar_t* hash);
BOOL WhitelistDBCheck(WhitelistDB* wdb, const wchar_t* hash, const wchar_t* publisher,
                      const wchar_t* path, const wchar_t* version, BOOL isSigned);
int WhitelistDBGetMatchLevel(WhitelistDB* wdb, const wchar_t* hash, const wchar_t* publisher,
                             const wchar_t* path, const wchar_t* version, BOOL isSigned);
void WhitelistDBUpdateUsage(WhitelistDB* wdb, const wchar_t* hash);
void WhitelistDBPurgeOldEntries(WhitelistDB* wdb, uint64_t maxAgeMs);
void WhitelistDBDump(WhitelistDB* wdb);

#endif