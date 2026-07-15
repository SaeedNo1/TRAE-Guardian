#pragma once

#include <windows.h>
#include <stdint.h>

#define MAX_SIGNATURE_NAME 128
#define MAX_SIGNATURE_DESC 512
#define MAX_STRINGS_PER_SIGNATURE 32
#define MAX_IMPORTS_PER_SIGNATURE 32
#define MAX_HASHES_PER_SIGNATURE 16
#define MAX_SIGNATURES 128

typedef enum {
    SIGNATURE_TYPE_UNKNOWN = 0,
    SIGNATURE_TYPE_HASH,
    SIGNATURE_TYPE_STRINGS,
    SIGNATURE_TYPE_IMPORTS,
    SIGNATURE_TYPE_COMBINED
} SignatureType;

typedef enum {
    THREAT_LEVEL_LOW = 1,
    THREAT_LEVEL_MEDIUM = 2,
    THREAT_LEVEL_HIGH = 3,
    THREAT_LEVEL_CRITICAL = 4
} ThreatLevel;

typedef enum {
    ACTION_NONE = 0,
    ACTION_TERMINATE,
    ACTION_DELETE_FILE,
    ACTION_REPEATED_KILL,
    ACTION_RESTORE_SYSTEM,
    ACTION_FULL_CLEANUP
} SignatureAction;

typedef struct {
    char name[MAX_SIGNATURE_NAME];
    char description[MAX_SIGNATURE_DESC];
    SignatureType type;
    ThreatLevel level;
    SignatureAction action;
    int hashCount;
    uint8_t hashes[MAX_HASHES_PER_SIGNATURE][32];
    int stringCount;
    char* strings[MAX_STRINGS_PER_SIGNATURE];
    int importCount;
    char* imports[MAX_IMPORTS_PER_SIGNATURE];
    int minStringMatches;
    int minImportMatches;
} VirusSignature;

typedef struct {
    VirusSignature signatures[MAX_SIGNATURES];
    int signatureCount;
    BOOL initialized;
} VirusSignatureDatabase;

void VirusSignatureInit(VirusSignatureDatabase* db);
void VirusSignatureAdd(VirusSignatureDatabase* db, const VirusSignature* sig);
int VirusSignatureMatchHash(VirusSignatureDatabase* db, const uint8_t* hash);
int VirusSignatureMatchStrings(VirusSignatureDatabase* db, const char* fileData, size_t dataSize);
int VirusSignatureMatchImports(VirusSignatureDatabase* db, const char* importNames[], int importCount);
VirusSignature* VirusSignatureGetById(VirusSignatureDatabase* db, int index);
void VirusSignatureLoadBuiltin(VirusSignatureDatabase* db);
