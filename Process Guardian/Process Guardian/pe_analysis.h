#ifndef PE_ANALYSIS_H
#define PE_ANALYSIS_H

#include <windows.h>
#include <stdint.h>

#define PE_MAX_IMPORTS 256
#define PE_MAX_SECTIONS 64
#define PE_SCAN_MAX_SIZE (16 * 1024 * 1024)
#define PE_MAX_BEHAVIORS 32

typedef enum {
    PE_THREAT_NONE = 0,
    PE_THREAT_LOW,
    PE_THREAT_MEDIUM,
    PE_THREAT_HIGH,
    PE_THREAT_CRITICAL
} PEThreatLevel;

typedef enum {
    PE_BEHAVIOR_NONE = 0,
    
    PE_BEHAVIOR_PHYSICAL_DRIVE_API = 0x0001,
    PE_BEHAVIOR_BSOD_API = 0x0002,
    PE_BEHAVIOR_PACKED_HIGH_ENTROPY = 0x0004,
    PE_BEHAVIOR_PROCESS_MUTUAL_PROTECTION = 0x0008,
    PE_BEHAVIOR_SELF_DELETE = 0x0010,
    PE_BEHAVIOR_INJECT_SYSTEM_PROCESS = 0x0020,
    PE_BEHAVIOR_DISGUISE_SYSTEM_PROCESS = 0x0040,
    PE_BEHAVIOR_FILELESS_PAYLOAD = 0x0080,
    PE_BEHAVIOR_POWERSHELL_OBFUSCATION = 0x0100,
    PE_BEHAVIOR_DRIVER_RELEASE = 0x0200,
    PE_BEHAVIOR_ENCRYPTION_SHELL = 0x0400,
    
    PE_BEHAVIOR_ADVERTISING_POPUP = 0x1000,
    PE_BEHAVIOR_BUNDLE_DOWNLOAD = 0x2000,
    PE_BEHAVIOR_HOMEPAGE_HIJACK = 0x4000,
    PE_BEHAVIOR_SHORTCUT_TAMPER = 0x8000,
    PE_BEHAVIOR_AUTO_START = 0x10000,
    PE_BEHAVIOR_HIDDEN_SERVICE = 0x20000,
    PE_BEHAVIOR_BROKEN_UNINSTALL = 0x40000,
    
    PE_BEHAVIOR_DIRECT_KILL_PHYSICAL_DRIVE = 0x100000,
    PE_BEHAVIOR_DIRECT_KILL_REMOTE_INJECT = 0x200000,
    PE_BEHAVIOR_DIRECT_KILL_BSOD_CALL = 0x400000,
    PE_BEHAVIOR_DIRECT_KILL_MBR_OVERWRITE = 0x800000,
    PE_BEHAVIOR_DIRECT_KILL_HASH_MATCH = 0x1000000
} PEBehaviorFlag;

typedef struct {
    PEBehaviorFlag flag;
    const char* name;
    int score;
    BOOL directKill;
    const char* description;
} PEBehaviorScoreItem;

typedef struct {
    BOOL isValidPE;
    BOOL is64Bit;
    DWORD fileSize;
    uint16_t machine;
    DWORD entryPoint;
    DWORD imageBase;
    int sectionCount;
    char sectionNames[PE_MAX_SECTIONS][9];
    DWORD sectionVirtualSizes[PE_MAX_SECTIONS];
    DWORD sectionRawSizes[PE_MAX_SECTIONS];
    DWORD sectionCharacteristics[PE_MAX_SECTIONS];
    BOOL hasExecutableWritableSection;
    int importCount;
    char importNames[PE_MAX_IMPORTS][128];
    int importDllCount;
    char importDlls[64][128];
    BOOL hasPhysicalDriveString;
    BOOL hasSuspiciousImports;
    uint8_t sha256[32];
    BOOL hashComputed;
    BYTE* fileData;
    DWORD fileDataSize;
    double entropy;
    int behaviorCount;
    PEBehaviorFlag behaviors[PE_MAX_BEHAVIORS];
} PEAnalysisResult;

BOOL PEAnalyzeFile(const wchar_t* filePath, PEAnalysisResult* result);
BOOL PEComputeSHA256(const wchar_t* filePath, uint8_t hash[32]);
PEThreatLevel PEAssessThreat(const PEAnalysisResult* result);
PEThreatLevel PEQuickAnalyze(const wchar_t* filePath, PEAnalysisResult* result);
void PEFreeResult(PEAnalysisResult* result);
int PEGetVirusScore(const PEAnalysisResult* result, BOOL* shouldKill);
int PEGetRogueScore(const PEAnalysisResult* result);
void PEAddBehavior(PEAnalysisResult* result, PEBehaviorFlag flag);

#endif
