#define UNICODE
#define _UNICODE

#include "pe_analysis.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <wincrypt.h>
#include <math.h>

#pragma comment(lib, "advapi32.lib")

static DWORD PERvaToFileOffset(IMAGE_NT_HEADERS* ntHeaders, BYTE* fileBase, DWORD rva) {
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)
        ((BYTE*)ntHeaders + sizeof(IMAGE_NT_HEADERS));
    WORD numSections = ntHeaders->FileHeader.NumberOfSections;
    for (int i = 0; i < numSections; i++) {
        DWORD vaStart = sections[i].VirtualAddress;
        DWORD vaSize = sections[i].Misc.VirtualSize;
        if (vaSize == 0) vaSize = sections[i].SizeOfRawData;
        if (rva >= vaStart && rva < vaStart + vaSize) {
            return sections[i].PointerToRawData + (rva - vaStart);
        }
    }
    return 0;
}

static BOOL PEAnalyzeSections(IMAGE_NT_HEADERS* ntHeaders, PEAnalysisResult* result) {
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)
        ((BYTE*)ntHeaders + sizeof(IMAGE_NT_HEADERS));
    WORD numSections = ntHeaders->FileHeader.NumberOfSections;
    if (numSections > PE_MAX_SECTIONS) numSections = PE_MAX_SECTIONS;

    result->sectionCount = numSections;
    result->hasExecutableWritableSection = FALSE;

    for (int i = 0; i < numSections; i++) {
        memcpy(result->sectionNames[i], sections[i].Name, 8);
        result->sectionNames[i][8] = '\0';
        result->sectionVirtualSizes[i] = sections[i].Misc.VirtualSize;
        result->sectionRawSizes[i] = sections[i].SizeOfRawData;
        result->sectionCharacteristics[i] = sections[i].Characteristics;

        DWORD chars = sections[i].Characteristics;
        if ((chars & IMAGE_SCN_MEM_EXECUTE) && (chars & IMAGE_SCN_MEM_WRITE)) {
            result->hasExecutableWritableSection = TRUE;
        }
    }
    return TRUE;
}

static double PEComputeEntropy(BYTE* data, DWORD size) {
    if (size == 0) return 0.0;
    int freq[256] = {0};
    for (DWORD i = 0; i < size; i++) {
        freq[data[i]]++;
    }
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / size;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

void PEAddBehavior(PEAnalysisResult* result, PEBehaviorFlag flag) {
    if (!result || result->behaviorCount >= PE_MAX_BEHAVIORS) return;
    for (int i = 0; i < result->behaviorCount; i++) {
        if (result->behaviors[i] == flag) return;
    }
    result->behaviors[result->behaviorCount++] = flag;
}

static BOOL PEExtractImports(BYTE* fileBase, DWORD fileSize, IMAGE_NT_HEADERS* ntHeaders,
                              PEAnalysisResult* result) {
    IMAGE_DATA_DIRECTORY* importDir =
        &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!importDir->VirtualAddress || !importDir->Size) return FALSE;

    DWORD offset = PERvaToFileOffset(ntHeaders, fileBase, importDir->VirtualAddress);
    if (offset == 0 || offset >= fileSize) return FALSE;

    IMAGE_IMPORT_DESCRIPTOR* desc =
        (IMAGE_IMPORT_DESCRIPTOR*)(fileBase + offset);
    int count = 0;
    int dllCount = 0;
    BOOL is64 = (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    while (desc->Name && count < PE_MAX_IMPORTS) {
        DWORD nameOff = PERvaToFileOffset(ntHeaders, fileBase, desc->Name);
        if (nameOff && nameOff < fileSize && dllCount < 64) {
            strncpy(result->importDlls[dllCount], (char*)(fileBase + nameOff), 127);
            result->importDlls[dllCount][127] = '\0';
            dllCount++;
        }

        DWORD thunkRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        if (thunkRva) {
            DWORD thunkOff = PERvaToFileOffset(ntHeaders, fileBase, thunkRva);
            if (thunkOff && thunkOff < fileSize) {
                IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)(fileBase + thunkOff);
                while (thunk->u1.AddressOfData && count < PE_MAX_IMPORTS) {
                    ULONGLONG ordinalFlag = is64 ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32;
                    if (!(thunk->u1.Ordinal & ordinalFlag)) {
                        DWORD impRva = (DWORD)thunk->u1.AddressOfData;
                        DWORD impOff = PERvaToFileOffset(ntHeaders, fileBase, impRva);
                        if (impOff && impOff < fileSize) {
                            IMAGE_IMPORT_BY_NAME* imp =
                                (IMAGE_IMPORT_BY_NAME*)(fileBase + impOff);
                            strncpy(result->importNames[count], (char*)imp->Name, 127);
                            result->importNames[count][127] = '\0';
                            count++;
                        }
                    }
                    thunk++;
                    if ((BYTE*)thunk >= fileBase + fileSize) break;
                }
            }
        }
        desc++;
        if ((BYTE*)desc >= fileBase + fileSize) break;
    }

    result->importCount = count;
    result->importDllCount = dllCount;
    return count > 0;
}

static BOOL MemMatchAsciiOrWide(const BYTE* ptr, const char* needle, size_t len) {
    if (memcmp(ptr, needle, len) == 0) return TRUE;
    for (size_t i = 0; i < len; i++) {
        if (ptr[i * 2] != (BYTE)needle[i] || ptr[i * 2 + 1] != 0) return FALSE;
    }
    return TRUE;
}

static BOOL PEScanSuspiciousStrings(BYTE* fileBase, DWORD fileSize, PEAnalysisResult* result) {
    result->hasPhysicalDriveString = FALSE;
    result->hasSuspiciousImports = FALSE;

    DWORD scanSize = fileSize < (1024 * 1024) ? fileSize : (1024 * 1024);

    for (DWORD i = 0; i + 42 <= scanSize; i++) {
        if (MemMatchAsciiOrWide(fileBase + i, "PhysicalDrive", 13) ||
            MemMatchAsciiOrWide(fileBase + i, "\\\\.\\Physical", 12)) {
            result->hasPhysicalDriveString = TRUE;
            PEAddBehavior(result, PE_BEHAVIOR_PHYSICAL_DRIVE_API);
        }
        if (MemMatchAsciiOrWide(fileBase + i, "NtRaiseHardError", 16) ||
            MemMatchAsciiOrWide(fileBase + i, "NtShutdownSystem", 16) ||
            MemMatchAsciiOrWide(fileBase + i, "NtSetSystemPowerState", 21)) {
            result->hasSuspiciousImports = TRUE;
            PEAddBehavior(result, PE_BEHAVIOR_BSOD_API);
        }
        if (MemMatchAsciiOrWide(fileBase + i, "CreateRemoteThread", 19) ||
            MemMatchAsciiOrWide(fileBase + i, "WriteProcessMemory", 20)) {
            PEAddBehavior(result, PE_BEHAVIOR_INJECT_SYSTEM_PROCESS);
        }
        if (MemMatchAsciiOrWide(fileBase + i, "DeleteFile", 10) ||
            MemMatchAsciiOrWide(fileBase + i, "DeleteFileW", 11)) {
            PEAddBehavior(result, PE_BEHAVIOR_SELF_DELETE);
        }
        if (MemMatchAsciiOrWide(fileBase + i, "powershell", 10) ||
            MemMatchAsciiOrWide(fileBase + i, "powershell.exe", 14)) {
            PEAddBehavior(result, PE_BEHAVIOR_POWERSHELL_OBFUSCATION);
        }
        if (MemMatchAsciiOrWide(fileBase + i, ".sys", 4) ||
            MemMatchAsciiOrWide(fileBase + i, ".drv", 4)) {
            PEAddBehavior(result, PE_BEHAVIOR_DRIVER_RELEASE);
        }
        if (MemMatchAsciiOrWide(fileBase + i, "Run\\", 5) ||
            MemMatchAsciiOrWide(fileBase + i, "RunOnce\\", 9)) {
            PEAddBehavior(result, PE_BEHAVIOR_AUTO_START);
        }
        if (MemMatchAsciiOrWide(fileBase + i, "CreateService", 13) ||
            MemMatchAsciiOrWide(fileBase + i, "StartService", 12)) {
            PEAddBehavior(result, PE_BEHAVIOR_HIDDEN_SERVICE);
        }
        if (MemMatchAsciiOrWide(fileBase + i, "SetDefaultBrowser", 17) ||
            MemMatchAsciiOrWide(fileBase + i, "SetStartPage", 12)) {
            PEAddBehavior(result, PE_BEHAVIOR_HOMEPAGE_HIJACK);
        }
        if (MemMatchAsciiOrWide(fileBase + i, "ShellExecute", 13) ||
            MemMatchAsciiOrWide(fileBase + i, "WinExec", 7)) {
            PEAddBehavior(result, PE_BEHAVIOR_ADVERTISING_POPUP);
        }
        if (MemMatchAsciiOrWide(fileBase + i, "URLDownloadToFile", 17) ||
            MemMatchAsciiOrWide(fileBase + i, "HttpOpenRequest", 15)) {
            PEAddBehavior(result, PE_BEHAVIOR_BUNDLE_DOWNLOAD);
        }
    }
    return TRUE;
}

static BOOL PEComputeHashFromMemory(BYTE* data, DWORD dataSize, uint8_t hash[32]) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BOOL ok = FALSE;

    if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            if (CryptHashData(hHash, data, dataSize, 0)) {
                DWORD hashLen = 32;
                if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
                    ok = TRUE;
                }
            }
        }
    }
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    return ok;
}

BOOL PEComputeSHA256(const wchar_t* filePath, uint8_t hash[32]) {
    if (!filePath || !hash) return FALSE;

    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BOOL result = FALSE;

    if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            BYTE buffer[8192];
            DWORD bytesRead = 0;
            while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
                if (!CryptHashData(hHash, buffer, bytesRead, 0)) break;
            }
            DWORD hashLen = 32;
            if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
                result = TRUE;
            }
        }
    }

    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
    return result;
}

BOOL PEAnalyzeFile(const wchar_t* filePath, PEAnalysisResult* result) {
    if (!filePath || !result) return FALSE;
    memset(result, 0, sizeof(PEAnalysisResult));

    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0 || fileSize > PE_SCAN_MAX_SIZE) {
        CloseHandle(hFile);
        return FALSE;
    }

    BYTE* buf = (BYTE*)malloc(fileSize);
    if (!buf) { CloseHandle(hFile); return FALSE; }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buf, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        free(buf);
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);

    result->fileData = buf;
    result->fileDataSize = fileSize;
    result->fileSize = fileSize;

    if (PEComputeHashFromMemory(buf, fileSize, result->sha256)) {
        result->hashComputed = TRUE;
    }

    result->entropy = PEComputeEntropy(buf, fileSize);
    if (result->entropy > 7.8) {
        PEAddBehavior(result, PE_BEHAVIOR_PACKED_HIGH_ENTROPY);
        PEAddBehavior(result, PE_BEHAVIOR_ENCRYPTION_SHELL);
    }

    if (fileSize < sizeof(IMAGE_DOS_HEADER)) return TRUE;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || (DWORD)dos->e_lfanew >= fileSize) return TRUE;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(buf + dos->e_lfanew);
    if ((BYTE*)nt + sizeof(IMAGE_NT_HEADERS) > buf + fileSize) return TRUE;
    if (nt->Signature != IMAGE_NT_SIGNATURE) return TRUE;

    result->isValidPE = TRUE;
    result->is64Bit = (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    result->machine = nt->FileHeader.Machine;
    result->entryPoint = nt->OptionalHeader.AddressOfEntryPoint;
    result->imageBase = (DWORD)nt->OptionalHeader.ImageBase;

    PEAnalyzeSections(nt, result);
    PEExtractImports(buf, fileSize, nt, result);
    PEScanSuspiciousStrings(buf, fileSize, result);

    if (result->hasExecutableWritableSection) {
        PEAddBehavior(result, PE_BEHAVIOR_ENCRYPTION_SHELL);
    }

    if (result->hasPhysicalDriveString && result->hasSuspiciousImports) {
        PEAddBehavior(result, PE_BEHAVIOR_DIRECT_KILL_PHYSICAL_DRIVE);
    }

    return TRUE;
}

PEThreatLevel PEAssessThreat(const PEAnalysisResult* result) {
    if (!result || !result->isValidPE) return PE_THREAT_NONE;

    if (result->hasSuspiciousImports && result->hasPhysicalDriveString) {
        return PE_THREAT_CRITICAL;
    }
    if (result->hasSuspiciousImports || result->hasPhysicalDriveString) {
        return PE_THREAT_HIGH;
    }
    if (result->hasExecutableWritableSection) {
        return PE_THREAT_HIGH;
    }
    if (result->importCount == 0 && result->fileSize > 1024) {
        return PE_THREAT_MEDIUM;
    }
    return PE_THREAT_NONE;
}

PEThreatLevel PEQuickAnalyze(const wchar_t* filePath, PEAnalysisResult* result) {
    if (!PEAnalyzeFile(filePath, result)) return PE_THREAT_NONE;
    return PEAssessThreat(result);
}

static PEBehaviorScoreItem virusScoreTable[] = {
    {PE_BEHAVIOR_PACKED_HIGH_ENTROPY, "High entropy/packed", 15, FALSE, "Entropy > 7.8 indicates encrypted/compressed payload"},
    {PE_BEHAVIOR_PROCESS_MUTUAL_PROTECTION, "Process mutual protection", 20, FALSE, "Multi-process mutual guard logic"},
    {PE_BEHAVIOR_SELF_DELETE, "Self-delete", 15, FALSE, "Contains self-deletion code"},
    {PE_BEHAVIOR_INJECT_SYSTEM_PROCESS, "Inject system process", 20, FALSE, "Remote thread injection into system processes"},
    {PE_BEHAVIOR_DISGUISE_SYSTEM_PROCESS, "Disguise system process", 18, FALSE, "Fake system process name but non-system path"},
    {PE_BEHAVIOR_FILELESS_PAYLOAD, "Fileless payload", 12, FALSE, "Contains fileless execution logic"},
    {PE_BEHAVIOR_POWERSHELL_OBFUSCATION, "PowerShell obfuscation", 15, FALSE, "Embedded PowerShell obfuscated commands"},
    {PE_BEHAVIOR_DRIVER_RELEASE, "Driver release", 18, FALSE, "Contains driver file release logic"},
    {PE_BEHAVIOR_ENCRYPTION_SHELL, "Encryption shell", 15, FALSE, "Multi-layer encryption/packing detected"},
    {PE_BEHAVIOR_PHYSICAL_DRIVE_API, "PhysicalDrive API", 30, FALSE, "Contains PhysicalDrive access strings"},
    {PE_BEHAVIOR_BSOD_API, "BSOD API", 30, FALSE, "Contains NtRaiseHardError or similar"},
    {PE_BEHAVIOR_DIRECT_KILL_PHYSICAL_DRIVE, "PhysicalDrive+BSOD", 0, TRUE, "Direct kill: both PhysicalDrive and BSOD APIs present"},
    {PE_BEHAVIOR_DIRECT_KILL_HASH_MATCH, "Hash blacklist match", 0, TRUE, "Direct kill: Known malware hash match"},
    {0, NULL, 0, FALSE, NULL}
};

static PEBehaviorScoreItem rogueScoreTable[] = {
    {PE_BEHAVIOR_ADVERTISING_POPUP, "Advertising popup", 5, FALSE, "Contains ad popup generation code"},
    {PE_BEHAVIOR_BUNDLE_DOWNLOAD, "Bundle download", 6, FALSE, "Background download of bundled software"},
    {PE_BEHAVIOR_HOMEPAGE_HIJACK, "Homepage hijack", 7, FALSE, "Browser homepage modification API"},
    {PE_BEHAVIOR_SHORTCUT_TAMPER, "Shortcut tamper", 5, FALSE, "Shortcut/link modification logic"},
    {PE_BEHAVIOR_AUTO_START, "Auto start", 4, FALSE, "Writes to Run registry or startup folder"},
    {PE_BEHAVIOR_HIDDEN_SERVICE, "Hidden service", 7, FALSE, "Creates protected system service"},
    {PE_BEHAVIOR_BROKEN_UNINSTALL, "Broken uninstall", 3, FALSE, "No proper uninstall entry"},
    {0, NULL, 0, FALSE, NULL}
};

int PEGetVirusScore(const PEAnalysisResult* result, BOOL* shouldKill) {
    if (!result || !shouldKill) return 0;
    *shouldKill = FALSE;
    int totalScore = 0;
    
    for (int i = 0; i < result->behaviorCount; i++) {
        PEBehaviorFlag flag = result->behaviors[i];
        for (int j = 0; virusScoreTable[j].name; j++) {
            if (virusScoreTable[j].flag == flag) {
                if (virusScoreTable[j].directKill) {
                    *shouldKill = TRUE;
                    return 0;
                }
                totalScore += virusScoreTable[j].score;
                break;
            }
        }
    }
    return totalScore;
}

int PEGetRogueScore(const PEAnalysisResult* result) {
    if (!result) return 0;
    int totalScore = 0;
    
    for (int i = 0; i < result->behaviorCount; i++) {
        PEBehaviorFlag flag = result->behaviors[i];
        for (int j = 0; rogueScoreTable[j].name; j++) {
            if (rogueScoreTable[j].flag == flag) {
                totalScore += rogueScoreTable[j].score;
                break;
            }
        }
    }
    return totalScore;
}

void PEFreeResult(PEAnalysisResult* result) {
    if (result && result->fileData) {
        free(result->fileData);
        result->fileData = NULL;
        result->fileDataSize = 0;
    }
}
