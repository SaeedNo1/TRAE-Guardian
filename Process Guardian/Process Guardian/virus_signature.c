#include "virus_signature.h"
#include <string.h>
#include <stdio.h>

void VirusSignatureInit(VirusSignatureDatabase* db) {
    if (!db) return;
    memset(db, 0, sizeof(VirusSignatureDatabase));
    VirusSignatureLoadBuiltin(db);
}

void VirusSignatureAdd(VirusSignatureDatabase* db, const VirusSignature* sig) {
    if (!db || !sig || db->signatureCount >= MAX_SIGNATURES) return;
    memcpy(&db->signatures[db->signatureCount], sig, sizeof(VirusSignature));
    db->signatureCount++;
}

VirusSignature* VirusSignatureGetById(VirusSignatureDatabase* db, int index) {
    if (!db || index < 0 || index >= db->signatureCount) return NULL;
    return &db->signatures[index];
}

static char* strdup_safe(const char* str) {
    if (!str) return NULL;
    size_t len = strlen(str) + 1;
    char* dup = (char*)malloc(len);
    if (dup) memcpy(dup, str, len);
    return dup;
}

void VirusSignatureLoadBuiltin(VirusSignatureDatabase* db) {
    if (!db) return;

    VirusSignature sig = {0};

    strcpy(sig.name, "MEMZ (Rainbow Cat)");
    strcpy(sig.description, "彩虹猫病毒 - 引导扇区破坏型恶意软件，触发蓝屏并显示彩虹猫动画");
    sig.type = SIGNATURE_TYPE_COMBINED;
    sig.level = THREAT_LEVEL_CRITICAL;
    sig.action = ACTION_FULL_CLEANUP;
    sig.minStringMatches = 1;
    sig.minImportMatches = 1;
    sig.strings[sig.stringCount++] = strdup_safe("PhysicalDrive");
    sig.strings[sig.stringCount++] = strdup_safe("NtRaiseHardError");
    sig.strings[sig.stringCount++] = strdup_safe("ntdll.dll");
    sig.strings[sig.stringCount++] = strdup_safe("Rainbow");
    sig.strings[sig.stringCount++] = strdup_safe("MEMZ");
    sig.imports[sig.importCount++] = strdup_safe("NtRaiseHardError");
    sig.imports[sig.importCount++] = strdup_safe("NtShutdownSystem");
    sig.imports[sig.importCount++] = strdup_safe("NtSetSystemPowerState");
    VirusSignatureAdd(db, &sig);

    memset(&sig, 0, sizeof(VirusSignature));
    strcpy(sig.name, "Petya/NotPetya");
    strcpy(sig.description, "骷髅勒索病毒 - MBR加密型勒索软件，加密引导扇区和用户文件");
    sig.type = SIGNATURE_TYPE_COMBINED;
    sig.level = THREAT_LEVEL_CRITICAL;
    sig.action = ACTION_FULL_CLEANUP;
    sig.minStringMatches = 2;
    sig.minImportMatches = 1;
    sig.strings[sig.stringCount++] = strdup_safe("PhysicalDrive0");
    sig.strings[sig.stringCount++] = strdup_safe("\\Device\\Harddisk");
    sig.strings[sig.stringCount++] = strdup_safe("MBR");
    sig.strings[sig.stringCount++] = strdup_safe("Petya");
    sig.strings[sig.stringCount++] = strdup_safe("NotPetya");
    sig.strings[sig.stringCount++] = strdup_safe("EternalBlue");
    sig.strings[sig.stringCount++] = strdup_safe("SMB");
    sig.strings[sig.stringCount++] = strdup_safe("ransomware");
    sig.imports[sig.importCount++] = strdup_safe("NtWriteFile");
    sig.imports[sig.importCount++] = strdup_safe("NtReadFile");
    sig.imports[sig.importCount++] = strdup_safe("CreateFileW");
    VirusSignatureAdd(db, &sig);

    memset(&sig, 0, sizeof(VirusSignature));
    strcpy(sig.name, "Black Lotus");
    strcpy(sig.description, "黑莲花引导型木马 - 修改MBR引导扇区，系统启动前执行恶意代码");
    sig.type = SIGNATURE_TYPE_COMBINED;
    sig.level = THREAT_LEVEL_CRITICAL;
    sig.action = ACTION_FULL_CLEANUP;
    sig.minStringMatches = 2;
    sig.minImportMatches = 1;
    sig.strings[sig.stringCount++] = strdup_safe("PhysicalDrive0");
    sig.strings[sig.stringCount++] = strdup_safe("Boot Sector");
    sig.strings[sig.stringCount++] = strdup_safe("MBR");
    sig.strings[sig.stringCount++] = strdup_safe("BlackLotus");
    sig.strings[sig.stringCount++] = strdup_safe("EFI");
    sig.strings[sig.stringCount++] = strdup_safe("GRUB");
    sig.strings[sig.stringCount++] = strdup_safe("VBR");
    sig.imports[sig.importCount++] = strdup_safe("NtWriteFile");
    sig.imports[sig.importCount++] = strdup_safe("CreateFileW");
    sig.imports[sig.importCount++] = strdup_safe("DeviceIoControl");
    VirusSignatureAdd(db, &sig);

    memset(&sig, 0, sizeof(VirusSignature));
    strcpy(sig.name, "Panda Burning Incense");
    strcpy(sig.description, "熊猫烧香病毒 - 文件感染型恶意软件，通过USB传播，感染EXE文件");
    sig.type = SIGNATURE_TYPE_COMBINED;
    sig.level = THREAT_LEVEL_HIGH;
    sig.action = ACTION_FULL_CLEANUP;
    sig.minStringMatches = 2;
    sig.minImportMatches = 1;
    sig.strings[sig.stringCount++] = strdup_safe("Worm.Nimaya");
    sig.strings[sig.stringCount++] = strdup_safe("setup.exe");
    sig.strings[sig.stringCount++] = strdup_safe("autorun.inf");
    sig.strings[sig.stringCount++] = strdup_safe("USB");
    sig.strings[sig.stringCount++] = strdup_safe("UDisk");
    sig.strings[sig.stringCount++] = strdup_safe("\\RECYCLER\\");
    sig.strings[sig.stringCount++] = strdup_safe("ShellExecute");
    sig.strings[sig.stringCount++] = strdup_safe("CreateProcess");
    sig.imports[sig.importCount++] = strdup_safe("WriteFile");
    sig.imports[sig.importCount++] = strdup_safe("CopyFileW");
    sig.imports[sig.importCount++] = strdup_safe("CreateFileW");
    sig.imports[sig.importCount++] = strdup_safe("RegSetValueExW");
    sig.imports[sig.importCount++] = strdup_safe("ShellExecuteW");
    VirusSignatureAdd(db, &sig);

    memset(&sig, 0, sizeof(VirusSignature));
    strcpy(sig.name, "WannaCry");
    strcpy(sig.description, "永恒之蓝勒索软件 - 通过SMB漏洞传播，加密用户文件");
    sig.type = SIGNATURE_TYPE_COMBINED;
    sig.level = THREAT_LEVEL_CRITICAL;
    sig.action = ACTION_FULL_CLEANUP;
    sig.minStringMatches = 2;
    sig.minImportMatches = 1;
    sig.strings[sig.stringCount++] = strdup_safe("WannaCry");
    sig.strings[sig.stringCount++] = strdup_safe("EternalBlue");
    sig.strings[sig.stringCount++] = strdup_safe("SMBv1");
    sig.strings[sig.stringCount++] = strdup_safe("mssecsvc.exe");
    sig.strings[sig.stringCount++] = strdup_safe("ransomware");
    sig.strings[sig.stringCount++] = strdup_safe(".WNCRY");
    sig.strings[sig.stringCount++] = strdup_safe("DoublePulsar");
    sig.imports[sig.importCount++] = strdup_safe("NtCreateThreadEx");
    sig.imports[sig.importCount++] = strdup_safe("CreateRemoteThread");
    sig.imports[sig.importCount++] = strdup_safe("WriteProcessMemory");
    VirusSignatureAdd(db, &sig);

    memset(&sig, 0, sizeof(VirusSignature));
    strcpy(sig.name, "Conficker");
    strcpy(sig.description, "飞虫蠕虫 - 通过RPC漏洞传播，创建后门，下载其他恶意软件");
    sig.type = SIGNATURE_TYPE_COMBINED;
    sig.level = THREAT_LEVEL_HIGH;
    sig.action = ACTION_FULL_CLEANUP;
    sig.minStringMatches = 2;
    sig.minImportMatches = 1;
    sig.strings[sig.stringCount++] = strdup_safe("Conficker");
    sig.strings[sig.stringCount++] = strdup_safe("Downadup");
    sig.strings[sig.stringCount++] = strdup_safe("RPC");
    sig.strings[sig.stringCount++] = strdup_safe("LSASS");
    sig.strings[sig.stringCount++] = strdup_safe("netapi32");
    sig.strings[sig.stringCount++] = strdup_safe("sc.exe");
    sig.strings[sig.stringCount++] = strdup_safe("svchost.exe");
    sig.imports[sig.importCount++] = strdup_safe("CreateProcessW");
    sig.imports[sig.importCount++] = strdup_safe("WinExec");
    sig.imports[sig.importCount++] = strdup_safe("URLDownloadToFileW");
    VirusSignatureAdd(db, &sig);

    memset(&sig, 0, sizeof(VirusSignature));
    strcpy(sig.name, "SilverFox");
    strcpy(sig.description, "银狐远控 - 远程控制木马，窃取敏感信息，允许攻击者远程控制");
    sig.type = SIGNATURE_TYPE_COMBINED;
    sig.level = THREAT_LEVEL_HIGH;
    sig.action = ACTION_FULL_CLEANUP;
    sig.minStringMatches = 2;
    sig.minImportMatches = 1;
    sig.strings[sig.stringCount++] = strdup_safe("SilverFox");
    sig.strings[sig.stringCount++] = strdup_safe("RemoteControl");
    sig.strings[sig.stringCount++] = strdup_safe("ReverseShell");
    sig.strings[sig.stringCount++] = strdup_safe("C2");
    sig.strings[sig.stringCount++] = strdup_safe("CommandAndControl");
    sig.strings[sig.stringCount++] = strdup_safe("keylogger");
    sig.strings[sig.stringCount++] = strdup_safe("screenshot");
    sig.imports[sig.importCount++] = strdup_safe("CreateRemoteThread");
    sig.imports[sig.importCount++] = strdup_safe("WSASocket");
    sig.imports[sig.importCount++] = strdup_safe("connect");
    sig.imports[sig.importCount++] = strdup_safe("Send");
    VirusSignatureAdd(db, &sig);

    memset(&sig, 0, sizeof(VirusSignature));
    strcpy(sig.name, "Test-MEMZ-Sim");
    strcpy(sig.description, "测试用MEMZ模拟器 - 模拟MEMZ病毒特征");
    sig.type = SIGNATURE_TYPE_COMBINED;
    sig.level = THREAT_LEVEL_CRITICAL;
    sig.action = ACTION_FULL_CLEANUP;
    sig.minStringMatches = 2;
    sig.minImportMatches = 2;
    sig.strings[sig.stringCount++] = strdup_safe("MBR_OVERWRITE");
    sig.strings[sig.stringCount++] = strdup_safe("BOOTLOADER_PAYLOAD");
    sig.strings[sig.stringCount++] = strdup_safe("REMOTE_INJECT");
    sig.strings[sig.stringCount++] = strdup_safe("PROCESS_HIJACK");
    sig.strings[sig.stringCount++] = strdup_safe("KERNEL_PATCH");
    sig.imports[sig.importCount++] = strdup_safe("DeviceIoControl");
    sig.imports[sig.importCount++] = strdup_safe("NtWriteFile");
    sig.imports[sig.importCount++] = strdup_safe("NtOpenFile");
    VirusSignatureAdd(db, &sig);

    memset(&sig, 0, sizeof(VirusSignature));
    strcpy(sig.name, "Test-Petya-Sim");
    strcpy(sig.description, "测试用Petya模拟器 - 模拟Petya勒索软件特征");
    sig.type = SIGNATURE_TYPE_COMBINED;
    sig.level = THREAT_LEVEL_CRITICAL;
    sig.action = ACTION_FULL_CLEANUP;
    sig.minStringMatches = 2;
    sig.minImportMatches = 2;
    sig.strings[sig.stringCount++] = strdup_safe("PETYA_ENCRYPT");
    sig.strings[sig.stringCount++] = strdup_safe("MBR_ENCRYPTOR");
    sig.strings[sig.stringCount++] = strdup_safe("VOLUME_ENCRYPT");
    sig.strings[sig.stringCount++] = strdup_safe("BOOTKIT");
    sig.strings[sig.stringCount++] = strdup_safe("ENCRYPT_MASTER");
    sig.imports[sig.importCount++] = strdup_safe("DeviceIoControl");
    sig.imports[sig.importCount++] = strdup_safe("CryptEncrypt");
    sig.imports[sig.importCount++] = strdup_safe("GetVolumeInformationW");
    VirusSignatureAdd(db, &sig);

    memset(&sig, 0, sizeof(VirusSignature));
    strcpy(sig.name, "Test-WannaCry-Sim");
    strcpy(sig.description, "测试用WannaCry模拟器 - 模拟WannaCry勒索软件特征");
    sig.type = SIGNATURE_TYPE_COMBINED;
    sig.level = THREAT_LEVEL_CRITICAL;
    sig.action = ACTION_FULL_CLEANUP;
    sig.minStringMatches = 2;
    sig.minImportMatches = 2;
    sig.strings[sig.stringCount++] = strdup_safe("WANNACRY_RANSOM");
    sig.strings[sig.stringCount++] = strdup_safe("BITCOIN_ADDRESS");
    sig.strings[sig.stringCount++] = strdup_safe("ENCRYPT_ALL_FILES");
    sig.strings[sig.stringCount++] = strdup_safe("ETERNALBLUE");
    sig.strings[sig.stringCount++] = strdup_safe("SMB_EXPLOIT");
    sig.imports[sig.importCount++] = strdup_safe("CryptEncrypt");
    sig.imports[sig.importCount++] = strdup_safe("GetAdaptersAddresses");
    sig.imports[sig.importCount++] = strdup_safe("CryptDeriveKey");
    VirusSignatureAdd(db, &sig);

    memset(&sig, 0, sizeof(VirusSignature));
    strcpy(sig.name, "Test-Ransomware-Sim");
    strcpy(sig.description, "测试用勒索软件模拟器 - 模拟通用勒索软件特征");
    sig.type = SIGNATURE_TYPE_COMBINED;
    sig.level = THREAT_LEVEL_CRITICAL;
    sig.action = ACTION_FULL_CLEANUP;
    sig.minStringMatches = 2;
    sig.minImportMatches = 2;
    sig.strings[sig.stringCount++] = strdup_safe("AES_ENCRYPT");
    sig.strings[sig.stringCount++] = strdup_safe("RANSOM_DECRYPT");
    sig.strings[sig.stringCount++] = strdup_safe("BITCOIN");
    sig.strings[sig.stringCount++] = strdup_safe("ENCRYPTED_FILE");
    sig.strings[sig.stringCount++] = strdup_safe("DECRYPTION_KEY");
    sig.strings[sig.stringCount++] = strdup_safe("SHADOW_COPY_DELETE");
    sig.imports[sig.importCount++] = strdup_safe("CryptEncrypt");
    sig.imports[sig.importCount++] = strdup_safe("CryptExportKey");
    sig.imports[sig.importCount++] = strdup_safe("DeleteFileW");
    VirusSignatureAdd(db, &sig);

    memset(&sig, 0, sizeof(VirusSignature));
    strcpy(sig.name, "Test-Worm-Sim");
    strcpy(sig.description, "测试用蠕虫病毒模拟器 - 模拟蠕虫传播特征");
    sig.type = SIGNATURE_TYPE_COMBINED;
    sig.level = THREAT_LEVEL_CRITICAL;
    sig.action = ACTION_FULL_CLEANUP;
    sig.minStringMatches = 2;
    sig.minImportMatches = 2;
    sig.strings[sig.stringCount++] = strdup_safe("SELF_REPLICATE");
    sig.strings[sig.stringCount++] = strdup_safe("NETWORK_SCAN");
    sig.strings[sig.stringCount++] = strdup_safe("SMB_EXPLOIT");
    sig.strings[sig.stringCount++] = strdup_safe("REMOTE_ACCESS");
    sig.strings[sig.stringCount++] = strdup_safe("WORM_PROPAGATE");
    sig.strings[sig.stringCount++] = strdup_safe("SPREAD_TO_NETWORK");
    sig.imports[sig.importCount++] = strdup_safe("NetShareEnum");
    sig.imports[sig.importCount++] = strdup_safe("GetAdaptersAddresses");
    sig.imports[sig.importCount++] = strdup_safe("WNetAddConnection2W");
    VirusSignatureAdd(db, &sig);

    db->initialized = TRUE;
}

int VirusSignatureMatchHash(VirusSignatureDatabase* db, const uint8_t* hash) {
    if (!db || !hash || !db->initialized) return -1;
    for (int i = 0; i < db->signatureCount; i++) {
        VirusSignature* sig = &db->signatures[i];
        for (int j = 0; j < sig->hashCount; j++) {
            if (memcmp(hash, sig->hashes[j], 32) == 0) {
                return i;
            }
        }
    }
    return -1;
}

int VirusSignatureMatchStrings(VirusSignatureDatabase* db, const char* fileData, size_t dataSize) {
    if (!db || !fileData || dataSize == 0 || !db->initialized) return -1;
    for (int i = 0; i < db->signatureCount; i++) {
        VirusSignature* sig = &db->signatures[i];
        int matches = 0;
        for (int j = 0; j < sig->stringCount; j++) {
            if (sig->strings[j] && strstr(fileData, sig->strings[j])) {
                matches++;
            }
        }
        if (matches >= sig->minStringMatches) {
            return i;
        }
    }
    return -1;
}

int VirusSignatureMatchImports(VirusSignatureDatabase* db, const char* importNames[], int importCount) {
    if (!db || !importNames || importCount == 0 || !db->initialized) return -1;
    for (int i = 0; i < db->signatureCount; i++) {
        VirusSignature* sig = &db->signatures[i];
        int matches = 0;
        for (int j = 0; j < sig->importCount; j++) {
            if (!sig->imports[j]) continue;
            for (int k = 0; k < importCount; k++) {
                if (importNames[k] && strcmp(importNames[k], sig->imports[j]) == 0) {
                    matches++;
                    break;
                }
            }
        }
        if (matches >= sig->minImportMatches) {
            return i;
        }
    }
    return -1;
}
