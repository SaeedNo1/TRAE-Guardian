#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "kernel32.lib")

void SimulateRansomNote() {
    printf("[WannaCry] Simulating ransom note creation...\n");
    const char* ransomNote = 
        "This computer has been infected with WannaCry ransomware.\n"
        "All your files have been encrypted.\n"
        "To decrypt your files, you must pay 300 USD in Bitcoin.\n"
        "Bitcoin address: 1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ\n"
        "WARNING: Do not shut down your computer.\n"
        "Your files will be permanently encrypted.\n";
    
    FILE* fp = fopen("ransom_note.txt", "w");
    if (fp) {
        fputs(ransomNote, fp);
        fclose(fp);
        printf("[WannaCry] Ransom note created\n");
    }
}

void SimulateCryptoOperations() {
    printf("[WannaCry] Simulating cryptographic operations...\n");
    
    HCRYPTPROV hProv = 0;
    CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    
    if (hProv) {
        HCRYPTKEY hKey = 0;
        CryptGenKey(hProv, CALG_AES_256, 0, &hKey);
        
        if (hKey) {
            BYTE data[1024] = {0};
            DWORD dataLen = sizeof(data);
            CryptEncrypt(hKey, 0, TRUE, 0, data, &dataLen, sizeof(data));
            
            HCRYPTKEY hDerivedKey = 0;
            BYTE salt[8] = {0};
            DWORD saltLen = sizeof(salt);
            CryptDeriveKey(hProv, CALG_AES_256, hKey, 0, &hDerivedKey);
            
            printf("[WannaCry] AES-256 encryption and key derivation completed\n");
            if (hDerivedKey) CryptDestroyKey(hDerivedKey);
            CryptDestroyKey(hKey);
        }
        CryptReleaseContext(hProv, 0);
    }
}

void SimulateNetworkScan() {
    printf("[WannaCry] Simulating network scan...\n");
    HMODULE hIphlpapi = LoadLibraryW(L"iphlpapi.dll");
    if (hIphlpapi) {
        FARPROC GetAdaptersAddresses = GetProcAddress(hIphlpapi, "GetAdaptersAddresses");
        if (GetAdaptersAddresses) {
            ULONG outBufLen = 0;
            ((DWORD(WINAPI*)(ULONG, ULONG, PVOID, PVOID, PULONG))GetAdaptersAddresses)(AF_UNSPEC, 0x100, NULL, NULL, &outBufLen);
            printf("[WannaCry] Network adapter scan initiated\n");
        }
        FreeLibrary(hIphlpapi);
    }
}

void SimulateFileEnumeration() {
    printf("[WannaCry] Simulating file enumeration for encryption...\n");
    const char* extensions[] = {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".pdf", ".jpg", ".png", ".zip", ".rar", ".txt",
        ".db", ".sql", ".mdf", ".bak", ".tar", ".gz",
        NULL
    };
    
    for (int i = 0; extensions[i]; i++) {
        printf("[WannaCry] Targeting extension: %s\n", extensions[i]);
    }
}

void SimulateEternalBlueScan() {
    printf("[WannaCry] Simulating EternalBlue vulnerability scan...\n");
    printf("[WannaCry] Scanning for SMBv1 vulnerabilities...\n");
}

int main() {
    printf("WannaCry Simulator - Demonstrating WannaCry-like PE characteristics\n");
    printf("Features: CryptEncrypt, CryptDeriveKey, GetAdaptersAddresses\n\n");
    
    const wchar_t* maliciousStrings[] = {
        L"WANNACRY_RANSOM",
        L"BITCOIN_ADDRESS",
        L"ENCRYPT_ALL_FILES",
        L"DECRYPT_KEY",
        L"PAYMENT_REQUIRED",
        L"ETERNALBLUE",
        L"SMB_EXPLOIT",
        NULL
    };
    
    for (int i = 0; maliciousStrings[i]; i++) {
        wprintf(L"[WannaCry] String present: %ls\n", maliciousStrings[i]);
    }
    
    SimulateCryptoOperations();
    SimulateNetworkScan();
    SimulateFileEnumeration();
    SimulateRansomNote();
    SimulateEternalBlueScan();
    
    printf("\nWaiting for detection (30 seconds)...\n");
    for (int i = 0; i < 30; i++) {
        printf("  Waiting %d/30...\r", i+1);
        fflush(stdout);
        Sleep(1000);
    }
    printf("\n");
    
    return 0;
}
