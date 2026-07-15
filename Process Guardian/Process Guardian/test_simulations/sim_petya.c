#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "advapi32.lib")

void SimulateMBRAttack() {
    printf("[Petya] Simulating MBR encryption attack...\n");
    HANDLE hDisk = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE, 
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk != INVALID_HANDLE_VALUE) {
        BYTE mbr[512] = {0};
        DWORD bytesRead;
        ReadFile(hDisk, mbr, 512, &bytesRead, NULL);
        printf("[Petya] MBR read successfully\n");
        CloseHandle(hDisk);
    }
}

void SimulateDeviceIoControl() {
    printf("[Petya] Simulating DeviceIoControl for disk access...\n");
    HANDLE hDisk = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ, 
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk != INVALID_HANDLE_VALUE) {
        DWORD bytesReturned;
        DeviceIoControl(hDisk, 0, NULL, 0, NULL, 0, &bytesReturned, NULL);
        CloseHandle(hDisk);
    }
}

void SimulateCryptEncrypt() {
    printf("[Petya] Simulating CryptEncrypt usage...\n");
    HCRYPTPROV hProv;
    if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        HCRYPTKEY hKey;
        if (CryptGenKey(hProv, CALG_AES_256, CRYPT_EXPORTABLE, &hKey)) {
            BYTE data[1024] = {0};
            DWORD dataLen = sizeof(data);
            CryptEncrypt(hKey, 0, TRUE, 0, data, &dataLen, sizeof(data));
            CryptDestroyKey(hKey);
        }
        CryptReleaseContext(hProv, 0);
    }
}

void SimulateVolumeScan() {
    printf("[Petya] Simulating volume scan using GetVolumeInformation...\n");
    wchar_t volName[MAX_PATH] = {0};
    DWORD serialNum;
    GetVolumeInformationW(L"C:\\", volName, MAX_PATH, &serialNum, NULL, NULL, NULL, 0);
    wprintf(L"[Petya] Found volume: %ls\n", volName);
}

void SimulateShutdownTricks() {
    printf("[Petya] Simulating shutdown/reboot manipulation...\n");
    HKEY hKey;
    RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute", 
        0, KEY_READ, &hKey);
    RegCloseKey(hKey);
}

void SimulateShadowCopyDelete() {
    printf("[Petya] Simulating shadow copy deletion...\n");
    system("vssadmin delete shadows /all /quiet");
}

int main() {
    printf("Petya/NotPetya Simulator - Demonstrating Petya-like PE characteristics\n");
    printf("Features: DeviceIoControl, CryptEncrypt, GetVolumeInformationW\n\n");
    
    const wchar_t* maliciousStrings[] = {
        L"PETYA_ENCRYPT",
        L"MBR_ENCRYPTOR",
        L"VOLUME_ENCRYPT",
        L"BOOTKIT",
        L"ENCRYPT_MASTER",
        L"DECRYPT_KEY",
        NULL
    };
    
    for (int i = 0; maliciousStrings[i]; i++) {
        wprintf(L"[Petya] String present: %ls\n", maliciousStrings[i]);
    }
    
    SimulateMBRAttack();
    SimulateDeviceIoControl();
    SimulateCryptEncrypt();
    SimulateVolumeScan();
    SimulateShutdownTricks();
    SimulateShadowCopyDelete();
    
    printf("\nWaiting for detection (30 seconds)...\n");
    for (int i = 0; i < 30; i++) {
        printf("  Waiting %d/30...\r", i+1);
        fflush(stdout);
        Sleep(1000);
    }
    printf("\n");
    
    return 0;
}
