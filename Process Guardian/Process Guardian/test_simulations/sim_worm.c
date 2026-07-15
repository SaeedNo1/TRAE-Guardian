#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <lm.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "mpr.lib")
#pragma comment(lib, "netapi32.lib")

void SimulateNetworkScan() {
    printf("[Worm] Simulating network scanning...\n");
    
    HMODULE hIphlpapi = LoadLibraryW(L"iphlpapi.dll");
    if (hIphlpapi) {
        FARPROC GetAdaptersAddresses = GetProcAddress(hIphlpapi, "GetAdaptersAddresses");
        if (GetAdaptersAddresses) {
            ULONG outBufLen = 0;
            ((DWORD(WINAPI*)(ULONG, ULONG, PVOID, PVOID, PULONG))GetAdaptersAddresses)(AF_UNSPEC, 0x100, NULL, NULL, &outBufLen);
            printf("[Worm] Network adapter scan initiated using GetAdaptersAddresses\n");
        }
        FreeLibrary(hIphlpapi);
    }
    
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    const char* targetPorts[] = {
        "135", "139", "445", "3389", "22", "80", "443", NULL
    };
    
    for (int i = 0; targetPorts[i]; i++) {
        printf("[Worm] Scanning port %s...\n", targetPorts[i]);
    }
    
    WSACleanup();
}

void SimulateNetworkShareEnum() {
    printf("[Worm] Simulating network share enumeration using NetShareEnum...\n");
    SHARE_INFO_1* pBuf = NULL;
    DWORD entriesRead = 0;
    DWORD totalEntries = 0;
    NetShareEnum(NULL, 1, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries, NULL);
    if (pBuf) NetApiBufferFree(pBuf);
}

void SimulateSelfReplication() {
    printf("[Worm] Simulating self-replication...\n");
    
    wchar_t sourcePath[MAX_PATH];
    GetModuleFileNameW(NULL, sourcePath, MAX_PATH);
    
    const wchar_t* targetPaths[] = {
        L"C:\\Users\\Public\\Documents\\update.exe",
        L"C:\\ProgramData\\Microsoft\\Windows Defender\\msmpeng.exe",
        NULL
    };
    
    for (int i = 0; targetPaths[i]; i++) {
        printf("[Worm] Copying to: %ls\n", targetPaths[i]);
        CopyFileW(sourcePath, targetPaths[i], FALSE);
    }
}

void SimulateSMBExploitation() {
    printf("[Worm] Simulating SMB exploitation attempts...\n");
    
    const wchar_t* smbPaths[] = {
        L"\\\\127.0.0.1\\IPC$",
        L"\\\\localhost\\admin$",
        NULL
    };
    
    for (int i = 0; smbPaths[i]; i++) {
        printf("[Worm] Attempting access to: %ls\n", smbPaths[i]);
        NETRESOURCEW nr = {0};
        nr.dwType = RESOURCETYPE_DISK;
        nr.lpRemoteName = smbPaths[i];
        WNetAddConnection2W(&nr, NULL, NULL, 0);
    }
}

void SimulateRegistryPersistence() {
    printf("[Worm] Simulating registry persistence...\n");
    
    HKEY hKey;
    RegCreateKeyExW(HKEY_LOCAL_MACHINE, 
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    
    if (hKey) {
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        RegSetValueExW(hKey, L"WindowsUpdate", 0, REG_SZ, 
            (BYTE*)exePath, (wcslen(exePath) + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }
}

void SimulateProcessInjection() {
    printf("[Worm] Simulating process injection...\n");
    
    const char* targetProcesses[] = {
        "explorer.exe",
        "svchost.exe",
        NULL
    };
    
    for (int i = 0; targetProcesses[i]; i++) {
        printf("[Worm] Attempting injection into: %s\n", targetProcesses[i]);
    }
}

int main() {
    printf("Worm Virus Simulator - Demonstrating worm PE characteristics\n");
    printf("Features: NetShareEnum, GetAdaptersAddresses, WNetAddConnection2W\n\n");
    
    const char* maliciousStrings[] = {
        "SELF_REPLICATE",
        "NETWORK_SCAN",
        "SMB_EXPLOIT",
        "REMOTE_ACCESS",
        "PERSISTENCE",
        "WORM_PROPAGATE",
        "SYSTEM_INJECT",
        "SPREAD_TO_NETWORK",
        NULL
    };
    
    for (int i = 0; maliciousStrings[i]; i++) {
        printf("[Worm] String present: %s\n", maliciousStrings[i]);
    }
    
    SimulateNetworkScan();
    SimulateNetworkShareEnum();
    SimulateSMBExploitation();
    SimulateSelfReplication();
    SimulateRegistryPersistence();
    SimulateProcessInjection();
    
    printf("\nWaiting for detection (30 seconds)...\n");
    for (int i = 0; i < 30; i++) {
        printf("  Waiting %d/30...\r", i+1);
        fflush(stdout);
        Sleep(1000);
    }
    printf("\n");
    
    return 0;
}
