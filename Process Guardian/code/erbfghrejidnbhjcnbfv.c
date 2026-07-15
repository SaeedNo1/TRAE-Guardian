#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

int main() {
    printf("=== erbfghrejidnbhjcnbfv Test Program ===\n");
    printf("Testing registry modification and network data transmission\n\n");

    printf("[TEST 1] Registry Modification\n");
    printf("Writing to HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run...\n");
    
    HKEY hKey = NULL;
    LONG result = RegCreateKeyExA(HKEY_LOCAL_MACHINE, 
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    
    if (result == ERROR_SUCCESS && hKey) {
        const char* valueData = "C:\\Windows\\Temp\\malicious.exe";
        result = RegSetValueExA(hKey, "MaliciousTest", 0, REG_SZ, 
            (const BYTE*)valueData, strlen(valueData) + 1);
        
        if (result == ERROR_SUCCESS) {
            printf("SUCCESS: Registry key written!\n");
        } else {
            printf("FAILED: RegSetValueEx failed (error %lu)\n", GetLastError());
        }
        RegCloseKey(hKey);
    } else {
        printf("FAILED: RegCreateKeyEx failed (error %lu)\n", GetLastError());
        printf("Trying HKCU instead...\n");
        
        result = RegCreateKeyExA(HKEY_CURRENT_USER, 
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
        
        if (result == ERROR_SUCCESS && hKey) {
            const char* valueData = "C:\\Windows\\Temp\\malicious.exe";
            result = RegSetValueExA(hKey, "MaliciousTest", 0, REG_SZ, 
                (const BYTE*)valueData, strlen(valueData) + 1);
            
            if (result == ERROR_SUCCESS) {
                printf("SUCCESS: Registry key written to HKCU!\n");
            } else {
                printf("FAILED: RegSetValueEx failed (error %lu)\n", GetLastError());
            }
            RegCloseKey(hKey);
        } else {
            printf("FAILED: RegCreateKeyEx HKCU failed (error %lu)\n", GetLastError());
        }
    }

    printf("\n[TEST 2] Network Data Transmission (>100KB)\n");
    printf("Sending data to external server...\n");
    
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("FAILED: WSAStartup failed\n");
        printf("\nPress Enter to exit...\n");
        getchar();
        return 1;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        printf("FAILED: socket creation failed (error %lu)\n", WSAGetLastError());
        WSACleanup();
        printf("\nPress Enter to exit...\n");
        getchar();
        return 1;
    }

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(80);
    serverAddr.sin_addr.s_addr = inet_addr("8.8.8.8");

    result = connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    if (result == SOCKET_ERROR) {
        printf("FAILED: connect failed (error %lu)\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        printf("\nPress Enter to exit...\n");
        getchar();
        return 1;
    }

    printf("SUCCESS: Connected to server!\n");
    printf("Sending 150KB of data...\n");
    
    char* buffer = (char*)malloc(1024);
    if (!buffer) {
        printf("FAILED: Memory allocation failed\n");
        closesocket(sock);
        WSACleanup();
        printf("\nPress Enter to exit...\n");
        getchar();
        return 1;
    }

    memset(buffer, 'X', 1024);
    int bytesSent = 0;
    int targetBytes = 150 * 1024;

    for (int i = 0; i < 150 && bytesSent < targetBytes; i++) {
        int sent = send(sock, buffer, 1024, 0);
        if (sent == SOCKET_ERROR) {
            printf("FAILED: send failed at iteration %d (error %lu)\n", i, WSAGetLastError());
            break;
        }
        bytesSent += sent;
        if ((i + 1) % 30 == 0) {
            printf("Sent %d/%d KB\n", bytesSent / 1024, targetBytes / 1024);
        }
    }

    printf("Total bytes sent: %d (%d KB)\n", bytesSent, bytesSent / 1024);

    closesocket(sock);
    WSACleanup();
    free(buffer);

    printf("\n[TEST 3] PhysicalDrive Access\n");
    printf("Attempting to open PhysicalDrive0...\n");
    
    HANDLE h = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
                          NULL, OPEN_EXISTING, 0, NULL);
    
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        printf("Open PhysicalDrive failed (error %lu)\n", err);
        if (err == ERROR_ACCESS_DENIED) {
            printf("Trying alternative path...\n");
            h = CreateFileA("\\\\.\\Harddisk0\\DR0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
                          NULL, OPEN_EXISTING, 0, NULL);
            if (h == INVALID_HANDLE_VALUE) {
                printf("Harddisk path also failed\n");
            } else {
                printf("SUCCESS: Harddisk handle opened!\n");
                printf("Keeping handle open for 10 seconds...\n");
                Sleep(10000);
                CloseHandle(h);
            }
        }
    } else {
        printf("SUCCESS: PhysicalDrive0 opened!\n");
        printf("Keeping handle open for 10 seconds...\n");
        Sleep(10000);
        CloseHandle(h);
    }

    printf("\nAll tests completed.\n");
    printf("Press Enter to exit...\n");
    getchar();
    return 0;
}