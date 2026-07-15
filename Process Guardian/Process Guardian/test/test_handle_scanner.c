#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <tlhelp32.h>


#define TEST_LOG L"C:\\tmp\\handle_scanner_test.log"

static void Log(const wchar_t* format, ...) {
    wchar_t message[4096];
    va_list args;
    va_start(args, format);
    vswprintf(message, sizeof(message)/sizeof(wchar_t), format, args);
    va_end(args);
    
    FILE* f = _wfopen(TEST_LOG, L"a");
    if (!f) return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    fwprintf(f, L"[%04d-%02d-%02d %02d:%02d:%02d] %ls\n",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, message);
    fclose(f);
    wprintf(L"%ls\n", message);
}

static DWORD FindProcessByName(const wchar_t* name) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe;
    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return pid;
}

static BOOL IsDaemonRunning() {
    return FindProcessByName(L"trae_guardian_daemon.exe") != 0;
}

static void Test1_PhysicalDrive0_Open() {
    Log(L"=== Test 1: Open PhysicalDrive0 ===");
    
    HANDLE hDrive = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                OPEN_EXISTING, 0, NULL);
    
    if (hDrive != INVALID_HANDLE_VALUE) {
        Log(L"SUCCESS: Opened PhysicalDrive0 handle");
        Log(L"PID=%lu has opened PhysicalDrive0", GetCurrentProcessId());
        Log(L"WARNING: Keeping PhysicalDrive0 open - daemon should terminate this process!");
        
        while (IsDaemonRunning()) {
            Log(L"PhysicalDrive0 still open, waiting for daemon to terminate me...");
            Sleep(5000);
        }
        
        CloseHandle(hDrive);
        Log(L"Closed PhysicalDrive0 handle");
    } else {
        Log(L"FAIL: Cannot open PhysicalDrive0, error=%lu (requires admin/SYSTEM)", GetLastError());
    }
}

static void Test2_PhysicalDrive1_Open() {
    Log(L"=== Test 2: Open PhysicalDrive1 ===");
    
    HANDLE hDrive = CreateFileW(L"\\\\.\\PhysicalDrive1", GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                OPEN_EXISTING, 0, NULL);
    
    if (hDrive != INVALID_HANDLE_VALUE) {
        Log(L"SUCCESS: Opened PhysicalDrive1 handle");
        Sleep(3000);
        CloseHandle(hDrive);
        Log(L"Closed PhysicalDrive1 handle");
    } else {
        Log(L"FAIL: Cannot open PhysicalDrive1, error=%lu", GetLastError());
    }
}

static void Test3_Volume_Open() {
    Log(L"=== Test 3: Open Volume Handle ===");
    
    HANDLE hVolume = CreateFileW(L"\\\\.\\C:", GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                 OPEN_EXISTING, 0, NULL);
    
    if (hVolume != INVALID_HANDLE_VALUE) {
        Log(L"SUCCESS: Opened Volume C:\\ handle");
        Sleep(3000);
        CloseHandle(hVolume);
        Log(L"Closed Volume C:\\ handle");
    } else {
        Log(L"FAIL: Cannot open Volume C:\\, error=%lu", GetLastError());
    }
}

static void Test4_MBR_Read() {
    Log(L"=== Test 4: Read MBR (512 bytes) ===");
    
    HANDLE hDrive = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                OPEN_EXISTING, 0, NULL);
    
    if (hDrive != INVALID_HANDLE_VALUE) {
        BYTE mbr[512] = {0};
        DWORD bytesRead = 0;
        
        if (ReadFile(hDrive, mbr, 512, &bytesRead, NULL)) {
            Log(L"SUCCESS: Read %lu bytes from MBR", bytesRead);
            Log(L"MBR Signature: 0x%02X%02X", mbr[510], mbr[511]);
            
            if (mbr[510] == 0x55 && mbr[511] == 0xAA) {
                Log(L"INFO: Valid MBR signature detected");
            } else {
                Log(L"WARNING: Invalid MBR signature");
            }
        } else {
            Log(L"FAIL: ReadFile failed, error=%lu", GetLastError());
        }
        
        Sleep(5000);
        CloseHandle(hDrive);
    } else {
        Log(L"FAIL: Cannot open PhysicalDrive0, error=%lu", GetLastError());
    }
}

static void Test5_MBR_Write_Simulation() {
    Log(L"=== Test 5: MBR Write Attempt (Simulation) ===");
    
    HANDLE hDrive = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                OPEN_EXISTING, 0, NULL);
    
    if (hDrive != INVALID_HANDLE_VALUE) {
        Log(L"SUCCESS: Opened PhysicalDrive0 with WRITE access - THIS IS DANGEROUS!");
        
        BYTE fakeMbr[512] = {0};
        memset(fakeMbr, 0xCC, 512);
        fakeMbr[510] = 0x55;
        fakeMbr[511] = 0xAA;
        
        Log(L"WARNING: Simulating MBR write... daemon should terminate this process!");
        Sleep(10000);
        
        CloseHandle(hDrive);
    } else {
        Log(L"INFO: Cannot open PhysicalDrive0 with WRITE, error=%lu", GetLastError());
    }
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    
    CreateDirectoryW(L"C:\\tmp", NULL);
    
    Log(L"========================================");
    Log(L"HandleScanner Test Suite v1.0");
    Log(L"PID=%lu", GetCurrentProcessId());
    Log(L"Daemon running: %s", IsDaemonRunning() ? L"YES" : L"NO");
    Log(L"========================================");
    
    if (!IsDaemonRunning()) {
        Log(L"ERROR: Daemon is not running! Start trae_guardian_daemon.exe first.");
        return 1;
    }
    
    Test1_PhysicalDrive0_Open();
    Test2_PhysicalDrive1_Open();
    Test3_Volume_Open();
    Test4_MBR_Read();
    Test5_MBR_Write_Simulation();
    
    Log(L"========================================");
    Log(L"All tests completed");
    Log(L"Check daemon.log for HandleScanner responses");
    Log(L"========================================");
    
    return 0;
}