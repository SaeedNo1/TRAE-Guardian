#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

#define APP_NAME L"TRAE Guardian"
#define MAX_TABS 6
#define IDM_TOOLBAR_TOGGLE 2001

static const wchar_t* g_tabNames[MAX_TABS] = {
    L"进程管理", L"服务管理", L"注册表", L"分区管理", L"任务管理", L"AI 对话"
};

static BOOL SaveBitmap(HBITMAP hBitmap, const wchar_t* filename) {
    if (!hBitmap || !filename) return FALSE;
    
    BITMAP bmp;
    if (!GetObject(hBitmap, sizeof(BITMAP), &bmp)) return FALSE;
    
    BITMAPFILEHEADER bfh = {0};
    BITMAPINFOHEADER bih = {0};
    
    bfh.bfType = 0x4D42;
    bfh.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + bmp.bmWidthBytes * bmp.bmHeight;
    bfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    
    bih.biSize = sizeof(BITMAPINFOHEADER);
    bih.biWidth = bmp.bmWidth;
    bih.biHeight = bmp.bmHeight;
    bih.biPlanes = 1;
    bih.biBitCount = 24;
    
    FILE* f = _wfopen(filename, L"wb");
    if (!f) return FALSE;
    
    fwrite(&bfh, sizeof(BITMAPFILEHEADER), 1, f);
    fwrite(&bih, sizeof(BITMAPINFOHEADER), 1, f);
    
    HDC hdc = CreateCompatibleDC(NULL);
    HBITMAP hOld = (HBITMAP)SelectObject(hdc, hBitmap);
    
    BYTE* buffer = (BYTE*)malloc(bmp.bmWidthBytes * bmp.bmHeight);
    if (buffer) {
        GetDIBits(hdc, hBitmap, 0, bmp.bmHeight, buffer, (BITMAPINFO*)&bih, DIB_RGB_COLORS);
        fwrite(buffer, bmp.bmWidthBytes * bmp.bmHeight, 1, f);
        free(buffer);
    }
    
    SelectObject(hdc, hOld);
    DeleteDC(hdc);
    fclose(f);
    
    return TRUE;
}

static BOOL CaptureWindowToFile(HWND hWnd, const wchar_t* filename) {
    if (!hWnd) return FALSE;
    
    RECT rect;
    if (!GetWindowRect(hWnd, &rect)) return FALSE;
    
    int width = rect.right - rect.left;
    int height = rect.bottom - rect.top;
    
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, width, height);
    HBITMAP hOld = (HBITMAP)SelectObject(hdcMem, hBitmap);
    
    PrintWindow(hWnd, hdcMem, 0);
    
    BOOL result = SaveBitmap(hBitmap, filename);
    
    SelectObject(hdcMem, hOld);
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    
    return result;
}

static HWND FindWindowWithTimeout(const wchar_t* title, int timeoutSeconds) {
    for (int i = 0; i < timeoutSeconds * 2; i++) {
        HWND hWnd = FindWindowW(NULL, title);
        if (hWnd) {
            RECT rect;
            GetWindowRect(hWnd, &rect);
            if (rect.right > rect.left && rect.bottom > rect.top) {
                return hWnd;
            }
        }
        Sleep(500);
    }
    return NULL;
}

static HWND FindChildWindow(HWND hParent, const wchar_t* className) {
    return FindWindowExW(hParent, NULL, className, NULL);
}

static int CountListViewItems(HWND hListView) {
    if (!hListView) return -1;
    return ListView_GetItemCount(hListView);
}

static BOOL SwitchToTab(HWND hWnd, HWND hTabs, int index) {
    if (!hTabs) return FALSE;
    SendMessageW(hTabs, TCM_SETCURFOCUS, index, 0);
    SendMessageW(hTabs, TCM_SETCURSEL, index, 0);
    NMHDR nmh;
    nmh.hwndFrom = hTabs;
    nmh.idFrom = GetDlgCtrlID(hTabs);
    nmh.code = TCN_SELCHANGE;
    SendMessageW(hWnd, WM_NOTIFY, nmh.idFrom, (LPARAM)&nmh);
    InvalidateRect(hWnd, NULL, TRUE);
    UpdateWindow(hWnd);
    Sleep(2000);
    return TRUE;
}

static BOOL CheckWindowControls(HWND hWnd) {
    wprintf(L"\n--- 窗口控件检查 ---\n");
    
    HWND hToolbar = FindChildWindow(hWnd, TOOLBARCLASSNAME);
    if (hToolbar) {
        wprintf(L"✓ 工具栏存在\n");
    } else {
        wprintf(L"✗ 工具栏不存在\n");
        return FALSE;
    }
    
    HWND hTabs = FindChildWindow(hWnd, WC_TABCONTROL);
    if (hTabs) {
        int tabCount = TabCtrl_GetItemCount(hTabs);
        wprintf(L"✓ 标签控件存在，共 %d 个标签\n", tabCount);
    } else {
        wprintf(L"✗ 标签控件不存在\n");
        return FALSE;
    }
    
    HWND hStatusBar = FindChildWindow(hWnd, STATUSCLASSNAME);
    if (hStatusBar) {
        wprintf(L"✓ 状态栏存在\n");
    } else {
        wprintf(L"✗ 状态栏不存在\n");
        return FALSE;
    }
    
    return TRUE;
}

static BOOL TestToolbarToggle(HWND hWnd) {
    wprintf(L"\n--- 工具栏隐藏/显示测试 ---\n");
    BOOL ok = TRUE;

    if (CaptureWindowToFile(hWnd, L"gui_test_toolbar_visible.bmp")) {
        wprintf(L"✓ 工具栏显示截图成功\n");
    } else {
        wprintf(L"✗ 工具栏显示截图失败\n");
        ok = FALSE;
    }

    SendMessageW(hWnd, WM_COMMAND, IDM_TOOLBAR_TOGGLE, 0);
    Sleep(1500);

    if (CaptureWindowToFile(hWnd, L"gui_test_toolbar_hidden.bmp")) {
        wprintf(L"✓ 工具栏隐藏截图成功\n");
    } else {
        wprintf(L"✗ 工具栏隐藏截图失败\n");
        ok = FALSE;
    }

    SendMessageW(hWnd, WM_COMMAND, IDM_TOOLBAR_TOGGLE, 0);
    Sleep(1500);

    if (CaptureWindowToFile(hWnd, L"gui_test_toolbar_restored.bmp")) {
        wprintf(L"✓ 工具栏恢复截图成功\n");
    } else {
        wprintf(L"✗ 工具栏恢复截图失败\n");
        ok = FALSE;
    }

    return ok;
}

static BOOL TestAllTabs(HWND hWnd, HWND hTabs) {
    wprintf(L"\n--- 标签页内容测试 ---\n");
    
    BOOL allPassed = TRUE;
    
    for (int i = 0; i < MAX_TABS; i++) {
        SwitchToTab(hWnd, hTabs, i);
        
        wchar_t filename[256];
        swprintf(filename, 256, L"gui_test_%d_%ls.bmp", i, g_tabNames[i]);
        
        if (CaptureWindowToFile(hWnd, filename)) {
            wprintf(L"✓ [%d] %ls - 截图成功\n", i, g_tabNames[i]);
        } else {
            wprintf(L"✗ [%d] %ls - 截图失败\n", i, g_tabNames[i]);
            allPassed = FALSE;
        }
        
        if (i < 4) {
            HWND hListView = FindChildWindow(hWnd, WC_LISTVIEW);
            if (hListView) {
                int itemCount = CountListViewItems(hListView);
                if (itemCount > 0) {
                    wprintf(L"  └─ ListView 有 %d 项数据\n", itemCount);
                } else {
                    wprintf(L"  └─ ⚠ ListView 为空！\n");
                    allPassed = FALSE;
                }
            } else {
                wprintf(L"  └─ ✗ 未找到 ListView\n");
                allPassed = FALSE;
            }
        } else if (i == 4) {
            HWND hListView = FindChildWindow(hWnd, WC_LISTVIEW);
            if (hListView) {
                int itemCount = CountListViewItems(hListView);
                wprintf(L"  └─ 任务列表有 %d 项\n", itemCount);
            }
            HWND hEdit = FindChildWindow(hWnd, L"Edit");
            if (hEdit) wprintf(L"  └─ 输入框存在\n");
        } else {
            HWND hEdit = FindChildWindow(hWnd, L"Edit");
            if (hEdit) wprintf(L"  └─ 聊天控件存在\n");
        }
    }
    
    return allPassed;
}

int main(void) {
    wprintf(L"========================================\n");
    wprintf(L"TRAE Guardian GUI 自动化测试工具\n");
    wprintf(L"========================================\n\n");
    
    wprintf(L"[1/5] 准备启动程序...\n");
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    wchar_t* p = wcsrchr(exePath, L'\\');
    if (p) *p = L'\0';
    wcscat(exePath, L"\\bin\\trae_guardian.exe");
    
    wprintf(L"程序路径: %ls\n", exePath);
    
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(STARTUPINFOW);
    
    wprintf(L"\n[2/5] 启动 TRAE Guardian...\n");
    if (!CreateProcessW(exePath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        wprintf(L"✗ 启动失败！错误码: %lu\n", GetLastError());
        return 1;
    }
    
    wprintf(L"✓ 程序已启动 (PID: %lu)\n", pi.dwProcessId);
    
    wprintf(L"\n[3/5] 等待窗口出现 (最多30秒)...\n");
    HWND hWnd = FindWindowWithTimeout(APP_NAME, 30);
    if (!hWnd) {
        wprintf(L"✗ 未找到窗口！\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }
    
    wprintf(L"✓ 窗口已找到 (HWND: %p)\n", hWnd);
    
    ShowWindow(hWnd, SW_SHOW);
    SetForegroundWindow(hWnd);
    Sleep(2000);
    
    wprintf(L"\n[4/5] 检查窗口控件...\n");
    if (!CheckWindowControls(hWnd)) {
        wprintf(L"✗ 控件检查失败！\n");
    }
    
    HWND hTabs = FindChildWindow(hWnd, WC_TABCONTROL);

    wprintf(L"\n[5/7] 测试工具栏隐藏/显示...\n");
    BOOL toolbarOk = TestToolbarToggle(hWnd);

    wprintf(L"\n[6/7] 测试所有标签页...\n");
    BOOL result = TestAllTabs(hWnd, hTabs);

    result = result && toolbarOk;

    wprintf(L"\n========================================\n");
    if (result) {
        wprintf(L"✓✓✓ 所有测试通过！\n");
    } else {
        wprintf(L"✗✗✗ 部分测试失败！\n");
    }
    wprintf(L"========================================\n");
    wprintf(L"\n截图文件已保存到当前目录\n");

    wprintf(L"\n[7/7] 关闭程序...\n");

    Sleep(1000);

    wprintf(L"\n正在关闭程序...\n");
    SendMessageW(hWnd, WM_CLOSE, 0, 0);
    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    wprintf(L"✓ 完成！\n");
    
    return result ? 0 : 1;
}