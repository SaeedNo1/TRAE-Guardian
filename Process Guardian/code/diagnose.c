#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <commctrl.h>
#include <stdio.h>

#define APP_NAME L"TRAE Guardian"

int main(void) {
    wprintf(L"========================================\n");
    wprintf(L"TRAE Guardian GUI 诊断工具\n");
    wprintf(L"========================================\n\n");
    
    wprintf(L"[1] 查找窗口...\n");
    HWND hWnd = FindWindowW(NULL, APP_NAME);
    if (!hWnd) {
        wprintf(L"✗ 未找到窗口！\n");
        wprintf(L"正在启动程序...\n");
        
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        wchar_t* p = wcsrchr(exePath, L'\\');
        if (p) *p = L'\0';
        wcscat(exePath, L"\\bin\\trae_guardian.exe");
        
        STARTUPINFOW si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(STARTUPINFOW);
        
        if (!CreateProcessW(exePath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            wprintf(L"✗ 启动失败！错误码: %lu\n", GetLastError());
            return 1;
        }
        
        wprintf(L"✓ 程序已启动，等待窗口...\n");
        for (int i = 0; i < 30; i++) {
            hWnd = FindWindowW(NULL, APP_NAME);
            if (hWnd) break;
            Sleep(500);
        }
    }
    
    if (!hWnd) {
        wprintf(L"✗ 窗口仍未出现！\n");
        return 1;
    }
    
    wprintf(L"✓ 窗口找到 (HWND: %p)\n", hWnd);
    
    RECT rect;
    GetWindowRect(hWnd, &rect);
    wprintf(L"  窗口位置: (%d, %d) - (%d, %d)\n", rect.left, rect.top, rect.right, rect.bottom);
    wprintf(L"  窗口大小: %dx%d\n", rect.right - rect.left, rect.bottom - rect.top);
    
    wprintf(L"\n[2] 检查子控件...\n");
    
    HWND hToolbar = FindWindowExW(hWnd, NULL, TOOLBARCLASSNAME, NULL);
    if (hToolbar) {
        wprintf(L"✓ 工具栏: %p\n", hToolbar);
    } else {
        wprintf(L"✗ 工具栏: 未找到\n");
    }
    
    HWND hTabs = FindWindowExW(hWnd, NULL, WC_TABCONTROL, NULL);
    if (hTabs) {
        int count = TabCtrl_GetItemCount(hTabs);
        wprintf(L"✓ 标签控件: %p, %d个标签\n", hTabs, count);
        
        wchar_t text[256];
        for (int i = 0; i < count; i++) {
            TCITEMW tci = {0};
            tci.mask = TCIF_TEXT;
            tci.pszText = text;
            tci.cchTextMax = 256;
            TabCtrl_GetItem(hTabs, i, &tci);
            wprintf(L"    标签%d: %ls\n", i, text);
        }
    } else {
        wprintf(L"✗ 标签控件: 未找到\n");
    }
    
    HWND hListView = FindWindowExW(hWnd, NULL, WC_LISTVIEW, NULL);
    if (hListView) {
        int items = ListView_GetItemCount(hListView);
        int cols = 0;
        while (TRUE) {
            LVCOLUMNW tempCol = {0};
            if (!ListView_GetColumn(hListView, cols, &tempCol)) break;
            cols++;
        }
        wprintf(L"✓ ListView: %p, %d项, %d列\n", hListView, items, cols);
        
        wchar_t colText[256];
        LVCOLUMNW col = {0};
        col.mask = LVCF_TEXT;
        col.pszText = colText;
        col.cchTextMax = 256;
        for (int i = 0; i < cols; i++) {
            ListView_GetColumn(hListView, i, &col);
            wprintf(L"    列%d: %ls\n", i, colText);
        }
        
        if (items > 0) {
            wprintf(L"    前3项数据:\n");
            for (int i = 0; i < min(items, 3); i++) {
                wchar_t itemText[256];
                ListView_GetItemText(hListView, i, 0, itemText, 256);
                wprintf(L"      项%d: %ls\n", i, itemText);
            }
        } else {
            wprintf(L"    ⚠ ListView为空！\n");
        }
    } else {
        wprintf(L"✗ ListView: 未找到\n");
    }
    
    HWND hStatusBar = FindWindowExW(hWnd, NULL, STATUSCLASSNAME, NULL);
    if (hStatusBar) {
        wprintf(L"✓ 状态栏: %p\n", hStatusBar);
    } else {
        wprintf(L"✗ 状态栏: 未找到\n");
    }
    
    wprintf(L"\n[3] 检查窗口样式...\n");
    LONG style = GetWindowLong(hWnd, GWL_STYLE);
    wprintf(L"  窗口样式: 0x%08lX\n", style);
    
    wprintf(L"\n[4] 切换标签页测试...\n");
    if (hTabs) {
        for (int i = 0; i < TabCtrl_GetItemCount(hTabs); i++) {
            SendMessageW(hTabs, TCM_SETCURSEL, i, 0);
            Sleep(500);
            
            HWND hLV = FindWindowExW(hWnd, NULL, WC_LISTVIEW, NULL);
            if (hLV) {
                int items = ListView_GetItemCount(hLV);
                wprintf(L"  标签%d: ListView有%d项\n", i, items);
            }
        }
    }
    
    wprintf(L"\n========================================\n");
    wprintf(L"诊断完成！\n");
    wprintf(L"========================================\n");
    
    return 0;
}