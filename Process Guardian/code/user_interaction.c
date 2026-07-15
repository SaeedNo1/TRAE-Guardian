#define UNICODE
#define _UNICODE

#include "user_interaction.h"
#include <stdio.h>

UserInteractionMonitor g_userInteraction = {0};

BOOL UserInteractionMonitorInit(UserInteractionMonitor* uim) {
    if (!uim) return FALSE;
    InitializeCriticalSection(&uim->cs);
    uim->entryCount = 0;
    uim->running = FALSE;
    uim->hKeyboardHook = NULL;
    uim->hMouseHook = NULL;
    return TRUE;
}

void UserInteractionMonitorCleanup(UserInteractionMonitor* uim) {
    if (!uim) return;
    DeleteCriticalSection(&uim->cs);
    if (uim->hKeyboardHook) UnhookWindowsHookEx(uim->hKeyboardHook);
    if (uim->hMouseHook) UnhookWindowsHookEx(uim->hMouseHook);
}

InteractionEntry* UserInteractionGetEntry(UserInteractionMonitor* uim, DWORD pid) {
    if (!uim || !pid) return NULL;
    for (int i = 0; i < uim->entryCount; i++) {
        if (uim->entries[i].pid == pid) return &uim->entries[i];
    }
    return NULL;
}

InteractionEntry* UserInteractionCreateEntry(UserInteractionMonitor* uim, DWORD pid) {
    if (!uim || uim->entryCount >= MAX_INTERACTION_ENTRIES) return NULL;
    InteractionEntry* entry = &uim->entries[uim->entryCount++];
    memset(entry, 0, sizeof(InteractionEntry));
    entry->pid = pid;
    entry->lastCheckTime = GetTickCount64();
    return entry;
}

void UserInteractionMarkAction(DWORD pid, const char* actionType) {
    if (!pid) return;
    EnterCriticalSection(&g_userInteraction.cs);
    
    InteractionEntry* entry = UserInteractionGetEntry(&g_userInteraction, pid);
    if (!entry) {
        entry = UserInteractionCreateEntry(&g_userInteraction, pid);
    }
    
    if (entry) {
        uint64_t now = GetTickCount64();
        if (!strcmp(actionType, "keyboard")) entry->lastKeyboardTime = now;
        else if (!strcmp(actionType, "mouse_click")) entry->lastMouseClickTime = now;
        else if (!strcmp(actionType, "mouse_move")) entry->lastMouseMoveTime = now;
        else if (!strcmp(actionType, "focus")) entry->lastFocusTime = now;
        entry->lastCheckTime = now;
    }
    
    LeaveCriticalSection(&g_userInteraction.cs);
}

BOOL UserInteractionHasRecentAction(DWORD pid, uint64_t maxMs) {
    if (!pid) return FALSE;
    
    EnterCriticalSection(&g_userInteraction.cs);
    InteractionEntry* entry = UserInteractionGetEntry(&g_userInteraction, pid);
    if (!entry) {
        LeaveCriticalSection(&g_userInteraction.cs);
        return FALSE;
    }
    
    uint64_t now = GetTickCount64();
    uint64_t timeSinceKey = now - entry->lastKeyboardTime;
    uint64_t timeSinceClick = now - entry->lastMouseClickTime;
    uint64_t timeSinceMove = now - entry->lastMouseMoveTime;
    uint64_t timeSinceFocus = now - entry->lastFocusTime;
    
    LeaveCriticalSection(&g_userInteraction.cs);
    
    return (timeSinceKey <= maxMs || timeSinceClick <= maxMs || 
            timeSinceMove <= maxMs || timeSinceFocus <= maxMs);
}

int UserInteractionGetScoreAdjustment(DWORD pid) {
    if (!pid) return 0;
    
    EnterCriticalSection(&g_userInteraction.cs);
    InteractionEntry* entry = UserInteractionGetEntry(&g_userInteraction, pid);
    if (!entry) {
        LeaveCriticalSection(&g_userInteraction.cs);
        return 0;
    }
    
    uint64_t now = GetTickCount64();
    uint64_t timeSinceKey = now - entry->lastKeyboardTime;
    uint64_t timeSinceClick = now - entry->lastMouseClickTime;
    uint64_t timeSinceFocus = now - entry->lastFocusTime;
    
    BOOL hasRecentFocus = (timeSinceFocus <= 5000);
    BOOL hasRecentInput = (timeSinceKey <= 5000 || timeSinceClick <= 5000);
    
    LeaveCriticalSection(&g_userInteraction.cs);
    
    if (hasRecentFocus && hasRecentInput) {
        return -15;
    } else if (hasRecentFocus) {
        return -8;
    } else if (hasRecentInput) {
        return -5;
    }
    
    return 0;
}

DWORD WINAPI UserInteractionMonitorThreadProc(LPVOID param) {
    UserInteractionMonitor* uim = &g_userInteraction;
    if (!uim) return 0;
    
    POINT lastMousePos = {0, 0};
    
    while (uim->running) {
        HWND foreground = GetForegroundWindow();
        if (foreground) {
            DWORD foregroundPid = 0;
            GetWindowThreadProcessId(foreground, &foregroundPid);
            if (foregroundPid != 0) {
                UserInteractionMarkAction(foregroundPid, "focus");
            }
        }
        
        LASTINPUTINFO inputInfo = {0};
        inputInfo.cbSize = sizeof(inputInfo);
        if (GetLastInputInfo(&inputInfo)) {
            uint64_t now = GetTickCount64();
            uint64_t inputDelta = now - inputInfo.dwTime;
            
            if (inputDelta < 500) {
                POINT mousePos = {0, 0};
                if (GetCursorPos(&mousePos)) {
                    if (mousePos.x != lastMousePos.x || mousePos.y != lastMousePos.y) {
                        HWND hwnd = WindowFromPoint(mousePos);
                        if (hwnd) {
                            DWORD pid = 0;
                            GetWindowThreadProcessId(hwnd, &pid);
                            if (pid != 0) {
                                UserInteractionMarkAction(pid, "mouse_move");
                            }
                        }
                        lastMousePos = mousePos;
                    }
                }
            }
        }
        
        EnterCriticalSection(&uim->cs);
        uint64_t now = GetTickCount64();
        for (int i = uim->entryCount - 1; i >= 0; i--) {
            if (now - uim->entries[i].lastCheckTime > 60000) {
                for (int j = i; j < uim->entryCount - 1; j++) {
                    uim->entries[j] = uim->entries[j + 1];
                }
                uim->entryCount--;
            }
        }
        LeaveCriticalSection(&uim->cs);
        
        Sleep(200);
    }
    
    return 0;
}

void UserInteractionMonitorStart(UserInteractionMonitor* uim) {
    if (!uim) return;
    uim->running = TRUE;
    CreateThread(NULL, 0, UserInteractionMonitorThreadProc, uim, 0, NULL);
}

void UserInteractionMonitorStop(UserInteractionMonitor* uim) {
    if (!uim) return;
    uim->running = FALSE;
}
