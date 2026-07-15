#ifndef USER_INTERACTION_H
#define USER_INTERACTION_H

#include <windows.h>
#include <stdint.h>

#define MAX_INTERACTION_ENTRIES 512

typedef struct {
    DWORD pid;
    uint64_t lastKeyboardTime;
    uint64_t lastMouseClickTime;
    uint64_t lastMouseMoveTime;
    uint64_t lastFocusTime;
    BOOL hasFocus;
    uint64_t lastCheckTime;
} InteractionEntry;

typedef struct {
    InteractionEntry entries[MAX_INTERACTION_ENTRIES];
    int entryCount;
    CRITICAL_SECTION cs;
    BOOL running;
    HHOOK hKeyboardHook;
    HHOOK hMouseHook;
} UserInteractionMonitor;

BOOL UserInteractionMonitorInit(UserInteractionMonitor* uim);
void UserInteractionMonitorCleanup(UserInteractionMonitor* uim);
void UserInteractionMonitorStart(UserInteractionMonitor* uim);
void UserInteractionMonitorStop(UserInteractionMonitor* uim);
DWORD WINAPI UserInteractionMonitorThreadProc(LPVOID param);
BOOL UserInteractionHasRecentAction(DWORD pid, uint64_t maxMs);
void UserInteractionMarkAction(DWORD pid, const char* actionType);
int UserInteractionGetScoreAdjustment(DWORD pid);

#endif
