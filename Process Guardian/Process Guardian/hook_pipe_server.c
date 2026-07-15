#include "hook_pipe_server.h"
#include "daemon_core.h"
#include "state_machine.h"
#include "score_center.h"
#include <stdio.h>

static HANDLE g_hPipeServer = NULL;
static HANDLE g_hPipeThread = NULL;
static volatile BOOL g_pipeRunning = FALSE;
static DaemonState* g_pState = NULL;

static void HandleHookMessage(DaemonState* s, const HookMessage* msg) {
    if (!s || !msg)
        return;

    switch (msg->type) {
    case HOOK_MSG_FIRST_CALL:
        {
            DetectEvent event = {0};
            event.type = DETECT_EVENT_PROCESS_SPAWN;
            event.pid = msg->pid;
            wcsncpy(event.processName, msg->procName, 255);
            wcsncpy(event.imagePath, msg->imagePath, MAX_PATH - 1);
            wcsncpy(event.eventDetails, msg->apiName, 1023);
            event.timestamp = msg->timestamp;

            DispatchDetectEvent(s, &event);

            StateMachineAddEvidence(&s->stateMachine, msg->pid, L"First API call via hook");
            ScoreCenterAddBehaviorScore(&s->scoreCenter, (uint64_t)msg->pid, 5, L"hook_first_call");
        }
        break;

    case HOOK_MSG_API_CALL:
        {
            ScoreCenterAddBehaviorScore(&s->scoreCenter, (uint64_t)msg->pid, 2, msg->apiName);
        }
        break;

    case HOOK_MSG_BLOCKED:
        {
            DetectEvent event = {0};
            event.type = DETECT_EVENT_INJECTION;
            event.pid = msg->pid;
            wcsncpy(event.processName, msg->procName, 255);
            wcsncpy(event.imagePath, msg->imagePath, MAX_PATH - 1);
            wsprintf(event.eventDetails, L"Blocked dangerous API call: %ls", msg->apiName);
            event.timestamp = msg->timestamp;

            DispatchDetectEvent(s, &event);

            ScoreCenterAddBehaviorScore(&s->scoreCenter, (uint64_t)msg->pid, 30, msg->apiName);
        }
        break;

    default:
        break;
    }
}

DWORD WINAPI HookPipeServerThread(LPVOID lpParam) {
    DaemonState* s = (DaemonState*)lpParam;
    g_pState = s;

    while (g_pipeRunning) {
        g_hPipeServer = CreateNamedPipeW(
            HOOK_PIPE_NAME,
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            0,
            sizeof(HookMessage),
            HOOK_TIMEOUT_MS,
            NULL
        );

        if (g_hPipeServer == INVALID_HANDLE_VALUE) {
            Sleep(1000);
            continue;
        }

        BOOL connected = ConnectNamedPipe(g_hPipeServer, NULL);
        if (connected || GetLastError() == ERROR_PIPE_CONNECTED) {
            HookMessage msg = {0};
            DWORD bytesRead = 0;

            while (ReadFile(g_hPipeServer, &msg, sizeof(HookMessage), &bytesRead, NULL)) {
                if (bytesRead >= sizeof(HookMessage)) {
                    HandleHookMessage(s, &msg);
                }
                ZeroMemory(&msg, sizeof(HookMessage));
            }
        }

        DisconnectNamedPipe(g_hPipeServer);
        CloseHandle(g_hPipeServer);
        g_hPipeServer = NULL;
    }

    return 0;
}

void StartHookPipeServer(DaemonState* s) {
    if (!s || g_pipeRunning)
        return;

    g_pipeRunning = TRUE;
    g_hPipeThread = CreateThread(NULL, 0, HookPipeServerThread, s, 0, NULL);
}

void StopHookPipeServer(DaemonState* s) {
    g_pipeRunning = FALSE;

    if (g_hPipeServer != NULL) {
        DisconnectNamedPipe(g_hPipeServer);
        CloseHandle(g_hPipeServer);
        g_hPipeServer = NULL;
    }

    if (g_hPipeThread != NULL) {
        WaitForSingleObject(g_hPipeThread, 5000);
        CloseHandle(g_hPipeThread);
        g_hPipeThread = NULL;
    }
}