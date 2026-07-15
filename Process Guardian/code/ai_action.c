/* ai_action.c - Client side of the Guardian AI action pipe. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "ai_action.h"

static int send_raw(const char *json, char *out, int outSz, int timeoutMs) {
    if (timeoutMs <= 0) timeoutMs = 5000;
    HANDLE hPipe = CreateFileA(AIA_PIPE_NAME, GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        if (out) snprintf(out, outSz, "{\"ok\":false,\"msg\":\"pipe not available (%lu)\"}", GetLastError());
        return -1;
    }
    DWORD mode = PIPE_READMODE_BYTE;
    SetNamedPipeHandleState(hPipe, &mode, NULL, NULL);

    DWORD wrote = 0;
    if (!WriteFile(hPipe, json, (DWORD)strlen(json), &wrote, NULL)) {
        if (out) snprintf(out, outSz, "{\"ok\":false,\"msg\":\"write fail (%lu)\"}", GetLastError());
        CloseHandle(hPipe);
        return -1;
    }
    FlushFileBuffers(hPipe);
    if (out && outSz > 0) {
        DWORD read = 0;
        if (!ReadFile(hPipe, out, outSz - 1, &read, NULL)) {
            snprintf(out + (out ? strlen(out) : 0), outSz, "");
        }
        out[read] = 0;
    }
    CloseHandle(hPipe);
    return 0;
}

int AiAct_Send(const char *jsonCmd, char *outResp, int outRespSz, int timeoutMs) {
    return send_raw(jsonCmd, outResp, outRespSz, timeoutMs);
}

int AiAct_KillPid(DWORD pid, char *out, int outSz) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "{\"cmd\":\"kill_pid\",\"pid\":%lu}", (unsigned long)pid);
    return send_raw(cmd, out, outSz, 5000);
}

int AiAct_RepeatedKill(const char *name, int tree, char *out, int outSz) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "{\"cmd\":\"repeated_kill\",\"name\":\"%s\",\"tree\":%s}",
             name, tree ? "true" : "false");
    return send_raw(cmd, out, outSz, 5000);
}

int AiAct_StopRepeated(const char *name, char *out, int outSz) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "{\"cmd\":\"stop_repeated\",\"name\":\"%s\"}", name);
    return send_raw(cmd, out, outSz, 5000);
}

int AiAct_Protect(const char *name, int tree, char *out, int outSz) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "{\"cmd\":\"protect\",\"name\":\"%s\",\"tree\":%s}",
             name, tree ? "true" : "false");
    return send_raw(cmd, out, outSz, 5000);
}

int AiAct_Unprotect(const char *name, char *out, int outSz) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "{\"cmd\":\"unprotect\",\"name\":\"%s\"}", name);
    return send_raw(cmd, out, outSz, 5000);
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID l) {
    (void)h; (void)r; (void)l;
    return TRUE;
}
