#ifndef HOOK_PIPE_SERVER_H
#define HOOK_PIPE_SERVER_H

#include <windows.h>
#include "daemon_core.h"
#include "guardian_hook.h"

void StartHookPipeServer(DaemonState* s);
void StopHookPipeServer(DaemonState* s);
DWORD WINAPI HookPipeServerThread(LPVOID lpParam);

#endif