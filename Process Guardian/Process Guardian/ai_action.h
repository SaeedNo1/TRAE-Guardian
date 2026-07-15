/* ai_action.h - Send action commands to guardiand.exe over named pipe.
 *  pipe: \\.\pipe\GuardianAIAction
 *  protocol: JSON line in, JSON line out.
 */
#ifndef AI_ACTION_H
#define AI_ACTION_H

#include <windows.h>

#ifdef BUILD_AI_ACTION_DLL
#define AIA_API __declspec(dllexport)
#else
#define AIA_API __declspec(dllimport)
#endif

#define AIA_PIPE_NAME "\\\\.\\pipe\\GuardianAIAction"
#define AIA_MAX_IO     4096

/* Send one command synchronously, blocking up to timeoutMs (default 5000). */
AIA_API int  AiAct_Send(const char *jsonCmd, char *outResp, int outRespSz, int timeoutMs);

/* Convenience helpers - all return 0 on success, -1 on error.
 * outResp is filled with the daemon's response (may be empty). */
AIA_API int  AiAct_KillPid(DWORD pid, char *outResp, int outRespSz);
AIA_API int  AiAct_RepeatedKill(const char *procName, int tree, char *outResp, int outRespSz);
AIA_API int  AiAct_StopRepeated(const char *procName, char *outResp, int outRespSz);
AIA_API int  AiAct_Protect(const char *procName, int tree, char *outResp, int outRespSz);
AIA_API int  AiAct_Unprotect(const char *procName, char *outResp, int outRespSz);

#endif
