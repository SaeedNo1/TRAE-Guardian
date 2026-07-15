/* log_compressor.h - Compress repeated event lines into "X N times" form
 * Reads raw.log -> writes compressed.log
 * Keeps original raw log untouched.
 */
#ifndef LOG_COMPRESSOR_H
#define LOG_COMPRESSOR_H

#include <windows.h>

#ifdef BUILD_LOG_COMPRESSOR_DLL
#define LOGC_API __declspec(dllexport)
#else
#define LOGC_API __declspec(dllimport)
#endif

/* Append a new compression pass to compressed.log. Idempotent if file is rewritten
 * (caller may choose to truncate first). Returns lines written, -1 on error. */
LOGC_API int LogCmp_Compress(const char *rawLogPath, const char *compressedLogPath, int append);

/* Read last `bytes` of compressed.log into outBuf. */
LOGC_API int LogCmp_ReadTail(const char *compressedLogPath, int bytes, char *outBuf, int outBufSize);

/* Wipe the compressed log (used when a new raw range starts). */
LOGC_API int LogCmp_Reset(const char *compressedLogPath);

#endif
