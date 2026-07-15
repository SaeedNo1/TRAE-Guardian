/* log_searcher.h - Search a log file for keyword, return matching lines. */
#ifndef LOG_SEARCHER_H
#define LOG_SEARCHER_H

#include <windows.h>

#ifdef BUILD_LOG_SEARCHER_DLL
#define LOGS_API __declspec(dllexport)
#else
#define LOGS_API __declspec(dllimport)
#endif

#define LOGS_MAX_HITS    256
#define LOGS_MAX_LINELEN 1024

typedef struct {
    int  lineNo;            /* 1-based */
    char line[LOGS_MAX_LINELEN];
} LogSearchHit;

/* Case-insensitive substring search. Returns number of hits (capped at LOGS_MAX_HITS). */
LOGS_API int LogSrch_Search(const char *logPath, const char *keyword, LogSearchHit *outHits, int maxHits);

#endif
