/* log_searcher.c */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "log_searcher.h"

static char *str_icasestr(const char *hay, const char *needle) {
    if (!hay || !needle || !*needle) return (char *)hay;
    size_t nl = strlen(needle);
    for (const char *p = hay; *p; p++) {
        if (tolower((unsigned char)*p) == tolower((unsigned char)*needle)) {
            size_t i = 1;
            while (i < nl && tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) i++;
            if (i == nl) return (char *)p;
        }
    }
    return NULL;
}

int LogSrch_Search(const char *logPath, const char *keyword, LogSearchHit *outHits, int maxHits) {
    if (!logPath || !keyword || !outHits || maxHits <= 0) return 0;
    FILE *fp = fopen(logPath, "r");
    if (!fp) return 0;
    char line[LOGS_MAX_LINELEN];
    int lineNo = 0, hits = 0;
    while (fgets(line, sizeof(line), fp)) {
        lineNo++;
        if (str_icasestr(line, keyword)) {
            if (hits < maxHits) {
                outHits[hits].lineNo = lineNo;
                size_t L = strlen(line);
                while (L > 0 && (line[L-1] == '\n' || line[L-1] == '\r')) line[--L] = 0;
                strncpy(outHits[hits].line, line, LOGS_MAX_LINELEN-1);
                outHits[hits].line[LOGS_MAX_LINELEN-1] = 0;
                hits++;
            }
        }
    }
    fclose(fp);
    return hits;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID l) {
    (void)h; (void)r; (void)l;
    return TRUE;
}
