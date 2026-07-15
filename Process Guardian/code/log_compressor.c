/* log_compressor.c
 *
 * Parses lines like:
 *   [2026-06-24 09:00:01] EVENT type=process_start name=notepad.exe pid=1234 ppid=567
 *   [2026-06-24 09:00:35] EVENT type=process_exit  name=notepad.exe pid=1234 code=0
 *
 * Counts by (type,name) pair and writes:
 *   [2026-06-24 09:00:00 - 09:30:00 SUMMARY]
 *   process_start notepad.exe: 5 times
 *   process_exit  notepad.exe: 5 times
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "log_compressor.h"

#define MAX_KEYS 4096

typedef struct {
    char key[256];   /* "type=... name=..." */
    int  count;
    char firstTs[32];
    char lastTs[32];
} KeyRec;

static KeyRec g_keys[MAX_KEYS];
static int    g_keyN = 0;
static char   g_firstTsGlobal[32] = "";
static char   g_lastTsGlobal[32]  = "";

/* Extract the type=... and name=... substring, lowercased */
static void make_key(const char *line, char *out, int sz) {
    const char *pType = strstr(line, "type=");
    const char *pName = strstr(line, "name=");
    if (!pType || !pName) { out[0] = 0; return; }
    const char *eType = strchr(pType, ' ');
    if (!eType) eType = pType + strlen(pType);
    const char *eName = strchr(pName, ' ');
    if (!eName) eName = pName + strlen(pName);
    int lenType = (int)(eType - pType);
    int lenName = (int)(eName - pName);
    int n = 0;
    for (int i = 0; i < lenType && n < sz-1; i++) out[n++] = (char)tolower(pType[i]);
    out[n++] = ' ';
    for (int i = 0; i < lenName && n < sz-1; i++) out[n++] = (char)tolower(pName[i]);
    out[n] = 0;
}

static void extract_ts(const char *line, char *out, int sz) {
    const char *lb = strchr(line, '[');
    const char *rb = lb ? strchr(lb, ']') : NULL;
    if (!lb || !rb || rb-lb >= sz) { out[0]=0; return; }
    int n = (int)(rb - lb - 1);
    memcpy(out, lb+1, n);
    out[n] = 0;
}

int LogCmp_Compress(const char *rawLogPath, const char *compressedLogPath, int append) {
    FILE *fp = fopen(rawLogPath, "r");
    if (!fp) return -1;

    if (!append) {
        g_keyN = 0;
        g_firstTsGlobal[0] = 0;
        g_lastTsGlobal[0] = 0;
    }

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char ts[32];
        extract_ts(line, ts, sizeof(ts));
        if (ts[0]) {
            if (!g_firstTsGlobal[0]) strncpy(g_firstTsGlobal, ts, sizeof(g_firstTsGlobal)-1);
            strncpy(g_lastTsGlobal, ts, sizeof(g_lastTsGlobal)-1);
        }
        char key[256];
        make_key(line, key, sizeof(key));
        if (!key[0]) continue;
        int found = 0;
        for (int i = 0; i < g_keyN; i++) {
            if (strcmp(g_keys[i].key, key) == 0) {
                g_keys[i].count++;
                if (ts[0]) strncpy(g_keys[i].lastTs, ts, sizeof(g_keys[i].lastTs)-1);
                found = 1; break;
            }
        }
        if (!found && g_keyN < MAX_KEYS) {
            strncpy(g_keys[g_keyN].key, key, sizeof(g_keys[g_keyN].key)-1);
            g_keys[g_keyN].count = 1;
            if (ts[0]) {
                strncpy(g_keys[g_keyN].firstTs, ts, sizeof(g_keys[g_keyN].firstTs)-1);
                strncpy(g_keys[g_keyN].lastTs, ts, sizeof(g_keys[g_keyN].lastTs)-1);
            }
            g_keyN++;
        }
    }
    fclose(fp);

    FILE *out = fopen(compressedLogPath, append ? "a" : "w");
    if (!out) return -1;
    fprintf(out, "[%s - %s SUMMARY]\n",
            g_firstTsGlobal[0] ? g_firstTsGlobal : "?",
            g_lastTsGlobal[0]  ? g_lastTsGlobal  : "?");
    for (int i = 0; i < g_keyN; i++) {
        fprintf(out, "%s: %d times\n", g_keys[i].key, g_keys[i].count);
    }
    fclose(out);
    return g_keyN;
}

int LogCmp_ReadTail(const char *path, int bytes, char *outBuf, int outBufSize) {
    if (bytes <= 0 || bytes >= outBufSize) bytes = outBufSize - 1;
    FILE *fp = fopen(path, "rb");
    if (!fp) { outBuf[0] = 0; return 0; }
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    long start = (sz > bytes) ? (sz - bytes) : 0;
    fseek(fp, start, SEEK_SET);
    int n = (int)fread(outBuf, 1, bytes, fp);
    outBuf[n] = 0;
    fclose(fp);
    return n;
}

int LogCmp_Reset(const char *path) {
    FILE *fp = fopen(path, "w");
    if (!fp) return -1;
    fclose(fp);
    g_keyN = 0;
    g_firstTsGlobal[0] = 0;
    g_lastTsGlobal[0]  = 0;
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID l) {
    (void)h; (void)r; (void)l;
    return TRUE;
}
