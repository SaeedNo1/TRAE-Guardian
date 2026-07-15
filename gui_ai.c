/* gui_ai.c - AI dialogs (no sidebar). Right-click menu in main.c opens
 * "Create AI Monitor Task..." which calls GuiAi_OpenNewTask. The toolbar
 * "Ask AI" button (ID 2008) calls GuiAi_OpenAskAiDialog.
 *
 * The Ask AI dialog transparently prompts for a SiliconFlow API key the
 * first time it is used and stores it obfuscated in data\api_key.dat.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <commctrl.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <richedit.h>
#include "gui_ai.h"
#include "resource.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")

/* ---- shared AI paths (resolved against exe directory) ---- */
#define AI_TASKS_JSON   "data\\ai_tasks.json"
#define AI_KEY_FILE     "data\\api_key.dat"
#define AI_NOTIF_LOG    "data\\ai_notifications.log"
#define AI_CACHE_ROOT   "cache\\ai_tasks"
#define AI_MEMORY_ROOT  "data\\ai_memory"

/* ---- last touched tracking (unused now, kept for ABI) ---- */
static struct {
    int  inUse[4];
    char name[4][260];
} g_last = {0};

void GuiAi_NotifyLastTouched(int type, const char *name) {
    if (type < 0 || type > 3 || !name) return;
    g_last.inUse[type] = 1;
    strncpy(g_last.name[type], name, 259);
    g_last.name[type][259] = 0;
}

/* ---- exe-directory resolver ---- */
static void exe_dir(char *out, int sz) {
    char p[MAX_PATH] = "";
    GetModuleFileNameA(NULL, p, MAX_PATH);
    char *s = strrchr(p, '\\');
    if (s) *s = 0;
    if (out && sz > 0) { strncpy(out, p, sz-1); out[sz-1] = 0; }
}

static int build_path(char *out, int sz, const char *rel) {
    char dir[MAX_PATH];
    exe_dir(dir, sizeof(dir));
    return snprintf(out, sz, "%s\\%s", dir, rel);
}

/* =====================================================================
 *  API key obfuscation (XOR with a derived 16-byte key).
 *  Must stay in sync with ai_key_setup.bat.
 * ===================================================================== */
static void derive_xk(unsigned char xk[16]) {
    const char *k = "PGK1_2026";
    for (int i = 0; i < 16; i++)
        xk[i] = (unsigned char)(k[i % 9] ^ (i * 31 + 7));
}

static int save_api_key(const char *key) {
    char path[MAX_PATH];
    build_path(path, sizeof(path), AI_KEY_FILE);
    CreateDirectoryA("data", NULL);  /* relative to current dir (the exe dir at startup) */
    unsigned char xk[16]; derive_xk(xk);
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    int n = (int)strlen(key);
    for (int i = 0; i < n; i++) {
        unsigned char c = (unsigned char)key[i] ^ xk[i % 16];
        fputc((int)c, fp);
    }
    fclose(fp);
    return 0;
}

static int load_api_key(char *out, int out_sz) {
    char path[MAX_PATH];
    build_path(path, sizeof(path), AI_KEY_FILE);
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz <= 0 || sz >= out_sz) { fclose(fp); return -1; }
    unsigned char *buf = (unsigned char *)malloc((size_t)sz);
    if (!buf) { fclose(fp); return -1; }
    fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    unsigned char xk[16]; derive_xk(xk);
    for (int i = 0; i < sz; i++) out[i] = (char)(buf[i] ^ xk[i % 16]);
    out[sz] = 0;
    free(buf);
    return 0;
}

/* =====================================================================
 *  API-key entry mini-dialog (IDD_KEYSET = 400). Shown automatically the
 *  first time the user clicks "Ask AI" without an api_key.dat.
 * ===================================================================== */
static INT_PTR CALLBACK KeysetDlgProc(HWND hDlg, UINT msg, WPARAM w, LPARAM l) {
    switch (msg) {
        case WM_INITDIALOG: {
            /* center on parent */
            HWND parent = GetParent(hDlg);
            if (parent) {
                RECT pr; GetWindowRect(parent, &pr);
                RECT dr; GetWindowRect(hDlg, &dr);
                int w2 = dr.right - dr.left, h2 = dr.bottom - dr.top;
                SetWindowPos(hDlg, HWND_TOP,
                    pr.left + ((pr.right-pr.left)-w2)/2,
                    pr.top  + ((pr.bottom-pr.top)-h2)/2,
                    0, 0, SWP_NOSIZE | SWP_NOZORDER);
            }
            SetWindowTextA(GetDlgItem(hDlg, IDC_KEYSET_EDIT),
                "Paste your SiliconFlow API key (sk-...). It is stored obfuscated in data\\api_key.dat.");
            /* password-style edit */
            HWND e = GetDlgItem(hDlg, IDC_KEYSET_EDIT);
            SendMessageA(e, EM_SETPASSWORDCHAR, (WPARAM)'*', 0);
            return TRUE;
        }
        case WM_COMMAND:
            if (LOWORD(w) == IDC_KEYSET_OK) {
                char k[512] = "";
                GetWindowTextA(GetDlgItem(hDlg, IDC_KEYSET_EDIT), k, sizeof(k));
                /* trim */
                char *p = k; while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
                char *end = p + strlen(p);
                while (end > p && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n')) end--;
                *end = 0;
                if (p[0] == 0) { MessageBoxA(hDlg, "Please paste a key.", "Process Guardian", MB_OK); return TRUE; }
                if (save_api_key(p) != 0) {
                    MessageBoxA(hDlg, "Failed to save key (check write permissions).", "Process Guardian", MB_OK);
                    return TRUE;
                }
                EndDialog(hDlg, IDOK);
                return TRUE;
            }
            if (LOWORD(w) == IDC_KEYSET_CANCEL || LOWORD(w) == IDCANCEL) {
                EndDialog(hDlg, IDCANCEL);
                return TRUE;
            }
            break;
    }
    return FALSE;
}

static int prompt_for_api_key(HWND hParent) {
    INT_PTR r = DialogBoxParam(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_KEYSET),
        hParent, KeysetDlgProc, 0);
    return (r == IDOK) ? 0 : -1;
}

/* =====================================================================
 *  JSON task list (data\ai_tasks.json)
 *  Schema: {"tasks":[{...}, ...]}
 *  We keep this C-side because the new-task dialog writes tasks; a Go
 *  tool reads/writes the same file. Each task object has at minimum:
 *    id, name, startTime, endTime, readIntervalSec, readBytes,
 *    status, createdAt, targets:[{type,name,pid,tree}, ...]
 * ===================================================================== */
static char *slurp(const char *path, long *out_sz) {
    FILE *fp = fopen(path, "rb");
    if (!fp) { *out_sz = 0; return NULL; }
    fseek(fp, 0, SEEK_END); long sz = ftell(fp); fseek(fp, 0, SEEK_SET);
    char *buf = (char *)malloc(sz + 1);
    if (!buf) { fclose(fp); *out_sz = 0; return NULL; }
    fread(buf, 1, sz, fp); buf[sz] = 0; fclose(fp);
    *out_sz = sz;
    return buf;
}

static int count_tasks(const char *path) {
    long sz; char *buf = slurp(path, &sz);
    if (!buf) return 0;
    int n = 0;
    const char *p = strstr(buf, "\"tasks\"");
    if (p) { p = strchr(p, '['); if (p) { while (*p && *p != ']') { if (*p == '{') n++; p++; } } }
    free(buf);
    return n;
}

static int find_task_json(const char *path, const char *id, char *outBuf, int outSz) {
    long sz; char *buf = slurp(path, &sz);
    if (!buf) return -1;
    int idx = -1, cur = -1;
    const char *p = strstr(buf, "\"tasks\"");
    if (p) p = strchr(p, '[');
    if (!p) { free(buf); return -1; }
    const char *objStart = NULL;
    int depth = 0;
    while (*p) {
        if (*p == '[') { p++; continue; }
        if (*p == ']') break;
        if (*p == '{') { objStart = p; depth = 1; cur++; p++; continue; }
        if (objStart) {
            if (*p == '{') depth++;
            else if (*p == '}') {
                depth--;
                if (depth == 0) {
                    char tmp[8192];
                    int n = (int)(p - objStart + 1);
                    if (n >= (int)sizeof(tmp)) n = (int)sizeof(tmp) - 1;
                    memcpy(tmp, objStart, n); tmp[n] = 0;
                    char idBuf[128] = "";
                    const char *q = strstr(tmp, "\"id\"");
                    if (q) {
                        q = strchr(q, ':');
                        if (q) {
                            q++;
                            while (*q == ' ' || *q == '"') q++;
                            int k = 0;
                            while (*q && *q != '"' && k < 127) idBuf[k++] = *q++;
                            idBuf[k] = 0;
                        }
                    }
                    if (strcmp(idBuf, id) == 0) {
                        idx = cur;
                        if (outBuf) { int cp = n < outSz-1 ? n : outSz-1; memcpy(outBuf, tmp, cp); outBuf[cp] = 0; }
                        break;
                    }
                    objStart = NULL;
                }
            }
        }
        p++;
    }
    free(buf);
    return idx;
}

/* helper: ensure parent directory of a full path exists */
static void ensure_parent_dir(const char *fullPath) {
    char dir[MAX_PATH];
    strncpy(dir, fullPath, sizeof(dir)-1);
    dir[sizeof(dir)-1] = '\0';
    char *slash = strrchr(dir, '\\');
    if (!slash) slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        CreateDirectoryA(dir, NULL);
    }
}

/* write a notification line to data\ai_notifications.log */
static void write_notification(const char *type, const char *name,
                               const char *taskId, const char *message) {
    char path[MAX_PATH];
    build_path(path, sizeof(path), AI_NOTIF_LOG);
    ensure_parent_dir(path);
    FILE *fp = fopen(path, "a");  /* append mode */
    if (!fp) return;
    SYSTEMTIME st; GetLocalTime(&st);
    fprintf(fp, "[%04d-%02d-%02d %02d:%02d:%02d] type=%s  name=%s  "
                "task_id=%s  message=%s\n",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond,
            type, name ? name : "-", taskId ? taskId : "-",
            message ? message : "");
    fclose(fp);
}

static int append_task(const char *path, const char *taskJson) {
    long sz; char *buf = slurp(path, &sz);
    if (!buf) { buf = (char *)malloc(64); strcpy(buf, "{\"tasks\":[]}"); sz = (long)strlen(buf); }
    char *p = strstr(buf, "\"tasks\"");
    if (!p) { free(buf); return -1; }
    p = strchr(p, '[');
    if (!p) { free(buf); return -1; }
    p++; /* skip [ */

    /* Find closing ] of tasks array, handling nesting */
    char *close = p;
    int depth = 1;
    while (*close && depth > 0) {
        if (*close == '[') depth++;
        else if (*close == ']') depth--;
        if (depth > 0) close++;
    }
    /* close now points to ] */

    int prefix = (int)(close - buf);  /* everything before ] */
    int suffix_len = (int)strlen(close);  /* ] and everything after */

    char *out = (char *)malloc(prefix + (int)strlen(taskJson) + suffix_len + 4);
    memcpy(out, buf, prefix);  /* {"tasks":[ ... up to ] */
    int off = prefix;

    /* Add comma separator if there are existing elements */
    if (close != p) {
        out[off++] = ',';
    }

    memcpy(out + off, taskJson, (int)strlen(taskJson));
    off += (int)strlen(taskJson);
    memcpy(out + off, close, suffix_len + 1);

    ensure_parent_dir(path);
    FILE *fp = fopen(path, "wb");
    if (!fp) { free(buf); free(out); return -1; }
    fputs(out, fp);
    fclose(fp);
    free(buf); free(out);
    return 0;
}

static int remove_task(const char *path, const char *id) {
    long sz; char *buf = slurp(path, &sz);
    if (!buf) return -1;
    char *out = (char *)malloc(sz + 1);
    out[0] = 0;
    char *p = strstr(buf, "\"tasks\"");
    if (!p) { free(buf); free(out); return -1; }
    char *lb = strchr(p, '[');
    if (!lb) { free(buf); free(out); return -1; }
    int prefix = (int)(lb - buf + 1);
    memcpy(out, buf, prefix);
    out[prefix] = 0;
    int off = prefix;
    p = lb + 1;
    int first = 1;
    while (*p && *p != ']') {
        while (*p == ' ' || *p == ',' || *p == '\n' || *p == '\r' || *p == '\t') p++;
        if (*p != '{') break;
        const char *start = p;
        int depth = 0;
        while (*p) {
            if (*p == '{') depth++;
            else if (*p == '}') { depth--; if (depth == 0) { p++; break; } }
            p++;
        }
        char obj[8192];
        int n = (int)(p - start); if (n >= (int)sizeof(obj)) n = (int)sizeof(obj) - 1;
        memcpy(obj, start, n); obj[n] = 0;
        char idBuf[128] = "";
        const char *q = strstr(obj, "\"id\"");
        if (q) {
            q = strchr(q, ':');
            if (q) {
                q++;
                while (*q == ' ' || *q == '"') q++;
                int k = 0;
                while (*q && *q != '"' && k < 127) idBuf[k++] = *q++;
                idBuf[k] = 0;
            }
        }
        if (strcmp(idBuf, id) == 0) continue;
        if (!first) out[off++] = ',';
        memcpy(out + off, obj, n);
        off += n;
        first = 0;
    }
    out[off++] = ']';
    strcpy(out + off, p);
    ensure_parent_dir(path);
    FILE *fp = fopen(path, "wb");
    if (!fp) { free(buf); free(out); return -1; }
    fputs(out, fp);
    fclose(fp);
    free(buf); free(out);
    return 0;
}

static int replace_task(const char *path, const char *id, const char *newJson) {
    char old[8192] = "";
    if (find_task_json(path, id, old, sizeof(old)) < 0) return -1;
    long sz; char *buf = slurp(path, &sz);
    if (!buf) return -1;
    char *hit = strstr(buf, old);
    if (!hit) { free(buf); return -1; }
    int oldLen = (int)strlen(old);
    int newLen = (int)strlen(newJson);
    char *out = (char *)malloc(sz - oldLen + newLen + 1);
    int prefix = (int)(hit - buf);
    memcpy(out, buf, prefix);
    memcpy(out + prefix, newJson, newLen);
    strcpy(out + prefix + newLen, hit + oldLen);
    ensure_parent_dir(path);
    FILE *fp = fopen(path, "wb");
    if (!fp) { free(buf); free(out); return -1; }
    fputs(out, fp);
    fclose(fp);
    free(buf); free(out);
    return 0;
}

/* ---- Small JSON helpers (assumes simple flat schema) ---- */
static const char *json_find_str(const char *json, const char *key, char *out, int outSz) {
    char pat[64]; snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) { out[0] = 0; return NULL; }
    p = strchr(p, ':');
    if (!p) { out[0] = 0; return NULL; }
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') { out[0] = 0; return NULL; }
    p++;
    int i = 0;
    while (*p && *p != '"' && i < outSz - 1) {
        if (*p == '\\' && p[1]) { p++; }
        out[i++] = *p++;
    }
    out[i] = 0;
    return out;
}

static int json_find_int(const char *json, const char *key, int defaultVal) {
    char pat[64]; snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return defaultVal;
    p = strchr(p, ':');
    if (!p) return defaultVal;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    return atoi(p);
}

static int json_find_bool(const char *json, const char *key, int defaultVal) {
    char pat[64]; snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return defaultVal;
    p = strchr(p, ':');
    if (!p) return defaultVal;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (strncmp(p, "true", 4) == 0) return 1;
    if (strncmp(p, "false", 5) == 0) return 0;
    return defaultVal;
}

static void json_escape_str(const char *in, char *out, int outSz) {
    int i = 0;
    for (const char *s = in; *s && i < outSz - 2; s++) {
        if (*s == '"' || *s == '\\') out[i++] = '\\';
        out[i++] = *s;
    }
    out[i] = 0;
}

static void ensure_soul_md(void) {
    char path[MAX_PATH];
    build_path(path, sizeof(path), AI_MEMORY_ROOT "\\SOUL.md");
    ensure_parent_dir(path);
    FILE *fp = fopen(path, "r");
    if (fp) { fclose(fp); return; }
    fp = fopen(path, "w");
    if (!fp) return;
    fprintf(fp,
        "# SOUL\n\n"
        "You are the security analyst for Process Guardian.\n"
        "Your job is to monitor target processes, detect suspicious behavior,\n"
        "and classify risk as one of: LOW, MEDIUM, HIGH, CONFIRMED.\n\n"
        "Rules:\n"
        "- LOW: unusual but likely benign; notify only in the bell panel.\n"
        "- MEDIUM: suspicious behavior; notify only in the bell panel.\n"
        "- HIGH: dangerous behavior; show a popup and ask user before cleanup.\n"
        "- CONFIRMED: clear malware; clean automatically, then notify in the bell panel.\n\n"
        "Always respond with a single JSON object:\n"
        "{\"level\":\"LOW|MEDIUM|HIGH|CONFIRMED\",\"path\":\"...\",\"reason\":\"...\"}\n");
    fclose(fp);
}

/* ---- Create AI Monitor Task dialog (ID 200) ---- */
typedef struct {
    HWND hName, hType, hProcName, hPid, hTree;
    HWND hList;
    HWND hStart, hEnd, hInterval, hBytes;
    char targets[16][260];
    int  targetType[16];   /* 1=process 2=service 3=registry 4=partition */
    int  targetTree[16];
    int  targetPid[16];
    int  targetN;
    char editId[64];
    int  cameFromRightClick;  /* 1 if opened from right-click */
} DlgData;

static void parse_task_into_dlgdata(const char *json, DlgData *d) {
    if (!json || !d) return;
    char name[256] = "", startT[64] = "", endT[64] = "", intS[32] = "", byS[32] = "";
    json_find_str(json, "name", name, sizeof(name));
    json_find_str(json, "startTime", startT, sizeof(startT));
    json_find_str(json, "endTime", endT, sizeof(endT));
    int interval = json_find_int(json, "readIntervalSec", 300);
    int bytes    = json_find_int(json, "readBytes", 4096);
    snprintf(intS, sizeof(intS), "%d", interval);
    snprintf(byS, sizeof(byS), "%d", bytes);
    if (name[0])     SetWindowTextA(d->hName, name);
    if (startT[0])   SetWindowTextA(d->hStart, startT);
    if (endT[0])     SetWindowTextA(d->hEnd, endT);
    if (intS[0])     SetWindowTextA(d->hInterval, intS);
    if (byS[0])      SetWindowTextA(d->hBytes, byS);

    const char *ta = strstr(json, "\"targets\"");
    if (!ta) return;
    ta = strchr(ta, '[');
    if (!ta) return;
    ta++;
    int depth = 1;
    d->targetN = 0;
    while (*ta && depth > 0 && d->targetN < 16) {
        if (*ta == '[') depth++;
        else if (*ta == ']') { depth--; if (depth == 0) break; }
        if (*ta == '{') {
            const char *objStart = ta;
            int od = 1;
            ta++;
            while (*ta && od > 0) {
                if (*ta == '{') od++;
                else if (*ta == '}') od--;
                if (od > 0) ta++;
            }
            int objLen = (int)(ta - objStart + 1);
            if (objLen >= 4096) continue;
            char obj[4096];
            memcpy(obj, objStart, objLen); obj[objLen] = 0;

            char tname[260] = "", ttype[32] = "";
            int pid = json_find_int(obj, "pid", 0);
            int tree = json_find_bool(obj, "tree", 0);
            json_find_str(obj, "name", tname, sizeof(tname));
            json_find_str(obj, "type", ttype, sizeof(ttype));
            if (tname[0]) {
                strncpy(d->targets[d->targetN], tname, 259);
                d->targetPid[d->targetN] = pid;
                d->targetTree[d->targetN] = tree;
                if (!_stricmp(ttype, "service"))   d->targetType[d->targetN] = 2;
                else if (!_stricmp(ttype, "registry")) d->targetType[d->targetN] = 3;
                else if (!_stricmp(ttype, "partition")) d->targetType[d->targetN] = 4;
                else d->targetType[d->targetN] = 1;
                d->targetN++;
            }
        }
        ta++;
    }
}

/* Process Picker dialog proc (IDD_PROC_PICKER = 600) */
static INT_PTR CALLBACK ProcPickerDlgProc(HWND hDlg, UINT msg, WPARAM w, LPARAM l) {
    static char *selName = NULL; static int *selPid = NULL; static int *selTree = NULL;
    switch (msg) {
        case WM_INITDIALOG: {
            selName = ((char **)l)[0];
            selPid  = ((int **)l)[1];
            selTree = ((int **)l)[2];
            HWND hList = GetDlgItem(hDlg, 6001);
            HWND hType = GetDlgItem(hDlg, 6002);
            SendMessageA(hType, CB_ADDSTRING, 0, (LPARAM)"process");
            SendMessageA(hType, CB_ADDSTRING, 0, (LPARAM)"service");
            SendMessageA(hType, CB_ADDSTRING, 0, (LPARAM)"registry");
            SendMessageA(hType, CB_SETCURSEL, 0, 0);
            SendMessageA(hList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT);
            LVCOLUMNA col = {0};
            col.mask = LVCF_TEXT | LVCF_WIDTH;
            col.pszText = (LPSTR)"Process Name"; col.cx = 200;
            SendMessageA(hList, LVM_INSERTCOLUMNA, 0, (LPARAM)&col);
            col.pszText = (LPSTR)"PID"; col.cx = 80;
            SendMessageA(hList, LVM_INSERTCOLUMNA, 1, (LPARAM)&col);
            /* Enumerate processes */
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe = {0}; pe.dwSize = sizeof(pe);
                int row = 0;
                if (Process32FirstW(hSnap, &pe)) {
                    do {
                        char nameA[260];
                        WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, nameA, sizeof(nameA), NULL, NULL);
                        LVITEMA it = {0};
                        it.mask = LVIF_TEXT; it.iItem = row; it.pszText = nameA;
                        SendMessageA(hList, LVM_INSERTITEMA, 0, (LPARAM)&it);
                        char pidS[32]; snprintf(pidS, sizeof(pidS), "%lu", pe.th32ProcessID);
                        LVITEMA s = {0};
                        s.mask = LVIF_TEXT; s.iItem = row; s.iSubItem = 1; s.pszText = pidS;
                        SendMessageA(hList, LVM_SETITEMTEXTA, row, (LPARAM)&s);
                        row++;
                    } while (Process32NextW(hSnap, &pe) && row < 2000);
                }
                CloseHandle(hSnap);
            }
            return TRUE;
        }
        case WM_COMMAND:
            if (LOWORD(w) == IDOK) {
                HWND hList = GetDlgItem(hDlg, 6001);
                int sel = (int)SendMessageA(hList, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
                if (sel < 0) { MessageBoxA(hDlg, "Select a process.", "Input", MB_OK); break; }
                char name[260] = "", pidS[32] = "";
                LVITEMA it = {0}; it.mask = LVIF_TEXT; it.iItem = sel; it.pszText = name; it.cchTextMax = sizeof(name);
                SendMessageA(hList, LVM_GETITEMTEXTA, sel, (LPARAM)&it);
                it.iSubItem = 1; it.pszText = pidS; it.cchTextMax = sizeof(pidS);
                SendMessageA(hList, LVM_GETITEMTEXTA, sel, (LPARAM)&it);
                if (selName) strcpy(selName, name);
                if (selPid) *selPid = atoi(pidS);
                if (selTree) *selTree = (SendMessage(GetDlgItem(hDlg, 6003), BM_GETCHECK, 0, 0) == BST_CHECKED) ? 1 : 0;
                EndDialog(hDlg, IDOK);
                return TRUE;
            }
            if (LOWORD(w) == IDCANCEL) { EndDialog(hDlg, IDCANCEL); return TRUE; }
            break;
    }
    return FALSE;
}

static int ShowProcessPicker(HWND hParent, char *outName, int *outPid, int *outTree) {
    void *params[3] = { outName, outPid, outTree };
    return (int)DialogBoxParam(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_PROC_PICKER),
        hParent, ProcPickerDlgProc, (LPARAM)params);
}

static INT_PTR CALLBACK NewTaskDlgProc(HWND hDlg, UINT msg, WPARAM w, LPARAM l) {
    DlgData *d = (DlgData *)GetWindowLongPtr(hDlg, GWLP_USERDATA);
    switch (msg) {
        case WM_INITDIALOG: {
            d = (DlgData *)l;
            SetWindowLongPtr(hDlg, GWLP_USERDATA, (LONG_PTR)d);
            d->hName     = GetDlgItem(hDlg, IDC_DLG_NAME_EDIT);
            d->hType     = GetDlgItem(hDlg, IDC_DLG_TYPE_CB);
            d->hProcName = GetDlgItem(hDlg, IDC_DLG_PROC_NAME);
            d->hPid      = GetDlgItem(hDlg, IDC_DLG_PID_EDIT);
            d->hTree     = GetDlgItem(hDlg, IDC_DLG_TREE_CHK);
            d->hList     = GetDlgItem(hDlg, IDC_DLG_TARGET_LV);
            d->hStart    = GetDlgItem(hDlg, IDC_DLG_START);
            d->hEnd      = GetDlgItem(hDlg, IDC_DLG_END);
            d->hInterval = GetDlgItem(hDlg, IDC_DLG_INTERVAL);
            d->hBytes    = GetDlgItem(hDlg, IDC_DLG_BYTES);
            /* Use ANSI API explicitly so ComboBox/LV columns stay readable */
            SendMessageA(d->hType, CB_ADDSTRING, 0, (LPARAM)"process");
            SendMessageA(d->hType, CB_ADDSTRING, 0, (LPARAM)"service");
            SendMessageA(d->hType, CB_ADDSTRING, 0, (LPARAM)"registry");
            SendMessageA(d->hType, CB_ADDSTRING, 0, (LPARAM)"partition");
            SendMessageA(d->hType, CB_SETCURSEL, 0, 0);
            SetWindowTextA(d->hInterval, "300");
            SetWindowTextA(d->hBytes, "4096");
            SetWindowTextA(d->hStart, "2026-06-24 09:00:00");
            SetWindowTextA(d->hEnd,   "2026-06-24 18:00:00");
            if (d->editId[0]) {
                SetWindowTextA(hDlg, "Edit AI Monitor Task");
                SetWindowTextA(d->hName, d->editId);
            }
            /* Load existing task data when editing */
            if (d->editId[0]) {
                char path[MAX_PATH], json[8192];
                build_path(path, sizeof(path), AI_TASKS_JSON);
                if (find_task_json(path, d->editId, json, sizeof(json)) >= 0) {
                    parse_task_into_dlgdata(json, d);
                }
            }
            /* Pre-fill from right-click: auto-fill procName/PID if first target exists */
            if (d->targetN > 0 && d->cameFromRightClick) {
                SetWindowTextA(d->hProcName, d->targets[0]);
                char pidS[32]; snprintf(pidS, sizeof(pidS), "%d", d->targetPid[0]);
                SetWindowTextA(d->hPid, pidS);
                if (d->targetTree[0]) SendMessage(d->hTree, BM_SETCHECK, BST_CHECKED, 0);
            }
            SendMessageA(d->hList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT);
            LVCOLUMNA col = {0};
            col.mask = LVCF_TEXT | LVCF_WIDTH;
            col.pszText = (LPSTR)"Type"; col.cx = 80;
            SendMessageA(d->hList, LVM_INSERTCOLUMNA, 0, (LPARAM)&col);
            col.pszText = (LPSTR)"Name"; col.cx = 200;
            SendMessageA(d->hList, LVM_INSERTCOLUMNA, 1, (LPARAM)&col);
            col.pszText = (LPSTR)"PID"; col.cx = 60;
            SendMessageA(d->hList, LVM_INSERTCOLUMNA, 2, (LPARAM)&col);
            col.pszText = (LPSTR)"Tree"; col.cx = 50;
            SendMessageA(d->hList, LVM_INSERTCOLUMNA, 3, (LPARAM)&col);
            for (int i = 0; i < d->targetN; i++) {
                LVITEMA it = {0};
                it.mask = LVIF_TEXT;
                it.iItem = i;
                const char *tp = "?";
                switch (d->targetType[i]) {
                    case 1: tp = "process"; break;
                    case 2: tp = "service"; break;
                    case 3: tp = "registry"; break;
                    case 4: tp = "partition"; break;
                }
                it.pszText = (LPSTR)tp;
                SendMessageA(d->hList, LVM_INSERTITEMA, 0, (LPARAM)&it);
                { LVITEMA _s = {0}; _s.mask = LVIF_TEXT; _s.iItem = i; _s.iSubItem = 1; _s.pszText = d->targets[i];
                  SendMessageA(d->hList, LVM_SETITEMTEXTA, i, (LPARAM)&_s); }
                char p[16]; snprintf(p, sizeof(p), "%d", d->targetPid[i]);
                { LVITEMA _s = {0}; _s.mask = LVIF_TEXT; _s.iItem = i; _s.iSubItem = 2; _s.pszText = p;
                  SendMessageA(d->hList, LVM_SETITEMTEXTA, i, (LPARAM)&_s); }
                { LVITEMA _s = {0}; _s.mask = LVIF_TEXT; _s.iItem = i; _s.iSubItem = 3; _s.pszText = (LPSTR)(d->targetTree[i] ? "Y" : "N");
                  SendMessageA(d->hList, LVM_SETITEMTEXTA, i, (LPARAM)&_s); }
            }
            return TRUE;
        }
        case WM_COMMAND:
            if (LOWORD(w) == IDC_DLG_ADD_BTN) {
                if (d->targetN >= 16) { MessageBoxA(hDlg, "max 16 targets", "limit", MB_OK); break; }
                /* Use process picker dialog */
                char name[260] = "";
                int pid = 0, tree = 0;
                if (ShowProcessPicker(hDlg, name, &pid, &tree) != IDOK) break;
                if (!name[0]) break;
                int type = 1; /* processes are type 1 */
                int row = d->targetN;
                strncpy(d->targets[row], name, 259);
                d->targetType[row] = type;
                d->targetTree[row] = tree;
                d->targetPid[row]  = pid;
                d->targetN++;
                const char *tp = "process";
                LVITEMA it = {0};
                it.mask = LVIF_TEXT; it.iItem = row; it.pszText = (LPSTR)tp;
                SendMessageA(d->hList, LVM_INSERTITEMA, 0, (LPARAM)&it);
                { LVITEMA _s = {0}; _s.mask = LVIF_TEXT; _s.iItem = row; _s.iSubItem = 1; _s.pszText = name;
                  SendMessageA(d->hList, LVM_SETITEMTEXTA, row, (LPARAM)&_s); }
                char p[16]; snprintf(p, sizeof(p), "%d", pid);
                { LVITEMA _s = {0}; _s.mask = LVIF_TEXT; _s.iItem = row; _s.iSubItem = 2; _s.pszText = p;
                  SendMessageA(d->hList, LVM_SETITEMTEXTA, row, (LPARAM)&_s); }
                { LVITEMA _s = {0}; _s.mask = LVIF_TEXT; _s.iItem = row; _s.iSubItem = 3; _s.pszText = (LPSTR)(tree ? "Y" : "N");
                  SendMessageA(d->hList, LVM_SETITEMTEXTA, row, (LPARAM)&_s); }
                /* Clear fields for next add */
                SetWindowTextA(d->hProcName, "");
                SetWindowTextA(d->hPid, "");
            } else if (LOWORD(w) == IDC_DLG_DEL_BTN) {
                int row = (int)SendMessageA(d->hList, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
                if (row < 0) break;
                SendMessageA(d->hList, LVM_DELETEITEM, row, 0);
                for (int i = row; i < d->targetN - 1; i++) {
                    strcpy(d->targets[i], d->targets[i+1]);
                    d->targetType[i] = d->targetType[i+1];
                    d->targetTree[i] = d->targetTree[i+1];
                    d->targetPid[i]  = d->targetPid[i+1];
                }
                d->targetN--;
            } else if (LOWORD(w) == IDC_DLG_OK) {
                if (d->targetN == 0) { MessageBoxA(hDlg, "Add at least one target", "input", MB_OK); break; }
                char name[256] = "", startT[64] = "", endT[64] = "", intS[32] = "", byS[32] = "";
                GetWindowTextA(d->hName, name, sizeof(name));
                GetWindowTextA(d->hStart, startT, sizeof(startT));
                GetWindowTextA(d->hEnd, endT, sizeof(endT));
                GetWindowTextA(d->hInterval, intS, sizeof(intS));
                GetWindowTextA(d->hBytes, byS, sizeof(byS));
                if (!name[0]) { MessageBoxA(hDlg, "Enter task name", "input", MB_OK); break; }
                int interval = atoi(intS); if (interval < 60) interval = 60; if (interval > 86400) interval = 86400;
                int bytes = atoi(byS); if (bytes < 1) bytes = 1; if (bytes > 1048576) bytes = 1048576;

                char id[64];
                if (d->editId[0]) strncpy(id, d->editId, sizeof(id)-1);
                else {
                    SYSTEMTIME st; GetLocalTime(&st);
                    snprintf(id, sizeof(id), "task-%04d%02d%02d-%02d%02d%02d",
                             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
                }
                char ts[32]; SYSTEMTIME st; GetLocalTime(&st);
                snprintf(ts, sizeof(ts), "%04d-%02d-%02d %02d:%02d:%02d",
                         st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

                /* Preserve memoryFile and createdAt when editing */
                char oldJson[8192] = "";
                char memoryFile[MAX_PATH] = "";
                char createdAt[32] = "";
                if (d->editId[0]) {
                    char path[MAX_PATH];
                    build_path(path, sizeof(path), AI_TASKS_JSON);
                    if (find_task_json(path, d->editId, oldJson, sizeof(oldJson)) >= 0) {
                        json_find_str(oldJson, "memoryFile", memoryFile, sizeof(memoryFile));
                        json_find_str(oldJson, "createdAt", createdAt, sizeof(createdAt));
                    }
                }
                if (!memoryFile[0]) {
                    snprintf(memoryFile, sizeof(memoryFile), "%s\\task_%s.log", AI_MEMORY_ROOT, id);
                }
                if (!createdAt[0]) strcpy(createdAt, ts);

                char escName[520] = "";
                json_escape_str(name, escName, sizeof(escName));
                char escMemoryFile[520] = "";
                json_escape_str(memoryFile, escMemoryFile, sizeof(escMemoryFile));

                char *json = (char *)malloc(16384);
                int off = snprintf(json, 16384,
                    "{\"id\":\"%s\",\"name\":\"%s\",\"startTime\":\"%s\",\"endTime\":\"%s\","
                    "\"readIntervalSec\":%d,\"readBytes\":%d,\"status\":\"pending\","
                    "\"memoryFile\":\"%s\",\"soulFile\":\"data\\\\ai_memory\\\\SOUL.md\","
                    "\"enabled\":true,\"createdAt\":\"%s\",\"targets\":[",
                    id, escName, startT, endT, interval, bytes,
                    escMemoryFile, createdAt);

                for (int i = 0; i < d->targetN; i++) {
                    const char *tp = "process";
                    switch (d->targetType[i]) {
                        case 1: tp = "process"; break; case 2: tp = "service"; break;
                        case 3: tp = "registry"; break; case 4: tp = "partition"; break;
                    }
                    char escTarget[520] = "";
                    const char *s = d->targets[i];
                    for (int k = 0; s[k] && k < 260; k++) {
                        int L = (int)strlen(escTarget);
                        if (s[k] == '"' || s[k] == '\\') escTarget[L++] = '\\';
                        escTarget[L] = s[k]; escTarget[L+1] = 0;
                    }
                    off += snprintf(json + off, 16384 - off,
                        "%s{\"type\":\"%s\",\"name\":\"%s\",\"pid\":%d,\"tree\":%s}",
                        i ? "," : "", tp, escTarget, d->targetPid[i],
                        d->targetTree[i] ? "true" : "false");
                }
                snprintf(json + off, 16384 - off, "]}");
                char path[MAX_PATH]; build_path(path, sizeof(path), AI_TASKS_JSON);
                int saved = (d->editId[0]) ? replace_task(path, d->editId, json)
                                           : append_task(path, json);
                free(json);
                if (saved != 0) {
                    MessageBoxA(hDlg,
                        "Failed to save task.\n\n"
                        "Make sure the program has write access to its own directory.",
                        "Process Guardian", MB_OK | MB_ICONERROR);
                    break;
                }
                /* write notification to log */
                write_notification("task_created", name, id,
                    d->editId[0] ? "任务已更新" : "任务已成功创建");
                /* ensure shared SOUL.md and per-task memory directory exist */
                ensure_soul_md();
                {
                    char memAbs[MAX_PATH];
                    build_path(memAbs, sizeof(memAbs), memoryFile);
                    ensure_parent_dir(memAbs);
                }
                /* ensure cache dir */
                char cacheAbs[MAX_PATH];
                build_path(cacheAbs, sizeof(cacheAbs), AI_CACHE_ROOT);
                CreateDirectoryA(cacheAbs, NULL);
                char dirx[MAX_PATH];
                snprintf(dirx, sizeof(dirx), "%s\\%s", cacheAbs, id);
                CreateDirectoryA(dirx, NULL);
                EndDialog(hDlg, IDOK);
            } else if (LOWORD(w) == IDC_DLG_CANCEL) {
                EndDialog(hDlg, IDCANCEL);
            }
            break;
    }
    return FALSE;
}

/* =====================================================================
 *  Task-specific Chat dialog (IDD_ASK_CHAT = 301)
 *  Opens when user selects a task and clicks "Talk with AI".
 *  Shows task name at top, has question input + AI response output.
 * ===================================================================== */
typedef struct {
    char taskName[256];
    char taskId[64];
    char taskJson[16384];
    char apiKey[256];
    char model[128];
    HWND hHistory;
    HWND hInput;
    char memPath[MAX_PATH];
} ChatData;

typedef struct {
    HWND hDlg;
    char apiKey[256];
    char model[128];
    char systemPrompt[65536];
    char userPrompt[131072];
    int baseLen;  /* text length before "AI: (thinking...)" so it can be replaced cleanly */
} AiThreadData;

static DWORD WINAPI AiRequestThread(LPVOID lpParam);

/* UTF-8 / ANSI to wide helpers for RichEdit20W */
static wchar_t* Utf8ToWide(const char* s) {
    int len = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (len <= 0) {
        wchar_t* empty = (wchar_t*)malloc(sizeof(wchar_t));
        if (empty) empty[0] = 0;
        return empty;
    }
    wchar_t* w = (wchar_t*)malloc(len * sizeof(wchar_t));
    if (!w) {
        wchar_t* empty = (wchar_t*)malloc(sizeof(wchar_t));
        if (empty) empty[0] = 0;
        return empty;
    }
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, len);
    return w;
}

static wchar_t* AnsiToWide(const char* s) {
    int len = MultiByteToWideChar(CP_ACP, 0, s, -1, NULL, 0);
    if (len <= 0) {
        wchar_t* empty = (wchar_t*)malloc(sizeof(wchar_t));
        if (empty) empty[0] = 0;
        return empty;
    }
    wchar_t* w = (wchar_t*)malloc(len * sizeof(wchar_t));
    if (!w) {
        wchar_t* empty = (wchar_t*)malloc(sizeof(wchar_t));
        if (empty) empty[0] = 0;
        return empty;
    }
    MultiByteToWideChar(CP_ACP, 0, s, -1, w, len);
    return w;
}

static char* WideToUtf8(const wchar_t* s) {
    int len = WideCharToMultiByte(CP_UTF8, 0, s, -1, NULL, 0, NULL, NULL);
    if (len <= 0) {
        char* empty = (char*)malloc(1);
        if (empty) empty[0] = 0;
        return empty;
    }
    char* out = (char*)malloc(len);
    if (!out) {
        char* empty = (char*)malloc(1);
        if (empty) empty[0] = 0;
        return empty;
    }
    WideCharToMultiByte(CP_UTF8, 0, s, -1, out, len, NULL, NULL);
    return out;
}

static BOOL IsValidUtf8(const char* s) {
    int len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, NULL, 0);
    return len > 0;
}

/* append text to chat history edit and scroll to bottom */
static void Chat_Append(HWND hEdit, const char *who, const char *text) {
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t line[128];
    int existingLen = GetWindowTextLengthW(hEdit);

    wchar_t* wwho = Utf8ToWide(who);
    wchar_t* wtext = Utf8ToWide(text);

    /* Use a single formatted block so the control does not flicker */
    swprintf(line, sizeof(line)/sizeof(line[0]), L"[%02d:%02d:%02d] %s:\r\n",
             st.wHour, st.wMinute, st.wSecond, wwho);

    /* Prepend a blank line between messages only when history is not empty */
    if (existingLen > 0) {
        SendMessageW(hEdit, EM_SETSEL, existingLen, existingLen);
        SendMessageW(hEdit, EM_REPLACESEL, FALSE, (LPARAM)L"\r\n");
    }
    int len = GetWindowTextLengthW(hEdit);
    SendMessageW(hEdit, EM_SETSEL, len, len);
    SendMessageW(hEdit, EM_REPLACESEL, FALSE, (LPARAM)line);
    len = GetWindowTextLengthW(hEdit);
    SendMessageW(hEdit, EM_SETSEL, len, len);
    SendMessageW(hEdit, EM_REPLACESEL, FALSE, (LPARAM)wtext);
    len = GetWindowTextLengthW(hEdit);
    SendMessageW(hEdit, EM_SETSEL, len, len);
    SendMessageW(hEdit, EM_REPLACESEL, FALSE, (LPARAM)L"\r\n");
    /* auto-scroll to bottom */
    SendMessageW(hEdit, EM_SCROLLCARET, 0, 0);

    free(wwho);
    free(wtext);
}

/* ---------- Markdown formatter using RichEdit character formats ---------- */
static void AppendPlainW(HWND hEdit, const wchar_t* text) {
    int len = GetWindowTextLengthW(hEdit);
    SendMessageW(hEdit, EM_SETSEL, len, len);
    SendMessageW(hEdit, EM_REPLACESEL, FALSE, (LPARAM)text);
}

static void AppendWithFormatW(HWND hEdit, const wchar_t* text, DWORD effects,
                              const wchar_t* face, int height, COLORREF color) {
    int start = GetWindowTextLengthW(hEdit);
    AppendPlainW(hEdit, text);
    int end = GetWindowTextLengthW(hEdit);
    SendMessageW(hEdit, EM_SETSEL, start, end);

    CHARFORMAT2W cf = {0};
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_BOLD | CFM_ITALIC | CFM_FACE | CFM_SIZE | CFM_COLOR;
    cf.dwEffects = effects;
    if (face) wcsncpy(cf.szFaceName, face, LF_FACESIZE);
    cf.yHeight = height;
    cf.crTextColor = color;
    SendMessageW(hEdit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
}

/* Parse a single inline segment that may contain **bold**, *italic*, and `code`.
   The segment does not cross line boundaries. */
static void AppendInlineFormattedW(HWND hEdit, const wchar_t* text) {
    const wchar_t* p = text;
    wchar_t buf[4096];
    int bufLen = 0;

    while (*p) {
        if (wcsncmp(p, L"**", 2) == 0) {
            if (bufLen > 0) { buf[bufLen] = 0; AppendPlainW(hEdit, buf); bufLen = 0; }
            p += 2;
            const wchar_t* end = wcsstr(p, L"**");
            if (!end) end = p + wcslen(p);
            wchar_t* b = (wchar_t*)malloc((end - p + 1) * sizeof(wchar_t));
            if (b) {
                memcpy(b, p, (end - p) * sizeof(wchar_t)); b[end - p] = 0;
                AppendWithFormatW(hEdit, b, CFE_BOLD, NULL, 200, RGB(0,0,0));
                free(b);
            }
            p = end;
            if (wcsncmp(p, L"**", 2) == 0) p += 2;
        } else if (*p == '*') {
            if (bufLen > 0) { buf[bufLen] = 0; AppendPlainW(hEdit, buf); bufLen = 0; }
            p++;
            const wchar_t* end = wcschr(p, '*');
            if (!end) end = p + wcslen(p);
            wchar_t* i = (wchar_t*)malloc((end - p + 1) * sizeof(wchar_t));
            if (i) {
                memcpy(i, p, (end - p) * sizeof(wchar_t)); i[end - p] = 0;
                AppendWithFormatW(hEdit, i, CFE_ITALIC, NULL, 200, RGB(0,0,0));
                free(i);
            }
            p = end;
            if (*p == '*') p++;
        } else if (*p == '`') {
            if (bufLen > 0) { buf[bufLen] = 0; AppendPlainW(hEdit, buf); bufLen = 0; }
            p++;
            const wchar_t* end = wcschr(p, '`');
            if (!end) end = p + wcslen(p);
            wchar_t* c = (wchar_t*)malloc((end - p + 1) * sizeof(wchar_t));
            if (c) {
                memcpy(c, p, (end - p) * sizeof(wchar_t)); c[end - p] = 0;
                AppendWithFormatW(hEdit, c, 0, L"Consolas", 180, RGB(120,120,120));
                free(c);
            }
            p = end;
            if (*p == '`') p++;
        } else {
            if (bufLen < (int)(sizeof(buf)/sizeof(buf[0])) - 1) buf[bufLen++] = *p;
            p++;
        }
    }
    if (bufLen > 0) { buf[bufLen] = 0; AppendPlainW(hEdit, buf); }
}

/* Append a message to the chat history with basic Markdown formatting.
   Supports: # headings, **bold**, *italic*, `inline code`, ```code blocks```, - lists. */
static void Chat_AppendMarkdown(HWND hEdit, const char *who, const char *text) {
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t header[128];

    wchar_t* wwho = Utf8ToWide(who);
    wchar_t* wtext = Utf8ToWide(text);

    swprintf(header, sizeof(header)/sizeof(header[0]), L"[%02d:%02d:%02d] %s:\r\n",
             st.wHour, st.wMinute, st.wSecond, wwho);

    /* separator line */
    int existingLen = GetWindowTextLengthW(hEdit);
    if (existingLen > 0) AppendPlainW(hEdit, L"\r\n");

    AppendWithFormatW(hEdit, header, CFE_BOLD, NULL, 200, RGB(0,0,0));

    const wchar_t* p = wtext;
    while (*p) {
        if (*p == L'\r') { p++; continue; }
        if (*p == L'\n') { AppendPlainW(hEdit, L"\r\n"); p++; continue; }

        /* code block */
        if (wcsncmp(p, L"```", 3) == 0) {
            p += 3;
            while (*p && *p != L'\n') p++;  /* skip language line */
            if (*p == L'\n') p++;
            const wchar_t* end = wcsstr(p, L"```");
            if (!end) end = p + wcslen(p);
            wchar_t* code = (wchar_t*)malloc((end - p + 1) * sizeof(wchar_t));
            if (code) {
                memcpy(code, p, (end - p) * sizeof(wchar_t)); code[end - p] = 0;
                AppendWithFormatW(hEdit, code, 0, L"Consolas", 180, RGB(120,120,120));
                free(code);
            }
            AppendPlainW(hEdit, L"\r\n");
            p = end;
            if (wcsncmp(p, L"```", 3) == 0) p += 3;
            while (*p == L'\n' || *p == L'\r') p++;
            continue;
        }

        /* headings */
        if (*p == L'#') {
            int level = 0;
            while (*p == L'#' && level < 6) { level++; p++; }
            if (*p == L' ') {
                p++;
                const wchar_t* end = p;
                while (*end && *end != L'\n') end++;
                wchar_t* h = (wchar_t*)malloc((end - p + 1) * sizeof(wchar_t));
                if (h) {
                    memcpy(h, p, (end - p) * sizeof(wchar_t)); h[end - p] = 0;
                    int fs = 260 - level * 24;
                    AppendWithFormatW(hEdit, h, CFE_BOLD, NULL, fs, RGB(0,0,0));
                    free(h);
                }
                AppendPlainW(hEdit, L"\r\n");
                p = end;
                if (*p == L'\n') p++;
                continue;
            } else {
                p -= level;
            }
        }

        /* list item */
        if (wcsncmp(p, L"- ", 2) == 0) {
            p += 2;
            const wchar_t* end = p;
            while (*end && *end != L'\n') end++;
            wchar_t* item = (wchar_t*)malloc((end - p + 1) * sizeof(wchar_t));
            if (item) {
                memcpy(item, p, (end - p) * sizeof(wchar_t)); item[end - p] = 0;
                AppendPlainW(hEdit, L"\u2022 ");
                AppendInlineFormattedW(hEdit, item);
                AppendPlainW(hEdit, L"\r\n");
                free(item);
            }
            p = end;
            if (*p == L'\n') p++;
            continue;
        }

        /* normal line */
        const wchar_t* end = p;
        while (*end && *end != L'\n') end++;
        wchar_t* line = (wchar_t*)malloc((end - p + 1) * sizeof(wchar_t));
        if (line) {
            memcpy(line, p, (end - p) * sizeof(wchar_t)); line[end - p] = 0;
            AppendInlineFormattedW(hEdit, line);
            AppendPlainW(hEdit, L"\r\n");
            free(line);
        }
        p = end;
        if (*p == L'\n') p++;
    }
    SendMessageW(hEdit, EM_SCROLLCARET, 0, 0);

    free(wwho);
    free(wtext);
}

/* Reload persisted chat history, re-rendering AI messages with Markdown formatting. */
static void LoadChatHistory(HWND hEdit, const char* text) {
    wchar_t* wtext = IsValidUtf8(text) ? Utf8ToWide(text) : AnsiToWide(text);
    const wchar_t* p = wtext;
    while (*p) {
        /* Skip leading whitespace/blank lines */
        while (*p == L'\r' || *p == L'\n') p++;
        if (!*p) break;

        /* Look for [HH:MM:SS] who: header */
        if (*p == L'[' &&
            p[1] >= L'0' && p[1] <= L'9' && p[2] >= L'0' && p[2] <= L'9' && p[3] == L':' &&
            p[4] >= L'0' && p[4] <= L'9' && p[5] >= L'0' && p[5] <= L'9' && p[6] == L':' &&
            p[7] >= L'0' && p[7] <= L'9' && p[8] >= L'0' && p[8] <= L'9' && p[9] == L']' &&
            p[10] == L' ') {
            const wchar_t* whoStart = p + 11;
            const wchar_t* colon = wcschr(whoStart, L':');
            if (colon) {
                int whoLen = (int)(colon - whoStart);
                if (whoLen > 0 && whoLen < 32) {
                    wchar_t who[32];
                    memcpy(who, whoStart, whoLen * sizeof(wchar_t));
                    who[whoLen] = 0;

                    const wchar_t* content = colon + 1;
                    while (*content == L'\r' || *content == L'\n') content++;

                    /* Find next message header or end of text */
                    const wchar_t* next = content;
                    while (*next) {
                        if (*next == L'[' &&
                            next[1] >= L'0' && next[1] <= L'9' && next[2] >= L'0' && next[2] <= L'9' && next[3] == L':' &&
                            next[4] >= L'0' && next[4] <= L'9' && next[5] >= L'0' && next[5] <= L'9' && next[6] == L':' &&
                            next[7] >= L'0' && next[7] <= L'9' && next[8] >= L'0' && next[8] <= L'9' && next[9] == L']' &&
                            next[10] == L' ') {
                            break;
                        }
                        next++;
                    }

                    int msgLen = (int)(next - content);
                    while (msgLen > 0 && (content[msgLen - 1] == L'\r' || content[msgLen - 1] == L'\n')) msgLen--;
                    if (msgLen > 0) {
                        char* msg = (char*)malloc(msgLen * 4 + 1);
                        if (msg) {
                            WideCharToMultiByte(CP_UTF8, 0, content, msgLen, msg, msgLen * 4 + 1, NULL, NULL);
                            msg[msgLen * 4] = 0;
                            if (wcscmp(who, L"You") == 0)
                                Chat_Append(hEdit, "You", msg);
                            else
                                Chat_AppendMarkdown(hEdit, "AI", msg);
                            free(msg);
                        }
                    }
                    p = next;
                    continue;
                }
            }
        }
        p++;
    }
    free(wtext);
}

/* save full conversation to per-task memory file (UTF-8) */
static void Chat_SaveMem(const char *memPath, HWND hHistory) {
    int len = GetWindowTextLengthW(hHistory);
    if (len <= 0) return;
    wchar_t *wtext = (wchar_t *)malloc((len + 1) * sizeof(wchar_t));
    if (!wtext) return;
    GetWindowTextW(hHistory, wtext, len + 1);
    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wtext, -1, NULL, 0, NULL, NULL);
    char *text = (char *)malloc(utf8Len);
    if (text) {
        WideCharToMultiByte(CP_UTF8, 0, wtext, -1, text, utf8Len, NULL, NULL);
        FILE *f = fopen(memPath, "w");
        if (f) { fputs(text, f); fclose(f); }
        free(text);
    }
    free(wtext);
}

static BOOL LogLineIsNotable(const char* line) {
    static const char* keywords[] = {
        "HIGH", "CONFIRMED", "INJECTION", "[ACTION]", "[AI-ACTION]",
        "[SUSPECT]", "[AI-FORENSICS]", "Critical object modified",
        "terminated system process", "Repeated kill", "quarantined", NULL
    };
    for (int i = 0; keywords[i]; i++) {
        if (strstr(line, keywords[i])) return TRUE;
    }
    return FALSE;
}

/* Read the daemon log for Global Chat. Prioritizes notable/security-relevant
   lines (HIGH, CONFIRMED, INJECTION, etc.) and fills the rest with recent lines. */
static void ReadRecentDaemonLog(char* out, int outSize, int maxLines) {
    out[0] = '\0';
    char path[MAX_PATH];
    build_path(path, sizeof(path), "data\\daemon.log");
    FILE* f = fopen(path, "rb");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz <= 0) { fclose(f); return; }
    long readSz = sz > 2 * 1024 * 1024 ? 2 * 1024 * 1024 : sz; /* up to 2 MB */
    char* buf = (char*)malloc(readSz + 1);
    if (!buf) { fclose(f); return; }
    fseek(f, sz - readSz, SEEK_SET);
    size_t n = fread(buf, 1, readSz, f);
    buf[n] = '\0';
    fclose(f);

    /* First pass: collect notable lines from the end of the file */
    char* lines[512];
    int lineCount = 0;
    char* p = buf;
    while (*p && lineCount < 512) {
        char* end = strchr(p, '\n');
        if (!end) end = p + strlen(p);
        int lineLen = (int)(end - p);
        if (lineLen > 0) {
            char* line = (char*)malloc(lineLen + 1);
            memcpy(line, p, lineLen);
            line[lineLen] = 0;
            lines[lineCount++] = line;
        }
        if (*end == '\n') p = end + 1; else break;
    }

    int used = 0;
    int o = 0;
    /* Notable lines in reverse chronological order */
    for (int i = lineCount - 1; i >= 0 && used < maxLines; i--) {
        if (LogLineIsNotable(lines[i])) {
            int l = (int)strlen(lines[i]);
            if (o + l + 2 < outSize) {
                memcpy(out + o, lines[i], l);
                o += l;
                out[o++] = '\r';
                out[o++] = '\n';
                out[o] = 0;
            }
            used++;
        }
    }
    /* Fill remaining slots with the most recent non-notable lines */
    for (int i = lineCount - 1; i >= 0 && used < maxLines; i--) {
        if (!LogLineIsNotable(lines[i])) {
            int l = (int)strlen(lines[i]);
            if (o + l + 2 < outSize) {
                memcpy(out + o, lines[i], l);
                o += l;
                out[o++] = '\r';
                out[o++] = '\n';
                out[o] = 0;
            }
            used++;
        }
    }

    for (int i = 0; i < lineCount; i++) free(lines[i]);
    free(buf);
}

/* forward declaration — defined after AskDlgProc */
static int winhttp_ask_ai(const char *apiKey, const char *systemPrompt,
    const char *userPrompt, const char *model, char *result, int resultSize);

static INT_PTR CALLBACK ChatDlgProc(HWND hDlg, UINT msg, WPARAM w, LPARAM l) {
    ChatData *cd = (ChatData *)GetWindowLongPtr(hDlg, GWLP_USERDATA);
    switch (msg) {
        case WM_INITDIALOG: {
            static BOOL s_richEditLoaded = FALSE;
            if (!s_richEditLoaded) {
                LoadLibraryW(L"riched20.dll");
                s_richEditLoaded = TRUE;
            }
            cd = (ChatData *)l;
            SetWindowLongPtr(hDlg, GWLP_USERDATA, (LONG_PTR)cd);
            cd->hHistory = GetDlgItem(hDlg, IDC_CHAT_OUTPUT);
            cd->hInput   = GetDlgItem(hDlg, IDC_CHAT_INPUT);

            /* Title and memory path depend on global vs task-specific mode */
            char title[320];
            if (cd->taskId[0]) {
                snprintf(title, sizeof(title), "Task: %s", cd->taskName);
                snprintf(cd->memPath, sizeof(cd->memPath),
                         "data\\ai_memory\\task_%s.log", cd->taskId);
            } else {
                snprintf(title, sizeof(title), "Global AI Chat");
                snprintf(cd->memPath, sizeof(cd->memPath),
                         "data\\ai_memory\\global_chat.md");
            }
            SetWindowTextA(GetDlgItem(hDlg, IDC_CHAT_TITLE), title);

            /* Load existing chat history; trim if it grew too large */
            long sz = 0;
            char path[MAX_PATH];
            build_path(path, sizeof(path), cd->memPath);
            char *prev = slurp(path, &sz);
            if (prev) {
                const long MAX_MEM = 100000; /* ~100 KB */
                if (sz > MAX_MEM) {
                    char *keep = prev + sz - MAX_MEM;
                    char *newline = strchr(keep, '\n');
                    if (newline) keep = newline + 1;
                    LoadChatHistory(cd->hHistory, keep);
                } else {
                    LoadChatHistory(cd->hHistory, prev);
                }
                free(prev);
            }

            /* Center on parent */
            HWND parent = GetParent(hDlg);
            if (parent) {
                RECT pr, dr;
                GetWindowRect(parent, &pr);
                GetWindowRect(hDlg, &dr);
                int ww = dr.right - dr.left, wh = dr.bottom - dr.top;
                SetWindowPos(hDlg, HWND_TOP,
                    pr.left + ((pr.right-pr.left)-ww)/2,
                    pr.top  + ((pr.bottom-pr.top)-wh)/2,
                    0, 0, SWP_NOSIZE | SWP_NOZORDER);
            }
            /* Set focus to input */
            SetFocus(cd->hInput);
            return FALSE; /* let system set focus */
        }
        case WM_COMMAND:
            if (LOWORD(w) == IDC_CHAT_SEND) {
                wchar_t wq[4096] = L"";
                GetWindowTextW(cd->hInput, wq, sizeof(wq)/sizeof(wq[0]));
                if (!wq[0]) break;
                char* q = WideToUtf8(wq);

                /* Append user message to history */
                Chat_Append(cd->hHistory, "You", q);
                SetWindowTextW(cd->hInput, L"");

                /* Read knowledge base (always) and SOUL.md (task chats only) */
                char soul[8192] = "";
                if (cd->taskId[0]) {
                    char soulPath[MAX_PATH];
                    build_path(soulPath, sizeof(soulPath), AI_MEMORY_ROOT "\\SOUL.md");
                    FILE *soulF = fopen(soulPath, "rb");
                    if (soulF) { fread(soul, 1, sizeof(soul)-1, soulF); fclose(soulF); }
                }

                char knowledge[16384] = "";
                char knowPath[MAX_PATH];
                build_path(knowPath, sizeof(knowPath), AI_MEMORY_ROOT "\\ai_knowledge.md");
                FILE *knowF = fopen(knowPath, "rb");
                if (knowF) { fread(knowledge, 1, sizeof(knowledge)-1, knowF); fclose(knowF); }

                /* Build combined system prompt */
                char systemPrompt[65536];
                if (cd->taskId[0]) {
                    snprintf(systemPrompt, sizeof(systemPrompt),
        "You are a helpful security analyst helping the user with a specific protection task. "
        "Use the daemon context below only when it is relevant to the user's question. "
        "Do NOT introduce yourself, explain your role, or list generic responsibilities. "
        "Answer directly and concisely. Use Markdown formatting.\n\n"
        "Daemon context (SOUL.md):\n%s\n\n"
        "Daemon experience base (ai_knowledge.md):\n%s\n\n"
        "CRITICAL: This is a natural-language chat. NEVER output JSON. "
        "Use only plain ASCII characters: standard quotes ' and \", plain hyphens - for lists, no smart quotes, no emojis, no fancy Unicode symbols. "
        "Do not include any code block containing JSON. Answer in plain English Markdown only.",
        soul, knowledge);
                } else {
                    snprintf(systemPrompt, sizeof(systemPrompt),
        "You are a helpful security analyst having a casual chat with the user. "
        "You have access to the daemon's experience base below. "
        "Do NOT introduce yourself, explain your role, or list generic responsibilities. "
        "Focus on the user's actual question and answer it directly, like a normal conversation. "
        "If the user refers to 'the aggressive Alibaba process' or similar, they mean AlibabaProtect.exe from the knowledge base. "
        "Use Markdown formatting (headings, bold, lists) only when it helps readability. "
        "For known PUPs, give a clear recommendation but ask the user before any cleanup.\n\n"
        "Daemon experience base (ai_knowledge.md):\n%s\n\n"
        "CRITICAL: This is a natural-language chat. NEVER output JSON. "
        "Use only plain ASCII characters: standard quotes ' and \", plain hyphens - for lists, no smart quotes, no emojis, no fancy Unicode symbols. "
        "Do not include any code block containing JSON. Answer in plain English Markdown only.",
        knowledge);
                }

                /* Read existing memory as context */
                char memBuf[16384] = "";
                {
                    long msz = 0;
                    char mpath[MAX_PATH];
                    build_path(mpath, sizeof(mpath), cd->memPath);
                    char *pmem = slurp(mpath, &msz);
                    if (pmem) {
                        int copy = msz > 16383 ? 16383 : (int)msz;
                        memcpy(memBuf, pmem, copy);
                        memBuf[copy] = '\0';
                        free(pmem);
                    }
                }

                /* Show typing indicator. Remember where the user message ends
                   so we can replace the "(thinking...)" placeholder cleanly. */
                int baseLen = GetWindowTextLengthW(cd->hHistory);
                Chat_Append(cd->hHistory, "AI", "(thinking...)");

                /* Build composite prompt */
                char userPrompt[131072];
                if (cd->taskId[0]) {
                    snprintf(userPrompt, sizeof(userPrompt),
                        "Task: %s (ID: %s)\n\n"
                        "Details: %s\n\n"
                        "Previous conversation:\n%s\n\n"
                        "User: %s\n\n"
                        "Respond in English with a detailed analysis. When asked about a suspicious event, "
                        "identify the process, its purpose, its publisher/signature, and recommend HIGH/CONFIRMED "
                        "if you believe it is malicious. Provide clear reasoning.",
                        cd->taskName, cd->taskId,
                        cd->taskJson[0] ? cd->taskJson : "(none)",
                        memBuf[0] ? memBuf : "(no previous conversation)",
                        q);
                } else {
                    /* Global AI chat: include recent daemon log */
                    char logSummary[32768] = "";
                    ReadRecentDaemonLog(logSummary, sizeof(logSummary), 80);
                    snprintf(userPrompt, sizeof(userPrompt),
                        "User question: %s\n\n"
                        "Recent daemon log summary (last 80 lines):\n%s\n\n"
                        "Previous conversation:\n%s\n\n"
                        "Answer the user's question directly in natural English. "
                        "Use Markdown formatting. Do NOT output JSON.",
                        q,
                        logSummary[0] ? logSummary : "(no recent log entries)",
                        memBuf[0] ? memBuf : "(no previous conversation)");
                }

                /* Launch AI request in a background thread so the UI stays responsive */
                AiThreadData* td = (AiThreadData*)malloc(sizeof(AiThreadData));
                if (td) {
                    td->hDlg = hDlg;
                    strncpy(td->apiKey, cd->apiKey, sizeof(td->apiKey) - 1);
                    td->apiKey[sizeof(td->apiKey) - 1] = '\0';
                    strncpy(td->model, cd->model, sizeof(td->model) - 1);
                    td->model[sizeof(td->model) - 1] = '\0';
                    strncpy(td->systemPrompt, systemPrompt, sizeof(td->systemPrompt) - 1);
                    td->systemPrompt[sizeof(td->systemPrompt) - 1] = '\0';
                    strncpy(td->userPrompt, userPrompt, sizeof(td->userPrompt) - 1);
                    td->userPrompt[sizeof(td->userPrompt) - 1] = '\0';
                    td->baseLen = baseLen;
                    EnableWindow(cd->hInput, FALSE);
                    EnableWindow(GetDlgItem(hDlg, IDC_CHAT_SEND), FALSE);
                    HANDLE hThread = CreateThread(NULL, 0, AiRequestThread, td, 0, NULL);
                    if (hThread) CloseHandle(hThread);
                }
                free(q);
            } else if (LOWORD(w) == IDC_CHAT_CLEAR) {
                SetWindowTextW(cd->hHistory, L"");
                SetWindowTextW(cd->hInput, L"");
                /* Also clear the file */
                char mpath[MAX_PATH];
                build_path(mpath, sizeof(mpath), cd->memPath);
                FILE *f = fopen(mpath, "w");
                if (f) fclose(f);
            } else if (LOWORD(w) == IDC_CHAT_CLOSE) {
                EndDialog(hDlg, 0);
            }
            break;
        case WM_APP + 1: {
            /* AI request completed in background thread; wParam = response string */
            char *resp = (char *)w;
            if (cd && resp) {
                int baseLen = (int)l;
                int curLen = GetWindowTextLengthW(cd->hHistory);
                /* Remove the "(thinking...)" placeholder and any following content */
                if (baseLen >= 0 && baseLen <= curLen) {
                    SendMessageW(cd->hHistory, EM_SETSEL, baseLen, curLen);
                    SendMessageW(cd->hHistory, EM_REPLACESEL, FALSE, (LPARAM)L"");
                }
                Chat_AppendMarkdown(cd->hHistory, "AI", resp);
                free(resp);
                EnableWindow(cd->hInput, TRUE);
                EnableWindow(GetDlgItem(hDlg, IDC_CHAT_SEND), TRUE);
                SetFocus(cd->hInput);
                {
                    char mpath[MAX_PATH];
                    build_path(mpath, sizeof(mpath), cd->memPath);
                    Chat_SaveMem(mpath, cd->hHistory);
                }
            }
            break;
        }
    }
    return FALSE;
}

void GuiAi_OpenNewTask(HWND hParent, const char *type, const char *name,
                       int pid, int tree) {
    DlgData *d = (DlgData *)calloc(1, sizeof(DlgData));
    if (type && name && name[0]) {
        int t = 1;
        if      (!_stricmp(type, "service"))   t = 2;
        else if (!_stricmp(type, "registry"))  t = 3;
        else if (!_stricmp(type, "partition")) t = 4;
        strncpy(d->targets[0], name, 259);
        d->targetType[0] = t;
        d->targetTree[0] = tree;
        d->targetPid[0]  = pid;
        d->targetN = 1;
        d->cameFromRightClick = 1;
    }
    INT_PTR r = DialogBoxParam(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_NEW_TASK),
        hParent, NewTaskDlgProc, (LPARAM)d);
    if (r == IDOK) {
        MessageBoxA(hParent,
            "AI Monitor Task saved.\n\n"
            "Click 'Ask AI' on toolbar to view tasks and talk to AI.\n"
            "Check the  notification bell for recent activity.",
            "Process Guardian", MB_OK | MB_ICONINFORMATION);
    }
    free(d);
}

void GuiAi_OpenEditTask(HWND hParent, const char *taskId) {
    if (!taskId || !taskId[0]) return;
    DlgData *d = (DlgData *)calloc(1, sizeof(DlgData));
    strncpy(d->editId, taskId, sizeof(d->editId) - 1);
    DialogBoxParam(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_NEW_TASK),
        hParent, NewTaskDlgProc, (LPARAM)d);
    free(d);
}

/* =====================================================================
 *  Ask AI dialog (ID 300). Shows task list, "Talk with AI" for selected task.
 * ===================================================================== */
#include <winhttp.h>

typedef struct {
    HWND hModel, hTaskList;
    char model[128];
    char selectedTaskId[64];
    char selectedTaskJson[16384];
} AskData;

/* Direct API call for Ask AI (without guardiand/ai_client.dll) */
static char *winhttp_json_escape(const char *src)
{
    if (!src) return NULL;
    int slen = (int)strlen(src);
    char *dst = (char *)malloc(slen * 2 + 4);
    if (!dst) return NULL;
    int di = 0;
    for (int i = 0; i < slen; i++) {
        unsigned char c = (unsigned char)src[i];
        switch (c) {
            case '"':  dst[di++] = '\\'; dst[di++] = '"';  break;
            case '\\': dst[di++] = '\\'; dst[di++] = '\\'; break;
            case '\n': dst[di++] = '\\'; dst[di++] = 'n';  break;
            case '\r': dst[di++] = '\\'; dst[di++] = 'r';  break;
            case '\t': dst[di++] = '\\'; dst[di++] = 't';  break;
            default:
                if (c < 0x20) { di += snprintf(dst + di, 8, "\\u%04x", c); }
                else { dst[di++] = c; }
                break;
        }
    }
    dst[di] = '\0';
    return dst;
}

static int winhttp_ask_ai(const char *apiKey, const char *systemPrompt,
    const char *userPrompt, const char *model, char *result, int resultSize)
{
    HINTERNET hSess = WinHttpOpen(L"AskAI/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) { snprintf(result, resultSize, "ERROR: WinHttpOpen failed"); return -1; }

    HINTERNET hConn = WinHttpConnect(hSess, L"api.siliconflow.cn", 443, 0);
    if (!hConn) { WinHttpCloseHandle(hSess); snprintf(result, resultSize, "ERROR: WinHttpConnect failed"); return -1; }

    HINTERNET hReq = WinHttpOpenRequest(hConn, L"POST", L"/v1/chat/completions",
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hReq) { WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
        snprintf(result, resultSize, "ERROR: WinHttpOpenRequest failed"); return -1; }

    /* Set generous timeouts for AI inference (can take 10-60s) */
    {
        DWORD connectTimeout = 30000; /* 30s to connect */
        DWORD sendTimeout    = 60000; /* 60s to send body */
        DWORD recvTimeout    = 600000; /* 600s to receive response (AI generation) */
        WinHttpSetOption(hReq, WINHTTP_OPTION_CONNECT_TIMEOUT, &connectTimeout, sizeof(connectTimeout));
        WinHttpSetOption(hReq, WINHTTP_OPTION_SEND_TIMEOUT,    &sendTimeout,    sizeof(sendTimeout));
        WinHttpSetOption(hReq, WINHTTP_OPTION_RECEIVE_TIMEOUT, &recvTimeout,    sizeof(recvTimeout));
    }

    char *escUser = winhttp_json_escape(userPrompt ? userPrompt : "");
    char *escSys = (systemPrompt && systemPrompt[0]) ? winhttp_json_escape(systemPrompt) : NULL;

    int bodySize = 524288;
    char *body = (char *)malloc(bodySize);
    if (escSys) {
        snprintf(body, bodySize,
            "{\"model\":\"%s\",\"messages\":["
            "{\"role\":\"system\",\"content\":\"%s\"},"
            "{\"role\":\"user\",\"content\":\"%s\"}"
            "],\"temperature\":0.7}", model, escSys, escUser);
    } else {
        snprintf(body, bodySize,
            "{\"model\":\"%s\",\"messages\":["
            "{\"role\":\"user\",\"content\":\"%s\"}"
            "],\"temperature\":0.7}", model, escUser);
    }
    free(escUser); if (escSys) free(escSys);

    /* Build auth header safely — avoid wsprintfW %%S ambiguity */
    char authHdr[600];
    int authLen = snprintf(authHdr, sizeof(authHdr),
        "Authorization: Bearer %s", apiKey);
    if (authLen < 0 || authLen >= (int)sizeof(authHdr)) {
        free(body); WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
        snprintf(result, resultSize, "ERROR: auth header too long"); return -1;
    }

    /* Convert narrow headers to wide */
    wchar_t ctype[] = L"Content-Type: application/json\r\n";
    wchar_t wauth[600];
    int wlen = MultiByteToWideChar(CP_UTF8, 0, authHdr, -1, wauth, 600);
    if (wlen <= 0) {
        free(body); WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
        snprintf(result, resultSize, "ERROR: wide-char conversion failed"); return -1;
    }

    WinHttpAddRequestHeaders(hReq, ctype, -1, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    WinHttpAddRequestHeaders(hReq, wauth, -1, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

    DWORD bodyLen = (DWORD)strlen(body);
    if (!WinHttpSendRequest(hReq, NULL, 0, (LPVOID)body, bodyLen, bodyLen, 0)) {
        DWORD err = GetLastError();
        free(body); WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
        snprintf(result, resultSize, "ERROR: SendRequest failed (err=%lu)", err); return -1;
    }
    free(body);

    if (!WinHttpReceiveResponse(hReq, NULL)) {
        DWORD err = GetLastError();
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
        snprintf(result, resultSize, "ERROR: ReceiveResponse failed (err=%lu)", (unsigned long)err); return -1;
    }

    /* Read HTTP status code to diagnose errors */
    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(hReq,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize,
        WINHTTP_NO_HEADER_INDEX);

    if (statusCode != 200) {
        /* Read error body for diagnostics */
        DWORD avail2 = 0, total2 = 0;
        char errBody[4096] = "";
        while (WinHttpQueryDataAvailable(hReq, &avail2) && avail2 > 0) {
            if (total2 + avail2 >= sizeof(errBody) - 1) break;
            DWORD read2 = 0;
            if (!WinHttpReadData(hReq, errBody + total2, avail2, &read2)) break;
            total2 += read2;
        }
        errBody[total2] = '\0';
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
        snprintf(result, resultSize,
            "ERROR: HTTP %lu  %s",
            (unsigned long)statusCode,
            errBody[0] ? errBody : "(no body)");
        return -1;
    }

    DWORD avail = 0, total = 0;
    char *resp = (char *)malloc(262144);
    if (!resp) { WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess); return -1; }

    while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
        if (total + avail >= 262144) break;
        DWORD read = 0;
        if (!WinHttpReadData(hReq, resp + total, avail, &read)) break;
        total += read;
    }
    resp[total] = '\0';

    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);

    /* Extract content */
    const char *c = strstr(resp, "\"content\":\"");
    if (c) {
        c += 11;
        const char *end = c;
        int esc = 0;
        while (*end) {
            if (esc) { esc = 0; end++; continue; }
            if (*end == '\\') { esc = 1; end++; continue; }
            if (*end == '"') break;
            end++;
        }
        int clen = (int)(end - c);
        int di = 0; esc = 0;
        for (int i = 0; i < clen && di < resultSize - 1; i++) {
            if (esc) {
                switch (c[i]) {
                    case 'n': result[di++] = '\n'; break;
                    case 'r': result[di++] = '\r'; break;
                    case 't': result[di++] = '\t'; break;
                    default: result[di++] = c[i]; break;
                }
                esc = 0;
            } else if (c[i] == '\\') { esc = 1; }
            else { result[di++] = c[i]; }
        }
        result[di] = '\0';
        free(resp);
        return di;
    }
    /* Fallback: return raw */
    strncpy(result, resp, resultSize - 1);
    result[resultSize - 1] = '\0';
    free(resp);
    return (int)strlen(result);
}

static DWORD WINAPI AiRequestThread(LPVOID lpParam)
{
    AiThreadData* td = (AiThreadData*)lpParam;
    char* resp = (char*)malloc(524288);
    if (!resp) {
        char* err = _strdup("ERROR: out of memory");
        PostMessage(td->hDlg, WM_APP + 1, (WPARAM)err, (LPARAM)td->baseLen);
        free(td);
        return 0;
    }
    resp[0] = '\0';
    winhttp_ask_ai(td->apiKey, td->systemPrompt, td->userPrompt, td->model, resp, 524288);
    char* result = _strdup(resp);
    free(resp);
    PostMessage(td->hDlg, WM_APP + 1, (WPARAM)result, (LPARAM)td->baseLen);
    free(td);
    return 0;
}

/* Public wrapper — callable from Qt frontend (in a worker thread) */
int GuiAi_AskApi(const char *apiKey, const char *systemPrompt,
                 const char *userPrompt, const char *model,
                 char *result, int resultSize) {
    return winhttp_ask_ai(apiKey, systemPrompt, userPrompt, model, result, resultSize);
}

/* Public wrapper — load API key (decrypt from file) */
int GuiAi_LoadApiKey(char *out, int out_sz) {
    return load_api_key(out, out_sz);
}

/* Refresh task list in Ask AI dialog */
static void AskDlg_RefreshTaskList(HWND hList)
{
    ListView_DeleteAllItems(hList);
    while (Header_GetItemCount(ListView_GetHeader(hList)) > 0)
        SendMessageA(hList, LVM_DELETECOLUMN, 0, 0);

    LVCOLUMNA col = {0};
    col.mask = LVCF_TEXT | LVCF_WIDTH;
    col.pszText = (LPSTR)"ID"; col.cx = 200;
    SendMessageA(hList, LVM_INSERTCOLUMNA, 0, (LPARAM)&col);
    col.pszText = (LPSTR)"Name"; col.cx = 150;
    SendMessageA(hList, LVM_INSERTCOLUMNA, 1, (LPARAM)&col);
    col.pszText = (LPSTR)"Targets"; col.cx = 80;
    SendMessageA(hList, LVM_INSERTCOLUMNA, 2, (LPARAM)&col);
    col.pszText = (LPSTR)"Status"; col.cx = 80;
    SendMessageA(hList, LVM_INSERTCOLUMNA, 3, (LPARAM)&col);

    char path[MAX_PATH];
    build_path(path, sizeof(path), AI_TASKS_JSON);
    long sz; char *buf = slurp(path, &sz);
    if (!buf) return;

    const char *b = strstr(buf, "\"tasks\"");
    if (!b) { free(buf); return; }
    b = strchr(b, '[');
    if (!b) { free(buf); return; }
    b++;

    int row = 0;
    while (*b && row < 1000) {
        while (*b == ' ' || *b == ',' || *b == '\n' || *b == '\r' || *b == '\t') b++;
        if (*b == ']' || *b == '\0') break;
        if (*b != '{') { b++; continue; }
        const char *start = b;
        int depth = 1; b++;
        while (*b && depth > 0) { if (*b == '{') depth++; else if (*b == '}') depth--; b++; }
        int len = (int)(b - start);
        char obj[8192];
        if (len > 8191) len = 8191;
        memcpy(obj, start, len); obj[len] = '\0';

        /* Extract fields */
        char id[128] = "", name[256] = "", status[64] = "pending";
        int targetCount = 0;
        const char *p = obj;
        while ((p = strchr(p, '"'))) {
            p++;
            char k[64]; int ki = 0;
            while (*p && *p != '"') k[ki++] = *p++;
            if (*p == '"') p++;
            while (*p == ' ' || *p == ':') p++;
            if (!strcmp(k, "id")) { int xi = 0; if (*p == '"') p++; while (*p && *p != '"' && xi < 127) id[xi++] = *p++; id[xi] = 0; }
            else if (!strcmp(k, "name")) { int xi = 0; if (*p == '"') p++; while (*p && *p != '"' && xi < 255) name[xi++] = *p++; name[xi] = 0; }
            else if (!strcmp(k, "status")) { int xi = 0; if (*p == '"') p++; while (*p && *p != '"' && xi < 63) status[xi++] = *p++; status[xi] = 0; }
            else if (!strcmp(k, "targets") && *p == '[') { p++; while (*p && *p != ']') { if (*p == '{') targetCount++; p++; } }
        }

        LVITEMA it = {0};
        it.mask = LVIF_TEXT;
        it.iItem = row;
        it.pszText = id;
        SendMessageA(hList, LVM_INSERTITEMA, 0, (LPARAM)&it);
        { LVITEMA s = {0}; s.mask = LVIF_TEXT; s.iItem = row; s.iSubItem = 1; s.pszText = name;
          SendMessageA(hList, LVM_SETITEMTEXTA, row, (LPARAM)&s); }
        char tc[32]; snprintf(tc, sizeof(tc), "%d", targetCount);
        { LVITEMA s = {0}; s.mask = LVIF_TEXT; s.iItem = row; s.iSubItem = 2; s.pszText = tc;
          SendMessageA(hList, LVM_SETITEMTEXTA, row, (LPARAM)&s); }
        { LVITEMA s = {0}; s.mask = LVIF_TEXT; s.iItem = row; s.iSubItem = 3; s.pszText = status;
          SendMessageA(hList, LVM_SETITEMTEXTA, row, (LPARAM)&s); }
        row++;
    }
    free(buf);
}

static INT_PTR CALLBACK AskDlgProc(HWND hDlg, UINT msg, WPARAM w, LPARAM l) {
    AskData *d = (AskData *)GetWindowLongPtr(hDlg, GWLP_USERDATA);
    switch (msg) {
        case WM_INITDIALOG: {
            SetWindowTextW(hDlg, L"Ask AI - Process Guardian");
            d = (AskData *)l;
            SetWindowLongPtr(hDlg, GWLP_USERDATA, (LONG_PTR)d);
            d->hModel    = GetDlgItem(hDlg, 9303);
            d->hTaskList = GetDlgItem(hDlg, 9315);
            d->selectedTaskId[0] = '\0';
            d->selectedTaskJson[0] = '\0';
            strncpy(d->model, "deepseek-ai/DeepSeek-R1-0528-Qwen3-8B", sizeof(d->model)-1);
            SetWindowTextA(d->hModel, d->model);

            /* Setup task list */
            SendMessageA(d->hTaskList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT);
            AskDlg_RefreshTaskList(d->hTaskList);

            /* Disable action buttons until a task is selected */
            EnableWindow(GetDlgItem(hDlg, IDC_AI_TALK), FALSE);
            EnableWindow(GetDlgItem(hDlg, IDC_AI_EDIT), FALSE);
            EnableWindow(GetDlgItem(hDlg, IDC_AI_DELETE), FALSE);

            /* Check API key silently */
            char k[256] = "";
            if (load_api_key(k, sizeof(k)) != 0) {
                prompt_for_api_key(hDlg);
            }
            return TRUE;
        }
        case WM_NOTIFY: {
            NMHDR *nm = (NMHDR *)l;
            if (nm->idFrom == 9315 && nm->code == LVN_ITEMCHANGED) {
                NMLISTVIEW *nlv = (NMLISTVIEW *)l;
                if (nlv->uNewState & LVIS_SELECTED) {
                    char id[128] = "";
                    LVITEMA it = {0};
                    it.mask = LVIF_TEXT; it.iItem = nlv->iItem; it.pszText = id; it.cchTextMax = sizeof(id);
                    SendMessageA(d->hTaskList, LVM_GETITEMTEXTA, nlv->iItem, (LPARAM)&it);
                    strncpy(d->selectedTaskId, id, sizeof(d->selectedTaskId)-1);

                    char path[MAX_PATH];
                    build_path(path, sizeof(path), AI_TASKS_JSON);
                    find_task_json(path, id, d->selectedTaskJson, sizeof(d->selectedTaskJson));

                    EnableWindow(GetDlgItem(hDlg, IDC_AI_TALK), TRUE);
                    EnableWindow(GetDlgItem(hDlg, IDC_AI_EDIT), TRUE);
                    EnableWindow(GetDlgItem(hDlg, IDC_AI_DELETE), TRUE);
                } else if (nlv->uNewState == 0 && nlv->iItem >= 0) {
                    int sel = (int)SendMessageA(d->hTaskList, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
                    if (sel < 0) {
                        d->selectedTaskId[0] = '\0';
                        d->selectedTaskJson[0] = '\0';
                        EnableWindow(GetDlgItem(hDlg, IDC_AI_TALK), FALSE);
                        EnableWindow(GetDlgItem(hDlg, IDC_AI_EDIT), FALSE);
                        EnableWindow(GetDlgItem(hDlg, IDC_AI_DELETE), FALSE);
                    }
                }
            }
            break;
        }
        case WM_COMMAND:
            if (LOWORD(w) == IDC_AI_TALK) { /* Talk with AI -> open chat dialog */
                if (!d->selectedTaskId[0]) break;
                char apiKey[256] = "";
                if (load_api_key(apiKey, sizeof(apiKey)) != 0) {
                    if (prompt_for_api_key(hDlg) != 0) break;
                    if (load_api_key(apiKey, sizeof(apiKey)) != 0) break;
                }
                /* Get task name from list */
                char tname[256] = "unknown";
                int sel = (int)SendMessageA(d->hTaskList, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
                if (sel >= 0) {
                    LVITEMA it = {0};
                    it.mask = LVIF_TEXT; it.iItem = sel; it.iSubItem = 1;
                    it.pszText = tname; it.cchTextMax = sizeof(tname);
                    SendMessageA(d->hTaskList, LVM_GETITEMTEXTA, sel, (LPARAM)&it);
                }
                ChatData cd = {0};
                strncpy(cd.taskName, tname, sizeof(cd.taskName)-1);
                strncpy(cd.taskId, d->selectedTaskId, sizeof(cd.taskId)-1);
                strncpy(cd.taskJson, d->selectedTaskJson, sizeof(cd.taskJson)-1);
                strncpy(cd.apiKey, apiKey, sizeof(cd.apiKey)-1);
                strncpy(cd.model, d->model, sizeof(cd.model)-1);
                DialogBoxParam(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_ASK_CHAT),
                    hDlg, ChatDlgProc, (LPARAM)&cd);
            } else if (LOWORD(w) == IDC_AI_EDIT) { /* Edit selected task */
                if (!d->selectedTaskId[0]) break;
                GuiAi_OpenEditTask(hDlg, d->selectedTaskId);
                AskDlg_RefreshTaskList(d->hTaskList);
            } else if (LOWORD(w) == IDC_AI_REFRESH) { /* Refresh task list */
                AskDlg_RefreshTaskList(d->hTaskList);
                d->selectedTaskId[0] = '\0';
                d->selectedTaskJson[0] = '\0';
                EnableWindow(GetDlgItem(hDlg, IDC_AI_TALK), FALSE);
                EnableWindow(GetDlgItem(hDlg, IDC_AI_EDIT), FALSE);
                EnableWindow(GetDlgItem(hDlg, IDC_AI_DELETE), FALSE);
            } else if (LOWORD(w) == IDC_AI_DELETE) { /* Delete selected task */
                if (!d->selectedTaskId[0]) break;
                char delMsg[512];
                snprintf(delMsg, sizeof(delMsg),
                    "Delete this AI monitor task?\n\nTask ID: %s\n\nThis cannot be undone.",
                    d->selectedTaskId);
                int ret = MessageBoxA(hDlg, delMsg, "Confirm Delete", MB_YESNO | MB_ICONWARNING);
                if (ret == IDYES) {
                    char path[MAX_PATH];
                    build_path(path, sizeof(path), AI_TASKS_JSON);
                    if (remove_task(path, d->selectedTaskId) == 0) {
                        write_notification("task_deleted", d->selectedTaskId,
                            d->selectedTaskId, "\344\273\273\345\212\241\345\267\262\345\210\240\351\231\244");
                        AskDlg_RefreshTaskList(d->hTaskList);
                        d->selectedTaskId[0] = '\0';
                        d->selectedTaskJson[0] = '\0';
                        EnableWindow(GetDlgItem(hDlg, IDC_AI_TALK), FALSE);
                        EnableWindow(GetDlgItem(hDlg, IDC_AI_EDIT), FALSE);
                        EnableWindow(GetDlgItem(hDlg, IDC_AI_DELETE), FALSE);
                    }
                }
            } else if (LOWORD(w) == IDC_AI_CHANGE_KEY) { /* Change API key */
                prompt_for_api_key(hDlg);
            } else if (LOWORD(w) == IDC_AI_GLOBAL_CHAT) { /* Global AI chat */
                char apiKey[256] = "";
                if (load_api_key(apiKey, sizeof(apiKey)) != 0) {
                    if (prompt_for_api_key(hDlg) != 0) break;
                    if (load_api_key(apiKey, sizeof(apiKey)) != 0) break;
                }
                ChatData cd = {0};
                cd.taskName[0] = '\0';
                cd.taskId[0] = '\0';
                cd.taskJson[0] = '\0';
                strncpy(cd.apiKey, apiKey, sizeof(cd.apiKey)-1);
                strncpy(cd.model, d->model, sizeof(cd.model)-1);
                DialogBoxParam(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_ASK_CHAT),
                    hDlg, ChatDlgProc, (LPARAM)&cd);
            } else if (LOWORD(w) == IDCANCEL) { /* Close / ESC */
                EndDialog(hDlg, IDCANCEL);
            }
            break;
    }
    return FALSE;
}

void GuiAi_OpenAskAiDialog(HWND hParent) {
    AskData *d = (AskData *)calloc(1, sizeof(AskData));
    DialogBoxParam(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_ASK_AI), hParent,
        AskDlgProc, (LPARAM)d);
    free(d);
}

/* ---- task_admin launcher (used by "Ask AI" toolbar button) ----
 * Finds task_admin.exe in the same directory as process_guardian.exe
 * and launches it. The launched program auto-opens the browser.
 * If a task_admin.exe is already running, it is detected via the
 * data\ai_tasks.json lock probe and we just open the URL. */
void GuiAi_LaunchTaskAdmin(HWND hParent) {
    char dir[MAX_PATH], exe[MAX_PATH];
    exe_dir(dir, sizeof(dir));
    snprintf(exe, sizeof(exe), "%s\\task_admin.exe", dir);
    /* Tell user what we're doing so the lack of a browser popup is not mysterious. */
    char msg[600];
    DWORD attr = GetFileAttributesA(exe);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        snprintf(msg, sizeof(msg),
            "task_admin.exe not found:\n%s\n\n"
            "Build it with:\n  g++ -O2 -static -mwindows -o task_admin.exe task_admin.cpp -lws2_32 -lshell32\n"
            "(see ai\\task_admin\\task_admin.cpp)",
            exe);
        MessageBoxA(hParent, msg, "Process Guardian", MB_ICONWARNING);
        return;
    }
    /* Avoid double-launching: check if a task_admin is already running on
     * a localhost port. Quick probe: try to connect to a few ephemeral
     * ports that task_admin would have chosen is impractical, so we just
     * try a single lock-probe on data\ai_tasks.json — task_admin opens it
     * for read. We use a short-lived share-read probe via CreateFileA. */
    HANDLE hProbe = CreateFileA("data\\ai_tasks.json",
        GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hProbe != INVALID_HANDLE_VALUE) CloseHandle(hProbe);
    /* Always relaunch: task_admin's WinMain opens a browser. Cheap to
     * double-launch — browser tab opens twice, but that's acceptable.
     * Use ShellExecuteA with "open" so file association isn't used. */
    HINSTANCE h = ShellExecuteA(hParent, "open", exe, NULL, dir, SW_SHOWNORMAL);
    if ((INT_PTR)h <= 32) {
        snprintf(msg, sizeof(msg),
            "Failed to start task_admin.exe (ShellExecute returned %d).\n"
            "Try running it manually from:\n%s", (int)(INT_PTR)h, dir);
        MessageBoxA(hParent, msg, "Process Guardian", MB_ICONERROR);
    }
}

/* ---- main dispatcher ----
 * Returns 1 if the message was consumed by AI subsystem, 0 otherwise. */
int GuiAi_HandleCommand(HWND hWnd, int id, WPARAM wParam, LPARAM lParam) {
    (void)wParam;
    /* ID 2008 is the "Ask AI" toolbar button. Opens the native Ask AI dialog
     * with task list, Talk with AI, and direct chat. */
    if (id == 2008) { GuiAi_OpenAskAiDialog(hWnd); return 1; }
    return 0;
}
