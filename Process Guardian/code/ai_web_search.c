/* ai_web_search.c - lightweight web search DLL for Process Guardian AI
 * Searches DuckDuckGo HTML and returns a plain-text summary of top results.
 */

#define BUILD_AI_WEB_SEARCH_DLL
#include "ai_web_search.h"

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#pragma comment(lib, "winhttp.lib")

#define MAX_URL 4096
#define MAX_BODY (512 * 1024)
#define RESULT_LIMIT 5

/* Release build: no debug logging. Set to 1 to enable diagnostic logs. */
#define WS_LOG_ENABLED 0

#if WS_LOG_ENABLED
static void ws_log(const char* fmt, ...) {
    FILE* f = fopen("C:\\tmp\\web_search_debug.log", "a");
    if (!f) return;
    time_t now = time(NULL);
    struct tm* tm = localtime(&now);
    fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] ", tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
            tm->tm_hour, tm->tm_min, tm->tm_sec);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fprintf(f, "\n");
    fclose(f);
}
#else
#define ws_log(...) ((void)0)
#endif

static void url_encode(const char* in, char* out, int outSz) {
    const char hex[] = "0123456789ABCDEF";
    int i = 0, j = 0;
    while (in[i] && j < outSz - 4) {
        unsigned char c = (unsigned char)in[i];
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out[j++] = c;
        } else if (c == ' ') {
            out[j++] = '+';
        } else {
            out[j++] = '%';
            out[j++] = hex[c >> 4];
            out[j++] = hex[c & 0xF];
        }
        i++;
    }
    out[j] = '\0';
}

static int fetch_url(const wchar_t* url, char* body, int bodySz) {
    URL_COMPONENTSW uc = {0};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256] = {0};
    wchar_t path[MAX_URL] = {0};
    uc.lpszHostName = host;
    uc.dwHostNameLength = sizeof(host) / sizeof(wchar_t);
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = sizeof(path) / sizeof(wchar_t);

    if (!WinHttpCrackUrl(url, 0, 0, &uc)) {
        ws_log("WinHttpCrackUrl failed: %lu", GetLastError());
        return -1;
    }

    HINTERNET hSession = WinHttpOpen(L"ProcessGuardianAI/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        ws_log("WinHttpOpen failed: %lu", GetLastError());
        return -2;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, host, uc.nPort, 0);
    if (!hConnect) {
        ws_log("WinHttpConnect failed: %lu", GetLastError());
        WinHttpCloseHandle(hSession);
        return -3;
    }

    DWORD flags = uc.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path,
                                            NULL, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            flags);
    if (!hRequest) {
        ws_log("WinHttpOpenRequest failed: %lu", GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return -4;
    }

    /* Ignore certificate errors so SYSTEM service can complete HTTPS */
    DWORD securityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                          SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
                          SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                     (void*)&securityFlags, sizeof(securityFlags));

    BOOL ok = WinHttpSendRequest(hRequest,
                                 WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                 WINHTTP_NO_REQUEST_DATA, 0,
                                 0, 0);
    if (!ok) {
        ws_log("WinHttpSendRequest failed: %lu", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return -5;
    }
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        ws_log("WinHttpReceiveResponse failed: %lu", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return -6;
    }

    int total = 0;
    DWORD available = 0;
    DWORD read = 0;
    while (WinHttpQueryDataAvailable(hRequest, &available) && available > 0) {
        if (total + (int)available >= bodySz - 1) available = bodySz - 1 - total;
        if (available == 0) break;
        if (!WinHttpReadData(hRequest, body + total, available, &read)) break;
        total += read;
    }
    body[total] = '\0';

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return total;
}

/* Simple HTML tag stripper: replaces tags with spaces and decodes common entities */
static void strip_tags(const char* in, char* out, int outSz) {
    int i = 0, j = 0;
    int inTag = 0;
    while (in[i] && j < outSz - 1) {
        char c = in[i];
        if (c == '<') {
            inTag = 1;
            if (j > 0 && out[j-1] != ' ') out[j++] = ' ';
        } else if (c == '>') {
            inTag = 0;
        } else if (!inTag) {
            out[j++] = c;
        }
        i++;
    }
    out[j] = '\0';

    /* decode named entities */
    struct { const char* ent; char ch; } ents[] = {
        {"&amp;", '&'}, {"&lt;", '<'}, {"&gt;", '>'},
        {"&quot;", '"'}, {"&#39;", '\''}, {"&nbsp;", ' '},
        {"&ensp;", ' '}, {"&emsp;", ' '}, {"&thinsp;", ' '},
        {"&ndash;", '-'}, {"&mdash;", '-'}, {"&bull;", '*'},
        {"&copy;", ' '}, {"&reg;", ' '}, {"&trade;", ' '},
        {NULL, 0}
    };
    for (int e = 0; ents[e].ent; ++e) {
        char* p = out;
        int elen = (int)strlen(ents[e].ent);
        while ((p = strstr(p, ents[e].ent)) != NULL) {
            *p = ents[e].ch;
            memmove(p + 1, p + elen, strlen(p + elen) + 1);
            p++;
        }
    }

    /* decode numeric entities like &#0183; or &#xB7; */
    char* p2 = out;
    while ((p2 = strstr(p2, "&#")) != NULL) {
        char* end = strchr(p2, ';');
        if (!end) break;
        unsigned int code = 0;
        if (p2[2] == 'x' || p2[2] == 'X') {
            sscanf(p2 + 3, "%x", &code);
        } else {
            sscanf(p2 + 2, "%u", &code);
        }
        if (code > 0 && code <= 127) {
            *p2 = (char)code;
            memmove(p2 + 1, end + 1, strlen(end + 1) + 1);
            p2++;
        } else if (code == 0 || code > 127) {
            /* replace with space for non-ASCII */
            *p2 = ' ';
            memmove(p2 + 1, end + 1, strlen(end + 1) + 1);
            p2++;
        } else {
            p2++;
        }
    }

    /* collapse whitespace */
    char* dst = out;
    int lastSpace = 1;
    for (char* p = out; *p; ++p) {
        if (isspace((unsigned char)*p)) {
            if (!lastSpace) { *dst++ = ' '; lastSpace = 1; }
        } else {
            *dst++ = *p; lastSpace = 0;
        }
    }
    *dst = '\0';
}

static const char* find_attr(const char* html, const char* tagPrefix, const char* attrName) {
    const char* p = html;
    while ((p = strstr(p, tagPrefix)) != NULL) {
        const char* end = strchr(p, '>');
        if (!end) break;
        const char* attr = strstr(p, attrName);
        if (attr && attr < end) {
            const char* q = strchr(attr + strlen(attrName), '"');
            if (q) return q + 1;
        }
        p++;
    }
    return NULL;
}

AI_WEB_SEARCH_API int WebSearch(const char* query, char* outBuffer, int outBufferSize) {
    if (!query || !query[0] || !outBuffer || outBufferSize < 256) return -1;

    char encoded[2048] = {0};
    url_encode(query, encoded, sizeof(encoded));

    wchar_t url[MAX_URL] = {0};
    wcscpy(url, L"https://cn.bing.com/search?q=");
    int urlBaseLen = (int)wcslen(url);
    int encodedLen = (int)strlen(encoded);
    int copyLen = encodedLen;
    if (urlBaseLen + copyLen >= MAX_URL - 1) copyLen = MAX_URL - urlBaseLen - 1;
    for (int i = 0; i < copyLen; i++) {
        url[urlBaseLen + i] = (wchar_t)(unsigned char)encoded[i];
    }
    url[urlBaseLen + copyLen] = L'\0';

    ws_log("WebSearch query=%s url=%ls", query, url);

    char* body = (char*)malloc(MAX_BODY);
    if (!body) return -2;
    int bodyLen = fetch_url(url, body, MAX_BODY);
    if (bodyLen <= 0) {
        ws_log("fetch_url failed, bodyLen=%d", bodyLen);
        free(body);
        return -3;
    }
    ws_log("fetch_url succeeded, bodyLen=%d", bodyLen);

    char* plain = (char*)malloc(MAX_BODY);
    if (!plain) { free(body); return -4; }

    int written = _snprintf(outBuffer, outBufferSize,
                            "Web search results for: %s\n\n", query);
    if (written < 0) written = 0;

    const char* p = body;
    int count = 0;
    while (count < RESULT_LIMIT && (p = strstr(p, "b_algo")) != NULL) {
        /* Find <h2><a href="URL">TITLE</a></h2> inside this result */
        const char* h2 = strstr(p, "<h2");
        if (!h2) { p++; continue; }
        const char* aStart = strstr(h2, "<a");
        if (!aStart) { p++; continue; }
        const char* hrefStart = find_attr(aStart, "<a", "href=\"");
        const char* hrefEnd = hrefStart ? strchr(hrefStart, '"') : NULL;
        const char* titleStart = hrefEnd ? strchr(hrefEnd, '>') : NULL;
        const char* titleEnd = titleStart ? strstr(titleStart, "</a>") : NULL;

        if (titleStart && titleEnd) {
            int titleLen = (int)(titleEnd - titleStart - 1);
            if (titleLen > 0 && titleLen < 2048) {
                char title[2048] = {0};
                strncpy(title, titleStart + 1, titleLen);
                strip_tags(title, plain, MAX_BODY);

                int need = _snprintf(outBuffer + written, outBufferSize - written,
                                     "%d. %s\n", count + 1, plain);
                if (need > 0) written += need;

                /* look for adjacent snippet in <p> under b_caption */
                const char* caption = strstr(titleEnd, "b_caption");
                if (caption) {
                    const char* pStart = strstr(caption, "<p");
                    if (pStart) {
                        pStart = strchr(pStart, '>');
                        const char* pEnd = pStart ? strstr(pStart, "</p>") : NULL;
                        if (pStart && pEnd) {
                            int sLen = (int)(pEnd - pStart - 1);
                            if (sLen > 0 && sLen < 4096) {
                                char snippet[4096] = {0};
                                strncpy(snippet, pStart + 1, sLen);
                                strip_tags(snippet, plain, MAX_BODY);
                                need = _snprintf(outBuffer + written, outBufferSize - written,
                                                 "   %s\n\n", plain);
                                if (need > 0) written += need;
                            }
                        }
                    }
                }
                count++;
            }
        }
        p++;
    }

    if (count == 0) {
        _snprintf(outBuffer, outBufferSize, "No web search results returned for: %s", query);
    }

    free(plain);
    free(body);
    return count;
}
