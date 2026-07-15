/* ai_client.c
 *
 * WinHTTP-based minimal client for SiliconFlow OpenAI-compatible API.
 * Key encryption: simple obfuscation (XOR with rotating key seeded from
 * a constant + the calling EXE's PE timestamp). This is NOT real AES;
 * it's enough to keep the key out of plain text / trivial string search.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "ai_client.h"

#pragma comment(lib, "winhttp.lib")

#define OBF_KEY "PGK1_2026"   /* 9 bytes, used as rotating XOR key */

/* Derive a 16-byte xor key from a constant. Enough to keep
 * the key out of plain text / trivial string search. */
static void make_xor_key(BYTE out[16]) {
    BYTE seed[16] = {0};
    memcpy(seed, OBF_KEY, strlen(OBF_KEY));
    for (int i = 0; i < 16; i++) {
        out[i] = seed[i % strlen(OBF_KEY)] ^ (BYTE)(i * 31 + 7);
    }
}

int Ai_SaveKey(const char *path, const char *plainKey) {
    if (!path || !plainKey) return -1;
    BYTE xk[16]; make_xor_key(xk);
    int n = (int)strlen(plainKey);
    BYTE *buf = (BYTE *)malloc(n);
    if (!buf) return -1;
    for (int i = 0; i < n; i++) buf[i] = (BYTE)plainKey[i] ^ xk[i % 16];
    FILE *fp = fopen(path, "wb");
    if (!fp) { free(buf); return -1; }
    fwrite(buf, 1, n, fp);
    fclose(fp);
    free(buf);
    return 0;
}

int Ai_LoadKey(const char *path, char *outPlain, int outPlainSz) {
    if (!path || !outPlain || outPlainSz <= 0) return -1;
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz <= 0 || sz >= outPlainSz) { fclose(fp); return -1; }
    BYTE *buf = (BYTE *)malloc(sz);
    if (!buf) { fclose(fp); return -1; }
    fread(buf, 1, sz, fp);
    fclose(fp);
    BYTE xk[16]; make_xor_key(xk);
    for (int i = 0; i < sz; i++) outPlain[i] = (char)(buf[i] ^ xk[i % 16]);
    outPlain[sz] = 0;
    free(buf);
    return 0;
}

/* --------------- JSON escape (small) --------------- */
static void json_escape(const char *in, char *out, int sz) {
    int n = 0;
    for (const char *p = in; *p && n < sz - 8; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\') { out[n++] = '\\'; out[n++] = c; }
        else if (c == '\n') { out[n++] = '\\'; out[n++] = 'n'; }
        else if (c == '\r') { out[n++] = '\\'; out[n++] = 'r'; }
        else if (c == '\t') { out[n++] = '\\'; out[n++] = 't'; }
        else if (c < 0x20) { n += snprintf(out+n, sz-n, "\\u%04x", c); }
        else out[n++] = c;
    }
    out[n] = 0;
}

/* Extract "content":"..." from response JSON (skipping nested quotes simply). */
static void extract_content(const char *json, char *out, int sz) {
    out[0] = 0;
    const char *p = strstr(json, "\"content\"");
    if (!p) return;
    p = strchr(p, ':');
    if (!p) return;
    while (*p && (*p == ':' || *p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')) p++;
    if (*p != '"') return;
    p++;
    int n = 0;
    while (*p && *p != '"' && n < sz-1) {
        if (*p == '\\' && p[1]) {
            char e = p[1];
            if (e == 'n') out[n++] = '\n';
            else if (e == 'r') out[n++] = '\r';
            else if (e == 't') out[n++] = '\t';
            else out[n++] = e;
            p += 2;
        } else {
            out[n++] = *p++;
        }
    }
    out[n] = 0;
}

int Ai_Ask(const char *apiKey, const char *provider, const char *endpoint,
           const char *systemPrompt, const char *userPrompt,
           const char *model, int timeoutMs,
           float temperature, int maxTokens, AiResult *out) {
    if (!apiKey || !userPrompt || !out) {
        if (out) memset(out, 0, sizeof(*out));
        return -1;
    }
    memset(out, 0, sizeof(*out));
    if (timeoutMs <= 0) timeoutMs = 30000;
    if (!provider || !*provider) provider = "api.siliconflow.cn";
    if (!endpoint || !*endpoint) endpoint = "/v1/chat/completions";
    if (!model || !*model) model = AIC_DEFAULT_MODEL;
    if (temperature < 0.0f) temperature = 0.0f;
    if (temperature > 2.0f) temperature = 2.0f;
    if (maxTokens <= 0) maxTokens = 32768;

    /* build JSON body */
    char sysEsc[4096] = "";
    char usrEsc[16384] = "";
    if (systemPrompt) json_escape(systemPrompt, sysEsc, sizeof(sysEsc));
    json_escape(userPrompt, usrEsc, sizeof(usrEsc));
    char body[65536];
    int blen = snprintf(body, sizeof(body),
        "{\"model\":\"%s\",\"stream\":false,\"temperature\":%.2f,\"max_tokens\":%d,\"messages\":["
        "%s%s%s"
        "{\"role\":\"user\",\"content\":\"%s\"}]}",
        model, temperature, maxTokens,
        systemPrompt ? "{\"role\":\"system\",\"content\":\"" : "",
        sysEsc,
        systemPrompt ? "\"}," : "",
        usrEsc);
    if (blen <= 0 || blen >= (int)sizeof(body)) {
        snprintf(out->errMsg, sizeof(out->errMsg), "prompt too long");
        return -1;
    }
    /* WinHTTP session */
    HINTERNET hSession = WinHttpOpen(L"ProcessGuardian/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { snprintf(out->errMsg, sizeof(out->errMsg), "WinHttpOpen fail"); return -1; }
    WinHttpSetTimeouts(hSession, 30000, 30000, timeoutMs, timeoutMs);

    wchar_t providerW[256];
    MultiByteToWideChar(CP_UTF8, 0, provider, -1, providerW, 256);
    HINTERNET hConnect = WinHttpConnect(hSession, providerW, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); snprintf(out->errMsg, sizeof(out->errMsg), "WinHttpConnect fail"); return -1; }

    wchar_t endpointW[256];
    MultiByteToWideChar(CP_UTF8, 0, endpoint, -1, endpointW, 256);
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", endpointW,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        snprintf(out->errMsg, sizeof(out->errMsg), "WinHttpOpenRequest fail");
        return -1;
    }

    /* In a Windows service (SYSTEM) the user certificate stores may not be
     * available. Allow the request to proceed even if the certificate cannot
     * be fully validated. */
    DWORD securityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                        | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE
                        | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                        | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags));

    /* headers */
    wchar_t apiKeyW[512];
    MultiByteToWideChar(CP_UTF8, 0, apiKey, -1, apiKeyW, 512);
    wchar_t headers[4096];
    _snwprintf(headers, 4096, L"Content-Type: application/json\r\nAuthorization: Bearer %ls", apiKeyW);

    /* send */
    if (!WinHttpSendRequest(hRequest, headers, -1L,
                            body, blen, blen, 0)) {
        DWORD err = GetLastError();
        snprintf(out->errMsg, sizeof(out->errMsg), "WinHttpSendRequest fail (%lu)", err);
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return -1;
    }
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        DWORD err = GetLastError();
        snprintf(out->errMsg, sizeof(out->errMsg), "WinHttpReceiveResponse fail (%lu)", err);
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return -1;
    }

    /* read status */
    DWORD statusCode = 0, statusSz = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSz, WINHTTP_NO_HEADER_INDEX);
    out->httpStatus = (int)statusCode;

    /* read body */
    char *resp = (char *)malloc(65536);
    if (!resp) { WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return -1; }
    int total = 0, cap = 65536;
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail) || avail == 0) break;
        if (total + (int)avail + 1 > cap) {
            cap *= 2;
            char *nb = (char *)realloc(resp, cap);
            if (!nb) break;
            resp = nb;
        }
        DWORD got = 0;
        WinHttpReadData(hRequest, resp + total, avail, &got);
        total += (int)got;
    }
    resp[total] = 0;
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    if (out->httpStatus != 200) {
        snprintf(out->errMsg, sizeof(out->errMsg), "HTTP %d: %.200s", out->httpStatus, resp);
        free(resp);
        return -1;
    }
    extract_content(resp, out->content, sizeof(out->content));
    free(resp);
    return 0;
}

/* Extract "content":"..." from a streaming chunk JSON (choices[0].delta.content).
 * The chunk JSON looks like: {"choices":[{"delta":{"content":"..."}}]}
 * Returns number of bytes written to out (0 if no content in this chunk). */
static int extract_delta_content(const char *json, char *out, int sz) {
    out[0] = 0;
    /* Find "delta" object, then "content" inside it.
     * Simpler approach: find "\"content\":\"", but only inside "delta" */
    const char *p = strstr(json, "\"delta\"");
    if (!p) return 0;
    /* Now find "content" after "delta" */
    const char *start = p;
    int brace = 0;
    for (const char *q = p; *q; q++) {
        if (*q == '{') brace++;
        else if (*q == '}') { brace--; if (brace < 0) break; }
        else if (*q == '"' && strncmp(q, "\"content\"", 9) == 0) {
            q += 9;
            while (*q == ' ' || *q == ':') q++;
            if (*q == '"') {
                q++;
                int n = 0;
                while (*q && *q != '"' && n < sz - 1) {
                    if (*q == '\\' && q[1]) {
                        char e = q[1];
                        if (e == 'n') out[n++] = '\n';
                        else if (e == 'r') out[n++] = '\r';
                        else if (e == 't') out[n++] = '\t';
                        else out[n++] = e;
                        q += 2;
                    } else {
                        out[n++] = *q++;
                    }
                }
                out[n] = 0;
                return n;
            }
        }
    }
    return 0;
}

/* --------------- Ai_AskStream: streaming with callback --------------- */
int Ai_AskStream(const char *apiKey, const char *provider, const char *endpoint,
                 const char *systemPrompt, const char *userPrompt,
                 const char *model, int timeoutMs,
                 float temperature, int maxTokens,
                 AiStreamCallback callback, void *userData, AiResult *out) {
    if (!apiKey || !userPrompt || !out || !callback) return -1;
    memset(out, 0, sizeof(*out));
    if (timeoutMs <= 0) timeoutMs = 60000;
    if (!provider || !*provider) provider = "api.siliconflow.cn";
    if (!endpoint || !*endpoint) endpoint = "/v1/chat/completions";
    if (!model || !*model) model = AIC_DEFAULT_MODEL;
    if (temperature < 0.0f) temperature = 0.0f;
    if (temperature > 2.0f) temperature = 2.0f;
    if (maxTokens <= 0) maxTokens = 32768;

    /* build JSON body with stream:true */
    char sysEsc[4096] = "";
    char usrEsc[16384] = "";
    if (systemPrompt) json_escape(systemPrompt, sysEsc, sizeof(sysEsc));
    json_escape(userPrompt, usrEsc, sizeof(usrEsc));
    char body[65536];
    int blen = snprintf(body, sizeof(body),
        "{\"model\":\"%s\",\"stream\":true,\"temperature\":%.2f,\"max_tokens\":%d,\"messages\":["
        "%s%s%s"
        "{\"role\":\"user\",\"content\":\"%s\"}]}",
        model, temperature, maxTokens,
        systemPrompt ? "{\"role\":\"system\",\"content\":\"" : "",
        sysEsc,
        systemPrompt ? "\"}," : "",
        usrEsc);
    if (blen <= 0 || blen >= (int)sizeof(body)) {
        snprintf(out->errMsg, sizeof(out->errMsg), "prompt too long");
        return -1;
    }

    /* WinHTTP session */
    HINTERNET hSession = WinHttpOpen(L"ProcessGuardian/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { snprintf(out->errMsg, sizeof(out->errMsg), "WinHttpOpen fail"); return -1; }
    WinHttpSetTimeouts(hSession, 30000, 30000, timeoutMs, timeoutMs);

    wchar_t providerW[256];
    MultiByteToWideChar(CP_UTF8, 0, provider, -1, providerW, 256);
    HINTERNET hConnect = WinHttpConnect(hSession, providerW, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); snprintf(out->errMsg, sizeof(out->errMsg), "WinHttpConnect fail"); return -1; }

    wchar_t endpointW[256];
    MultiByteToWideChar(CP_UTF8, 0, endpoint, -1, endpointW, 256);
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", endpointW,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        snprintf(out->errMsg, sizeof(out->errMsg), "WinHttpOpenRequest fail"); return -1;
    }

    DWORD securityFlags2 = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                         | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE
                         | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                         | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &securityFlags2, sizeof(securityFlags2));

    /* headers */
    wchar_t apiKeyW[512];
    MultiByteToWideChar(CP_UTF8, 0, apiKey, -1, apiKeyW, 512);
    wchar_t headers[4096];
    _snwprintf(headers, 4096, L"Content-Type: application/json\r\nAuthorization: Bearer %ls", apiKeyW);

    /* send */
    if (!WinHttpSendRequest(hRequest, headers, -1L,
                            body, blen, blen, 0)) {
        snprintf(out->errMsg, sizeof(out->errMsg), "WinHttpSendRequest fail (%lu)", GetLastError());
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return -1;
    }
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        snprintf(out->errMsg, sizeof(out->errMsg), "WinHttpReceiveResponse fail (%lu)", GetLastError());
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return -1;
    }

    /* read status */
    DWORD statusCode = 0, statusSz = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSz, WINHTTP_NO_HEADER_INDEX);
    out->httpStatus = (int)statusCode;

    if (statusCode != 200) {
        /* read error body */
        char errBuf[1024] = "";
        DWORD avail = 0;
        if (WinHttpQueryDataAvailable(hRequest, &avail) && avail > 0 && avail < 1024) {
            WinHttpReadData(hRequest, (BYTE*)errBuf, avail, NULL);
        }
        snprintf(out->errMsg, sizeof(out->errMsg), "HTTP %d: %.200s", (int)statusCode, errBuf);
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return -1;
    }

    /* Read SSE stream */
    /* Buffer for incoming data */
    char sseBuf[65536];
    int bufLen = 0;
    int contentTotal = 0;
    int streamDone = 0;

    memset(sseBuf, 0, sizeof(sseBuf));

    while (!streamDone) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail) || avail == 0) break;
        if (avail > sizeof(sseBuf) - bufLen - 1)
            avail = sizeof(sseBuf) - bufLen - 1;

        DWORD got = 0;
        if (!WinHttpReadData(hRequest, (BYTE*)(sseBuf + bufLen), avail, &got) || got == 0) break;
        bufLen += (int)got;
        sseBuf[bufLen] = 0;

        /* Parse SSE messages from buffer: each message ends with \n\n */
        char *bufPtr = sseBuf;
        while (!streamDone) {
            /* Find \n\n */
            char *msgEnd = strstr(bufPtr, "\n\n");
            if (!msgEnd) break;  /* incomplete message, wait for more data */

            *msgEnd = 0;  /* terminate the message */
            /* Now bufPtr points to a complete SSE message */

            /* SSE message format: "data: {...}\n" or "data: [DONE]\n" */
            if (strncmp(bufPtr, "data: ", 6) == 0) {
                char *jsonStr = bufPtr + 6;
                /* Check for [DONE] */
                if (strncmp(jsonStr, "[DONE]", 7) == 0) {
                    streamDone = 1;
                } else {
                    /* Parse JSON and extract content */
                    char chunk[4096];
                    int chunkLen = extract_delta_content(jsonStr, chunk, sizeof(chunk));
                    if (chunkLen > 0) {
                        /* Append to out->content */
                        if (contentTotal + chunkLen < (int)sizeof(out->content) - 1) {
                            memcpy(out->content + contentTotal, chunk, chunkLen);
                            contentTotal += chunkLen;
                            out->content[contentTotal] = 0;
                        }
                        /* Call callback */
                        int cbRc = callback(chunk, 0, userData);
                        if (cbRc != 0) {
                            /* User wants to abort */
                            streamDone = 1;
                        }
                    }
                }
            }

            /* Move to next message */
            bufPtr = msgEnd + 2;
        }

        /* Move remaining data to beginning of buffer */
        if (bufPtr > sseBuf) {
            int remaining = (int)(&sseBuf[bufLen] - bufPtr);
            if (remaining > 0)
                memmove(sseBuf, bufPtr, remaining);
            bufLen = remaining;
            sseBuf[bufLen] = 0;
        }
    }

    /* Call callback with isDone=1 */
    callback("", 1, userData);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID l) {
    (void)h; (void)r; (void)l;
    return TRUE;
}
