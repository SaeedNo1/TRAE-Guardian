#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ai_service.h"

static char g_apiKey[256] = "";
static char g_provider[256] = "api.siliconflow.cn";
static char g_endpoint[256] = "/v1/chat/completions";
static char g_model[128] = "qwen-plus";

static const char* AI_SYSTEM_PROMPT = 
    "你是一个进程管理助手，名为TRAE Guardian。你可以帮助用户管理Windows进程。"
    "用户可以请求你："
    "1. 杀死进程 - 使用 killProcess:进程名:是否树杀"
    "2. 添加重复查杀 - 使用 addRepeated:进程名:是否树杀"
    "3. 移除重复查杀 - 使用 removeRepeated:进程名"
    "4. 获取进程列表 - 使用 getProcessList"
    "5. 获取管理列表 - 使用 getManagedList"
    "请根据用户的请求，生成相应的命令。"
    "如果用户有其他问题，请友好地回答。";

int AiSetApiKey(const char* key) {
    if (!key || strlen(key) == 0) return -1;
    strncpy(g_apiKey, key, 255);
    g_apiKey[255] = '\0';
    return 0;
}

int AiSetProvider(const char* provider, const char* endpoint) {
    if (!provider || strlen(provider) == 0) return -1;
    strncpy(g_provider, provider, 255);
    g_provider[255] = '\0';
    if (endpoint && strlen(endpoint) > 0) {
        strncpy(g_endpoint, endpoint, 255);
        g_endpoint[255] = '\0';
    }
    return 0;
}

int AiSetModel(const char* model) {
    if (!model || strlen(model) == 0) return -1;
    strncpy(g_model, model, 127);
    g_model[127] = '\0';
    return 0;
}

static void JsonEscape(const char* input, char* output, int outputSize) {
    int j = 0;
    for (int i = 0; input[i] && j < outputSize - 1; i++) {
        unsigned char c = (unsigned char)input[i];
        int need = 2;
        if (c == '"' || c == '\\' || c == '\n' || c == '\r' || c == '\t') need = 2;
        else if (c < 0x20) need = 6;
        if (j + need >= outputSize) break;

        switch (c) {
            case '"':  output[j++] = '\\'; output[j++] = '"';  break;
            case '\\': output[j++] = '\\'; output[j++] = '\\'; break;
            case '\n': output[j++] = '\\'; output[j++] = 'n';  break;
            case '\r': output[j++] = '\\'; output[j++] = 'r';  break;
            case '\t': output[j++] = '\\'; output[j++] = 't';  break;
            default:
                if (c < 0x20) {
                    j += snprintf(output + j, outputSize - j, "\\u%04x", c);
                } else {
                    output[j++] = c;
                }
                break;
        }
    }
    output[j] = '\0';
}

static void AiLog(const char* msg) {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    char* slash = strrchr(path, '\\');
    if (slash) *slash = '\0';
    strcat(path, "\\data\\ai_last_error.log");
    FILE* f = fopen(path, "a");
    if (!f) return;
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", t);
    fprintf(f, "[%s] %s\n", timebuf, msg);
    fclose(f);
}

static int BuildJsonRequestEx(const char* systemPrompt, const char* userPrompt, char* buffer, int bufferSize) {
    char escapedPrompt[AI_MAX_PROMPT * 2];
    char escapedModel[512];
    char escapedSystem[AI_MAX_PROMPT * 2];
    JsonEscape(userPrompt, escapedPrompt, sizeof(escapedPrompt));
    JsonEscape(g_model, escapedModel, sizeof(escapedModel));
    JsonEscape(systemPrompt ? systemPrompt : AI_SYSTEM_PROMPT, escapedSystem, sizeof(escapedSystem));

    /* SiliconFlow / deepseek models reject some parameters or very long system prompts.
       Keep the body minimal: model, messages, temperature. */
    int len = snprintf(buffer, bufferSize,
        "{\"model\":\"%s\",\"messages\":["
        "{\"role\":\"system\",\"content\":\"%s\"},"
        "{\"role\":\"user\",\"content\":\"%s\"}"
        "],\"temperature\":0.7}",
        escapedModel, escapedSystem, escapedPrompt);

    return len;
}

int AiAsk(const char* prompt, char* response, int responseSize) {
    return AiAskEx(AI_SYSTEM_PROMPT, prompt, response, responseSize);
}

int AiAskEx(const char* systemPrompt, const char* userPrompt, char* response, int responseSize) {
    if (!userPrompt || !response || responseSize <= 0) return -1;
    if (strlen(g_apiKey) == 0) {
        strncpy(response, "请先设置API密钥。", responseSize);
        return 0;
    }
    
    HINTERNET hSession = WinHttpOpen(L"TRAE Guardian/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    if (!hSession) {
        strncpy(response, "WinHttpOpen failed", responseSize);
        AiLog("WinHttpOpen failed");
        return -11;
    }

    /* Prefer TLS 1.2 / 1.3 */
    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    WinHttpSetOption(hSession, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols));

    wchar_t providerW[256];
    MultiByteToWideChar(CP_UTF8, 0, g_provider, -1, providerW, 256);
    
    HINTERNET hConnect = WinHttpConnect(hSession,
        providerW,
        INTERNET_DEFAULT_HTTPS_PORT, 0);
    
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        _snprintf(response, responseSize, "Connect failed: check provider '%s' and network", g_provider);
        return -12;
    }
    
    wchar_t endpointW[256];
    MultiByteToWideChar(CP_UTF8, 0, g_endpoint, -1, endpointW, 256);
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect,
        L"POST",
        endpointW,
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);

    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        _snprintf(response, responseSize, "OpenRequest failed: check endpoint '%s'", g_endpoint);
        return -13;
    }

    /* Set generous timeouts for AI inference */
    {
        DWORD connectTimeout = 30000;
        DWORD sendTimeout    = 60000;
        DWORD recvTimeout    = 600000;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_CONNECT_TIMEOUT, &connectTimeout, sizeof(connectTimeout));
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SEND_TIMEOUT,    &sendTimeout,    sizeof(sendTimeout));
        WinHttpSetOption(hRequest, WINHTTP_OPTION_RECEIVE_TIMEOUT, &recvTimeout,    sizeof(recvTimeout));
    }

    /* Build auth header as UTF-8 then convert to wide (MinGW swprintf %S semantics differ from MSVC) */
    char authHdr[600];
    int authLen = snprintf(authHdr, sizeof(authHdr), "Authorization: Bearer %s", g_apiKey);
    if (authLen < 0 || authLen >= (int)sizeof(authHdr)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        strncpy(response, "Auth header too long", responseSize);
        return -18;
    }
    wchar_t wauth[600];
    if (MultiByteToWideChar(CP_UTF8, 0, authHdr, -1, wauth, 600) <= 0) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        strncpy(response, "Auth header conversion failed", responseSize);
        return -19;
    }

    WinHttpAddRequestHeaders(hRequest, L"Content-Type: application/json", -1,
        WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    WinHttpAddRequestHeaders(hRequest, L"Accept: application/json", -1,
        WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    WinHttpAddRequestHeaders(hRequest, wauth, -1,
        WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

    char jsonBuffer[AI_MAX_PROMPT * 2 + 1024];
    int jsonLen = BuildJsonRequestEx(systemPrompt, userPrompt, jsonBuffer, sizeof(jsonBuffer));

    {
        char logBuf[512];
        _snprintf(logBuf, sizeof(logBuf), "Request provider=%s endpoint=%s model=%s bodyLen=%d",
                  g_provider, g_endpoint, g_model, jsonLen);
        AiLog(logBuf);
    }

    BOOL sent = WinHttpSendRequest(hRequest, NULL, 0,
        (LPVOID)jsonBuffer, jsonLen, jsonLen, 0);
    
    if (!sent) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        strncpy(response, "SendRequest failed", responseSize);
        AiLog("SendRequest failed");
        return -14;
    }

    BOOL received = WinHttpReceiveResponse(hRequest, NULL);
    if (!received) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        strncpy(response, "ReceiveResponse failed", responseSize);
        AiLog("ReceiveResponse failed");
        return -15;
    }

    DWORD statusCode = 0;
    DWORD statusSize = sizeof(DWORD);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        NULL, &statusCode, &statusSize, NULL);

    if (statusCode != 200) {
        char errBody[4096] = {0};
        DWORD bytesRead = 0;
        while (WinHttpReadData(hRequest, errBody + strlen(errBody), sizeof(errBody) - strlen(errBody) - 1, &bytesRead) && bytesRead > 0) {
        }
        _snprintf(response, responseSize, "HTTP %lu: %s", statusCode, errBody);
        char logBuf[1024];
        _snprintf(logBuf, sizeof(logBuf), "HTTP %lu: %s", statusCode, errBody);
        AiLog(logBuf);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return -(int)statusCode;
    }
    
    char buf[4096];
    DWORD bytesRead = 0;
    response[0] = '\0';

    char *raw = (char*)malloc(AI_MAX_RESPONSE);
    if (!raw) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return -20;
    }
    raw[0] = '\0';
    while (WinHttpReadData(hRequest, buf, sizeof(buf) - 1, &bytesRead) && bytesRead > 0) {
        buf[bytesRead] = '\0';
        strncat(raw, buf, AI_MAX_RESPONSE - strlen(raw) - 1);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    /* Extract the assistant's content from the JSON response */
    const char *c = strstr(raw, "\"content\":\"");
    int ret = 0;
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
        for (int i = 0; i < clen && di < responseSize - 1; i++) {
            if (esc) {
                switch (c[i]) {
                    case 'n': response[di++] = '\n'; break;
                    case 'r': response[di++] = '\r'; break;
                    case 't': response[di++] = '\t'; break;
                    case '\\': response[di++] = '\\'; break;
                    case '"': response[di++] = '"'; break;
                    case '/': response[di++] = '/'; break;
                    case 'b': response[di++] = '\b'; break;
                    case 'f': response[di++] = '\f'; break;
                    case 'u': {
                        if (i + 4 < clen) {
                            char hex[5] = {c[i+1], c[i+2], c[i+3], c[i+4], 0};
                            unsigned int cp = (unsigned int)strtol(hex, NULL, 16);
                            if (cp < 0x80) {
                                response[di++] = (char)cp;
                            } else if (cp < 0x800) {
                                if (di + 2 < responseSize - 1) {
                                    response[di++] = (char)(0xC0 | (cp >> 6));
                                    response[di++] = (char)(0x80 | (cp & 0x3F));
                                }
                            } else {
                                if (di + 3 < responseSize - 1) {
                                    response[di++] = (char)(0xE0 | (cp >> 12));
                                    response[di++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                                    response[di++] = (char)(0x80 | (cp & 0x3F));
                                }
                            }
                            i += 4;
                        }
                        break;
                    }
                    default: response[di++] = c[i]; break;
                }
                esc = 0;
            } else if (c[i] == '\\') {
                esc = 1;
            } else {
                response[di++] = c[i];
            }
        }
        response[di] = '\0';
        ret = di;
    } else {
        /* Fallback: return raw response if content field not found */
        strncpy(response, raw, responseSize - 1);
        response[responseSize - 1] = '\0';
        ret = (int)strlen(response);
    }
    free(raw);
    return ret;
}

static int BuildJsonRequestStreamEx(const char* systemPrompt, const char* userPrompt, char* buffer, int bufferSize) {
    char escapedPrompt[AI_MAX_PROMPT * 2];
    char escapedModel[512];
    char escapedSystem[AI_MAX_PROMPT * 2];
    JsonEscape(userPrompt, escapedPrompt, sizeof(escapedPrompt));
    JsonEscape(g_model, escapedModel, sizeof(escapedModel));
    JsonEscape(systemPrompt ? systemPrompt : AI_SYSTEM_PROMPT, escapedSystem, sizeof(escapedSystem));

    int len = snprintf(buffer, bufferSize,
        "{\"model\":\"%s\",\"messages\":["
        "{\"role\":\"system\",\"content\":\"%s\"},"
        "{\"role\":\"user\",\"content\":\"%s\"}"
        "],\"temperature\":0.7,\"stream\":true}",
        escapedModel, escapedSystem, escapedPrompt);

    return len;
}

/* Extract content from a single SSE data line. Returns 1 if content present, 0 otherwise. */
static int ExtractStreamContent(const char* line, char* out, int outSize) {
    const char* prefix = "data: ";
    if (strncmp(line, prefix, strlen(prefix)) != 0) return 0;
    const char* data = line + strlen(prefix);
    if (strcmp(data, "[DONE]") == 0) return 0;

    const char* c = strstr(data, "\"content\":\"");
    if (!c) return 0;
    c += 11;

    const char* end = c;
    int esc = 0;
    while (*end) {
        if (esc) { esc = 0; end++; continue; }
        if (*end == '\\') { esc = 1; end++; continue; }
        if (*end == '"') break;
        end++;
    }

    int clen = (int)(end - c);
    int di = 0; esc = 0;
    for (int i = 0; i < clen && di < outSize - 1; i++) {
        if (esc) {
            switch (c[i]) {
                case 'n': out[di++] = '\n'; break;
                case 'r': out[di++] = '\r'; break;
                case 't': out[di++] = '\t'; break;
                case '\\': out[di++] = '\\'; break;
                case '"': out[di++] = '"'; break;
                case '/': out[di++] = '/'; break;
                case 'b': out[di++] = '\b'; break;
                case 'f': out[di++] = '\f'; break;
                case 'u': {
                    if (i + 4 < clen) {
                        char hex[5] = {c[i+1], c[i+2], c[i+3], c[i+4], 0};
                        unsigned int cp = (unsigned int)strtol(hex, NULL, 16);
                        if (cp < 0x80) out[di++] = (char)cp;
                        else if (cp < 0x800) {
                            if (di + 2 < outSize - 1) {
                                out[di++] = (char)(0xC0 | (cp >> 6));
                                out[di++] = (char)(0x80 | (cp & 0x3F));
                            }
                        } else {
                            if (di + 3 < outSize - 1) {
                                out[di++] = (char)(0xE0 | (cp >> 12));
                                out[di++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                                out[di++] = (char)(0x80 | (cp & 0x3F));
                            }
                        }
                        i += 4;
                    }
                    break;
                }
                default: out[di++] = c[i]; break;
            }
            esc = 0;
        } else if (c[i] == '\\') {
            esc = 1;
        } else {
            out[di++] = c[i];
        }
    }
    out[di] = '\0';
    return di > 0 ? 1 : 0;
}

int AiAskStreamEx(const char* systemPrompt, const char* userPrompt,
                  AiStreamCallback onChunk, void* userData) {
    if (!userPrompt || !onChunk) return -1;
    if (strlen(g_apiKey) == 0) return -2;

    HINTERNET hSession = WinHttpOpen(L"TRAE Guardian/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { AiLog("WinHttpOpen failed"); return -11; }

    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    WinHttpSetOption(hSession, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols));

    wchar_t providerW[256];
    MultiByteToWideChar(CP_UTF8, 0, g_provider, -1, providerW, 256);
    HINTERNET hConnect = WinHttpConnect(hSession, providerW, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); AiLog("Connect failed"); return -12; }

    wchar_t endpointW[256];
    MultiByteToWideChar(CP_UTF8, 0, g_endpoint, -1, endpointW, 256);
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", endpointW,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return -13; }

    {
        DWORD connectTimeout = 30000;
        DWORD sendTimeout    = 60000;
        DWORD recvTimeout    = 600000;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_CONNECT_TIMEOUT, &connectTimeout, sizeof(connectTimeout));
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SEND_TIMEOUT,    &sendTimeout,    sizeof(sendTimeout));
        WinHttpSetOption(hRequest, WINHTTP_OPTION_RECEIVE_TIMEOUT, &recvTimeout,    sizeof(recvTimeout));
    }

    char authHdr[600];
    int authLen = snprintf(authHdr, sizeof(authHdr), "Authorization: Bearer %s", g_apiKey);
    if (authLen < 0 || authLen >= (int)sizeof(authHdr)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return -18;
    }
    wchar_t wauth[600];
    if (MultiByteToWideChar(CP_UTF8, 0, authHdr, -1, wauth, 600) <= 0) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return -19;
    }

    WinHttpAddRequestHeaders(hRequest, L"Content-Type: application/json", -1,
        WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    WinHttpAddRequestHeaders(hRequest, L"Accept: text/event-stream", -1,
        WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    WinHttpAddRequestHeaders(hRequest, wauth, -1,
        WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

    char jsonBuffer[AI_MAX_PROMPT * 2 + 1024];
    int jsonLen = BuildJsonRequestStreamEx(systemPrompt, userPrompt, jsonBuffer, sizeof(jsonBuffer));

    {
        char logBuf[512];
        _snprintf(logBuf, sizeof(logBuf), "Stream request provider=%s endpoint=%s model=%s bodyLen=%d",
                  g_provider, g_endpoint, g_model, jsonLen);
        AiLog(logBuf);
    }

    BOOL sent = WinHttpSendRequest(hRequest, NULL, 0, (LPVOID)jsonBuffer, jsonLen, jsonLen, 0);
    if (!sent) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        AiLog("SendRequest failed"); return -14;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        AiLog("ReceiveResponse failed"); return -15;
    }

    DWORD statusCode = 0;
    DWORD statusSize = sizeof(DWORD);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        NULL, &statusCode, &statusSize, NULL);
    if (statusCode != 200) {
        char errBody[4096] = {0};
        DWORD bytesRead = 0;
        while (WinHttpReadData(hRequest, errBody + strlen(errBody), sizeof(errBody) - strlen(errBody) - 1, &bytesRead) && bytesRead > 0) {}
        char logBuf[512];
        _snprintf(logBuf, sizeof(logBuf), "Stream HTTP %lu: %s", statusCode, errBody);
        AiLog(logBuf);
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return -(int)statusCode;
    }

    char *accum = (char*)malloc(AI_MAX_RESPONSE);
    if (!accum) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return -20;
    }
    accum[0] = '\0';
    char chunkBuf[4096];
    char lineBuf[4096];
    int linePos = 0;
    DWORD bytesRead = 0;
    int streamRet = 0;

    while (1) {
        BOOL ok = WinHttpReadData(hRequest, chunkBuf, sizeof(chunkBuf) - 1, &bytesRead);
        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_HANDLE_EOF && strlen(accum) > 0) {
                /* Server closed connection after sending all data; treat as success. */
                break;
            }
            char logBuf[256];
            _snprintf(logBuf, sizeof(logBuf), "WinHttpReadData failed, error=%lu, accumLen=%d", err, (int)strlen(accum));
            AiLog(logBuf);
            streamRet = -1000 - (int)err;
            goto done;
        }
        if (bytesRead == 0) break;
        chunkBuf[bytesRead] = '\0';
        for (DWORD i = 0; i < bytesRead; i++) {
            char ch = chunkBuf[i];
            if (ch == '\n') {
                lineBuf[linePos] = '\0';
                char content[8192] = {0};
                if (ExtractStreamContent(lineBuf, content, sizeof(content))) {
                    if (strlen(accum) + strlen(content) < AI_MAX_RESPONSE - 1) {
                        strcat(accum, content);
                        if (onChunk(content, userData) != 0) goto done;
                    }
                }
                linePos = 0;
            } else if (ch != '\r' && linePos < (int)sizeof(lineBuf) - 1) {
                lineBuf[linePos++] = ch;
            }
        }
    }

done:
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    int len = (int)strlen(accum);
    free(accum);
    return streamRet ? streamRet : len;
}

int AiAnalyzeLogs(const char* logContent, char* result, int resultSize) {
    if (!logContent || !result || resultSize <= 0) return -1;

    char prompt[AI_MAX_PROMPT];
    snprintf(prompt, AI_MAX_PROMPT,
        "请分析以下进程管理日志，总结关键事件和趋势：\n\n%s",
        logContent);

    return AiAsk(prompt, result, resultSize);
}
