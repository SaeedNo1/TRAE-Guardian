/* ai_client.h - Call OpenAI-compatible API via HTTPS
 *
 * API key is stored encrypted in data/ai_key.dat. On first use,
 * Ai_LoadKey is called (by ai_scheduler.exe) and the plaintext key
 * is held in process memory only.
 *
 * WinHTTP is used directly (no libcurl dependency).
 */
#ifndef AI_CLIENT_H
#define AI_CLIENT_H

#include <windows.h>

#ifdef BUILD_AI_CLIENT_DLL
#define AIC_API __declspec(dllexport)
#else
#define AIC_API __declspec(dllimport)
#endif

#define AIC_MAX_RESP      131072
#define AIC_DEFAULT_URL   "https://api.siliconflow.cn/v1/chat/completions"
#define AIC_DEFAULT_MODEL "deepseek-ai/DeepSeek-R1-0528-Qwen3-8B"

/* Result from one call */
typedef struct {
    int  httpStatus;             /* 0 if network err, else 200/400/... */
    char content[AIC_MAX_RESP];  /* assistant content (already extracted from JSON) */
    char errMsg[256];            /* human readable error */
} AiResult;

/* Callback for streaming: each time a chunk of content arrives, this is called. */
typedef int (*AiStreamCallback)(const char *chunk, int isDone, void *userData);

/* Load API key from encrypted file. */
AIC_API int  Ai_LoadKey(const char *encryptedKeyPath, char *outPlain, int outPlainSz);

/* Save plaintext key to encrypted file. */
AIC_API int  Ai_SaveKey(const char *encryptedKeyPath, const char *plainKey);

/* Call the model with explicit provider and endpoint.
 * provider: hostname only, e.g. "api.siliconflow.cn"
 * endpoint: path, e.g. "/v1/chat/completions"
 * systemPrompt may be NULL. userPrompt required.
 * temperature: 0.0 - 2.0, default 0.7.
 * maxTokens: max output tokens, <= 0 uses API default. */
AIC_API int  Ai_Ask(const char *apiKey, const char *provider, const char *endpoint,
                    const char *systemPrompt, const char *userPrompt,
                    const char *model, int timeoutMs,
                    float temperature, int maxTokens, AiResult *outResult);

/* Streaming variant with explicit provider/endpoint. */
AIC_API int  Ai_AskStream(const char *apiKey, const char *provider, const char *endpoint,
                          const char *systemPrompt, const char *userPrompt,
                          const char *model, int timeoutMs,
                          float temperature, int maxTokens,
                          AiStreamCallback callback, void *userData, AiResult *outResult);

#endif
