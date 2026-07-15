#pragma once

#define AI_MAX_PROMPT 65536
#define AI_MAX_RESPONSE 262144

typedef int (*AiStreamCallback)(const char* textChunk, void* userData);

int AiAsk(const char* prompt, char* response, int responseSize);
int AiAskEx(const char* systemPrompt, const char* userPrompt, char* response, int responseSize);
int AiAskStreamEx(const char* systemPrompt, const char* userPrompt,
                  AiStreamCallback onChunk, void* userData);
int AiSetApiKey(const char* key);
int AiSetProvider(const char* provider, const char* endpoint);
int AiSetModel(const char* model);
int AiAnalyzeLogs(const char* logContent, char* result, int resultSize);
