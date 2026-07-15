/* ai_web_search.h - public interface for AI web search DLL */

#ifndef AI_WEB_SEARCH_H
#define AI_WEB_SEARCH_H

#ifdef BUILD_AI_WEB_SEARCH_DLL
#define AI_WEB_SEARCH_API __declspec(dllexport)
#else
#define AI_WEB_SEARCH_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Search the web for `query` and write a plain-text summary into outBuffer.
 * Returns the number of results found, or a negative error code.
 * outBufferSize should be at least 4096 bytes.
 */
AI_WEB_SEARCH_API int WebSearch(const char* query, char* outBuffer, int outBufferSize);

#ifdef __cplusplus
}
#endif

#endif /* AI_WEB_SEARCH_H */
