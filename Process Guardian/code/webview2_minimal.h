#pragma once

#include <windows.h>
#include <unknwn.h>

#ifdef __cplusplus
extern "C" {
#endif

// EventRegistrationToken structure
typedef struct EventRegistrationToken {
    INT64 value;
} EventRegistrationToken;

// Forward declarations
typedef struct IWebView2WebView IWebView2WebView;
typedef struct IWebView2Settings IWebView2Settings;
typedef struct IWebView2Environment IWebView2Environment;
typedef struct IWebView2WebMessageReceivedEventArgs IWebView2WebMessageReceivedEventArgs;
typedef struct IWebView2Controller IWebView2Controller;

// WebView2 WebView interface
typedef struct IWebView2WebViewVtbl {
    HRESULT (STDMETHODCALLTYPE* QueryInterface)(IWebView2WebView* This, REFIID riid, void** ppvObject);
    ULONG (STDMETHODCALLTYPE* AddRef)(IWebView2WebView* This);
    ULONG (STDMETHODCALLTYPE* Release)(IWebView2WebView* This);
    HRESULT (STDMETHODCALLTYPE* get_Settings)(IWebView2WebView* This, IWebView2Settings** settings);
    HRESULT (STDMETHODCALLTYPE* Navigate)(IWebView2WebView* This, LPCWSTR uri);
    HRESULT (STDMETHODCALLTYPE* put_Bounds)(IWebView2WebView* This, RECT bounds);
    HRESULT (STDMETHODCALLTYPE* ExecuteScript)(IWebView2WebView* This, LPCWSTR javaScript, IUnknown* handler);
    HRESULT (STDMETHODCALLTYPE* add_WebMessageReceived)(IWebView2WebView* This, IUnknown* eventHandler, EventRegistrationToken* token);
    HRESULT (STDMETHODCALLTYPE* remove_WebMessageReceived)(IWebView2WebView* This, EventRegistrationToken token);
} IWebView2WebViewVtbl;

struct IWebView2WebView {
    const IWebView2WebViewVtbl* lpVtbl;
};

// WebView2 Settings interface
typedef struct IWebView2SettingsVtbl {
    HRESULT (STDMETHODCALLTYPE* QueryInterface)(IWebView2Settings* This, REFIID riid, void** ppvObject);
    ULONG (STDMETHODCALLTYPE* AddRef)(IWebView2Settings* This);
    ULONG (STDMETHODCALLTYPE* Release)(IWebView2Settings* This);
    HRESULT (STDMETHODCALLTYPE* put_IsScriptEnabled)(IWebView2Settings* This, BOOL enabled);
    HRESULT (STDMETHODCALLTYPE* put_AreDefaultScriptDialogsEnabled)(IWebView2Settings* This, BOOL enabled);
    HRESULT (STDMETHODCALLTYPE* put_AreHostObjectsAllowed)(IWebView2Settings* This, BOOL allowed);
} IWebView2SettingsVtbl;

struct IWebView2Settings {
    const IWebView2SettingsVtbl* lpVtbl;
};

// WebView2 Environment interface
typedef struct IWebView2EnvironmentVtbl {
    HRESULT (STDMETHODCALLTYPE* QueryInterface)(IWebView2Environment* This, REFIID riid, void** ppvObject);
    ULONG (STDMETHODCALLTYPE* AddRef)(IWebView2Environment* This);
    ULONG (STDMETHODCALLTYPE* Release)(IWebView2Environment* This);
    HRESULT (STDMETHODCALLTYPE* CreateWebView2Controller)(IWebView2Environment* This, HWND parentWindow, IUnknown* handler);
} IWebView2EnvironmentVtbl;

struct IWebView2Environment {
    const IWebView2EnvironmentVtbl* lpVtbl;
};

// WebView2 WebMessageReceivedEventArgs interface
typedef struct IWebView2WebMessageReceivedEventArgsVtbl {
    HRESULT (STDMETHODCALLTYPE* QueryInterface)(IWebView2WebMessageReceivedEventArgs* This, REFIID riid, void** ppvObject);
    ULONG (STDMETHODCALLTYPE* AddRef)(IWebView2WebMessageReceivedEventArgs* This);
    ULONG (STDMETHODCALLTYPE* Release)(IWebView2WebMessageReceivedEventArgs* This);
    HRESULT (STDMETHODCALLTYPE* get_WebMessageAsJson)(IWebView2WebMessageReceivedEventArgs* This, LPWSTR* webMessageAsJson);
    HRESULT (STDMETHODCALLTYPE* get_WebMessageAsString)(IWebView2WebMessageReceivedEventArgs* This, LPWSTR* webMessageAsString);
} IWebView2WebMessageReceivedEventArgsVtbl;

struct IWebView2WebMessageReceivedEventArgs {
    const IWebView2WebMessageReceivedEventArgsVtbl* lpVtbl;
};

// WebView2 Controller interface
typedef struct IWebView2ControllerVtbl {
    HRESULT (STDMETHODCALLTYPE* QueryInterface)(IWebView2Controller* This, REFIID riid, void** ppvObject);
    ULONG (STDMETHODCALLTYPE* AddRef)(IWebView2Controller* This);
    ULONG (STDMETHODCALLTYPE* Release)(IWebView2Controller* This);
    HRESULT (STDMETHODCALLTYPE* get_CoreWebView2)(IWebView2Controller* This, IWebView2WebView** webview);
    HRESULT (STDMETHODCALLTYPE* put_Bounds)(IWebView2Controller* This, RECT bounds);
} IWebView2ControllerVtbl;

struct IWebView2Controller {
    const IWebView2ControllerVtbl* lpVtbl;
};

// Function pointer types
typedef HRESULT (STDAPICALLTYPE* CreateCoreWebView2EnvironmentWithOptionsFunc)(
    LPCWSTR browserExecutableFolder,
    LPCWSTR userDataFolder,
    IUnknown* options,
    IUnknown* environment_created_handler
);

// Global variables for dynamic loading
static HMODULE g_webView2LoaderModule = NULL;
static CreateCoreWebView2EnvironmentWithOptionsFunc g_createCoreWebView2EnvironmentWithOptions = NULL;

// Load WebView2Loader.dll dynamically
static BOOL LoadWebView2Loader(void) {
    if (g_webView2LoaderModule) return TRUE;
    
    g_webView2LoaderModule = LoadLibraryW(L"WebView2Loader.dll");
    if (!g_webView2LoaderModule) return FALSE;
    
    g_createCoreWebView2EnvironmentWithOptions = (CreateCoreWebView2EnvironmentWithOptionsFunc)
        GetProcAddress(g_webView2LoaderModule, "CreateCoreWebView2EnvironmentWithOptions");
    
    return g_createCoreWebView2EnvironmentWithOptions != NULL;
}

// Unload WebView2Loader.dll
static void UnloadWebView2Loader(void) {
    if (g_webView2LoaderModule) {
        FreeLibrary(g_webView2LoaderModule);
        g_webView2LoaderModule = NULL;
        g_createCoreWebView2EnvironmentWithOptions = NULL;
    }
}

#ifdef __cplusplus
}
#endif