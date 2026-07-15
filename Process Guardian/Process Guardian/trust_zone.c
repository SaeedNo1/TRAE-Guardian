#include "trust_zone.h"
#include <wintrust.h>
#include <softpub.h>
#include <stdio.h>
#include <string.h>

void TzLoad(TrustZoneList* tz, const wchar_t* basePath) {
    tz->count = 0;
    if (!basePath) return;
    wchar_t path[MAX_PATH];
    swprintf(path, MAX_PATH, L"%s\\data\\trusted_zones.txt", basePath);
    FILE* f = _wfopen(path, L"r, ccs=UTF-8");
    if (!f) return;
    wchar_t line[TZ_MAX_PATH];
    while (fgetws(line, TZ_MAX_PATH, f) && tz->count < TZ_MAX_ZONES) {
        wchar_t* p = line;
        wchar_t* nl = wcschr(p, L'\n'); if (nl) *nl = L'\0';
        nl = wcschr(p, L'\r'); if (nl) *nl = L'\0';
        while (*p == L' ' || *p == L'\t') p++;
        if (!p[0] || p[0] == L'#') continue;
        wcsncpy(tz->zones[tz->count], p, TZ_MAX_PATH - 1);
        tz->zones[tz->count][TZ_MAX_PATH - 1] = L'\0';
        tz->count++;
    }
    fclose(f);
}

BOOL TzContains(const TrustZoneList* tz, const wchar_t* path) {
    if (!tz || !path || !path[0]) return FALSE;
    for (int i = 0; i < tz->count; i++) {
        if (tz->zones[i][0] == L'\0') continue;
        size_t len = wcslen(tz->zones[i]);
        if (_wcsnicmp(path, tz->zones[i], len) == 0) {
            if (path[len] == L'\\' || path[len] == L'\0' || path[len] == L'/') return TRUE;
        }
    }
    return FALSE;
}

BOOL TzIsWindowsSigned(const wchar_t* path) {
    if (!path || !path[0]) return FALSE;
    wchar_t winDir[MAX_PATH];
    GetWindowsDirectoryW(winDir, MAX_PATH);
    size_t winLen = wcslen(winDir);
    if (winLen == 0) return FALSE;
    if (_wcsnicmp(path, winDir, winLen) != 0) return FALSE;
    if (path[winLen] != L'\\' && path[winLen] != L'\0') return FALSE;

    WINTRUST_FILE_INFO fi = {0};
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = path;
    GUID act = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wd = {0};
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwUIContext = WTD_UICONTEXT_EXECUTE;
    LONG r = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &act, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &act, &wd);
    if (r != ERROR_SUCCESS) return FALSE;

    DWORD dwEncoding, dwContentType, dwFormatType;
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    BOOL ok = CryptQueryObject(CERT_QUERY_OBJECT_FILE, path,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY, 0,
        &dwEncoding, &dwContentType, &dwFormatType, &hStore, &hMsg, NULL);
    BOOL isMs = FALSE;
    if (ok) {
        DWORD cb = 0;
        if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &cb) && cb > 0) {
            CMSG_SIGNER_INFO* psi = (CMSG_SIGNER_INFO*)malloc(cb);
            if (psi && CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, psi, &cb)) {
                CERT_INFO ci = {0};
                ci.Issuer = psi->Issuer;
                ci.SerialNumber = psi->SerialNumber;
                PCCERT_CONTEXT ctx = CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    0, CERT_FIND_SUBJECT_CERT, &ci, NULL);
                if (ctx) {
                    wchar_t signer[256] = {0};
                    CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, signer, 256);
                    if (wcsstr(signer, L"Microsoft") || wcsstr(signer, L"Windows")) isMs = TRUE;
                    CertFreeCertificateContext(ctx);
                }
            }
            free(psi);
        }
        CryptMsgClose(hMsg);
        CertCloseStore(hStore, 0);
    }
    return isMs;
}

BOOL TzShouldSkip(const TrustZoneList* tz, const wchar_t* path) {
    if (TzContains(tz, path)) return TRUE;
    if (TzIsWindowsSigned(path)) return TRUE;
    return FALSE;
}
