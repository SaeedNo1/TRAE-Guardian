#ifndef TRUST_ZONE_H
#define TRUST_ZONE_H

#include <windows.h>

#define TZ_MAX_ZONES 32
#define TZ_MAX_PATH 512

typedef struct {
    wchar_t zones[TZ_MAX_ZONES][TZ_MAX_PATH];
    int count;
} TrustZoneList;

void TzLoad(TrustZoneList* tz, const wchar_t* basePath);
BOOL TzContains(const TrustZoneList* tz, const wchar_t* path);
BOOL TzIsWindowsSigned(const wchar_t* path);
BOOL TzShouldSkip(const TrustZoneList* tz, const wchar_t* path);

#endif
