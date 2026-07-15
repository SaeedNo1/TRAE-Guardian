# ETW Process Detection Fix + PE String Scanning Fix

## Summary

The ETW-driven process detection pipeline is not working. Three bugs prevent the
"PE static analysis at process start" feature from functioning:

1. **ETW event filtering bug** (etw_monitor.c): NT Kernel Logger process events are
   identified by `ProviderId` GUID, not by `Task` value. The code checks `task == 1`
   which never matches, so ALL process/thread/image-load events are silently dropped.

2. **PE string scanning bug** (pe_analysis.c): `PEScanSuspiciousStrings` only checks
   for ASCII strings (e.g. `"PhysicalDrive"`). Windows malware uses wide-string APIs
   (`CreateFileW`, `L"\\\\.\\PhysicalDrive0"`), so the compiled binary contains UTF-16
   strings that the ASCII scanner cannot find.

3. **Thread opcode bug** (etw_monitor.c): Thread start/end uses opcodes 3/4
   (`EVENT_TRACE_TYPE_THREAD` / `EVENT_TRACE_TYPE_THREAD_END`), not 1/2 as the code
   assumes.

## Current State Analysis

### ETW Event Flow (broken)

```
NT Kernel Logger → EventRecordCallback → checks task==1 → FAILS (task is 0)
                                           ↓
                              process events silently dropped
```

The daemon.log confirms:
- `ETW kernel monitor started` — session starts OK
- Registry events flow correctly (they use opcode-based filtering, not task)
- NO `[ETW-PROC-START]` or `[ETW-DBG] Process event` entries — zero process events
- `ETW EnableTraceEx2 Kernel-Process: status=5` — the Kernel-Process provider cannot
  be enabled on the NT Kernel Logger (expected; the kernel logger already provides
  process events via EnableFlags)

### NT Kernel Logger Event Identification

For the classic NT Kernel Logger, events are identified by `EventHeader.ProviderId`:

| Event Type     | ProviderId GUID                          | Opcode (Start) | Opcode (End) |
|----------------|------------------------------------------|----------------|--------------|
| Process        | {3D6FA8D0-FE05-11D0-9DDA-00C04FC7E733}   | 1              | 2            |
| Thread         | {3D6FA8D1-FE05-11D0-9DDA-00C04FC7E733}   | 3              | 4            |
| Image Load     | {2CB15D1D-1324-4FE4-9C9B-2B65E5ABC0C3}   | 10             | 11           |
| Registry       | {AE53722E-C863-11D2-8659-00C04FC7E733}   | 10-22          | —            |

The current code uses `task == 1` / `task == 2` / `task == 5` which never matches
these kernel events (their Task field is typically 0).

### PE String Scanning (broken for wide strings)

`test_threat.c` contains `L"\\\\.\\PhysicalDrive0"` which compiles to UTF-16
(`P\0h\0y\0s\0i\0c\0a\0l\0D\0r\0i\0v\0e\0`). The scanner only checks ASCII
(`PhysicalDrive`), so it won't match. Since `test_threat.exe` also doesn't import
suspicious functions, the PE analysis returns `PE_THREAT_NONE`.

## Proposed Changes

### Change 1: Fix ETW event filtering (etw_monitor.c)

**What**: Replace task-based filtering with ProviderId GUID-based filtering for
process/thread/image events.

**Why**: NT Kernel Logger events are identified by ProviderId, not by Task.

**How**: In `EventRecordCallback`:

1. Define kernel event GUIDs near the top of the file (after KernelProcessProviderGuid):
   ```c
   /* NT Kernel Logger event type GUIDs */
   static const GUID ProcessGuid =
       {0x3D6FA8D0, 0xFE05, 0x11D0, {0x9D, 0xDA, 0x00, 0xC0, 0x4F, 0xC7, 0xE7, 0x33}};
   static const GUID ThreadGuid =
       {0x3D6FA8D1, 0xFE05, 0x11D0, {0x9D, 0xDA, 0x00, 0xC0, 0x4F, 0xC7, 0xE7, 0x33}};
   static const GUID ImageLoadGuid =
       {0x2CB15D1D, 0x1324, 0x4FE4, {0x9C, 0x9B, 0x2B, 0x65, 0xE5, 0xAB, 0xC0, 0xC3}};
   ```

2. Rewrite the event dispatch in `EventRecordCallback` to check ProviderId first:
   ```c
   /* --- NT Kernel Logger events (identified by ProviderId GUID) --- */
   if (IsEqualGuid(&ev->EventHeader.ProviderId, &ProcessGuid)) {
       if (opcode == 1) {       /* EVENT_TRACE_TYPE_PROCESS (start) */
           if (pid != 0 && pid != 4) HandleProcStartEvent(m, ev, pid);
       } else if (opcode == 2) { /* EVENT_TRACE_TYPE_PROCESS_END */
           if (pid != 0 && pid != 4) HandleProcStopEvent(m, ev, pid);
       }
       return;
   }
   if (IsEqualGuid(&ev->EventHeader.ProviderId, &ThreadGuid)) {
       if (opcode == 3) {       /* EVENT_TRACE_TYPE_THREAD (start) */
           HandleThreadEvent(m, ev, pid);
       }
       return;
   }
   if (IsEqualGuid(&ev->EventHeader.ProviderId, &ImageLoadGuid)) {
       if (opcode == 10) {      /* EVENT_TRACE_TYPE_LOAD */
           HandleImageLoadEvent(m, ev, pid, TRUE);
       } else if (opcode == 11) { /* unload */
           HandleImageLoadEvent(m, ev, pid, FALSE);
       }
       return;
   }
   ```

3. Keep the existing registry and file event handling (opcode-based) for the
   remaining events. Remove the old `task == 1` / `task == 2` / `task == 5` checks
   and the `[ETW-DBG]` temporary debug log.

4. Remove the `EnableTraceEx2` call for `KernelProcessProviderGuid` (it always
   fails with status=5 on the NT Kernel Logger and just adds noise to the log).

### Change 2: Fix PE string scanning (pe_analysis.c)

**What**: `PEScanSuspiciousStrings` should also scan for UTF-16 (wide) strings.

**Why**: Windows malware uses `CreateFileW(L"\\\\.\\PhysicalDrive0", ...)`, which
compiles to UTF-16 in the binary. The current ASCII-only scan misses all wide
strings.

**How**: Add a helper that checks both ASCII and UTF-16 representations:

```c
/* Returns TRUE if either the ASCII or UTF-16LE encoding of `needle`
   (length `len`, not counting NUL) is found at `ptr`. */
static BOOL MemMatchAsciiOrWide(const BYTE* ptr, const char* needle, size_t len) {
    if (memcmp(ptr, needle, len) == 0) return TRUE;
    /* UTF-16LE: each byte is followed by \0 */
    for (size_t i = 0; i < len; i++) {
        if (ptr[i * 2] != (BYTE)needle[i] || ptr[i * 2 + 1] != 0) return FALSE;
    }
    return TRUE;
}
```

Then in `PEScanSuspiciousStrings`, replace:
```c
memcmp(fileBase + i, "PhysicalDrive", 13) == 0
```
with:
```c
MemMatchAsciiOrWide(fileBase + i, "PhysicalDrive", 13)
```
for each string check. Adjust the loop bound to `i + 26 <= scanSize` (2x the
longest wide string).

### Change 3: Clean up ETW session configuration (etw_monitor.c)

**What**: Set `Wnode.Guid = SystemTraceControlGuid` and `Wnode.Flags =
WNODE_FLAG_TRACED_GUID` in `EtwThreadProc` before `StartTraceW`.

**Why**: Microsoft documentation states these are required for the NT Kernel
Logger. The session currently starts because the name "NT Kernel Logger" is
recognized, but missing the Guid may cause incomplete event delivery.

**How**: Add the SystemTraceControlGuid definition and set the fields:
```c
static const GUID SystemTraceControlGuid =
    {0x9E814AAD, 0x3204, 0x11D2, {0x9A, 0x82, 0x00, 0x60, 0x08, 0xA8, 0x69, 0x39}};

/* ...in EtwThreadProc before StartTraceW... */
p->Wnode.Guid = SystemTraceControlGuid;
p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
```

## Files to Modify

1. **etw_monitor.c** (lines ~180-243): Rewrite `EventRecordCallback` event dispatch;
   remove `EnableTraceEx2` for Kernel-Process; add GUID definitions; add
   `SystemTraceControlGuid` in `EtwThreadProc`.

2. **pe_analysis.c** (lines ~106-127): Add `MemMatchAsciiOrWide` helper; rewrite
   `PEScanSuspiciousStrings` to check both ASCII and UTF-16 strings.

## Verification Steps

1. **Rebuild daemon**: Run `build_daemon_only.bat` — must complete without errors.
2. **Start daemon as admin**: Launch `bin\trae_guardian_daemon.exe` elevated.
3. **Verify ETW started**: Check `daemon.log` for `ETW kernel monitor started`.
4. **Launch test_threat.exe**: Start it and wait 5 seconds.
5. **Verify process detection**: Check `daemon.log` for:
   - `[ETW-DEBUG] ProcStart pid=... name=...test_threat.exe`
   - `[ETW-PROC-START] pid=... name=test_threat.exe`
6. **Verify PE analysis**: Check for one of:
   - `[VIRUS-DETECTED]` — if signature matched (string layer)
   - `[PE-THREAT]` — if PE structure threat detected (hasPhysicalDriveString)
7. **Verify response**: Check for process termination, file deletion, and popup.
8. **Clean up**: Remove test_threat.exe from any repeated-kill list if it survives.

If step 5 shows no process events, the NT Kernel Logger may need the separate-session
approach (create a regular ETW session with the Microsoft-Windows-Kernel-Process
provider). That would be a follow-up fix.

## Assumptions & Decisions

- **NT Kernel Logger produces process events** when `EVENT_TRACE_FLAG_PROCESS` is
  set in `EnableFlags`. The events use `ProviderId = ProcessGuid` and `Opcode = 1/2`.
  This is based on Microsoft documentation and the fact that registry events (which
  use the same EnableFlags mechanism) work correctly.
- **Keeping the NT Kernel Logger** (single session) rather than creating a separate
  regular session for Kernel-Process provider. The separate-session approach would add
  complexity (two sessions, two consumer threads) and should only be used if the
  GUID-based filtering doesn't work.
- **PE string scan covers both ASCII and UTF-16** because real Windows executables
  use both encodings depending on whether they use `CreateFileA` or `CreateFileW`.
