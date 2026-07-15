# Plan: Update Build Scripts for PE Analysis Module Integration

## Summary

The ETW + PE static analysis refactor is code-complete: `pe_analysis.c/h` has been created, `thread_modules.c` has been rewritten to use `PEQuickAnalyze` and `CheckProcessForDiskHandle`, and old global handle scanning logic (25万+ 句柄扫描) has been deleted. The `.o` files were compiled manually in the previous session. However, the build scripts do not yet include `pe_analysis.c` in their compilation and link steps. This plan updates all three build scripts to properly integrate the new module, then rebuilds and tests.

## Current State Analysis

### Already Complete (from previous session)
- **`pe_analysis.h`** — Defines `PEAnalysisResult`, `PEThreatLevel`, and functions `PEAnalyzeFile`, `PEQuickAnalyze`, `PEAssessThreat`, `PEFreeResult`, `PEComputeSHA256`
- **`pe_analysis.c`** — Full implementation (264 lines): RVA→file-offset fix (`PERvaToFileOffset`), import extraction, SHA256 hash, string scanning, threat assessment
- **`thread_modules.c`** — Already modified:
  - Includes `pe_analysis.h` (via `thread_modules.h`)
  - `CoreModulesOnNewProcess` (line 914) uses `PEQuickAnalyze` with 4-layer detection: Hash → Import → String → PE structure
  - `ExecuteVirusResponse` (line 880) — unified terminate/delete/restore function
  - `CheckProcessForDiskHandle` (line 428) — lightweight single-process handle scan via `DuplicateHandle`
  - `HandleScanThreadProc` (line 485) — lightweight, only scans `inHighFreqMonitor` processes
  - Old functions deleted: `ScanProcessHandles`, `ScanSingleProcessHandles`, `GetCurrentProcessList`, `HighSpeedScanThreadProc`, `QuickDetectThreadProc`, `ComputeSHA256Hash`, `CheckPEForMaliciousImports`, `CheckPEForPhysicalDriveString`
- **`thread_modules.h`** — Updated: removed `hHighSpeedScanThread`, `hQuickDetectThread` fields and their thread proc declarations
- **`build/pe_analysis.o`** — Already compiled successfully (manual gcc command)
- **`bin/trae_guardian_daemon.exe`** — Already exists (was linked manually with all .o files)

### What's Missing
The three build scripts do NOT compile or link `pe_analysis.c`/`pe_analysis.o`:

1. **`build_daemon_only.bat`** (line 39-52) — Compiles 14 .c files but misses `pe_analysis.c`; link command (line 52) misses `pe_analysis.o`
2. **`build_pro_mingw1310.bat`** (line 63-78) — Same issue: compiles 14 daemon .c files, misses `pe_analysis.c`; link command (line 78) misses `pe_analysis.o`
3. **`build_pro_mingw1310.ps1`** (line 59-64) — Even more outdated: only compiles 4 daemon .c files (daemon_core, trust_zone, etw_monitor, thread_modules), missing 10+ other .c files AND `pe_analysis.c`

## Proposed Changes

### Step 1: Update `build_daemon_only.bat`
**File:** `c:\Users\BaikerrNO1\Documents\trae_projects\Process Guardian\build_daemon_only.bat`

- **Add** after line 49 (after `user_interaction.c` compilation):
  ```bat
  echo [BUILD] Compiling pe_analysis.c...
  "%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE pe_analysis.c -o "%BUILD_DIR%\pe_analysis.o" 2>&1
  ```
- **Update** the link command (line 52) to add `"%BUILD_DIR%\pe_analysis.o"` before `-o "%OUTPUT_DIR%\trae_guardian_daemon.exe"`

### Step 2: Update `build_pro_mingw1310.bat`
**File:** `c:\Users\BaikerrNO1\Documents\trae_projects\Process Guardian\build_pro_mingw1310.bat`

- **Add** after line 77 (after `user_interaction.c` compilation):
  ```bat
  echo [BUILD] Compiling pe_analysis.c...
  "%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE pe_analysis.c -o "%BUILD_DIR%\pe_analysis.o" 2>&1 || (echo ERROR: Failed to compile pe_analysis.c & exit /b 1)
  ```
- **Update** the link command (line 78) to add `"%BUILD_DIR%\pe_analysis.o"` before `-o "%OUTPUT_DIR%\trae_guardian_daemon.exe"`

### Step 3: Update `build_pro_mingw1310.ps1`
**File:** `c:\Users\BaikerrNO1\Documents\trae_projects\Process Guardian\build_pro_mingw1310.ps1`

This script is significantly outdated — it only compiles 4 daemon .c files (daemon_core, trust_zone, etw_monitor, thread_modules) and is missing 10+ other modules. I'll bring it in sync with `build_pro_mingw1310.bat` by:

- **Add** compilation steps for ALL missing daemon .c files (state_machine, rule_engine, score_center, response_center, whitelist_db, config_json, sqlite_log, virus_signature, network_monitor, user_interaction, **pe_analysis**)
- **Update** the link command to include all .o files including `pe_analysis.o`

The new daemon compilation section will replace lines 59-65 and match the .bat version's daemon build steps (lines 64-78).

### Step 4: Rebuild the daemon
Run `build_daemon_only.bat` to compile and link the daemon with the new `pe_analysis.c` module. This verifies that:
1. `pe_analysis.c` compiles without errors
2. `thread_modules.c` links successfully with `pe_analysis.o` (resolving `PEQuickAnalyze`, `PEFreeResult`, etc.)
3. The final `trae_guardian_daemon.exe` is produced

### Step 5: Test with test_threat.exe
Verify the ETW + PE analysis pipeline works end-to-end:
1. Start the daemon (`bin\trae_guardian_daemon.exe`)
2. Run `test_threat.exe` (or build it if needed)
3. Check `daemon.log` for:
   - `[ETW-DEBUG] ProcStart` — ETW detected the new process
   - `[HIGH-FREQ] New process` — High-frequency monitoring started
   - `[VIRUS-DETECTED]` or `[PE-THREAT]` — PE analysis identified the threat
   - Process termination and file deletion in the log
4. Verify `test_threat.exe` was terminated and its file deleted

## Assumptions & Decisions

1. **The code changes are already complete** — This plan only updates build scripts and compiles/tests. No source code modifications needed beyond build scripts.
2. **`build_pro_mingw1310.ps1` will be fully synced with the .bat version** — Since the .ps1 is already broken (missing 10+ .c files), fixing it entirely is better than just adding pe_analysis.c.
3. **`-lcrypt32` is already in the link flags** — `pe_analysis.c` uses `CryptAcquireContextW` etc. from advapi32/crypt32. The .bat link command already has `-lcrypt32`.
4. **Test approach**: Use `build_daemon_only.bat` for the quick rebuild, then test with `test_threat.exe`.

## Verification

- [ ] `build_daemon_only.bat` runs without errors and produces `bin\trae_guardian_daemon.exe`
- [ ] `daemon.log` shows `[ETW-DEBUG] ProcStart` when a new process starts (not via handle scanning)
- [ ] `daemon.log` shows `[VIRUS-DETECTED]` or `[PE-THREAT]` when `test_threat.exe` runs
- [ ] `test_threat.exe` process is terminated and its file deleted
- [ ] No global handle scanning (no `NtQuerySystemInformation` with `SystemHandleInformation`) in the daemon log
- [ ] Lightweight single-process handle scan (`CheckProcessForDiskHandle`) works for high-freq monitored processes
