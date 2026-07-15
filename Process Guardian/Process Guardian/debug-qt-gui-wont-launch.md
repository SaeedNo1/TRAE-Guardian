# Debug Session: Qt GUI won't launch

**Status**: `[RESOLVED]`
**Session ID**: `qt-gui-wont-launch`
**Symptom**: `trae_guardian_qt.exe` compiled successfully, but when launched it did not open a window and the process exited immediately.

## Root Cause

The MinGW compiler at `D:\Program Files\mingw64` is GCC 16.1.0 configured for **UCRT**. Qt 6.8.3 `mingw_64` was built with a MinGW toolchain that uses **msvcrt.dll**. When the two are mixed, `malloc`/`free` operate on different heaps, causing immediate heap corruption during CRT/DLL initialization (exception `0xc0000374`, `STATUS_HEAP_CORRUPTION`).

A secondary issue was that the helper DLLs loaded by the Qt GUI — `service_manager.dll`, `registry_manager.dll`, `partition_manager.dll`, and the `permission/*.dll` files — had also been built with the UCRT toolchain. Even after switching the GUI executable to MSVCRT, cross-CRT `malloc`/`free` between these DLLs and the GUI process caused crashes during tab initialization.

## Fix Applied

1. Switched the Qt GUI build to the MSVCRT MinGW toolchain at `C:\c\mingw1310\mingw64\bin` (GCC 13.1.0, built by Brecht Sanders).
2. Added `set "PATH=%MINGW%;%PATH%"` to `qt_gui/build_qt.bat` so the compiler's helper tools (collect2, cc1plus, etc.) load the correct DLLs.
3. Created `build_dlls_mingw1310.bat` to rebuild all helper/permission DLLs with the same MSVCRT toolchain:
   - `bin/service_manager.dll`
   - `bin/registry_manager.dll`
   - `bin/partition_manager.dll`
   - `bin/permission/normal.dll`
   - `bin/permission/admin.dll`
   - `bin/permission/SYSTEM.dll`

## Verification

- `trae_guardian_qt.exe` now imports `msvcrt.dll` instead of `api-ms-win-crt-*`.
- All helper DLLs now import `msvcrt.dll`.
- The application starts successfully, creates its main window (`Process Guardian`), and responds to Windows messages.

## Remaining Notes

- The old UCRT build of `trae_guardian_qt.exe` may still be running as a zombie process (PID 4072) under a higher-privilege account; it cannot be terminated from the current session but will disappear after a reboot.
- To rebuild cleanly after reboot, run:
  1. `build_dlls_mingw1310.bat`
  2. `qt_gui/build_qt.bat`
