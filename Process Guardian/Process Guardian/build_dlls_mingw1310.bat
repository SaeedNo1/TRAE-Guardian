@echo off
setlocal enabledelayedexpansion

set "MINGW=C:\c\mingw1310\mingw64\bin"
set "PATH=%MINGW%;%PATH%"

if not exist "bin" mkdir "bin"
if not exist "bin\core" mkdir "bin\core"
if not exist "bin\AI" mkdir "bin\AI"
if not exist "bin\Observe" mkdir "bin\Observe"
if not exist "bin\permission" mkdir "bin\permission"

echo [BUILD] Compiling core DLLs...
"%MINGW%\gcc.exe" -shared -O2 -Wall -DBUILD_SERVICE_MANAGER_DLL service_manager.c -o bin\core\service_manager.dll -ladvapi32
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile service_manager.dll
    pause
    exit /b 1
)

"%MINGW%\gcc.exe" -shared -O2 -Wall -DBUILD_REGISTRY_MANAGER_DLL registry_manager.c -o bin\core\registry_manager.dll -ladvapi32 -lshell32
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile registry_manager.dll
    pause
    exit /b 1
)

"%MINGW%\gcc.exe" -shared -O2 -Wall -DBUILD_PARTITION_MANAGER_DLL partition_manager.c -o bin\core\partition_manager.dll -lkernel32 -lshell32 -luser32
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile partition_manager.dll
    pause
    exit /b 1
)

echo [BUILD] Compiling AI DLLs...
"%MINGW%\gcc.exe" -shared -O2 -Wall -DBUILD_AI_ACTION_DLL ai_action.c -o bin\AI\ai_action.dll -lwinhttp
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile ai_action.dll
    pause
    exit /b 1
)

"%MINGW%\gcc.exe" -shared -O2 -Wall -DBUILD_AI_CLIENT_DLL ai_client.c -o bin\AI\ai_client.dll -lwinhttp
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile ai_client.dll
    pause
    exit /b 1
)

"%MINGW%\gcc.exe" -shared -O2 -Wall -DBUILD_LOG_COMPRESSOR_DLL log_compressor.c -o bin\AI\log_compressor.dll
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile log_compressor.dll
    pause
    exit /b 1
)

"%MINGW%\gcc.exe" -shared -O2 -Wall -DBUILD_LOG_SEARCHER_DLL log_searcher.c -o bin\AI\log_searcher.dll
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile log_searcher.dll
    pause
    exit /b 1
)

echo [BUILD] Compiling permission DLLs...
"%MINGW%\g++.exe" -shared -O2 permission\Normal.cpp -o bin\permission\normal.dll -lkernel32
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile normal.dll
    pause
    exit /b 1
)

"%MINGW%\g++.exe" -shared -O2 permission\Admin.cpp -o bin\permission\admin.dll -lkernel32
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile admin.dll
    pause
    exit /b 1
)

"%MINGW%\g++.exe" -shared -O2 permission\SYSTEM.cpp -o bin\permission\SYSTEM.dll -lkernel32 -lshell32
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile SYSTEM.dll
    pause
    exit /b 1
)

echo.
echo [BUILD] SUCCESS: All DLLs compiled with MSVCRT runtime.
pause
