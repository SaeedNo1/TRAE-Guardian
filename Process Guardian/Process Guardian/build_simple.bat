@echo off
setlocal enabledelayedexpansion

echo ========================================
echo TRAE Guardian - Simple Build Script
echo ========================================
echo.

set "BUILD_DIR=build"
set "OUTPUT_DIR=bin"

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo [BUILD] Compiling core.c...
gcc -c -O2 -Wall -DUNICODE -D_UNICODE core.c -o "%BUILD_DIR%\core.o"
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile core.c
    pause
    exit /b 1
)

echo [BUILD] Compiling ai_service.c...
gcc -c -O2 -Wall -DUNICODE -D_UNICODE ai_service.c -o "%BUILD_DIR%\ai_service.o"
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile ai_service.c
    pause
    exit /b 1
)

echo [BUILD] Compiling main_simple.c...
gcc -c -O2 -Wall -DUNICODE -D_UNICODE main_simple.c -o "%BUILD_DIR%\main.o"
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile main_simple.c
    pause
    exit /b 1
)

echo [LINK] Linking executable...
gcc -o "%OUTPUT_DIR%\trae_guardian.exe" ^
    "%BUILD_DIR%\core.o" "%BUILD_DIR%\ai_service.o" "%BUILD_DIR%\main.o" ^
    -lkernel32 -luser32 -lpsapi -ladvapi32 -lwinhttp -lcomctl32 -lole32 -loleaut32 ^
    -mwindows -static-libgcc -static-libstdc++
if !errorlevel! neq 0 (
    echo ERROR: Failed to link executable
    pause
    exit /b 1
)

echo.
echo [COPY] Creating data directory...
if not exist "%OUTPUT_DIR%\data" mkdir "%OUTPUT_DIR%\data"

echo.
echo ========================================
echo BUILD SUCCESSFUL!
echo ========================================
echo Output: %CD%\%OUTPUT_DIR%\trae_guardian.exe
echo.
echo Notes:
echo 1. This is a simplified version using pure Win32 controls
echo 2. No WebView2 Runtime required
echo 3. Features: AI chat, task management, process list
echo.
pause