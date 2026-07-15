@echo off
setlocal enabledelayedexpansion

echo ========================================
echo TRAE Guardian - Build Script
echo ========================================
echo.

set "MSVC_DIR=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64"
set "INCLUDE_DIR=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\include"
set "INCLUDE_DIR=%INCLUDE_DIR%;C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\shared"
set "INCLUDE_DIR=%INCLUDE_DIR%;C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\ucrt"
set "INCLUDE_DIR=%INCLUDE_DIR%;C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um"
set "LIB_DIR=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\lib\x64"
set "LIB_DIR=%LIB_DIR%;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\ucrt\x64"
set "LIB_DIR=%LIB_DIR%;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64"

echo [INFO] Using MSVC: %MSVC_DIR%
echo.

set "BUILD_DIR=build"
set "OUTPUT_DIR=bin"

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo [BUILD] Compiling core.c...
"%MSVC_DIR%\cl.exe" /c /EHsc /W3 /O2 /I"%INCLUDE_DIR%" core.c /Fo"%BUILD_DIR%\core.obj"
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile core.c
    pause
    exit /b 1
)

echo [BUILD] Compiling ai_service.c...
"%MSVC_DIR%\cl.exe" /c /EHsc /W3 /O2 /I"%INCLUDE_DIR%" ai_service.c /Fo"%BUILD_DIR%\ai_service.obj"
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile ai_service.c
    pause
    exit /b 1
)

echo [BUILD] Compiling main.c...
"%MSVC_DIR%\cl.exe" /c /EHsc /W3 /O2 /I"%INCLUDE_DIR%" main.c /Fo"%BUILD_DIR%\main.obj"
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile main.c
    pause
    exit /b 1
)

echo [LINK] Linking executable...
"%MSVC_DIR%\link.exe" /OUT:"%OUTPUT_DIR%\trae_guardian.exe" /LIBPATH:"%LIB_DIR%" ^
    kernel32.lib user32.lib psapi.lib advapi32.lib comctl32.lib winhttp.lib ^
    "%BUILD_DIR%\core.obj" "%BUILD_DIR%\ai_service.obj" "%BUILD_DIR%\main.obj"
if !errorlevel! neq 0 (
    echo ERROR: Failed to link executable
    pause
    exit /b 1
)

echo.
echo [COPY] Copying HTML resources...
if not exist "%OUTPUT_DIR%\html" mkdir "%OUTPUT_DIR%\html"
copy /Y "html\index.html" "%OUTPUT_DIR%\html\" >nul
copy /Y "html\style.css" "%OUTPUT_DIR%\html\" >nul
copy /Y "html\script.js" "%OUTPUT_DIR%\html\" >nul

echo [COPY] Creating data directory...
if not exist "%OUTPUT_DIR%\data" mkdir "%OUTPUT_DIR%\data"

echo.
echo ========================================
echo BUILD SUCCESSFUL!
echo ========================================
echo Output: %CD%\%OUTPUT_DIR%\trae_guardian.exe
echo.
echo Notes:
echo 1. Make sure WebView2Loader.dll is in the same directory as the executable
echo 2. Get WebView2Loader.dll from: https://www.nuget.org/packages/Microsoft.Web.WebView2
echo 3. Requires WebView2 Runtime (Windows 10 22H2+ / Windows 11 pre-installed)
echo.
pause