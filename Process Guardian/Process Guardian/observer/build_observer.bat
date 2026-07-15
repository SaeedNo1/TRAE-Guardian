@echo off
setlocal enabledelayedexpansion

echo ========================================
echo Building observer.dll and observer.exe
echo ========================================

set "ROOT=%~dp0"
set "QT_ROOT=C:\c\Qt\6.8.3\mingw_64"
set "MINGW=C:\c\mingw1310\mingw64\bin"
set "PATH=%MINGW%;%PATH%"
set "BUILD_DIR=%ROOT%build"
set "OUTPUT_DIR=%ROOT%..\bin\Observe"

cd /d "%ROOT%"

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo [BUILD] Generating moc files...
"%QT_ROOT%\bin\moc.exe" observer_app.cpp -o "%BUILD_DIR%\observer_app_moc.cpp"
if !errorlevel! neq 0 goto fail

echo [BUILD] Compiling observer.dll...
"%MINGW%\g++.exe" -shared -O2 -std=c++17 -DUNICODE -D_UNICODE -DOBSERVER_DLL_EXPORTS -c observer_dll.cpp -o "%BUILD_DIR%\observer_dll.o"
if !errorlevel! neq 0 goto fail

"%MINGW%\g++.exe" -shared -O2 -std=c++17 -DUNICODE -D_UNICODE -DOBSERVER_DLL_EXPORTS -o "%OUTPUT_DIR%\observer.dll" "%BUILD_DIR%\observer_dll.o" -Wl,--out-implib,"%BUILD_DIR%\libobserver.a" -lpdh -lpsapi -ladvapi32 -lwintrust -lcrypt32 -lkernel32 -luser32
if !errorlevel! neq 0 goto fail

echo [BUILD] Compiling observer.exe...
"%MINGW%\g++.exe" -c -O2 -std=c++17 -DUNICODE -D_UNICODE -DQT_NO_DEBUG -DQT_WIDGETS_LIB -DQT_GUI_LIB -DQT_CORE_LIB -I"%QT_ROOT%\include" -I"%QT_ROOT%\include\QtCore" -I"%QT_ROOT%\include\QtGui" -I"%QT_ROOT%\include\QtWidgets" -I"%BUILD_DIR%" observer_app.cpp -o "%BUILD_DIR%\observer_app.o"
if !errorlevel! neq 0 goto fail

"%MINGW%\g++.exe" -o "%OUTPUT_DIR%\observer.exe" "%BUILD_DIR%\observer_app.o" -L"%QT_ROOT%\lib" -lQt6Core -lQt6Gui -lQt6Widgets -lkernel32 -luser32 -lpsapi -ladvapi32 -lwintrust -lcrypt32 -lpdh -lgdi32 -mwindows
if !errorlevel! neq 0 goto fail

echo [BUILD] Copying Qt platform plugin for standalone run...
xcopy /E /I /Y "%ROOT%..\bin\platforms" "%OUTPUT_DIR%\platforms" >nul 2>&1

echo.
echo [BUILD] SUCCESS
echo   observer.dll -> %OUTPUT_DIR%
echo   observer.exe -> %OUTPUT_DIR%
echo.
if "%NOPAUSE%"=="" pause
exit /b 0

:fail
echo.
echo [BUILD] FAILED
echo.
if "%NOPAUSE%"=="" pause
exit /b 1
