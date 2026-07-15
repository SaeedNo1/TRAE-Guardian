@echo off
setlocal enabledelayedexpansion
set "QT_ROOT=C:\c\Qt\6.8.3\mingw_64"
set "SCRIPT_DIR=%~dp0"

echo [BUILD] Updating translations...
"%QT_ROOT%\bin\lupdate.exe" "%SCRIPT_DIR%\trae_guardian_qt.pro"

echo [BUILD] Releasing translations...
"%QT_ROOT%\bin\lrelease.exe" "%SCRIPT_DIR%\trae_guardian_qt.pro"

if not exist "%SCRIPT_DIR%..\bin\translations" mkdir "%SCRIPT_DIR%..\bin\translations"
copy /Y "%SCRIPT_DIR%\*.qm" "%SCRIPT_DIR%..\bin\translations\"

echo [BUILD] Done. .qm files copied to ../bin/translations/.
pause
