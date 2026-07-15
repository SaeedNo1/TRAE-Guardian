@echo off
echo ============================================
echo Process Guardian - Cleanup and Restart
echo ============================================
echo.

echo [STEP 1] Stopping GuardianDaemon service...
sc stop GuardianDaemon 2>NUL
sc delete GuardianDaemon 2>NUL
echo Done.

echo.
echo [STEP 2] Killing all guardian processes...
taskkill /F /IM trae_guardian_daemon.exe 2>NUL
taskkill /F /IM trae_guardian_qt.exe 2>NUL
taskkill /F /IM trae_guardian.exe 2>NUL
echo Done.

echo.
echo [STEP 3] Waiting for processes to terminate...
timeout /t 3 /nobreak >NUL
echo Done.

echo.
echo [STEP 4] Starting Process Guardian Qt GUI...
start "" "%~dp0trae_guardian_qt.exe"
echo Done.

echo.
echo [STEP 5] Checking process status...
timeout /t 2 /nobreak >NUL
tasklist | findstr trae_guardian
echo.
echo ============================================
echo Operation completed!
echo ============================================
pause
