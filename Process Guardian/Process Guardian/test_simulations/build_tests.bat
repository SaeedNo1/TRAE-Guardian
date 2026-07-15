@echo off
setlocal enabledelayedexpansion

set GCC=gcc
set OUT_DIR=..\bin
set CFLAGS=-O2 -Wall -Wextra -std=c11 -m64

echo Building test simulation programs...

if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

echo Compiling test_inject_sim.c...
%GCC% %CFLAGS% test_inject_sim.c -o "%OUT_DIR%\test_inject_sim.exe" -lkernel32
if %errorlevel% neq 0 echo FAILED!

echo Compiling test_reg_sim.c...
%GCC% %CFLAGS% test_reg_sim.c -o "%OUT_DIR%\test_reg_sim.exe" -lkernel32
if %errorlevel% neq 0 echo FAILED!

echo Compiling test_file_encrypt_sim.c...
%GCC% %CFLAGS% test_file_encrypt_sim.c -o "%OUT_DIR%\test_file_encrypt_sim.exe" -lkernel32
if %errorlevel% neq 0 echo FAILED!

echo Compiling test_bsod_sim.c...
%GCC% %CFLAGS% test_bsod_sim.c -o "%OUT_DIR%\test_bsod_sim.exe" -lkernel32 -lntdll
if %errorlevel% neq 0 echo FAILED!

echo.
echo Build completed! Test programs are in %OUT_DIR%
echo.
echo To test:
echo   1. Start the daemon: ..\bin\trae_guardian_daemon.exe
echo   2. Run test programs:
echo      test_inject_sim.exe     - Tests injection detection
echo      test_reg_sim.exe        - Tests registry tampering detection
echo      test_file_encrypt_sim.exe - Tests ransomware detection
echo      test_bsod_sim.exe       - Tests BSOD attack detection