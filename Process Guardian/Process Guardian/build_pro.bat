@echo off
setlocal enabledelayedexpansion

echo ========================================
echo TRAE Guardian - Professional Build Script
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

echo [BUILD] Compiling partition_edit.c...
gcc -c -O2 -Wall -DUNICODE -D_UNICODE partition_edit.c -o "%BUILD_DIR%\partition_edit.o"
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile partition_edit.c
    pause
    exit /b 1
)

echo [BUILD] Compiling registry_tree.c...
gcc -c -O2 -Wall -DUNICODE -D_UNICODE registry_tree.c -o "%BUILD_DIR%\registry_tree.o"
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile registry_tree.c
    pause
    exit /b 1
)

echo [BUILD] Compiling registry_manager.c (static)...
gcc -c -O2 -Wall -DUNICODE -D_UNICODE registry_manager.c -o "%BUILD_DIR%\registry_manager_static.o"
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile registry_manager.c
    pause
    exit /b 1
)

echo [BUILD] Compiling gui_ai.c...
gcc -c -O2 -Wall -DUNICODE -D_UNICODE gui_ai.c -o "%BUILD_DIR%\gui_ai.o"
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile gui_ai.c
    pause
    exit /b 1
)

echo [BUILD] Compiling main_pro.c...
gcc -c -O2 -Wall -DUNICODE -D_UNICODE main_pro.c -o "%BUILD_DIR%\main.o"
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile main_pro.c
    pause
    exit /b 1
)

echo [BUILD] Compiling resource.rc...
windres -DUNICODE -D_UNICODE resource.rc -O coff -o "%BUILD_DIR%\resource.o"
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile resource.rc
    pause
    exit /b 1
)

echo [LINK] Linking executable...
gcc -o "%OUTPUT_DIR%\trae_guardian.exe" ^
    "%BUILD_DIR%\core.o" "%BUILD_DIR%\ai_service.o" "%BUILD_DIR%\partition_edit.o" "%BUILD_DIR%\registry_tree.o" "%BUILD_DIR%\registry_manager_static.o" "%BUILD_DIR%\gui_ai.o" "%BUILD_DIR%\main.o" "%BUILD_DIR%\resource.o" ^
    -lkernel32 -luser32 -lpsapi -ladvapi32 -lwinhttp -lcomctl32 -lole32 -loleaut32 -lgdi32 -lgdiplus ^
    -mwindows -static-libgcc -static-libstdc++
if !errorlevel! neq 0 (
    echo ERROR: Failed to link executable
    pause
    exit /b 1
)

echo.
echo [BUILD] Compiling extensions...

gcc -shared -O2 -Wall -DUNICODE -D_UNICODE -DBUILD_SERVICE_MANAGER_DLL service_manager.c -o "%OUTPUT_DIR%\service_manager.dll" -ladvapi32
if !errorlevel! neq 0 echo WARNING: service_manager.dll failed

gcc -shared -O2 -Wall -DUNICODE -D_UNICODE -DBUILD_REGISTRY_MANAGER_DLL registry_manager.c -o "%OUTPUT_DIR%\registry_manager.dll" -ladvapi32
if !errorlevel! neq 0 echo WARNING: registry_manager.dll failed

gcc -shared -O2 -Wall -DUNICODE -D_UNICODE -DBUILD_PARTITION_MANAGER_DLL partition_manager.c partition_edit.c -o "%OUTPUT_DIR%\partition_manager.dll" -lkernel32
if !errorlevel! neq 0 echo WARNING: partition_manager.dll failed

gcc -shared -O2 -Wall -DUNICODE -D_UNICODE -DBUILD_AI_ACTION_DLL ai_action.c -o "%OUTPUT_DIR%\ai_action.dll" -lwinhttp
if !errorlevel! neq 0 echo WARNING: ai_action.dll failed

gcc -shared -O2 -Wall -DUNICODE -D_UNICODE -DBUILD_AI_CLIENT_DLL ai_client.c -o "%OUTPUT_DIR%\ai_client.dll" -lwinhttp
if !errorlevel! neq 0 echo WARNING: ai_client.dll failed

gcc -shared -O2 -Wall -DUNICODE -D_UNICODE -DBUILD_LOG_COMPRESSOR_DLL log_compressor.c -o "%OUTPUT_DIR%\log_compressor.dll"
if !errorlevel! neq 0 echo WARNING: log_compressor.dll failed

gcc -shared -O2 -Wall -DUNICODE -D_UNICODE -DBUILD_LOG_SEARCHER_DLL log_searcher.c -o "%OUTPUT_DIR%\log_searcher.dll"
if !errorlevel! neq 0 echo WARNING: log_searcher.dll failed

echo [BUILD] Compiling daemon...
gcc -c -O2 -Wall -DUNICODE -D_UNICODE daemon_core.c -o "%BUILD_DIR%\daemon_core.o"
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile daemon_core.c
    pause
    exit /b 1
)
gcc -c -O2 -Wall -DUNICODE -D_UNICODE trust_zone.c -o "%BUILD_DIR%\trust_zone.o"
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile trust_zone.c
    pause
    exit /b 1
)
gcc -c -O2 -Wall -DUNICODE -D_UNICODE etw_monitor.c -o "%BUILD_DIR%\etw_monitor.o"
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile etw_monitor.c
    pause
    exit /b 1
)
echo [BUILD] Compiling state_machine.c...
gcc -c -O2 -Wall -DUNICODE -D_UNICODE state_machine.c -o "%BUILD_DIR%\state_machine.o"
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile state_machine.c
    pause
    exit /b 1
)
echo [BUILD] Compiling rule_engine.c...
gcc -c -O2 -Wall -DUNICODE -D_UNICODE rule_engine.c -o "%BUILD_DIR%\rule_engine.o"
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile rule_engine.c
    pause
    exit /b 1
)
echo [BUILD] Compiling score_center.c...
gcc -c -O2 -Wall -DUNICODE -D_UNICODE score_center.c -o "%BUILD_DIR%\score_center.o"
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile score_center.c
    pause
    exit /b 1
)
echo [BUILD] Compiling response_center.c...
gcc -c -O2 -Wall -DUNICODE -D_UNICODE response_center.c -o "%BUILD_DIR%\response_center.o"
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile response_center.c
    pause
    exit /b 1
)
echo [BUILD] Compiling whitelist_db.c...
gcc -c -O2 -Wall -DUNICODE -D_UNICODE whitelist_db.c -o "%BUILD_DIR%\whitelist_db.o"
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile whitelist_db.c
    pause
    exit /b 1
)
echo [BUILD] Compiling config_json.c...
gcc -c -O2 -Wall -DUNICODE -D_UNICODE config_json.c -o "%BUILD_DIR%\config_json.o"
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile config_json.c
    pause
    exit /b 1
)
echo [BUILD] Compiling sqlite_log.c...
gcc -c -O2 -Wall -DUNICODE -D_UNICODE sqlite_log.c -o "%BUILD_DIR%\sqlite_log.o"
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile sqlite_log.c
    pause
    exit /b 1
)
echo [BUILD] Compiling thread_modules.c...
gcc -c -O2 -Wall -DUNICODE -D_UNICODE thread_modules.c -o "%BUILD_DIR%\thread_modules.o"
if !errorlevel! neq 0 (
    echo ERROR: Failed to compile thread_modules.c
    pause
    exit /b 1
)
gcc -O2 -Wall -DUNICODE -D_UNICODE trae_guardian_daemon.c "%BUILD_DIR%\daemon_core.o" "%BUILD_DIR%\trust_zone.o" "%BUILD_DIR%\etw_monitor.o" "%BUILD_DIR%\state_machine.o" "%BUILD_DIR%\rule_engine.o" "%BUILD_DIR%\score_center.o" "%BUILD_DIR%\response_center.o" "%BUILD_DIR%\whitelist_db.o" "%BUILD_DIR%\config_json.o" "%BUILD_DIR%\sqlite_log.o" "%BUILD_DIR%\thread_modules.o" -o "%OUTPUT_DIR%\trae_guardian_daemon.exe" -mwindows -static-libgcc -lwintrust -lcrypt32 -lpsapi -ltdh -ladvapi32 -lws2_32 -liphlpapi
if !errorlevel! neq 0 echo WARNING: trae_guardian_daemon.exe failed

echo [BUILD] Compiling service wrapper...
gcc -O2 -Wall -DUNICODE -D_UNICODE -municode trae_guardian_service_wrapper.c -o "%OUTPUT_DIR%\trae_guardian_service_wrapper.exe" -mwindows -static-libgcc -ladvapi32
if !errorlevel! neq 0 echo WARNING: trae_guardian_service_wrapper.exe failed

echo [BUILD] Compiling service installer...
gcc -O2 -Wall -DUNICODE -D_UNICODE -municode install_service.c -o "%OUTPUT_DIR%\install_service.exe" -mwindows -static-libgcc -ladvapi32
if !errorlevel! neq 0 echo WARNING: install_service.exe failed

echo.
echo [COPY] Creating data directory...
if not exist "%OUTPUT_DIR%\data" mkdir "%OUTPUT_DIR%\data"

echo.
echo ========================================
echo BUILD SUCCESSFUL!
echo ========================================
echo Output: %CD%\%OUTPUT_DIR%\trae_guardian.exe
echo.
echo Features:
echo 1. Process Management - View and kill processes
echo 2. Service Management - Start/stop services
echo 3. Registry - View startup entries
echo 4. Drive Management - View disk partitions
echo 5. Task Management - Add/remove repeated kill tasks
echo 6. AI Chat - SiliconFlow API integration
echo 7. Toolbar - Refresh, toggle toolbar, exit
echo 8. Status Bar - Shows item counts
echo.
pause