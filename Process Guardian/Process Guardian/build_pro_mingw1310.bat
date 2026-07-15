@echo off
setlocal enabledelayedexpansion

set "MINGW=C:\c\mingw1310\mingw64\bin"
set "PATH=%MINGW%;%PATH%"
set "BUILD_DIR=build"
set "OUTPUT_DIR=bin"

echo ========================================
echo TRAE Guardian - MSVCRT Full Build (MinGW 13.1.0)
echo ========================================
echo.

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"
if not exist "%OUTPUT_DIR%\core" mkdir "%OUTPUT_DIR%\core"
if not exist "%OUTPUT_DIR%\AI" mkdir "%OUTPUT_DIR%\AI"
if not exist "%OUTPUT_DIR%\Observe" mkdir "%OUTPUT_DIR%\Observe"
if not exist "%OUTPUT_DIR%\permission" mkdir "%OUTPUT_DIR%\permission"

echo [BUILD] Compiling core.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE core.c -o "%BUILD_DIR%\core.o" 2>&1 || (echo ERROR: Failed to compile core.c & exit /b 1)

echo [BUILD] Compiling ai_service.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE ai_service.c -o "%BUILD_DIR%\ai_service.o" 2>&1 || (echo ERROR: Failed to compile ai_service.c & exit /b 1)

echo [BUILD] Compiling partition_edit.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE partition_edit.c -o "%BUILD_DIR%\partition_edit.o" 2>&1 || (echo ERROR: Failed to compile partition_edit.c & exit /b 1)

echo [BUILD] Compiling registry_tree.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE registry_tree.c -o "%BUILD_DIR%\registry_tree.o" 2>&1 || (echo ERROR: Failed to compile registry_tree.c & exit /b 1)

echo [BUILD] Compiling registry_manager.c (static)...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE registry_manager.c -o "%BUILD_DIR%\registry_manager_static.o" 2>&1 || (echo ERROR: Failed to compile registry_manager.c (static) & exit /b 1)

echo [BUILD] Compiling gui_ai.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE gui_ai.c -o "%BUILD_DIR%\gui_ai.o" 2>&1 || (echo ERROR: Failed to compile gui_ai.c & exit /b 1)

echo [BUILD] Compiling main_pro.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE main_pro.c -o "%BUILD_DIR%\main.o" 2>&1 || (echo ERROR: Failed to compile main_pro.c & exit /b 1)

echo [BUILD] Compiling resource.rc...
"%MINGW%\windres.exe" -DUNICODE -D_UNICODE resource.rc -O coff -o "%BUILD_DIR%\resource.o" 2>&1 || (echo ERROR: Failed to compile resource.rc & exit /b 1)

echo [LINK] Linking legacy GUI executable...
"%MINGW%\gcc.exe" -o "%OUTPUT_DIR%\trae_guardian.exe" ^
    "%BUILD_DIR%\core.o" "%BUILD_DIR%\ai_service.o" "%BUILD_DIR%\partition_edit.o" "%BUILD_DIR%\registry_tree.o" "%BUILD_DIR%\registry_manager_static.o" "%BUILD_DIR%\gui_ai.o" "%BUILD_DIR%\main.o" "%BUILD_DIR%\resource.o" ^
    -lkernel32 -luser32 -lpsapi -ladvapi32 -lwinhttp -lcomctl32 -lole32 -loleaut32 -lgdi32 -lgdiplus ^
    -mwindows 2>&1 || echo WARNING: Failed to link legacy executable (Qt GUI can still be built)

echo.
echo [BUILD] Compiling extensions...

"%MINGW%\gcc.exe" -shared -O2 -Wall -DBUILD_SERVICE_MANAGER_DLL service_manager.c -o "%OUTPUT_DIR%\core\service_manager.dll" -ladvapi32 2>&1 || echo WARNING: service_manager.dll failed
"%MINGW%\gcc.exe" -shared -O2 -Wall -DBUILD_REGISTRY_MANAGER_DLL registry_manager.c -o "%OUTPUT_DIR%\core\registry_manager.dll" -ladvapi32 2>&1 || echo WARNING: registry_manager.dll failed
"%MINGW%\gcc.exe" -shared -O2 -Wall -DBUILD_PARTITION_MANAGER_DLL partition_manager.c partition_edit.c -o "%OUTPUT_DIR%\core\partition_manager.dll" -lkernel32 2>&1 || echo WARNING: partition_manager.dll failed
"%MINGW%\gcc.exe" -shared -O2 -Wall -DBUILD_AI_ACTION_DLL ai_action.c -o "%OUTPUT_DIR%\AI\ai_action.dll" -lwinhttp 2>&1 || echo WARNING: ai_action.dll failed
"%MINGW%\gcc.exe" -shared -O2 -Wall -DBUILD_AI_CLIENT_DLL ai_client.c -o "%OUTPUT_DIR%\AI\ai_client.dll" -lwinhttp 2>&1 || echo WARNING: ai_client.dll failed
"%MINGW%\gcc.exe" -shared -O2 -Wall -DBUILD_LOG_COMPRESSOR_DLL log_compressor.c -o "%OUTPUT_DIR%\AI\log_compressor.dll" 2>&1 || echo WARNING: log_compressor.dll failed
"%MINGW%\gcc.exe" -shared -O2 -Wall -DBUILD_LOG_SEARCHER_DLL log_searcher.c -o "%OUTPUT_DIR%\AI\log_searcher.dll" 2>&1 || echo WARNING: log_searcher.dll failed
"%MINGW%\gcc.exe" -shared -O2 -Wall -DBUILD_AI_WEB_SEARCH_DLL ai_web_search.c -o "%OUTPUT_DIR%\AI\ai_web_search.dll" -lwinhttp 2>&1 || echo WARNING: ai_web_search.dll failed

echo [BUILD] Compiling daemon...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE hash_table.c -o "%BUILD_DIR%\hash_table.o" 2>&1 || (echo ERROR: Failed to compile hash_table.c & exit /b 1)
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE daemon_core.c -o "%BUILD_DIR%\daemon_core.o" 2>&1 || (echo ERROR: Failed to compile daemon_core.c & exit /b 1)
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE trust_zone.c -o "%BUILD_DIR%\trust_zone.o" 2>&1 || (echo ERROR: Failed to compile trust_zone.c & exit /b 1)
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE etw_monitor.c -o "%BUILD_DIR%\etw_monitor.o" 2>&1 || (echo ERROR: Failed to compile etw_monitor.c & exit /b 1)
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE state_machine.c -o "%BUILD_DIR%\state_machine.o" 2>&1 || (echo ERROR: Failed to compile state_machine.c & exit /b 1)
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE rule_engine.c -o "%BUILD_DIR%\rule_engine.o" 2>&1 || (echo ERROR: Failed to compile rule_engine.c & exit /b 1)
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE score_center.c -o "%BUILD_DIR%\score_center.o" 2>&1 || (echo ERROR: Failed to compile score_center.c & exit /b 1)
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE response_center.c -o "%BUILD_DIR%\response_center.o" 2>&1 || (echo ERROR: Failed to compile response_center.c & exit /b 1)
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE whitelist_db.c -o "%BUILD_DIR%\whitelist_db.o" 2>&1 || (echo ERROR: Failed to compile whitelist_db.c & exit /b 1)
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE config_json.c -o "%BUILD_DIR%\config_json.o" 2>&1 || (echo ERROR: Failed to compile config_json.c & exit /b 1)
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE sqlite_log.c -o "%BUILD_DIR%\sqlite_log.o" 2>&1 || (echo ERROR: Failed to compile sqlite_log.c & exit /b 1)
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE thread_modules.c -o "%BUILD_DIR%\thread_modules.o" 2>&1 || (echo ERROR: Failed to compile thread_modules.c & exit /b 1)
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE virus_signature.c -o "%BUILD_DIR%\virus_signature.o" 2>&1 || (echo ERROR: Failed to compile virus_signature.c & exit /b 1)
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE network_monitor.c -o "%BUILD_DIR%\network_monitor.o" 2>&1 || (echo ERROR: Failed to compile network_monitor.c & exit /b 1)
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE user_interaction.c -o "%BUILD_DIR%\user_interaction.o" 2>&1 || (echo ERROR: Failed to compile user_interaction.c & exit /b 1)
echo [BUILD] Compiling pe_analysis.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE pe_analysis.c -o "%BUILD_DIR%\pe_analysis.o" 2>&1 || (echo ERROR: Failed to compile pe_analysis.c & exit /b 1)
"%MINGW%\gcc.exe" -O2 -Wall -DUNICODE -D_UNICODE -municode "%BUILD_DIR%\hash_table.o" "%BUILD_DIR%\daemon_core.o" "%BUILD_DIR%\trust_zone.o" "%BUILD_DIR%\etw_monitor.o" "%BUILD_DIR%\state_machine.o" "%BUILD_DIR%\rule_engine.o" "%BUILD_DIR%\score_center.o" "%BUILD_DIR%\response_center.o" "%BUILD_DIR%\whitelist_db.o" "%BUILD_DIR%\config_json.o" "%BUILD_DIR%\sqlite_log.o" "%BUILD_DIR%\thread_modules.o" "%BUILD_DIR%\virus_signature.o" "%BUILD_DIR%\network_monitor.o" "%BUILD_DIR%\user_interaction.o" "%BUILD_DIR%\pe_analysis.o" -o "%OUTPUT_DIR%\trae_guardian_daemon.exe" -mwindows -lwintrust -lcrypt32 -lpsapi -ltdh -liphlpapi -lws2_32 -lshell32 -lole32 2>&1 || echo WARNING: trae_guardian_daemon.exe failed

echo [BUILD] Compiling service wrapper...
"%MINGW%\gcc.exe" -O2 -Wall -DUNICODE -D_UNICODE -municode trae_guardian_service_wrapper.c -o "%OUTPUT_DIR%\permission\trae_guardian_service_wrapper.exe" -mconsole -ladvapi32 2>&1 || echo WARNING: trae_guardian_service_wrapper.exe failed

echo [BUILD] Compiling service installer...
"%MINGW%\gcc.exe" -O2 -Wall -DUNICODE -D_UNICODE -municode install_service.c -o "%OUTPUT_DIR%\permission\install_service.exe" -mwindows -ladvapi32 2>&1 || echo WARNING: install_service.exe failed

echo.
echo [COPY] Creating data directory...
if not exist "%OUTPUT_DIR%\data" mkdir "%OUTPUT_DIR%\data"

echo.
echo ========================================
echo BUILD SUCCESSFUL!
echo ========================================
echo.
endlocal
exit /b 0
