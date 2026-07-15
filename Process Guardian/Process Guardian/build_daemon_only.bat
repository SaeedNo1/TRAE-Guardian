@echo off
setlocal
cd /d "c:\Users\BaikerrNO1\Documents\trae_projects\Process Guardian\Process Guardian"
set "MINGW=D:\Program Files\mingw64\bin"
set "PATH=%MINGW%;%PATH%"
set "BUILD_DIR=build"
set "OUTPUT_DIR=bin"

echo [BUILD] Compiling hash_table.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE hash_table.c -o "%BUILD_DIR%\hash_table.o" 2>&1

echo [BUILD] Compiling daemon_core.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE daemon_core.c -o "%BUILD_DIR%\daemon_core.o" 2>&1

echo [BUILD] Compiling trust_zone.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE trust_zone.c -o "%BUILD_DIR%\trust_zone.o" 2>&1

echo [BUILD] Compiling etw_monitor.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE etw_monitor.c -o "%BUILD_DIR%\etw_monitor.o" 2>&1

echo [BUILD] Compiling state_machine.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE state_machine.c -o "%BUILD_DIR%\state_machine.o" 2>&1

echo [BUILD] Compiling rule_engine.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE rule_engine.c -o "%BUILD_DIR%\rule_engine.o" 2>&1

echo [BUILD] Compiling score_center.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE score_center.c -o "%BUILD_DIR%\score_center.o" 2>&1

echo [BUILD] Compiling response_center.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE response_center.c -o "%BUILD_DIR%\response_center.o" 2>&1

echo [BUILD] Compiling whitelist_db.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE whitelist_db.c -o "%BUILD_DIR%\whitelist_db.o" 2>&1

echo [BUILD] Compiling config_json.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE config_json.c -o "%BUILD_DIR%\config_json.o" 2>&1

echo [BUILD] Compiling sqlite_log.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE sqlite_log.c -o "%BUILD_DIR%\sqlite_log.o" 2>&1

echo [BUILD] Compiling thread_modules.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE thread_modules.c -o "%BUILD_DIR%\thread_modules.o" 2>&1

echo [BUILD] Compiling virus_signature.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE virus_signature.c -o "%BUILD_DIR%\virus_signature.o" 2>&1

echo [BUILD] Compiling network_monitor.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE network_monitor.c -o "%BUILD_DIR%\network_monitor.o" 2>&1

echo [BUILD] Compiling user_interaction.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE user_interaction.c -o "%BUILD_DIR%\user_interaction.o" 2>&1

echo [BUILD] Compiling pe_analysis.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE pe_analysis.c -o "%BUILD_DIR%\pe_analysis.o" 2>&1

echo [BUILD] Compiling direct_syscall_detector.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE direct_syscall_detector.c -o "%BUILD_DIR%\direct_syscall_detector.o" 2>&1

echo [BUILD] Compiling hook_pipe_server.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE hook_pipe_server.c -o "%BUILD_DIR%\hook_pipe_server.o" 2>&1

echo [LINK] Linking daemon...
"%MINGW%\gcc.exe" -O2 -Wall -DUNICODE -D_UNICODE -municode "%BUILD_DIR%\hash_table.o" "%BUILD_DIR%\daemon_core.o" "%BUILD_DIR%\trust_zone.o" "%BUILD_DIR%\etw_monitor.o" "%BUILD_DIR%\state_machine.o" "%BUILD_DIR%\rule_engine.o" "%BUILD_DIR%\score_center.o" "%BUILD_DIR%\response_center.o" "%BUILD_DIR%\whitelist_db.o" "%BUILD_DIR%\config_json.o" "%BUILD_DIR%\sqlite_log.o" "%BUILD_DIR%\thread_modules.o" "%BUILD_DIR%\virus_signature.o" "%BUILD_DIR%\network_monitor.o" "%BUILD_DIR%\user_interaction.o" "%BUILD_DIR%\pe_analysis.o" "%BUILD_DIR%\direct_syscall_detector.o" "%BUILD_DIR%\hook_pipe_server.o" -o "%OUTPUT_DIR%\trae_guardian_daemon.exe" -mwindows -lwintrust -lcrypt32 -lpsapi -ltdh -liphlpapi -lws2_32 -lshell32 -lole32 -lshlwapi 2>&1

echo [BUILD] Compiling guardian_hook.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE -Iminhook guardian_hook.c -o "%BUILD_DIR%\guardian_hook.o" 2>&1

echo [BUILD] Compiling minhook/MinHook.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE -Iminhook minhook/MinHook.c -o "%BUILD_DIR%\MinHook.o" 2>&1

echo [BUILD] Compiling minhook/hde32.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE -Iminhook minhook/hde32.c -o "%BUILD_DIR%\hde32.o" 2>&1

echo [BUILD] Compiling minhook/hde64.c...
"%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE -Iminhook minhook/hde64.c -o "%BUILD_DIR%\hde64.o" 2>&1

echo [LINK] Linking guardian_hook.dll...
"%MINGW%\gcc.exe" -O2 -Wall -DUNICODE -D_UNICODE -shared -o "%OUTPUT_DIR%\guardian_hook.dll" "%BUILD_DIR%\guardian_hook.o" "%BUILD_DIR%\MinHook.o" "%BUILD_DIR%\hde32.o" "%BUILD_DIR%\hde64.o" -lwintrust -lcrypt32 -lpsapi 2>&1

echo Done!
endlocal