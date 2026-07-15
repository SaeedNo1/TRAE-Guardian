$MINGW = "C:\c\mingw1310\mingw64\bin"
$env:PATH = "$MINGW;$env:PATH"
$BUILD_DIR = "build"
$OUTPUT_DIR = "bin"

Write-Host "========================================"
Write-Host "TRAE Guardian - MSVCRT Full Build (MinGW 13.1.0)"
Write-Host "========================================"

if (!(Test-Path $BUILD_DIR)) { New-Item -ItemType Directory -Path $BUILD_DIR | Out-Null }
if (!(Test-Path $OUTPUT_DIR)) { New-Item -ItemType Directory -Path $OUTPUT_DIR | Out-Null }

function Invoke-BuildStep {
    param([string]$Name, [scriptblock]$Block, [switch]$AllowFail)
    Write-Host "[BUILD] $Name..."
    & $Block
    if ($LASTEXITCODE -ne 0) {
        if ($AllowFail) {
            Write-Host "WARNING: $Name failed" -ForegroundColor Yellow
        } else {
            Write-Host "ERROR: $Name failed" -ForegroundColor Red
            exit 1
        }
    }
}

Invoke-BuildStep "Compiling core.c" { & "$MINGW\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE core.c -o "$BUILD_DIR\core.o" }
Invoke-BuildStep "Compiling ai_service.c" { & "$MINGW\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE ai_service.c -o "$BUILD_DIR\ai_service.o" }
Invoke-BuildStep "Compiling partition_edit.c" { & "$MINGW\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE partition_edit.c -o "$BUILD_DIR\partition_edit.o" }
Invoke-BuildStep "Compiling registry_tree.c" { & "$MINGW\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE registry_tree.c -o "$BUILD_DIR\registry_tree.o" }
Invoke-BuildStep "Compiling registry_manager.c (static)" { & "$MINGW\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE registry_manager.c -o "$BUILD_DIR\registry_manager_static.o" }
Invoke-BuildStep "Compiling gui_ai.c" { & "$MINGW\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE gui_ai.c -o "$BUILD_DIR\gui_ai.o" }
Invoke-BuildStep "Compiling main_pro.c" { & "$MINGW\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE main_pro.c -o "$BUILD_DIR\main.o" }
Invoke-BuildStep "Compiling resource.rc" { & "$MINGW\windres.exe" -DUNICODE -D_UNICODE resource.rc -O coff -o "$BUILD_DIR\resource.o" }

Invoke-BuildStep "Linking legacy GUI executable" {
    & "$MINGW\gcc.exe" -o "$OUTPUT_DIR\trae_guardian.exe" `
        "$BUILD_DIR\core.o" "$BUILD_DIR\ai_service.o" "$BUILD_DIR\partition_edit.o" "$BUILD_DIR\registry_tree.o" "$BUILD_DIR\registry_manager_static.o" "$BUILD_DIR\gui_ai.o" "$BUILD_DIR\main.o" "$BUILD_DIR\resource.o" `
        -lkernel32 -luser32 -lpsapi -ladvapi32 -lwinhttp -lcomctl32 -lole32 -loleaut32 -lgdi32 -lgdiplus `
        -mwindows
} -AllowFail

Write-Host ""
Write-Host "[BUILD] Compiling extensions..."

if (!(Test-Path "$OUTPUT_DIR\core")) { New-Item -ItemType Directory -Path "$OUTPUT_DIR\core" | Out-Null }
if (!(Test-Path "$OUTPUT_DIR\AI")) { New-Item -ItemType Directory -Path "$OUTPUT_DIR\AI" | Out-Null }
if (!(Test-Path "$OUTPUT_DIR\Observe")) { New-Item -ItemType Directory -Path "$OUTPUT_DIR\Observe" | Out-Null }
if (!(Test-Path "$OUTPUT_DIR\permission")) { New-Item -ItemType Directory -Path "$OUTPUT_DIR\permission" | Out-Null }

Invoke-BuildStep "service_manager.dll" { & "$MINGW\gcc.exe" -shared -O2 -Wall -DBUILD_SERVICE_MANAGER_DLL service_manager.c -o "$OUTPUT_DIR\core\service_manager.dll" -ladvapi32 } -AllowFail
Invoke-BuildStep "registry_manager.dll" { & "$MINGW\gcc.exe" -shared -O2 -Wall -DBUILD_REGISTRY_MANAGER_DLL registry_manager.c -o "$OUTPUT_DIR\core\registry_manager.dll" -ladvapi32 } -AllowFail
Invoke-BuildStep "partition_manager.dll" { & "$MINGW\gcc.exe" -shared -O2 -Wall -DBUILD_PARTITION_MANAGER_DLL partition_manager.c partition_edit.c -o "$OUTPUT_DIR\core\partition_manager.dll" -lkernel32 } -AllowFail
Invoke-BuildStep "ai_action.dll" { & "$MINGW\gcc.exe" -shared -O2 -Wall -DBUILD_AI_ACTION_DLL ai_action.c -o "$OUTPUT_DIR\AI\ai_action.dll" -lwinhttp } -AllowFail
Invoke-BuildStep "ai_client.dll" { & "$MINGW\gcc.exe" -shared -O2 -Wall -DBUILD_AI_CLIENT_DLL ai_client.c -o "$OUTPUT_DIR\AI\ai_client.dll" -lwinhttp } -AllowFail
Invoke-BuildStep "log_compressor.dll" { & "$MINGW\gcc.exe" -shared -O2 -Wall -DBUILD_LOG_COMPRESSOR_DLL log_compressor.c -o "$OUTPUT_DIR\AI\log_compressor.dll" } -AllowFail
Invoke-BuildStep "log_searcher.dll" { & "$MINGW\gcc.exe" -shared -O2 -Wall -DBUILD_LOG_SEARCHER_DLL log_searcher.c -o "$OUTPUT_DIR\AI\log_searcher.dll" } -AllowFail

Invoke-BuildStep "Compiling daemon_core.c" { & "$MINGW\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE daemon_core.c -o "$BUILD_DIR\daemon_core.o" }
Invoke-BuildStep "Compiling trust_zone.c" { & "$MINGW\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE trust_zone.c -o "$BUILD_DIR\trust_zone.o" }
Invoke-BuildStep "Compiling etw_monitor.c" { & "$MINGW\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE etw_monitor.c -o "$BUILD_DIR\etw_monitor.o" }
Invoke-BuildStep "Compiling state_machine.c" { & "$MINGW\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE state_machine.c -o "$BUILD_DIR\state_machine.o" }
Invoke-BuildStep "Compiling rule_engine.c" { & "$MINGW\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE rule_engine.c -o "$BUILD_DIR\rule_engine.o" }
Invoke-BuildStep "Compiling score_center.c" { & "$MINGW\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE score_center.c -o "$BUILD_DIR\score_center.o" }
Invoke-BuildStep "Compiling response_center.c" { & "$MINGW\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE response_center.c -o "$BUILD_DIR\response_center.o" }
Invoke-BuildStep "Compiling whitelist_db.c" { & "$MINGW\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE whitelist_db.c -o "$BUILD_DIR\whitelist_db.o" }
Invoke-BuildStep "Compiling config_json.c" { & "$MINGW\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE config_json.c -o "$BUILD_DIR\config_json.o" }
Invoke-BuildStep "Compiling sqlite_log.c" { & "$MINGW\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE sqlite_log.c -o "$BUILD_DIR\sqlite_log.o" }
Invoke-BuildStep "Compiling thread_modules.c" { & "$MINGW\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE thread_modules.c -o "$BUILD_DIR\thread_modules.o" }
Invoke-BuildStep "Compiling virus_signature.c" { & "$MINGW\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE virus_signature.c -o "$BUILD_DIR\virus_signature.o" }
Invoke-BuildStep "Compiling network_monitor.c" { & "$MINGW\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE network_monitor.c -o "$BUILD_DIR\network_monitor.o" }
Invoke-BuildStep "Compiling user_interaction.c" { & "$MINGW\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE user_interaction.c -o "$BUILD_DIR\user_interaction.o" }
Invoke-BuildStep "Compiling pe_analysis.c" { & "$MINGW\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE pe_analysis.c -o "$BUILD_DIR\pe_analysis.o" }
Invoke-BuildStep "Linking daemon" {
    & "$MINGW\gcc.exe" -O2 -Wall -DUNICODE -D_UNICODE trae_guardian_daemon.c "$BUILD_DIR\daemon_core.o" "$BUILD_DIR\trust_zone.o" "$BUILD_DIR\etw_monitor.o" "$BUILD_DIR\state_machine.o" "$BUILD_DIR\rule_engine.o" "$BUILD_DIR\score_center.o" "$BUILD_DIR\response_center.o" "$BUILD_DIR\whitelist_db.o" "$BUILD_DIR\config_json.o" "$BUILD_DIR\sqlite_log.o" "$BUILD_DIR\thread_modules.o" "$BUILD_DIR\virus_signature.o" "$BUILD_DIR\network_monitor.o" "$BUILD_DIR\user_interaction.o" "$BUILD_DIR\pe_analysis.o" -o "$OUTPUT_DIR\trae_guardian_daemon.exe" -mwindows -lwintrust -lcrypt32 -lpsapi -ltdh -liphlpapi -lws2_32 -lshell32 -lole32
} -AllowFail

Invoke-BuildStep "service installer" { & "$MINGW\gcc.exe" -O2 -Wall -DUNICODE -D_UNICODE -municode install_service.c -o "$OUTPUT_DIR\permission\install_service.exe" -mwindows -ladvapi32 } -AllowFail
Invoke-BuildStep "service wrapper" { & "$MINGW\gcc.exe" -O2 -Wall -DUNICODE -D_UNICODE -municode trae_guardian_service_wrapper.c -o "$OUTPUT_DIR\permission\trae_guardian_service_wrapper.exe" -mconsole -ladvapi32 } -AllowFail

Invoke-BuildStep "observer tools" {
    $env:NOPAUSE = "1"
    & "$PSScriptRoot\observer\build_observer.bat"
    $env:NOPAUSE = ""
} -AllowFail

if (!(Test-Path "$OUTPUT_DIR\data")) { New-Item -ItemType Directory -Path "$OUTPUT_DIR\data" | Out-Null }

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "BUILD SUCCESSFUL!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
