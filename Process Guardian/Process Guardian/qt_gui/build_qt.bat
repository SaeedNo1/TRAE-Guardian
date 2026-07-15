@echo off
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "QT_ROOT=C:\c\Qt\6.8.3\mingw_64"
set "MINGW=C:\c\mingw1310\mingw64\bin"
set "PATH=%MINGW%;%PATH%"
set "BUILD_DIR=%SCRIPT_DIR%build_qt"
set "OUTPUT_DIR=%SCRIPT_DIR%..\bin"

cd /d "%SCRIPT_DIR%"

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo [BUILD] Generating moc files...
"%QT_ROOT%\bin\moc.exe" mainwindow.h -o "%BUILD_DIR%\moc_mainwindow.cpp"
"%QT_ROOT%\bin\moc.exe" processtab.h -o "%BUILD_DIR%\moc_processtab.cpp"
"%QT_ROOT%\bin\moc.exe" servicetab.h -o "%BUILD_DIR%\moc_servicetab.cpp"
"%QT_ROOT%\bin\moc.exe" registrytab.h -o "%BUILD_DIR%\moc_registrytab.cpp"
"%QT_ROOT%\bin\moc.exe" partitiontab.h -o "%BUILD_DIR%\moc_partitiontab.cpp"
"%QT_ROOT%\bin\moc.exe" settingsdialog.h -o "%BUILD_DIR%\moc_settingsdialog.cpp"
"%QT_ROOT%\bin\moc.exe" aichattab.h -o "%BUILD_DIR%\moc_aichattab.cpp"
"%QT_ROOT%\bin\moc.exe" livemonitortab.h -o "%BUILD_DIR%\moc_livemonitortab.cpp"
"%QT_ROOT%\bin\moc.exe" aihubtab.h -o "%BUILD_DIR%\moc_aihubtab.cpp"
"%QT_ROOT%\bin\moc.exe" taskchatdialog.h -o "%BUILD_DIR%\moc_taskchatdialog.cpp"
"%QT_ROOT%\bin\moc.exe" aiworker.h -o "%BUILD_DIR%\moc_aiworker.cpp"
"%QT_ROOT%\bin\moc.exe" ai_task_dialog.h -o "%BUILD_DIR%\moc_ai_task_dialog.cpp"
"%QT_ROOT%\bin\moc.exe" process_select_dialog.h -o "%BUILD_DIR%\moc_process_select_dialog.cpp"
"%QT_ROOT%\bin\moc.exe" roguesoftwaretab.h -o "%BUILD_DIR%\moc_roguesoftwaretab.cpp"

echo [BUILD] Compiling Qt GUI...
"%MINGW%\g++.exe" -c -O2 -std=c++17 -DUNICODE -D_UNICODE -DQT_NO_DEBUG -DQT_WIDGETS_LIB -DQT_GUI_LIB -DQT_CORE_LIB -I"%QT_ROOT%\include" -I"%QT_ROOT%\include\QtCore" -I"%QT_ROOT%\include\QtGui" -I"%QT_ROOT%\include\QtWidgets" -I.. main.cpp -o "%BUILD_DIR%\main.o"
if !errorlevel! neq 0 goto fail

"%MINGW%\g++.exe" -c -O2 -std=c++17 -DUNICODE -D_UNICODE -DQT_NO_DEBUG -DQT_WIDGETS_LIB -DQT_GUI_LIB -DQT_CORE_LIB -I"%QT_ROOT%\include" -I"%QT_ROOT%\include\QtCore" -I"%QT_ROOT%\include\QtGui" -I"%QT_ROOT%\include\QtWidgets" -I.. mainwindow.cpp -o "%BUILD_DIR%\mainwindow.o"
if !errorlevel! neq 0 goto fail

"%MINGW%\g++.exe" -c -O2 -std=c++17 -DUNICODE -D_UNICODE -DQT_NO_DEBUG -DQT_WIDGETS_LIB -DQT_GUI_LIB -DQT_CORE_LIB -I"%QT_ROOT%\include" -I"%QT_ROOT%\include\QtCore" -I"%QT_ROOT%\include\QtGui" -I"%QT_ROOT%\include\QtWidgets" -I.. processtab.cpp -o "%BUILD_DIR%\processtab.o"
if !errorlevel! neq 0 goto fail

"%MINGW%\g++.exe" -c -O2 -std=c++17 -DUNICODE -D_UNICODE -DQT_NO_DEBUG -DQT_WIDGETS_LIB -DQT_GUI_LIB -DQT_CORE_LIB -I"%QT_ROOT%\include" -I"%QT_ROOT%\include\QtCore" -I"%QT_ROOT%\include\QtGui" -I"%QT_ROOT%\include\QtWidgets" -I.. servicetab.cpp -o "%BUILD_DIR%\servicetab.o"
if !errorlevel! neq 0 goto fail

"%MINGW%\g++.exe" -c -O2 -std=c++17 -DUNICODE -D_UNICODE -DQT_NO_DEBUG -DQT_WIDGETS_LIB -DQT_GUI_LIB -DQT_CORE_LIB -I"%QT_ROOT%\include" -I"%QT_ROOT%\include\QtCore" -I"%QT_ROOT%\include\QtGui" -I"%QT_ROOT%\include\QtWidgets" -I.. registrytab.cpp -o "%BUILD_DIR%\registrytab.o"
if !errorlevel! neq 0 goto fail

"%MINGW%\g++.exe" -c -O2 -std=c++17 -DUNICODE -D_UNICODE -DQT_NO_DEBUG -DQT_WIDGETS_LIB -DQT_GUI_LIB -DQT_CORE_LIB -I"%QT_ROOT%\include" -I"%QT_ROOT%\include\QtCore" -I"%QT_ROOT%\include\QtGui" -I"%QT_ROOT%\include\QtWidgets" -I.. partitiontab.cpp -o "%BUILD_DIR%\partitiontab.o"
if !errorlevel! neq 0 goto fail

"%MINGW%\g++.exe" -c -O2 -std=c++17 -DUNICODE -D_UNICODE -DQT_NO_DEBUG -DQT_WIDGETS_LIB -DQT_GUI_LIB -DQT_CORE_LIB -I"%QT_ROOT%\include" -I"%QT_ROOT%\include\QtCore" -I"%QT_ROOT%\include\QtGui" -I"%QT_ROOT%\include\QtWidgets" -I.. settingsdialog.cpp -o "%BUILD_DIR%\settingsdialog.o"
if !errorlevel! neq 0 goto fail

"%MINGW%\g++.exe" -c -O2 -std=c++17 -DUNICODE -D_UNICODE -DQT_NO_DEBUG -DQT_WIDGETS_LIB -DQT_GUI_LIB -DQT_CORE_LIB -I"%QT_ROOT%\include" -I"%QT_ROOT%\include\QtCore" -I"%QT_ROOT%\include\QtGui" -I"%QT_ROOT%\include\QtWidgets" -I.. aichattab.cpp -o "%BUILD_DIR%\aichattab.o"
if !errorlevel! neq 0 goto fail

"%MINGW%\g++.exe" -c -O2 -std=c++17 -DUNICODE -D_UNICODE -DQT_NO_DEBUG -DQT_WIDGETS_LIB -DQT_GUI_LIB -DQT_CORE_LIB -I"%QT_ROOT%\include" -I"%QT_ROOT%\include\QtCore" -I"%QT_ROOT%\include\QtGui" -I"%QT_ROOT%\include\QtWidgets" -I.. livemonitortab.cpp -o "%BUILD_DIR%\livemonitortab.o"
if !errorlevel! neq 0 goto fail

"%MINGW%\g++.exe" -c -O2 -std=c++17 -DUNICODE -D_UNICODE -DQT_NO_DEBUG -DQT_WIDGETS_LIB -DQT_GUI_LIB -DQT_CORE_LIB -I"%QT_ROOT%\include" -I"%QT_ROOT%\include\QtCore" -I"%QT_ROOT%\include\QtGui" -I"%QT_ROOT%\include\QtWidgets" -I.. aihubtab.cpp -o "%BUILD_DIR%\aihubtab.o"
if !errorlevel! neq 0 goto fail

"%MINGW%\g++.exe" -c -O2 -std=c++17 -DUNICODE -D_UNICODE -DQT_NO_DEBUG -DQT_WIDGETS_LIB -DQT_GUI_LIB -DQT_CORE_LIB -I"%QT_ROOT%\include" -I"%QT_ROOT%\include\QtCore" -I"%QT_ROOT%\include\QtGui" -I"%QT_ROOT%\include\QtWidgets" -I.. taskchatdialog.cpp -o "%BUILD_DIR%\taskchatdialog.o"
if !errorlevel! neq 0 goto fail

"%MINGW%\g++.exe" -c -O2 -std=c++17 -DUNICODE -D_UNICODE -DQT_NO_DEBUG -DQT_WIDGETS_LIB -DQT_GUI_LIB -DQT_CORE_LIB -I"%QT_ROOT%\include" -I"%QT_ROOT%\include\QtCore" -I"%QT_ROOT%\include\QtGui" -I"%QT_ROOT%\include\QtWidgets" -I.. aiworker.cpp -o "%BUILD_DIR%\aiworker.o"
if !errorlevel! neq 0 goto fail

"%MINGW%\g++.exe" -c -O2 -std=c++17 -DUNICODE -D_UNICODE -DQT_NO_DEBUG -DQT_WIDGETS_LIB -DQT_GUI_LIB -DQT_CORE_LIB -I"%QT_ROOT%\include" -I"%QT_ROOT%\include\QtCore" -I"%QT_ROOT%\include\QtGui" -I"%QT_ROOT%\include\QtWidgets" -I.. ai_task_dialog.cpp -o "%BUILD_DIR%\ai_task_dialog.o"
if !errorlevel! neq 0 goto fail

"%MINGW%\g++.exe" -c -O2 -std=c++17 -DUNICODE -D_UNICODE -DQT_NO_DEBUG -DQT_WIDGETS_LIB -DQT_GUI_LIB -DQT_CORE_LIB -I"%QT_ROOT%\include" -I"%QT_ROOT%\include\QtCore" -I"%QT_ROOT%\include\QtGui" -I"%QT_ROOT%\include\QtWidgets" -I.. process_select_dialog.cpp -o "%BUILD_DIR%\process_select_dialog.o"
if !errorlevel! neq 0 goto fail

"%MINGW%\g++.exe" -c -O2 -std=c++17 -DUNICODE -D_UNICODE -DQT_NO_DEBUG -DQT_WIDGETS_LIB -DQT_GUI_LIB -DQT_CORE_LIB -I"%QT_ROOT%\include" -I"%QT_ROOT%\include\QtCore" -I"%QT_ROOT%\include\QtGui" -I"%QT_ROOT%\include\QtWidgets" -I.. roguesoftwaretab.cpp -o "%BUILD_DIR%\roguesoftwaretab.o"
if !errorlevel! neq 0 goto fail

for %%F in (moc_mainwindow moc_processtab moc_servicetab moc_registrytab moc_partitiontab moc_settingsdialog moc_aichattab moc_livemonitortab moc_aihubtab moc_taskchatdialog moc_aiworker moc_ai_task_dialog moc_process_select_dialog moc_roguesoftwaretab) do (
    "%MINGW%\g++.exe" -c -O2 -std=c++17 -DUNICODE -D_UNICODE -DQT_NO_DEBUG -DQT_WIDGETS_LIB -DQT_GUI_LIB -DQT_CORE_LIB -I"%QT_ROOT%\include" -I"%QT_ROOT%\include\QtCore" -I"%QT_ROOT%\include\QtGui" -I"%QT_ROOT%\include\QtWidgets" -I.. "%BUILD_DIR%\%%F.cpp" -o "%BUILD_DIR%\%%F.o"
    if !errorlevel! neq 0 goto fail
)

echo [BUILD] Compiling C backend...
for %%F in (core ai_service partition_edit registry_tree registry_manager gui_ai) do (
    "%MINGW%\gcc.exe" -c -O2 -Wall -DUNICODE -D_UNICODE -I"%QT_ROOT%\include" -I.. ..\%%F.c -o "%BUILD_DIR%\%%F.o"
    if !errorlevel! neq 0 goto fail
)

echo [LINK] Linking executable...
"%MINGW%\g++.exe" -o "%OUTPUT_DIR%\trae_guardian_qt.exe" "%BUILD_DIR%\main.o" "%BUILD_DIR%\mainwindow.o" "%BUILD_DIR%\processtab.o" "%BUILD_DIR%\servicetab.o" "%BUILD_DIR%\registrytab.o" "%BUILD_DIR%\partitiontab.o" "%BUILD_DIR%\settingsdialog.o" "%BUILD_DIR%\aichattab.o" "%BUILD_DIR%\livemonitortab.o" "%BUILD_DIR%\aihubtab.o" "%BUILD_DIR%\taskchatdialog.o" "%BUILD_DIR%\aiworker.o" "%BUILD_DIR%\ai_task_dialog.o" "%BUILD_DIR%\process_select_dialog.o" "%BUILD_DIR%\roguesoftwaretab.o" "%BUILD_DIR%\moc_mainwindow.o" "%BUILD_DIR%\moc_processtab.o" "%BUILD_DIR%\moc_servicetab.o" "%BUILD_DIR%\moc_registrytab.o" "%BUILD_DIR%\moc_partitiontab.o" "%BUILD_DIR%\moc_settingsdialog.o" "%BUILD_DIR%\moc_aichattab.o" "%BUILD_DIR%\moc_livemonitortab.o" "%BUILD_DIR%\moc_aihubtab.o" "%BUILD_DIR%\moc_taskchatdialog.o" "%BUILD_DIR%\moc_aiworker.o" "%BUILD_DIR%\moc_ai_task_dialog.o" "%BUILD_DIR%\moc_process_select_dialog.o" "%BUILD_DIR%\moc_roguesoftwaretab.o" "%BUILD_DIR%\core.o" "%BUILD_DIR%\ai_service.o" "%BUILD_DIR%\partition_edit.o" "%BUILD_DIR%\registry_tree.o" "%BUILD_DIR%\registry_manager.o" "%BUILD_DIR%\gui_ai.o" -L"%QT_ROOT%\lib" -lQt6Core -lQt6Gui -lQt6Widgets -lkernel32 -luser32 -lpsapi -ladvapi32 -lwinhttp -lcomctl32 -lole32 -loleaut32 -lgdi32 -lgdiplus -lshell32 -mwindows
if !errorlevel! neq 0 goto fail

echo [BUILD] SUCCESS: %OUTPUT_DIR%\trae_guardian_qt.exe
pause
exit /b 0

:fail
echo [BUILD] FAILED
pause
exit /b 1
