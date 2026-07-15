Set objShell = CreateObject("WScript.Shell")
Set objWMIService = GetObject("winmgmts:\\.\root\CIMV2")

WScript.Echo "=== Checking for Process Guardian window ==="

Set colWindows = objWMIService.ExecQuery("SELECT * FROM Win32_Process WHERE Name = 'trae_guardian_qt.exe'")
For Each objProcess in colWindows
    WScript.Echo "PID: " & objProcess.ProcessId
    WScript.Echo "SessionId: " & objProcess.SessionId
Next

Set objShellApp = CreateObject("Shell.Application")
WScript.Echo "Done"