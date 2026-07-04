@echo off
net session >nul 2>&1
if %errorlevel% neq 0 goto :elevate
goto :run

:elevate
powershell -NoProfile -WindowStyle Hidden -Command "Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-STA','-File','%~dp0HyoErase.ps1')"
exit /b

:run
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -STA -File "%~dp0HyoErase.ps1"
