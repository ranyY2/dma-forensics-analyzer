@echo off
setlocal
set "OUTPUT=%USERPROFILE%\Documents\DMA Forensics\output"
if not exist "%OUTPUT%" mkdir "%OUTPUT%"
%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoLogo -NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File "%~dp0Invoke-DmaForensics.Gui.ps1" -Mode QUICK -OutputDirectory "%OUTPUT%"
set "EXITCODE=%ERRORLEVEL%"
exit /b %EXITCODE%
