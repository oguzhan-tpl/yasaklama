@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Baslat-Yasaklama.ps1"
if errorlevel 1 (
  echo.
  echo Yasaklama baslatilamadi. Yukaridaki hatayi kontrol edin.
  pause
)
