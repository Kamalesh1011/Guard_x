@echo off
echo ===================================
echo   GUARDIAN Service Installer
echo ===================================
echo.
echo This will install GUARDIAN as a Windows service.
echo Run as Administrator.
echo.

set NSSM_PATH=%~dp0..\dist\nssm.exe
set GUARDIAN_PATH=%~dp0..\dist\Guardian.exe

if not exist "%GUARDIAN_PATH%" (
    echo Error: Guardian.exe not found at %GUARDIAN_PATH%
    echo Run build.bat first.
    pause
    exit /b 1
)

echo Installing service...
nssm install Guardian "%GUARDIAN_PATH%"
nssm set Guardian AppDirectory "%~dp0.."
nssm set Guardian DisplayName "GUARDIAN Security Monitor"
nssm set Guardian Description "Offline Explainable Behavioral Threat Detection"
nssm set Guardian Start SERVICE_AUTO_START

echo.
echo Starting service...
nssm start Guardian

echo.
echo ===================================
echo   Service installed and started
echo ===================================
pause
