@echo off
echo ===================================
echo   GUARDIAN Build Script
echo ===================================

echo.
echo [1/3] Building React frontend...
cd frontend
call npm install
call npm run build
cd ..

echo.
echo [2/3] Creating PyInstaller build...
cd agent
pyinstaller main.py ^
    --onefile ^
    --noconsole ^
    --name Guardian ^
    --add-data="rules.json;agent" ^
    --add-data="storage/schema.sql;agent/storage" ^
    --hidden-import=win32timezone ^
    --hidden-import=pyttsx3.drivers ^
    --hidden-import=pyttsx3.drivers.sapi5 ^
    --collect-all pystray ^
    --collect-all PIL

echo.
echo [3/3] Copying assets...
if not exist dist\assets mkdir dist\assets
copy ..\assets\shield.png dist\assets\ 2>nul

echo.
echo ===================================
echo   Build complete: dist\Guardian.exe
echo ===================================
pause
