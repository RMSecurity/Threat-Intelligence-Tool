@echo off
chcp 65001 >nul
title RMSecurity - Compilando Cyber Intel EXE
cd /d "%~dp0"

echo.
echo ============================================================
echo   RMSecurity - Threat Intelligence Ciberseguridad - Compilador
echo ============================================================
echo.

python -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo [!] Instalando PyInstaller...
    pip install pyinstaller
)

echo [*] Compilando...
echo.

:: Copiar icono si existe
if exist "..\PRENSA\dacc_eagle.ico" copy "..\PRENSA\dacc_eagle.ico" "." >nul 2>&1

python -m PyInstaller ^
    --onefile ^
    --windowed ^
    --name "RMSecurity_CyberIntel" ^
    --icon "dacc_eagle.ico" ^
    --add-data "dacc_eagle.ico;." ^
    --hidden-import feedparser ^
    --hidden-import requests ^
    --hidden-import openpyxl ^
    --collect-all openpyxl ^
    --distpath ".\EJECUTABLE" ^
    --workpath ".\BUILD_TEMP" ^
    --specpath ".\BUILD_TEMP" ^
    --noconfirm ^
    cyber_intel_gui.py

if errorlevel 1 (
    echo [ERROR] Compilacion fallida.
    pause
    exit /b 1
)

if exist "dacc_eagle.ico" copy "dacc_eagle.ico" "EJECUTABLE\" >nul 2>&1

if exist "BUILD_TEMP" rmdir /s /q "BUILD_TEMP" >nul 2>&1

echo.
echo ============================================================
echo   [OK] Compilacion exitosa: EJECUTABLE\RMSecurity_CyberIntel.exe
echo ============================================================
pause >nul
explorer ".\EJECUTABLE"
