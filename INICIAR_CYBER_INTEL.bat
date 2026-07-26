@echo off
chcp 65001 >nul
title RMSecurity - Threat Intelligence Ciberseguridad
cd /d "%~dp0"
echo.
echo ============================================================
echo   RMSecurity - Threat Intelligence de Ciberseguridad
echo   Iniciando programa...
echo ============================================================
echo.
python cyber_intel_gui.py
if errorlevel 1 (
    echo.
    echo [ERROR] El programa cerro con error.
    echo Asegurese de haber ejecutado INSTALAR_DEPENDENCIAS.bat primero.
    pause
)
