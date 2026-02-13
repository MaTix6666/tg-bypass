@echo off
chcp 65001 >nul
title Telegram DPI Bypass

:: Проверка прав администратора
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Требуются права администратора!
    echo [*] Перезапускаем с правами админа...
    powershell -Command "Start-Process '%~f0' -Verb runAs"
    exit /b
)

:: Активация окружения
call venv\Scripts\activate.bat

:: Запуск
python -m src.main %*

pause