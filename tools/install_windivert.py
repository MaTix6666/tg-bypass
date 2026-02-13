#!/usr/bin/env python3
"""
Установка WinDivert драйвера
Требует права администратора
"""

import os
import sys
import ctypes
import subprocess
from pathlib import Path


def is_admin():
    """Проверяет, запущен ли скрипт от администратора"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def install_windivert():
    """Устанавливает WinDivert драйвер"""
    
    if not is_admin():
        print("[!] Требуются права администратора!")
        print("[!] Перезапускаем с правами админа...")
        
        # Перезапускаем себя от админа
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit(0)
    
    # Путь к драйверу
    script_dir = Path(__file__).parent.parent.absolute()
    driver_path = script_dir / "deps" / "windivert" / "x64" / "WinDivert.sys"
    
    if not driver_path.exists():
        print(f"[!] Драйвер не найден: {driver_path}")
        print("[!] Убедись, что файлы WinDivert скопированы в deps/windivert/x64/")
        sys.exit(1)
    
    print(f"[*] Устанавливаем драйвер из: {driver_path}")
    
    # Устанавливаем через sc.exe
    try:
        # Удаляем старый если есть
        subprocess.run(["sc", "stop", "WinDivert"], capture_output=True)
        subprocess.run(["sc", "delete", "WinDivert"], capture_output=True)
        
        # Создаём новый сервис
        result = subprocess.run([
            "sc", "create", "WinDivert",
            "type=kernel",
            "start=demand",
            "error=normal",
            f"binPath={driver_path}",
            "DisplayName=WinDivert"
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"[!] Ошибка создания сервиса: {result.stderr}")
            sys.exit(1)
            
        print("[+] Сервис создан")
        
        # Запускаем
        result = subprocess.run(["sc", "start", "WinDivert"], 
                              capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"[!] Ошибка запуска: {result.stderr}")
            print("[*] Попробуем использовать без установки (через pydivert)...")
        else:
            print("[+] Драйвер запущен!")
            
    except Exception as e:
        print(f"[!] Ошибка: {e}")
        sys.exit(1)
    
    print("\n[*] Готово! Можно запускать main.py")
    input("Нажми Enter для выхода...")


def uninstall_windivert():
    """Удаляет драйвер"""
    if not is_admin():
        print("[!] Требуются права администратора!")
        return
    
    print("[*] Останавливаем и удаляем драйвер...")
    
    subprocess.run(["sc", "stop", "WinDivert"], capture_output=True)
    result = subprocess.run(["sc", "delete", "WinDivert"], 
                          capture_output=True, text=True)
    
    if result.returncode == 0:
        print("[+] Драйвер удалён")
    else:
        print(f"[!] {result.stderr}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--uninstall":
        uninstall_windivert()
    else:
        install_windivert()