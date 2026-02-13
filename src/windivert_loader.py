"""
Загрузка WinDivert с явным указанием пути к DLL
"""

import os
import sys
from pathlib import Path


def setup_windivert_path():
    """
    Настраивает путь к WinDivert DLL
    Возвращает True если успешно
    """
    
    # Определяем архитектуру
    is_64bit = sys.maxsize > 2**32
    
    # Путь к проекту
    project_root = Path(__file__).parent.parent.absolute()
    
    # Путь к DLL
    dll_dir = project_root / "deps" / "windivert" / ("x64" if is_64bit else "x86")
    dll_path = dll_dir / "WinDivert.dll"
    
    if not dll_path.exists():
        # Пробуем найти в системе
        print(f"[!] WinDivert.dll не найден в {dll_dir}")
        print("[*] Пробуем системный PATH...")
        return False
    
    # Добавляем в PATH для pydivert
    os.environ["PATH"] = str(dll_dir) + os.pathsep + os.environ.get("PATH", "")
    
    # Также можно попробовать LoadLibrary напрямую
    try:
        import ctypes
        ctypes.windll.LoadLibrary(str(dll_path))
        print(f"[+] WinDivert загружен из: {dll_path}")
        return True
    except Exception as e:
        print(f"[!] Ошибка загрузки DLL: {e}")
        return False
    
    return True


def check_driver():
    """Проверяет, установлен ли драйвер WinDivert"""
    try:
        import ctypes
        from ctypes import wintypes
        
        # Пробуем открыть драйвер
        # Если не установлен — будет ошибка
        GENERIC_READ = 0x80000000
        GENERIC_WRITE = 0x40000000
        
        handle = ctypes.windll.kernel32.CreateFileW(
            "\\\\.\\WinDivert",
            GENERIC_READ | GENERIC_WRITE,
            0, None, 3, 0, None  # OPEN_EXISTING = 3
        )
        
        if handle == -1:  # INVALID_HANDLE_VALUE
            return False
            
        ctypes.windll.kernel32.CloseHandle(handle)
        return True
        
    except Exception:
        return False