"""
Настройка логирования
"""

import logging
import sys
from pathlib import Path


def setup_logger(verbose: bool = False) -> logging.Logger:
    """
    Настраивает логгер приложения
    
    Args:
        verbose: Включить подробный вывод (DEBUG уровень)
    
    Returns:
        Настроенный логгер
    """
    logger = logging.getLogger("tg_bypass")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Очищаем старые обработчики (если есть)
    logger.handlers = []
    
    # Форматтер для консоли
    console_formatter = logging.Formatter(
        '[%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # Обработчик для консоли
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # Файловый лог (опционально, для отладки)
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    file_handler = logging.FileHandler(
        log_dir / "tg_bypass.log",
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    return logger


# Глобальный логгер (инициализируется позже)
logger = logging.getLogger("tg_bypass")