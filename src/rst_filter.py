"""
Фильтрация фейковых RST-пакетов от DPI/РКН
"""

from src.logger import logger


class RSTFilter:
    """
    Блокирует поддельные TCP RST пакеты от DPI
    
    РКН/DPI иногда внедряют RST-пакеты чтобы разорвать соединение.
    """
    
    def __init__(self):
        self.blocked_rst_count = 0
    
    def is_fake_rst(self, packet) -> bool:
        """
        Определяет, является ли RST-пакет фейковым
        """
        # Проверяем наличие RST флага
        if not hasattr(packet.tcp, 'rst') or not packet.tcp.rst:
            return False
        
        # Простая эвристика: блокируем входящие RST от Telegram IP
        # (в реальности RST должен идти от сервера, но DPI подделывает)
        
        src_port = packet.tcp.src_port
        dst_port = packet.tcp.dst_port
        
        # Telegram порты
        telegram_ports = [443, 80, 8080, 8443]
        
        if src_port in telegram_ports:
            self.blocked_rst_count += 1
            logger.debug(f"Blocked fake RST from {packet.src_addr}:{src_port}")
            return True
        
        return False
    
    def should_drop(self, packet) -> bool:
        """Возвращает True если пакет нужно дропнуть"""
        return self.is_fake_rst(packet)
    
    def get_stats(self) -> dict:
        return {"blocked_rst": self.blocked_rst_count}