"""
Фрагментация TCP-пакетов для обхода DPI
"""

import time
import pydivert
from typing import Optional


class FragmentationError(Exception):
    pass


class TCPFragmenter:
    """
    Фрагментирует TCP-пакеты для сбивания DPI с толку
    """
    
    def __init__(self, 
                 first_fragment_size: int = 1,
                 inter_fragment_delay_ms: float = 10.0):
        """
        Args:
            first_fragment_size: Размер первого фрагмента (обычно 1-8 байт)
            inter_fragment_delay_ms: Задержка между фрагментами в мс
        """
        self.first_fragment_size = first_fragment_size
        self.delay_ms = inter_fragment_delay_ms
        self.stats = {
            "fragmented": 0,
            "passed": 0,
            "errors": 0
        }
        
    def process_packet(self, 
                      w: pydivert.WinDivert, 
                      packet: pydivert.Packet) -> None:
        """
        Обрабатывает пакет: фрагментирует или пропускает как есть
        """
        try:
            payload = packet.tcp.payload
            
            if not payload or len(payload) <= self.first_fragment_size:
                # Нечего фрагментировать
                w.send(packet)
                self.stats["passed"] += 1
                return
                
            self._fragment(w, packet)
            self.stats["fragmented"] += 1
            
        except Exception as e:
            self.stats["errors"] += 1
            raise FragmentationError(f"Failed to fragment packet: {e}")
            
    def _fragment(self, 
                  w: pydivert.WinDivert, 
                  packet: pydivert.Packet) -> None:
        """
        Разбивает пакет на два фрагмента с корректными SEQ номерами
        """
        payload = packet.tcp.payload
        split_pos = self.first_fragment_size
        
        # Сохраняем оригинальные значения
        orig_seq = packet.tcp.seq_num
        orig_ack = packet.tcp.ack_num
        packet.tcp.psh = False
        
        # === ФРАГМЕНТ 1 ===
        # Модифицируем оригинальный пакет для первого фрагмента
        packet.tcp.payload = payload[:split_pos]
        
        # Снимаем PSH флаг у первого фрагмента (оптимизация)
        packet.tcp.psh = False
        
        # Пересчитываем чексуммы (WinDivert сделает это автоматически,
        # но явный вызов гарантирует корректность)
        packet.recalculate_checksums()
        
        # Отправляем первый фрагмент
        w.send(packet)
        
        # Задержка между фрагментами - КРИТИЧНО для обхода DPI
        if self.delay_ms > 0:
            time.sleep(self.delay_ms / 1000.0)
            
        # === ФРАГМЕНТ 2 ===
        # Создаём второй фрагмент с увеличенным SEQ
        # В pydivert мы модифицируем тот же объект, но сдвигаем SEQ
        packet.tcp.seq_num = orig_seq + split_pos
        packet.tcp.payload = payload[split_pos:]
        
        # Восстанавливаем флаги
        packet.tcp.psh = True
        
        # ACK остаётся тем же
        
        packet.recalculate_checksums()
        w.send(packet)
        
    def get_stats(self) -> dict:
        """Возвращает статистику фрагментации"""
        return self.stats.copy()
        
    def reset_stats(self):
        """Сбрасывает статистику"""
        self.stats = {"fragmented": 0, "passed": 0, "errors": 0}


class SmartFragmenter(TCPFragmenter):
    """
    Умный фрагментатор с адаптивной стратегией
    """
    
    # Telegram-related indicators
    TELEGRAM_SNIS = [
        "telegram", "teleg", "tg.dev", "t.me", 
        "telegra.ph", "tdesktop.com"
    ]
    
    TELEGRAM_IP_RANGES = [
        ("149.154.160.0", "149.154.175.255"),
        ("91.108.4.0", "91.108.19.255"),
        ("185.76.151.0", "185.76.151.255"),
    ]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.blocked_snis = set()
        
    def should_fragment(self, packet: pydivert.Packet, sni: Optional[str]) -> bool:
        """
        Определяет, нужно ли фрагментировать этот пакет
        """
        dst_ip = str(packet.dst_addr)
        
        # Проверка по IP
        if self._is_telegram_ip(dst_ip):
            return True
            
        # Проверка по SNI
        if sni:
            sni_lower = sni.lower()
            if any(ind in sni_lower for ind in self.TELEGRAM_SNIS):
                return True
            if sni in self.blocked_snis:
                return True
                
        return False
        
    def _is_telegram_ip(self, ip: str) -> bool:
        """Проверяет, принадлежит ли IP к диапазонам Telegram"""
        try:
            ip_int = self._ip_to_int(ip)
            for start, end in self.TELEGRAM_IP_RANGES:
                if self._ip_to_int(start) <= ip_int <= self._ip_to_int(end):
                    return True
        except ValueError:
            pass
        return False
        
    @staticmethod
    def _ip_to_int(ip: str) -> int:
        parts = [int(x) for x in ip.split('.')]
        return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]