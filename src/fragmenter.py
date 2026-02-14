"""
Фрагментация TCP-пакетов для обхода DPI
"""

from src.config import TELEGRAM, FRAGMENTATION
from src.logger import logger
import time
import pydivert
from typing import Optional
import functools

class FragmentationError(Exception):
    pass


class TCPFragmenter:
    """
    Фрагментирует TCP-пакеты для сбивания DPI с толку
    """
    
    def __init__(self, 
                 first_fragment_size: int = 1,
                 inter_fragment_delay_ms: float = 10.0):
        # НЕ вызываем super().__init__() с аргументами!
        self.first_fragment_size = first_fragment_size
        self.inter_fragment_delay_ms = inter_fragment_delay_ms
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
            # ВАЖНО: При ошибке фрагментации отправляем оригинальный пакет
            # чтобы не нарушать соединение
            try:
                w.send(packet)
                self.stats["passed"] += 1
            except:
                pass
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

    def __init__(self, 
                 first_fragment_size: int = 1,
                 inter_fragment_delay_ms: float = 10.0):
        # Вызываем родительский __init__ с именованными аргументами
        super().__init__(
            first_fragment_size=first_fragment_size,
            inter_fragment_delay_ms=inter_fragment_delay_ms
        )
    
        self.blocked_snis = set()
        self.telegram_snis = TELEGRAM.SNI_PATTERNS
        self.telegram_ip_ranges = TELEGRAM.IP_RANGES
        # Статистика по категориям
        self.size_stats = {
            "small": 0,   # < 1KB
            "medium": 0,  # 1-50KB
            "large": 0,   # 50-500KB
            "huge": 0,    # > 500KB
        }

    def get_adaptive_params(self, payload_size: int) -> tuple:
        """
        Возвращает параметры фрагментации в зависимости от размера пакета
        
        Returns:
            (fragment_size, delay_ms)
        """
        if payload_size < 1024:  # < 1KB - текст, команды
            return (1, 10.0)      # Максимальная защита
        elif payload_size < 50 * 1024:  # 1-50KB - фото, стикеры
            return (8, 5.0)       # Баланс
        elif payload_size < 500 * 1024:  # 50-500KB - документы
            return (100, 2.0)     # Скорость важнее
        else:  # > 500KB - видео, большие файлы
            return (500, 1.0)     # Минимальная фрагментация

    def process_packet_adaptive(self, w: pydivert.WinDivert, packet: pydivert.Packet) -> None:
        """
        Адаптивная фрагментация на основе размера пакета
        """
        try:
            payload = packet.tcp.payload
            
            if not payload:
                w.send(packet)
                self.stats["passed"] += 1
                return
            
            payload_size = len(payload)
            
            # Статистика по размерам
            if payload_size < 1024:
                self.size_stats["small"] += 1
            elif payload_size < 50 * 1024:
                self.size_stats["medium"] += 1
            elif payload_size < 500 * 1024:
                self.size_stats["large"] += 1
            else:
                self.size_stats["huge"] += 1
            
            # Получаем адаптивные параметры
            frag_size, delay = self.get_adaptive_params(payload_size)
            
            # Если пакет маленький или фрагментация не нужна
            if payload_size <= frag_size:
                w.send(packet)
                self.stats["passed"] += 1
                return
            
            # Применяем фрагментацию с адаптивными параметрами
            self._fragment_with_params(w, packet, frag_size, delay)
            self.stats["fragmented"] += 1
            
        except Exception as e:
            self.stats["errors"] += 1
            # Fallback: отправляем как есть
            try:
                w.send(packet)
                self.stats["passed"] += 1
            except:
                pass
            raise FragmentationError(f"Adaptive fragmentation failed: {e}")

    def _fragment_with_params(self, w: pydivert.WinDivert, packet: pydivert.Packet, 
                              frag_size: int, delay_ms: float) -> None:
        """
        Фрагментация с заданными параметрами (вместо self.first_fragment_size)
        """
        payload = packet.tcp.payload
        split_pos = frag_size


        # Сохраняем оригинальные значения
        orig_seq = packet.tcp.seq_num
        orig_ack = packet.tcp.ack_num
        
        # === ФРАГМЕНТ 1 ===
        packet.tcp.payload = payload[:split_pos]
        packet.tcp.psh = False
        packet.recalculate_checksums()
        w.send(packet)

        # Задержка
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)

        # === ФРАГМЕНТ 2 ===
        packet.tcp.seq_num = orig_seq + split_pos
        packet.tcp.payload = payload[split_pos:]
        packet.tcp.psh = True
        packet.recalculate_checksums()
        w.send(packet)
