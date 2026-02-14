"""
Сниффер трафика на базе WinDivert
"""
from src.logger import logger
from src.config import SNIFFER
from src.rst_filter import RSTFilter
import sys
import signal
from typing import Callable, Optional
import pydivert

from .tls_parser import get_sni_from_payload, is_tls_client_hello


class TrafficSniffer:
    """
    Перехватывает и анализирует исходящий HTTPS-трафик
    """
    
    def __init__(self, 
                 port: int = 443,
                 on_packet: Optional[Callable] = None,
                 on_error: Optional[Callable] = None):
        self.port = port
        self.on_packet = on_packet
        self.on_error = on_error
        self.running = False
        self.w = None
        
        self.rst_filter = RSTFilter()

        self.filter_str = SNIFFER.get_filter()

        # Генерируем фильтр для TCP и UDP
        tcp_filter = " or ".join([f"tcp.DstPort == {p}" for p in SNIFFER.TCP_PORTS])
        udp_filter = " or ".join([f"udp.DstPort == {p}" for p in SNIFFER.UDP_PORTS])
        self.filter_str = f"({tcp_filter}) or ({udp_filter})"
        
        logger.info(f"Filter: TCP[{len(SNIFFER.TCP_PORTS)} ports] + UDP[{len(SNIFFER.UDP_PORTS)} ports]")
        
        self.stats = {
            "total": 0,
            "tls": 0,
            "telegram": 0,
            "errors": 0
        }
        
    def start(self):
        """Запускает сниффер"""
        logger.info(f"Starting sniffer on port {self.port}...")
        logger.debug(f"Filter: {self.filter_str}")
        logger.info("Press Ctrl+C to stop\n")

        self.running = True
        
        # Сохраняем старый обработчик и устанавливаем новый
        self._old_signal_handler = signal.signal(signal.SIGINT, self._signal_handler)

        try:
            with pydivert.WinDivert(self.filter_str) as self.w:
                for packet in self.w:
                    if not self.running:
                        break
                    self._process_packet(packet)

        except Exception as e:
            logger.error(f"Sniffer error: {e}")
            raise
        finally:
            # Восстанавливаем старый обработчик
            if hasattr(self, '_old_signal_handler'):
                signal.signal(signal.SIGINT, self._old_signal_handler)
            
    def stop(self):
        """Останавливает сниффер"""
        self.running = False
        logger.info("Stopping sniffer...")
        
    def _process_packet(self, packet: pydivert.Packet):
        """Обрабатывает перехваченный пакет"""
        try:
            self.stats["total"] += 1
            
            # === ОБРАБОТКА TCP ===
            if hasattr(packet, 'tcp'):
                # Блокируем фейковые RST
                if self.rst_filter.should_drop(packet):
                    return
                
                # Обрабатываем TCP payload
                payload = None
                try:
                    payload = packet.tcp.payload
                except:
                    pass
                    
                if not payload:
                    self._forward(packet)
                    return
                    
                # Анализируем TLS
                sni = None
                is_telegram = False
                
                if len(payload) > 5 and payload[0] == 0x16:
                    self.stats["tls"] = self.stats.get("tls", 0) + 1
                    sni = get_sni_from_payload(payload)
                    
                    if sni and "telegram" in sni.lower():
                        is_telegram = True
                        self.stats["telegram"] = self.stats.get("telegram", 0) + 1
                        
                # Вызываем callback
                should_forward = True
                if self.on_packet:
                    try:
                        result = self.on_packet(packet, sni, is_telegram, self.w)
                        if result is False:
                            should_forward = False
                    except Exception as e:
                        self.stats["errors"] = self.stats.get("errors", 0) + 1
                        if self.on_error:
                            self.on_error(e, packet)

                if should_forward:
                    self._forward(packet)
            
            # === ОБРАБОТКА UDP (звонки) ===
            elif hasattr(packet, 'udp'):
                self.stats["udp"] = self.stats.get("udp", 0) + 1
                
                # Пока просто пропускаем UDP пакеты
                # Потом добавим фрагментацию UDP
                try:
                    payload = packet.udp.payload
                    if payload:
                        logger.debug(f"UDP packet: {packet.dst_addr}:{packet.udp.dst_port} ({len(payload)} bytes)")
                except:
                    pass
                
                self._forward(packet)
            
            # === ДРУГИЕ ПРОТОКОЛЫ ===
            else:
                # Неизвестный протокол — просто пропускаем
                self._forward(packet)
                
        except Exception as e:
            self.stats["errors"] = self.stats.get("errors", 0) + 1
            if self.on_error:
                self.on_error(e, packet)
            else:
                try:
                    self._forward(packet)
                except:
                    pass

    def _process_udp(self, packet: pydivert.Packet):
        """Обрабатывает UDP пакеты (VoIP)"""
        try:
            # Пока просто пропускаем все UDP пакеты
            # Потом добавим фрагментацию
            self.stats["udp"] = self.stats.get("udp", 0) + 1
            self._forward(packet)
        except Exception as e:
            logger.debug(f"UDP processing error: {e}")
            self._forward(packet)
                    
    def _forward(self, packet: pydivert.Packet):
        """Пропускает пакет дальше"""
        if self.w:
            self.w.send(packet)
            
    def _signal_handler(self, signum, frame):
        """Обработчик сигнала завершения"""
        logger.info("Получен сигнал остановки")
        self.stop()
        self._print_stats()
        # Восстанавливаем стандартное поведение и выходим
        sys.exit(0)
        
    def _print_stats(self):
        """Выводит статистику"""
        logger.info("=" * 50)
        logger.info("STATISTICS")
        logger.info("=" * 50)
        logger.info(f"Total packets: {self.stats['total']}")
        logger.info(f"TLS packets: {self.stats['tls']}")
        logger.info(f"Telegram: {self.stats['telegram']}")
        logger.info(f"Errors: {self.stats['errors']}")
        logger.info("=" * 50)
        
    def get_stats(self) -> dict:
        """Возвращает копию статистики"""
        return self.stats.copy()