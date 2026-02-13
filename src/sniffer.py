"""
Сниффер трафика на базе WinDivert
"""

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
        
        # ИСПРАВЛЕННЫЙ ФИЛЬТР WinDivertpython -m src.main -vpython -m src.main -v
        # Перехватываем все порты где может быть Telegram
        self.filter_str = "tcp.DstPort == 443 or tcp.DstPort == 80 or tcp.DstPort == 8080"
        
        self.stats = {
            "total": 0,
            "tls": 0,
            "telegram": 0,
            "errors": 0
        }
        
    def start(self):
        """Запускает сниффер"""
        print(f"[*] Starting sniffer on port {self.port}...")
        print(f"[*] Filter: {self.filter_str}")
        print(f"[*] Press Ctrl+C to stop\n")
        
        self.running = True
        signal.signal(signal.SIGINT, self._signal_handler)
        
        try:
            with pydivert.WinDivert(self.filter_str) as self.w:
                for packet in self.w:
                    if not self.running:
                        break
                    self._process_packet(packet)
                    
        except Exception as e:
            print(f"\n[!] Sniffer error: {e}")
            raise
            
    def stop(self):
        """Останавливает сниффер"""
        self.running = False
        print("\n[*] Stopping sniffer...")
        
    def _process_packet(self, packet: pydivert.Packet):
        """Обрабатывает перехваченный пакет"""
        try:
            self.stats["total"] += 1
            
            # Безопасная проверка payload
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
                self.stats["tls"] += 1
                sni = get_sni_from_payload(payload)
                
                if sni and "telegram" in sni.lower():
                    is_telegram = True
                    self.stats["telegram"] += 1
                    
            # Вызываем callback если есть
            if self.on_packet:
                result = self.on_packet(packet, sni, is_telegram, self.w)
                if result is False:
                    return
                    
            self._forward(packet)
            
        except Exception as e:
            self.stats["errors"] += 1
            if self.on_error:
                self.on_error(e, packet)
            else:
                try:
                    self._forward(packet)
                except:
                    pass
                    
    def _forward(self, packet: pydivert.Packet):
        """Пропускает пакет дальше"""
        if self.w:
            self.w.send(packet)
            
    def _signal_handler(self, signum, frame):
        """Обработчик сигнала завершения"""
        self.stop()
        self._print_stats()
        sys.exit(0)
        
    def _print_stats(self):
        """Выводит статистику"""
        print("\n" + "="*50)
        print("STATISTICS")
        print("="*50)
        print(f"Total packets:  {self.stats['total']}")
        print(f"TLS packets:    {self.stats['tls']}")
        print(f"Telegram:       {self.stats['telegram']}")
        print(f"Errors:         {self.stats['errors']}")
        print("="*50)
        
    def get_stats(self) -> dict:
        """Возвращает копию статистики"""
        return self.stats.copy()