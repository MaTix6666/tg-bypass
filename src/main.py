#!/usr/bin/env python3
"""
Telegram DPI Bypass Tool
Главный модуль
"""

import sys
import argparse
import ctypes
from typing import Optional

# Настраиваем путь к WinDivert ПЕРЕД импортом pydivert
from src.windivert_loader import setup_windivert_path, check_driver
setup_windivert_path()

from src.sniffer import TrafficSniffer
from src.fragmenter import SmartFragmenter
from src.tls_parser import get_sni_from_payload


class TelegramBypass:
    """
    Основной класс приложения
    """
    
    def __init__(self, 
                 fragment_size: int = 1,
                 delay_ms: float = 10.0,
                 verbose: bool = False):
        self.fragment_size = fragment_size
        self.delay_ms = delay_ms
        self.verbose = verbose
        
        self.fragmenter = SmartFragmenter(
            first_fragment_size=fragment_size,
            inter_fragment_delay_ms=delay_ms
        )
        self.sniffer: Optional[TrafficSniffer] = None
        
    def check_prerequisites(self):
        """Проверяет prerequisites"""
        print("[*] Проверка окружения...")
        
        # Проверка прав администратора
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[!] Требуются права администратора!")
            print("[!] Запусти: python -m src.main")
            return False
            
        # Проверка драйвера
        if not check_driver():
            print("[!] Драйвер WinDivert не установлен!")
            print("[*] Установи через: python tools/install_windivert.py")
            print("[*] Или pydivert попробует установить автоматически...")
            # Не возвращаем False — pydivert может установить сам
            
        print("[+] Окружение готово")
        return True
        
    def run(self):
        """Запускает обход блокировки"""
        if not self.check_prerequisites():
            sys.exit(1)
            
        print("="*60)
        print("Telegram DPI Bypass Tool v0.1")
        print("="*60)
        print(f"Fragment size: {self.fragment_size} bytes")
        print(f"Delay: {self.delay_ms} ms")
        print(f"Verbose: {self.verbose}")
        print("="*60 + "\n")
        
                # Callback для обработки пакетов
        def on_packet(packet, sni, is_telegram, w):
            dst_ip = str(packet.dst_addr)
            
            # Расширенный список Telegram IP/CDN
            tg_ips = [
                "149.154.", "91.108.", "95.161.",  # Официальные DC
                "45.12.133.",                       # telega.one CDN
                "185.215.247.",                     # MTProto прокси
            ]
            
            if not is_telegram:
                for ip_prefix in tg_ips:
                    if dst_ip.startswith(ip_prefix):
                        print(f"[TG] Detected: {dst_ip}")
                        is_telegram = True
                        break
            
            if self.verbose and sni:
                print(f"[TLS] {dst_ip} SNI={sni}")
                
            if is_telegram:
                if self.verbose:
                    print(f"[FRAG] {dst_ip}")
                try:
                    self.fragmenter.process_packet(w, packet)
                    return False
                except Exception as e:
                    print(f"[ERROR] {e}")
                    return True
                    
            return True
        
        def on_error(error, packet):
            print(f"[ERROR] {error}")
            
        self.sniffer = TrafficSniffer(
            port=443,
            on_packet=on_packet,
            on_error=on_error
        )
        
        try:
            self.sniffer.start()
        except KeyboardInterrupt:
            self._print_final_stats()
        except Exception as e:
            print(f"\n[!] Ошибка: {e}")
            print("[*] Возможно, драйвер WinDivert не установлен")
            print("[*] Запусти: python tools/install_windivert.py")
            
    def _print_final_stats(self):
        """Выводит финальную статистику"""
        if self.sniffer:
            self.sniffer._print_stats()
            
        frag_stats = self.fragmenter.get_stats()
        print("\nFragmentation stats:")
        print(f"  Fragmented: {frag_stats['fragmented']}")
        print(f"  Passed:     {frag_stats['passed']}")
        print(f"  Errors:     {frag_stats['errors']}")


def main():
    parser = argparse.ArgumentParser(
        description="Telegram DPI Bypass Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Запуск с настройками по умолчанию
  %(prog)s -s 2 -d 5          # Фрагменты по 2 байта, задержка 5мс
  %(prog)s -v                 # Подробный вывод
  
Установка драйвера:
  python tools/install_windivert.py
        """
    )
    
    parser.add_argument(
        "-s", "--fragment-size",
        type=int,
        default=1,
        help="Размер первого фрагмента (по умолчанию: 1 байт)"
    )
    
    parser.add_argument(
        "-d", "--delay",
        type=float,
        default=10.0,
        help="Задержка между фрагментами в мс (по умолчанию: 10)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Подробный вывод"
    )
    
    args = parser.parse_args()
    
    app = TelegramBypass(
        fragment_size=args.fragment_size,
        delay_ms=args.delay,
        verbose=args.verbose
    )
    
    try:
        app.run()
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()