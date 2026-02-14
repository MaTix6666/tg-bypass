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
from src.config import TELEGRAM, FRAGMENTATION
from src.logger import setup_logger, logger

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
        logger.info("Проверка окружения...")

        # Проверка прав администратора
        if not ctypes.windll.shell32.IsUserAnAdmin():
            logger.error("Требуются права администратора!")
            logger.info("Запусти: python -m src.main")
            return False

        # Проверка драйвера
        if not check_driver():
            logger.warning("Драйвер WinDivert не установлен!")
            logger.info("Установи через: python tools/install_windiver t.py")
            logger.info("Или pydivert попробует установить автоматически...")

        # ОБНОВЛЯЕМ IP ИЗ СЕТИ
        logger.info("Обновление списка IP Telegram...")
        if TELEGRAM.update_ips_from_network():
            logger.info(f"Загружено {len(TELEGRAM.IP_PREFIXES)} IP-префиксов")
        else:
            logger.info("Используем встроенный список IP")

        logger.info("Окружение готово")
        return True
        
    def run(self):
        """Запускает обход блокировки"""
        if not self.check_prerequisites():
            sys.exit(1)

        logger.info("=" * 60)
        logger.info("Telegram DPI Bypass Tool v0.1")
        logger.info("=" * 60)
        logger.info(f"Fragment size: {self.fragment_size} bytes")
        logger.info(f"Delay: {self.delay_ms} ms")
        logger.info(f"Verbose: {self.verbose}")
        logger.info("=" * 60)
        
        # Callback для обработки пакетов
        def on_packet(packet, sni, is_telegram, w):
            dst_ip = str(packet.dst_addr)

            # Используем конфиг вместо хардкода
            tg_ips = TELEGRAM.IP_PREFIXES

            if not is_telegram:
                for ip_prefix in tg_ips:
                    if dst_ip.startswith(ip_prefix):
                        logger.debug(f"Detected Telegram IP: {dst_ip}")
                        is_telegram = True
                        break

            if self.verbose and sni:
                logger.debug(f"[TLS] {dst_ip} SNI={sni}")

            if is_telegram:
                if self.verbose:
                    logger.debug(f"Fragmenting: {dst_ip} ({len(packet.tcp.payload) if packet.tcp.payload else 0} bytes)")
                try:
                    # Используем адаптивную фрагментацию!
                    self.fragmenter.process_packet_adaptive(w, packet)
                    return False
                except Exception as e:
                    logger.error(f"Fragmentation error: {e}")
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
            logger.info("Остановка по запросу пользователя")
            self._print_final_stats()
        except Exception as e:
            logger.error(f"Ошибка: {e}")
            logger.info("Возможно, драйвер WinDivert не установлен")
            logger.info("Запусти: python tools/install_windiver t.py")
            
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
  %(prog)s -s 2 -d 5         # Фрагменты по 2 байта, задержка 5мс
  %(prog)s -v                # Подробный вывод

Установка драйвера:
  python tools/install_windiver t.py
        """
    )

    parser.add_argument(
        "-s", "--fragment-size",
        type=int,
        default=FRAGMENTATION.DEFAULT_SIZE,
        choices=range(1, 9),  # Ограничиваем разумными пределами (1-8 байт)
        metavar="SIZE",
        help=f"Размер первого фрагмента 1-8 байт (по умолчанию: {FRAGMENTATION.DEFAULT_SIZE})"
    )

    parser.add_argument(
        "-d", "--delay",
        type=float,
        default=FRAGMENTATION.DEFAULT_DELAY_MS,
        help=f"Задержка между фрагментами в мс (по умолчанию: {FRAGMENTATION.DEFAULT_DELAY_MS}, макс: {FRAGMENTATION.MAX_DELAY_MS})"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Подробный вывод"
    )

    args = parser.parse_args()
    
    # Валидация задержки
    if args.delay < FRAGMENTATION.MIN_DELAY_MS or args.delay > FRAGMENTATION.MAX_DELAY_MS:
        print(f"[!] Ошибка: задержка должна быть между {FRAGMENTATION.MIN_DELAY_MS} и {FRAGMENTATION.MAX_DELAY_MS} мс")
        sys.exit(1)
    
    # Настраиваем логирование ДО создания приложения
    setup_logger(verbose=args.verbose)

    app = TelegramBypass(
        fragment_size=args.fragment_size,
        delay_ms=args.delay,
        verbose=args.verbose
    )

    try:
        app.run()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        import traceback
        logger.debug(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()