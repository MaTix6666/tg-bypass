"""
Конфигурация приложения
Все настройки в одном месте
"""

from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class TelegramConfig:
    """Настройки Telegram"""
    # IP-префиксы (будем загружать динамически)
    IP_PREFIXES: List[str] = None
    
    # SNI паттерны для определения Telegram-трафика
    SNI_PATTERNS: List[str] = None
    
    IP_RANGES: List[Tuple[str, str]] = None
    
    MTProto_PORTS: List[int] = None

    TCP_PORTS: List[int] = None
    UDP_PORTS: List[int] = None

    
    def __post_init__(self):
        if self.SNI_PATTERNS is None:
            self.SNI_PATTERNS = [
                "telegram",
                "teleg",
                "tg.dev",
                "t.me",
                "telegra.ph",
                "tdesktop.com",
                "mtproto",
            ]
        
        if self.IP_RANGES is None:
            self.IP_RANGES = [
                ("149.154.160.0", "149.154.175.255"),
                ("91.108.4.0", "91.108.19.255"),
                ("185.76.151.0", "185.76.151.255"),
            ]
        
        if self.MTProto_PORTS is None:
            self.MTProto_PORTS = [443, 80, 8080, 8443]
        
        # IP_PREFIXES инициализируем дефолтными, но можем обновить
        if self.IP_PREFIXES is None:
            self.IP_PREFIXES = [
                "149.154.",  # Официальные DC
                "91.108.",
                "95.161.",
                "45.12.133.",  # CDN
                "185.215.247.",  # MTProto
                "149.154.167.220",  # Web-кластер (новый!)
            ]
        if  self.TCP_PORTS is None:
            self.TCP_PORTS = [443, 80, 8080, 8443]
        
        # Порты для звонков и голоса
        if self.UDP_PORTS is None:
            self.UDP_PORTS = [
                3478,   # STUN
                5349,   # TURN (TLS)
                9350,   # Telegram VoIP
                10000, 10001, 10002, 10003,  # WebRTC медиа диапазон
            ]
    
    def update_ips_from_network(self):
        """Обновляет IP из сети (вызывать при старте)"""
        try:
            from src.ip_updater import get_telegram_ips
            new_ips = get_telegram_ips()
            if new_ips:
                # Добавляем новые IP к существующим
                existing = set(self.IP_PREFIXES)
                for ip in new_ips:
                    # Берём первые 2 октета для префикса
                    parts = ip.split(".")
                    if len(parts) >= 2:
                        prefix = f"{parts[0]}.{parts[1]}."
                        existing.add(prefix)
                self.IP_PREFIXES = list(existing)
                return True
        except Exception as e:
            from src.logger import logger
            logger.warning(f"Не удалось обновить IP: {e}")
        return False
    def get_tcp_filter(self) -> str:
        """Генерирует фильтр для TCP"""
        conditions = [f"tcp.DstPort == {p}" for p in self.TCP_PORTS]
        return " or ".join(conditions)
    
    def get_udp_filter(self) -> str:
        """Генерирует фильтр для UDP"""
        conditions = [f"udp.DstPort == {p}" for p in self.UDP_PORTS]
        return " or ".join(conditions)
    
    def get_filter(self) -> str:
        """Генерирует общий фильтр WinDivert"""
        tcp_part = self.get_tcp_filter()
        udp_part = self.get_udp_filter()
        return f"({tcp_part}) or ({udp_part})"


@dataclass
class FragmentationConfig:
    """Настройки фрагментации"""
    DEFAULT_SIZE: int = 1
    DEFAULT_DELAY_MS: float = 10.0
    MAX_DELAY_MS: float = 100.0
    MIN_DELAY_MS: float = 0.0


@dataclass
class SnifferConfig:
    PORTS: List[int] = None
    TCP_PORTS: List[int] = None
    UDP_PORTS: List[int] = None
    FILTER_TEMPLATE: str = "tcp.DstPort == {}"

    def __post_init__(self):
        if self.PORTS is None:
            self.PORTS = [443, 80, 8080]
        if self.TCP_PORTS is None:
            self.TCP_PORTS = [443, 80, 8080]
        if self.UDP_PORTS is None:
            self.UDP_PORTS = [3478, 5349, 9350]
    
    def get_filter(self) -> str:
        """Генерирует WinDivert фильтр"""
        conditions = [self.FILTER_TEMPLATE.format(port) for port in self.PORTS]
        return " or ".join(conditions)


# Глобальные инстансы конфигов
TELEGRAM = TelegramConfig()
FRAGMENTATION = FragmentationConfig()
SNIFFER = SnifferConfig()