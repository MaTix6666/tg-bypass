"""
Автообновление IP-адресов Telegram из официальных источников
"""

import json
import urllib.request
import urllib.error
from pathlib import Path
from typing import List, Set
from src.logger import logger


class TelegramIPUpdater:
    """
    Обновляет списки IP Telegram из официальных источников
    """
    
    # Официальные источники Telegram
    SOURCES = {
        "asn": "https://ipinfo.io/AS62041/json",  # ASN Telegram Messenger Inc
        "bgp": "https://api.bgpview.io/asn/62041/prefixes",
    }
    
    CACHE_FILE = Path("data/telegram_ips.json")
    CACHE_TTL_HOURS = 24  # Обновляем раз в сутки
    
    def __init__(self):
        self.CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    
    def get_ips(self) -> List[str]:
        """
        Возвращает актуальный список IP-адресов Telegram
        
        Returns:
            Список IP-префиксов (CIDR или отдельные IP)
        """
        # Пробуем загрузить из кэша
        if self._is_cache_valid():
            logger.debug("Загрузка IP из кэша")
            return self._load_from_cache()
        
        # Пробуем обновить из сети
        try:
            ips = self._fetch_from_network()
            self._save_to_cache(ips)
            logger.info(f"IP-адреса обновлены: {len(ips)} записей")
            return ips
        except Exception as e:
            logger.warning(f"Не удалось обновить IP из сети: {e}")
            # Fallback на кэш или дефолтные значения
            if self.CACHE_FILE.exists():
                return self._load_from_cache()
            return []
    
    def _is_cache_valid(self) -> bool:
        """Проверяет, актуален ли кэш"""
        if not self.CACHE_FILE.exists():
            return False
        
        import time
        cache_age = time.time() - self.CACHE_FILE.stat().st_mtime
        return cache_age < (self.CACHE_TTL_HOURS * 3600)
    
    def _load_from_cache(self) -> List[str]:
        """Загружает IP из кэша"""
        try:
            with open(self.CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("ips", [])
        except Exception as e:
            logger.error(f"Ошибка загрузки кэша: {e}")
            return []
    
    def _save_to_cache(self, ips: List[str]):
        """Сохраняет IP в кэш"""
        try:
            with open(self.CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "ips": ips,
                    "updated": str(Path().stat().st_mtime)
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Ошибка сохранения кэша: {e}")
    
    def _fetch_from_network(self) -> List[str]:
        """Загружает IP из официальных источников"""
        ips = set()
        
        # Пробуем BGPView API
        try:
            data = self._fetch_json(self.SOURCES["bgp"])
            if data and "data" in data:
                for prefix in data["data"].get("ipv4_prefixes", []):
                    ips.add(prefix["prefix"])
        except Exception as e:
            logger.debug(f"BGPView недоступен: {e}")
        
        # Пробуем ipinfo.io
        try:
            data = self._fetch_json(self.SOURCES["asn"])
            if data and "prefixes" in data:
                for prefix in data["prefixes"]:
                    ips.add(prefix["netblock"])
        except Exception as e:
            logger.debug(f"ipinfo.io недоступен: {e}")
        
        return sorted(list(ips))
    
    def _fetch_json(self, url: str) -> dict:
        """Загружает JSON по URL"""
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "TelegramBypass/1.0",
                "Accept": "application/json"
            }
        )
        
        with urllib.request.urlopen(req, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))


# Глобальный инстанс
_ip_updater = None

def get_telegram_ips() -> List[str]:
    """Получает актуальные IP Telegram (с кэшированием updater'а)"""
    global _ip_updater
    if _ip_updater is None:
        _ip_updater = TelegramIPUpdater()
    return _ip_updater.get_ips()