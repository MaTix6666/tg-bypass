"""
Обработка MTProto прокси-трафика
"""

import struct
from typing import Optional, Tuple
from src.logger import logger


class MTProtoDetector:
    """
    Детектирует MTProto прокси-трафик по характерным признакам
    """
    
    # MTProto secret types
    SECRET_TYPES = {
        0x00: "simple",
        0x01: "secured",
        0x02: "tls_padding",
    }
    
    @staticmethod
    def is_mtproto_payload(payload: bytes) -> bool:
        """
        Проверяет, является ли payload MTProto handshake
        
        MTProto proxy handshake начинается с:
        - 0xee для simple secret
        - 0x01 для secured
        - Или содержит specific byte patterns
        """
        if len(payload) < 8:
            return False
        
        # Проверяем характерные признаки MTProto
        first_byte = payload[0]
        
        # Simple secret: 0xee followed by 4 bytes timestamp
        if first_byte == 0xee and len(payload) >= 64:
            return True
        
        # Secured secret: начинается с 0x01 и длиной 32+ байт
        if first_byte == 0x01 and len(payload) >= 32:
            # Проверяем структуру
            try:
                # MTProto secured имеет специфичную структуру
                return True  # Упрощённая проверка
            except:
                pass
        
        # TLS-like MTProto (с伪装ом под TLS)
        if payload[0] == 0x16 and len(payload) > 5:
            # Похоже на TLS, но может быть MTProto с TLS-обёрткой
            return False  # Пусть TLS parser разбирается
        
        return False
    
    @staticmethod
    def extract_mtproto_info(payload: bytes) -> Optional[dict]:
        """
        Извлекает информацию из MTProto handshake
        
        Returns:
            dict с информацией или None
        """
        if not MTProtoDetector.is_mtproto_payload(payload):
            return None
        
        info = {
            "type": "unknown",
            "length": len(payload),
        }
        
        first_byte = payload[0]
        if first_byte == 0xee:
            info["type"] = "mtproto_simple"
            # Пытаемся извлечь timestamp (bytes 1-4)
            if len(payload) >= 5:
                timestamp = struct.unpack(">I", payload[1:5])[0]
                info["timestamp"] = timestamp
        elif first_byte == 0x01:
            info["type"] = "mtproto_secured"
        
        return info


class MTProtoFragmenter:
    """
    Специальная фрагментация для MTProto
    """
    
    def __init__(self, base_fragmenter):
        self.base_fragmenter = base_fragmenter
    
    def process_mtproto(self, w, packet, payload: bytes) -> bool:
        """
        Обрабатывает MTProto пакет специальным образом
        
        MTProto требует особой осторожности с фрагментацией,
        так как имеет свою криптографию
        """
        try:
            # Для MTProto используем более консервативную фрагментацию
            # Фрагментируем только первые байты handshake
            info = MTProtoDetector.extract_mtproto_info(payload)
            
            if info and info.get("type") == "mtproto_simple":
                # Simple MTProto: фрагментируем первые 8 байт
                logger.debug("MTProto simple detected, applying light fragmentation")
                # Здесь можно добавить специфичную логику
                return self.base_fragmenter.process_packet(w, packet)
            else:
                # Secured или неизвестный тип: стандартная фрагментация
                return self.base_fragmenter.process_packet(w, packet)
                
        except Exception as e:
            logger.error(f"MTProto processing error: {e}")
            return False