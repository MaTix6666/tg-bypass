"""
Парсер TLS ClientHello для извлечения SNI
RFC 8446 - TLS 1.3
"""

import struct
from dataclasses import dataclass
from typing import Optional, List, Tuple


@dataclass
class TLSExtension:
    type: int
    data: bytes


@dataclass
class ClientHello:
    legacy_version: Tuple[int, int]
    random: bytes
    session_id: bytes
    cipher_suites: List[int]
    compression_methods: List[int]
    extensions: List[TLSExtension]
    sni: Optional[str] = None


class TLSParserError(Exception):
    pass


class ClientHelloParser:
    """Парсер TLS ClientHello"""
    
    # Extension types
    EXT_SERVER_NAME = 0x0000
    
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.length = len(data)
        
    def parse(self) -> Optional[ClientHello]:
        """Парсит ClientHello из сырых данных"""
        try:
            # TLS Record Layer (5 bytes)
            content_type = self._read_uint8()
            if content_type != 0x16:  # Handshake
                return None
                
            version = self._read_uint16()
            record_length = self._read_uint16()
            
            # Проверяем, что данных достаточно
            if self.length < 5 + record_length:
                return None
                
            # Handshake Header (4 bytes)
            msg_type = self._read_uint8()
            if msg_type != 0x01:  # ClientHello
                return None
                
            hello_length = self._read_uint24()
            
            # ClientHello body
            legacy_version = (self._read_uint8(), self._read_uint8())
            random = self._read_bytes(32)
            
            # Session ID
            session_id_len = self._read_uint8()
            session_id = self._read_bytes(session_id_len)
            
            # Cipher Suites
            cipher_suites_len = self._read_uint16()
            cipher_suites = []
            for _ in range(cipher_suites_len // 2):
                cipher_suites.append(self._read_uint16())
                
            # Compression Methods
            comp_methods_len = self._read_uint8()
            compression_methods = list(self._read_bytes(comp_methods_len))
            
            # Extensions
            extensions = []
            sni = None
            
            if self.pos + 2 <= self.length:
                extensions_len = self._read_uint16()
                ext_end = self.pos + extensions_len
                
                while self.pos + 4 <= ext_end:
                    ext_type = self._read_uint16()
                    ext_len = self._read_uint16()
                    ext_data = self._read_bytes(ext_len)
                    extensions.append(TLSExtension(ext_type, ext_data))
                    
                    if ext_type == self.EXT_SERVER_NAME:
                        sni = self._parse_sni(ext_data)
                        
            return ClientHello(
                legacy_version=legacy_version,
                random=random,
                session_id=session_id,
                cipher_suites=cipher_suites,
                compression_methods=compression_methods,
                extensions=extensions,
                sni=sni
            )
            
        except (struct.error, IndexError) as e:
            raise TLSParserError(f"Failed to parse ClientHello: {e}")
            
    def _parse_sni(self, data: bytes) -> Optional[str]:
        """Парсит SNI из extension data"""
        try:
            if len(data) < 5:
                return None
                
            # SNI List Length (2 bytes)
            list_len = struct.unpack("!H", data[0:2])[0]
            pos = 2
            
            while pos < 2 + list_len:
                if pos + 3 > len(data):
                    break
                    
                name_type = data[pos]
                name_len = struct.unpack("!H", data[pos+1:pos+3])[0]
                pos += 3
                
                if name_type == 0x00:  # host_name
                    if pos + name_len <= len(data):
                        return data[pos:pos+name_len].decode('utf-8', errors='ignore')
                pos += name_len
                
        except Exception:
            pass
        return None
        
    def _read_uint8(self) -> int:
        val = self.data[self.pos]
        self.pos += 1
        return val
        
    def _read_uint16(self) -> int:
        val = struct.unpack("!H", self.data[self.pos:self.pos+2])[0]
        self.pos += 2
        return val
        
    def _read_uint24(self) -> int:
        val = ((self.data[self.pos] << 16) | 
               (self.data[self.pos+1] << 8) | 
               self.data[self.pos+2])
        self.pos += 3
        return val
        
    def _read_bytes(self, n: int) -> bytes:
        val = self.data[self.pos:self.pos+n]
        self.pos += n
        return val


def is_tls_client_hello(data: bytes) -> bool:
    """Быстрая проверка, является ли payload TLS ClientHello"""
    return (len(data) >= 6 and 
            data[0] == 0x16 and  # Handshake
            data[1] == 0x03 and  # TLS major version
            data[5] == 0x01)     # ClientHello


def get_sni_from_payload(payload: bytes) -> Optional[str]:
    """Утилита для быстрого получения SNI"""
    if not is_tls_client_hello(payload):
        return None
    try:
        parser = ClientHelloParser(payload)
        hello = parser.parse()
        return hello.sni if hello else None
    except TLSParserError:
        return None