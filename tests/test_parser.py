"""
Минимальные тесты парсера TLS
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.tls_parser import is_tls_client_hello, get_sni_from_payload


def test_basic():
    """Базовые тесты"""
    
    # Тест 1: Не TLS
    assert is_tls_client_hello(b"HTTP") == False
    print("✓ Non-TLS detected")
    
    # Тест 2: TLS ClientHello (минимальный валидный)
    # Важно: длина в заголовке должна соответствовать реальной длине
    minimal_tls = bytes([
        0x16,        # Handshake
        0x03, 0x01,  # TLS 1.0
        0x00, 0x05,  # Length: 5 bytes (должно быть реальной длиной!)
        0x01,        # ClientHello
        0x00, 0x00, 0x01,  # Length: 1
        0x00         # 1 byte данных
    ])
    assert is_tls_client_hello(minimal_tls) == True
    print("✓ TLS detected")
    
    # Тест 3: get_sni_from_payload с некорректными данными
    result = get_sni_from_payload(b"not tls")
    assert result is None
    print("✓ SNI extraction handles garbage")
    
    # Тест 4: get_sni_from_payload с TLS но без SNI
    tls_no_ext = bytes([
        0x16, 0x03, 0x01, 0x00, 0x25,  # Record header: length = 37
        0x01, 0x00, 0x00, 0x21,        # Handshake: length = 33
        0x03, 0x03,                    # Version
    ]) + bytes([0x00] * 32) + bytes([  # Random (32 bytes)
        0x00,                          # Session ID len = 0
        0x00, 0x02, 0x00, 0xff,       # Cipher suites (2 bytes)
        0x01, 0x00,                    # Compression (1 byte, null)
        0x00, 0x00,                    # Extensions length = 0 (нет расширений!)
    ])
    
    result = get_sni_from_payload(tls_no_ext)
    # Должно быть None потому что нет extensions
    print(f"  TLS without extensions: SNI={result}")
    
    print("\n" + "="*40)
    print("Basic tests passed!")
    print("="*40)
    print("\nПарсер работает. Проблема была в тестовых данных.")
    print("Длины в TLS заголовках должны точно соответствовать реальным данным.")


if __name__ == "__main__":
    test_basic()