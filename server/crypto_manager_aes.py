"""
XpertVPN Crypto Link System - AES Version
Шифрование подписочных ссылок с локальной дешифровкой

Формат: xpert://crypt2/[encrypted_data_base64]

Используется AES-256-GCM для шифрования.
Секретный ключ встроен в приложение для локальной дешифровки.
"""

import base64
import json
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class XpertCryptoManagerAES:
    """Менеджер для шифрования/дешифрования XpertVPN ссылок с AES"""
    
    PROTOCOL = "xpert://"
    VERSION = "crypt2"
    
    # Секретный ключ (32 байта для AES-256)
    # ВАЖНО: Этот же ключ должен быть в Android приложении!
    SECRET_KEY = "XpertVPN2024SecretKey!@#$%^&*()"
    
    def __init__(self, secret_key: str = None):
        """
        Инициализация менеджера
        
        Args:
            secret_key: Секретный ключ (если не указан, используется дефолтный)
        """
        key_str = secret_key or self.SECRET_KEY
        # Генерируем 32-байтный ключ из строки через SHA-256
        self.key = hashlib.sha256(key_str.encode()).digest()
        self.aesgcm = AESGCM(self.key)
        
        logger.info("AES-256-GCM crypto manager initialized")
    
    def encrypt_url(self, url: str, metadata: dict = None) -> str:
        """
        Шифрование обычной ссылки в xpert:// формат
        
        Args:
            url: Обычная подписочная ссылка (http://, https://)
            metadata: Дополнительные метаданные (опционально)
        
        Returns:
            Зашифрованная ссылка в формате xpert://crypt2/...
        """
        try:
            # Подготавливаем данные для шифрования
            data = {
                "url": url,
                "version": self.VERSION,
                "metadata": metadata or {}
            }
            
            # Конвертируем в JSON
            json_data = json.dumps(data).encode('utf-8')
            
            # Генерируем случайный nonce (12 байт для GCM)
            nonce = os.urandom(12)
            
            # Шифруем данные
            encrypted = self.aesgcm.encrypt(nonce, json_data, None)
            
            # Объединяем nonce + encrypted_data
            combined = nonce + encrypted
            
            # Кодируем в base64 (URL-safe)
            encrypted_b64 = base64.urlsafe_b64encode(combined).decode('utf-8')
            
            # Формируем финальную ссылку
            crypto_link = f"{self.PROTOCOL}{self.VERSION}/{encrypted_b64}"
            
            logger.info(f"Encrypted URL: {url[:50]}... -> {crypto_link[:80]}...")
            
            return crypto_link
            
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            raise
    
    def decrypt_url(self, crypto_link: str) -> dict:
        """
        Дешифрование xpert:// ссылки
        
        Args:
            crypto_link: Зашифрованная ссылка xpert://crypt2/...
        
        Returns:
            Словарь с расшифрованными данными
        """
        try:
            # Проверяем формат
            if not crypto_link.startswith(self.PROTOCOL):
                raise ValueError(f"Invalid protocol. Expected {self.PROTOCOL}")
            
            # Парсим ссылку
            parts = crypto_link[len(self.PROTOCOL):].split('/')
            
            if len(parts) < 2:
                raise ValueError("Invalid crypto link format")
            
            version = parts[0]
            encrypted_b64 = parts[1]
            
            # Проверяем версию
            if version != self.VERSION:
                raise ValueError(f"Unsupported version: {version}")
            
            # Декодируем из base64
            combined = base64.urlsafe_b64decode(encrypted_b64)
            
            # Извлекаем nonce (первые 12 байт) и зашифрованные данные
            nonce = combined[:12]
            encrypted = combined[12:]
            
            # Дешифруем данные
            decrypted = self.aesgcm.decrypt(nonce, encrypted, None)
            
            # Парсим JSON
            data = json.loads(decrypted.decode('utf-8'))
            
            logger.info(f"Decrypted URL: {data.get('url', '')[:50]}...")
            
            return data
            
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            raise
    
    def get_key_hex(self) -> str:
        """Получить ключ в hex формате для отладки"""
        return self.key.hex()


# Тестирование
if __name__ == "__main__":
    print("=== XpertVPN Crypto Link System (AES) Test ===\n")
    
    # Инициализация
    crypto = XpertCryptoManagerAES()
    
    # Тестовая ссылка
    test_url = "https://example.com/sub/test123"
    
    print(f"Original URL: {test_url}\n")
    
    # Шифрование
    crypto_link = crypto.encrypt_url(test_url, metadata={"server": "USA-1", "type": "premium"})
    print(f"Encrypted: {crypto_link}\n")
    
    # Дешифрование
    decrypted = crypto.decrypt_url(crypto_link)
    print(f"Decrypted URL: {decrypted['url']}")
    print(f"Metadata: {decrypted['metadata']}\n")
    
    # Проверка
    if decrypted['url'] == test_url:
        print("✅ Encryption/Decryption test PASSED!")
    else:
        print("❌ Encryption/Decryption test FAILED!")
    
    print(f"\nKey (hex): {crypto.get_key_hex()}")
