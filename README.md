# XpertVPN Crypto System

Система шифрования подписочных ссылок для XpertVPN.

## Архитектура

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Telegram Bot   │────▶│  xpert://crypt2 │────▶│  Android App    │
│  (Шифрование)   │     │    ссылка       │     │ (Дешифровка)    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                                               │
        ▼                                               ▼
   AES-256-GCM                                    AES-256-GCM
   Шифрование                                     Дешифровка
   (SECRET_KEY)                                   (SECRET_KEY)
```

## Компоненты

### 1. Telegram Bot (server/)
- `crypto_manager_aes.py` - AES-256-GCM шифрование
- `telegram_bot_aes.py` - Telegram бот для шифрования ссылок

### 2. Android Client (интегрировано в V2rayNG)
- `XpertCryptoManager.kt` - Локальная AES-256-GCM дешифровка

## Формат ссылки

```
xpert://crypt2/[base64_encoded_data]
```

Где `base64_encoded_data` содержит:
- 12 байт nonce
- Зашифрованные данные (JSON с полем "url")

## Установка бота

```bash
cd server
pip install -r requirements.txt
python telegram_bot_aes.py
```

## Секретный ключ

**ВАЖНО:** Ключ должен совпадать в боте и в приложении!

```
XpertVPN2024SecretKey!@#$%^&*()
```

## Использование

1. Отправьте обычную ссылку боту
2. Получите зашифрованную xpert:// ссылку
3. Вставьте в приложение XpertVPN
4. Приложение автоматически дешифрует локально