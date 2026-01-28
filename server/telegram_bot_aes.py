"""
XpertVPN Telegram Bot - AES Version
Конвертация обычных ссылок в зашифрованные xpert:// ссылки

Использует AES-256-GCM для шифрования.
Клиент дешифрует локально с тем же секретным ключом.
"""

import logging
import asyncio
from telegram import Update, ReplyKeyboardMarkup, KeyboardButton
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from crypto_manager_aes import XpertCryptoManagerAES
from datetime import datetime
import json
from pathlib import Path

# Настройка логирования
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Конфигурация (НЕ МЕНЯТЬ - данные уже вписаны)
BOT_TOKEN = "8565862140:AAFz20cgXVmhZUsr_YsFVxEaMEw58jsZgRA"
ADMIN_ID = 5372736703

# Инициализация crypto manager с AES
crypto = XpertCryptoManagerAES()

# История ссылок
HISTORY_FILE = Path("/root/xpert-crypto-system/links_history.json")
links_history = []


def load_history():
    """Загрузка истории ссылок"""
    global links_history
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                links_history = json.load(f)
            logger.info(f"Loaded {len(links_history)} links from history")
        except Exception as e:
            logger.error(f"Error loading history: {e}")
            links_history = []
    else:
        links_history = []


def save_history():
    """Сохранение истории ссылок"""
    try:
        with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump(links_history, f, ensure_ascii=False, indent=2)
        logger.info(f"Saved {len(links_history)} links to history")
    except Exception as e:
        logger.error(f"Error saving history: {e}")


def add_to_history(original_url: str, crypto_link: str, user_id: int, username: str = None):
    """Добавление ссылки в историю"""
    entry = {
        "timestamp": datetime.now().isoformat(),
        "original_url": original_url,
        "crypto_link": crypto_link,
        "user_id": user_id,
        "username": username
    }
    links_history.append(entry)
    save_history()


def get_admin_keyboard():
    """Клавиатура для админа"""
    keyboard = [
        [KeyboardButton("📊 Статистика"), KeyboardButton("📜 История ссылок")],
        [KeyboardButton("🔑 Секретный ключ"), KeyboardButton("ℹ️ Помощь")]
    ]
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True)


def get_user_keyboard():
    """Клавиатура для обычного пользователя"""
    keyboard = [
        [KeyboardButton("ℹ️ Помощь")]
    ]
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обработчик команды /start"""
    user_id = update.effective_user.id
    username = update.effective_user.username or "Unknown"
    
    is_admin = user_id == ADMIN_ID
    
    welcome_message = f"""
🚀 **XpertVPN Crypto Link Bot v2 (AES)**

Привет, {update.effective_user.first_name}!

Я конвертирую обычные подписочные ссылки в зашифрованные xpert:// ссылки.

**Как использовать:**
1. Отправь мне обычную ссылку (http:// или https://)
2. Получи зашифрованную ссылку xpert://crypt2/...
3. Используй её в приложении XpertVPN

**Формат:** `xpert://crypt2/[encrypted_data]`

🔐 Шифрование: AES-256-GCM
📱 Дешифровка: локально в приложении
"""
    
    if is_admin:
        welcome_message += "\n\n👑 **Вы администратор!**\nДоступны дополнительные функции."
        keyboard = get_admin_keyboard()
    else:
        keyboard = get_user_keyboard()
    
    await update.message.reply_text(
        welcome_message,
        reply_markup=keyboard,
        parse_mode='Markdown'
    )
    
    logger.info(f"User {user_id} ({username}) started the bot. Admin: {is_admin}")


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обработчик команды /help"""
    help_text = """
📖 **Помощь**

**Основные команды:**
/start - Начать работу с ботом
/help - Показать эту справку
/stats - Статистика (только для админа)
/history - История ссылок (только для админа)

**Как конвертировать ссылку:**
Просто отправь мне обычную ссылку, например:
`https://example.com/subscription/server1`

Я верну тебе зашифрованную ссылку:
`xpert://crypt2/...`

**Поддерживаемые форматы:**
- http://...
- https://...
- vless://...
- vmess://...
- ss://...
- trojan://...

**Безопасность:**
Все ссылки шифруются AES-256-GCM.
Дешифровка происходит локально в приложении XpertVPN.
"""
    
    await update.message.reply_text(help_text, parse_mode='Markdown')


async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Статистика (только для админа)"""
    user_id = update.effective_user.id
    
    if user_id != ADMIN_ID:
        await update.message.reply_text("❌ Эта команда доступна только администратору.")
        return
    
    total_links = len(links_history)
    unique_users = len(set(entry['user_id'] for entry in links_history))
    last_link = links_history[-1] if links_history else None
    
    stats_text = f"""
📊 **Статистика бота**

📝 Всего ссылок: {total_links}
👥 Уникальных пользователей: {unique_users}
🔐 Версия шифрования: AES-256-GCM (crypt2)
"""
    
    if last_link:
        stats_text += f"""
🕐 Последняя ссылка:
   • Время: {last_link['timestamp'][:19]}
   • URL: {last_link['original_url'][:50]}...
   • Пользователь: @{last_link.get('username', 'Unknown')}
"""
    
    await update.message.reply_text(stats_text, parse_mode='Markdown')


async def history_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """История ссылок (только для админа)"""
    user_id = update.effective_user.id
    
    if user_id != ADMIN_ID:
        await update.message.reply_text("❌ Эта команда доступна только администратору.")
        return
    
    if not links_history:
        await update.message.reply_text("📜 История пуста.")
        return
    
    recent_links = links_history[-10:]
    
    history_text = "📜 **Последние 10 ссылок:**\n\n"
    
    for i, entry in enumerate(reversed(recent_links), 1):
        timestamp = entry['timestamp'][:19]
        url = entry['original_url']
        username = entry.get('username', 'Unknown')
        
        history_text += f"{i}. **{timestamp}**\n"
        history_text += f"   URL: {url}\n"
        history_text += f"   User: @{username}\n\n"
    
    await update.message.reply_text(history_text, parse_mode='Markdown')


async def secretkey_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Получить секретный ключ (только для админа)"""
    user_id = update.effective_user.id
    
    if user_id != ADMIN_ID:
        await update.message.reply_text("❌ Эта команда доступна только администратору.")
        return
    
    key_hex = crypto.get_key_hex()
    
    message = f"""
🔑 **Секретный ключ AES-256**

Этот ключ используется для дешифрования xpert:// ссылок в приложении.

**Ключ (HEX):**
`{key_hex}`

**Исходная строка ключа:**
`{crypto.SECRET_KEY}`

⚠️ Этот ключ должен быть встроен в Android приложение!
"""
    
    await update.message.reply_text(message, parse_mode='Markdown')


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обработчик текстовых сообщений"""
    user_id = update.effective_user.id
    username = update.effective_user.username
    text = update.message.text
    
    # Обработка кнопок клавиатуры
    if text == "📊 Статистика":
        await stats_command(update, context)
        return
    elif text == "📜 История ссылок":
        await history_command(update, context)
        return
    elif text == "🔑 Секретный ключ":
        await secretkey_command(update, context)
        return
    elif text == "ℹ️ Помощь":
        await help_command(update, context)
        return
    
    # Проверяем, является ли сообщение ссылкой
    if not (text.startswith('http://') or text.startswith('https://') or 
            text.startswith('vless://') or text.startswith('vmess://') or
            text.startswith('ss://') or text.startswith('trojan://')):
        await update.message.reply_text(
            "❌ Пожалуйста, отправь валидную ссылку.\n\n"
            "Поддерживаемые форматы:\n"
            "• http://...\n"
            "• https://...\n"
            "• vless://...\n"
            "• vmess://...\n"
            "• ss://...\n"
            "• trojan://..."
        )
        return
    
    try:
        await update.message.chat.send_action("typing")
        
        # Шифруем ссылку с AES
        crypto_link = crypto.encrypt_url(
            text,
            metadata={
                "encrypted_by": "XpertVPN Bot v2",
                "timestamp": datetime.now().isoformat()
            }
        )
        
        add_to_history(text, crypto_link, user_id, username)
        
        response = f"""
✅ **Ссылка зашифрована! (AES-256)**

**Оригинал:**
`{text[:100]}{'...' if len(text) > 100 else ''}`

**Зашифрованная ссылка:**
`{crypto_link}`

📱 Используй эту ссылку в приложении XpertVPN
🔐 Дешифровка происходит локально
"""
        
        await update.message.reply_text(response, parse_mode='Markdown')
        
        logger.info(f"Encrypted link for user {user_id} (@{username})")
        
    except Exception as e:
        logger.error(f"Error encrypting link: {e}")
        await update.message.reply_text(
            f"❌ Ошибка при шифровании ссылки:\n{str(e)}"
        )


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обработчик ошибок"""
    logger.error(f"Update {update} caused error {context.error}")


def run_bot():
    """Запуск бота"""
    while True:
        try:
            load_history()
            
            application = Application.builder().token(BOT_TOKEN).build()
            
            application.add_handler(CommandHandler("start", start))
            application.add_handler(CommandHandler("help", help_command))
            application.add_handler(CommandHandler("stats", stats_command))
            application.add_handler(CommandHandler("history", history_command))
            application.add_handler(CommandHandler("secretkey", secretkey_command))
            application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
            
            application.add_error_handler(error_handler)
            
            logger.info("🚀 XpertVPN Crypto Bot v2 (AES) started!")
            logger.info(f"👑 Admin ID: {ADMIN_ID}")
            logger.info(f"🔐 Encryption: AES-256-GCM")
            
            application.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)
            
        except KeyboardInterrupt:
            logger.info("Bot stopped by user")
            break
        except Exception as e:
            logger.error(f"Bot crashed: {e}")
            logger.info("Restarting bot in 5 seconds...")
            import time
            time.sleep(5)


if __name__ == '__main__':
    run_bot()
