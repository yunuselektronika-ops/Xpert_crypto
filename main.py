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
from datetime import datetime
import json
from pathlib import Path
import base64
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from aiohttp import web
import threading

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)


class XpertCryptoManagerAES:
    """Менеджер для шифрования/дешифрования XpertVPN ссылок с AES"""
    
    PROTOCOL = "xpert://"
    VERSION = "crypt2"
    SECRET_KEY = "XpertVPN2024SecretKey!@#$%^&*()"
    
    def __init__(self, secret_key: str = None):
        key_str = secret_key or self.SECRET_KEY
        self.key = hashlib.sha256(key_str.encode()).digest()
        self.aesgcm = AESGCM(self.key)
        logger.info("AES-256-GCM crypto manager initialized")
    
    def encrypt_url(self, url: str, hwid: str = None, metadata: dict = None) -> str:
        """
        Шифрует URL с опциональной привязкой к HWID устройства.
        
        Args:
            url: Оригинальная ссылка для шифрования
            hwid: HWID устройства для привязки (None = без привязки)
            metadata: Дополнительные метаданные
            
        Returns:
            Зашифрованная xpert:// ссылка
        """
        try:
            data = {
                "url": url,
                "version": self.VERSION,
                "metadata": metadata or {}
            }
            
            # Добавляем HWID если указан
            if hwid:
                data["hwid"] = hwid
                logger.info(f"Encrypting with HWID binding: {hwid}")
            
            json_data = json.dumps(data).encode('utf-8')
            nonce = os.urandom(12)
            encrypted = self.aesgcm.encrypt(nonce, json_data, None)
            combined = nonce + encrypted
            encrypted_b64 = base64.urlsafe_b64encode(combined).decode('utf-8')
            crypto_link = f"{self.PROTOCOL}{self.VERSION}/{encrypted_b64}"
            
            logger.info(f"Encrypted URL: {url[:50]}... -> {crypto_link[:80]}...")
            return crypto_link
            
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            raise
    
    def get_key_hex(self) -> str:
        return self.key.hex()


BOT_TOKEN = "8565862140:AAGeXlspsLvxGryCVbRYGZvTvuV6gbz5Srw"
ADMIN_ID = 5372736703

crypto = XpertCryptoManagerAES()

HISTORY_FILE = Path("links_history.json")
HWID_FILE = Path("user_hwids.json")
links_history = []
user_hwids = {}  # user_id -> hwid
user_mode = {}  # user_id -> "free" или "hwid" (режим шифрования)
pending_hwid = {}  # user_id -> True (ожидает ввода HWID для привязки)


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


def load_hwids():
    """Загрузка HWID пользователей"""
    global user_hwids
    if HWID_FILE.exists():
        try:
            with open(HWID_FILE, 'r', encoding='utf-8') as f:
                user_hwids = json.load(f)
            logger.info(f"Loaded {len(user_hwids)} user HWIDs")
        except Exception as e:
            logger.error(f"Error loading HWIDs: {e}")
            user_hwids = {}
    else:
        user_hwids = {}


def save_hwids():
    """Сохранение HWID пользователей"""
    try:
        with open(HWID_FILE, 'w', encoding='utf-8') as f:
            json.dump(user_hwids, f, ensure_ascii=False, indent=2)
        logger.info(f"Saved {len(user_hwids)} user HWIDs")
    except Exception as e:
        logger.error(f"Error saving HWIDs: {e}")


def add_to_history(original_url: str, crypto_link: str, user_id: int, username: str = None, hwid: str = None):
    """Добавление ссылки в историю"""
    entry = {
        "timestamp": datetime.now().isoformat(),
        "original_url": original_url,
        "crypto_link": crypto_link,
        "user_id": user_id,
        "username": username,
        "hwid_bound": hwid is not None,
        "hwid": hwid
    }
    links_history.append(entry)
    save_history()


def get_admin_keyboard():
    """Клавиатура для админа"""
    keyboard = [
        [KeyboardButton("� Без HWID"), KeyboardButton("🔐 С HWID")],
        [KeyboardButton("�� Статистика"), KeyboardButton("📜 История ссылок")],
        [KeyboardButton("🔑 Секретный ключ"), KeyboardButton("📱 HWID список")],
        [KeyboardButton("ℹ️ Помощь")]
    ]
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True)


def get_user_keyboard():
    """Клавиатура для обычного пользователя"""
    keyboard = [
        [KeyboardButton(" С HWID")],
        [KeyboardButton("📱 Мой HWID"), KeyboardButton("ℹ️ Помощь")]
    ]
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обработчик команды /start"""
    user_id = update.effective_user.id
    username = update.effective_user.username or "Unknown"
    
    is_admin = user_id == ADMIN_ID
    
    welcome_message = f"""
� **XpertVPN Crypto Link Bot v2**

Привет, {update.effective_user.first_name}!

▫️ Отправьте ссылку для шифрования
▫️ Получите защищенную xpert:// ссылку
▫️ Используйте в приложении XpertVPN
"""
    
    if is_admin:
        welcome_message += "\n\n━━━━━━━━━━━━━━━━━━\n👑 Режим администратора"
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
📖 **Справка**

**Команды:**
/start - Главное меню
/help - Справка

**Использование:**
Отправьте ссылку для шифрования
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
📊 **Статистика**

━━━━━━━━━━━━━━━━━━
📝 Всего ссылок: {total_links}
👥 Пользователей: {unique_users}
🔐 Версия: crypt2 (AES-256-GCM)
━━━━━━━━━━━━━━━━━━
"""
    
    if last_link:
        stats_text += f"""
🕐 Последняя ссылка:
▫️ {last_link['timestamp'][:19]}
▫️ @{last_link.get('username', 'Unknown')}
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
    
    history_text = "📜 **История ссылок**\n\n━━━━━━━━━━━━━━━━━━\n"
    
    for i, entry in enumerate(reversed(recent_links), 1):
        timestamp = entry['timestamp'][:19]
        original_url = entry.get('original_url', 'N/A')
        crypto_link = entry.get('crypto_link', 'N/A')
        username = entry.get('username', 'Unknown')
        
        history_text += f"{i}. {timestamp} - @{username}\n"
        history_text += f"   📤 {original_url}\n\n"
    
    await update.message.reply_text(history_text, parse_mode='Markdown')


async def secretkey_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Получить секретный ключ (только для админа)"""
    user_id = update.effective_user.id
    
    if user_id != ADMIN_ID:
        await update.message.reply_text("❌ Эта команда доступна только администратору.")
        return
    
    key_hex = crypto.get_key_hex()
    
    message = f"""
🔑 **Секретный ключ**

━━━━━━━━━━━━━━━━━━
`{key_hex}`
━━━━━━━━━━━━━━━━━━

⚠️ Для Android приложения
"""
    
    await update.message.reply_text(message, parse_mode='Markdown')


async def hwid_list_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Список HWID пользователей (только для админа)"""
    user_id = update.effective_user.id
    
    if user_id != ADMIN_ID:
        await update.message.reply_text("❌ Эта команда доступна только администратору.")
        return
    
    if not user_hwids:
        await update.message.reply_text("📱 Список HWID пуст.\n\nПользователи могут зарегистрировать HWID командой /hwid <код>")
        return
    
    hwid_text = "📱 **Список HWID**\n\n━━━━━━━━━━━━━━━━━━\n"
    
    for uid, hwid in user_hwids.items():
        hwid_text += f"👤 User ID: `{uid}`\n"
        hwid_text += f"📱 HWID: `{hwid}`\n\n"
    
    hwid_text += f"━━━━━━━━━━━━━━━━━━\n📊 Всего: {len(user_hwids)}"
    
    await update.message.reply_text(hwid_text, parse_mode='Markdown')


async def hwid_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Регистрация HWID пользователя"""
    user_id = update.effective_user.id
    username = update.effective_user.username or "Unknown"
    
    if not context.args:
        # Показать текущий HWID
        current_hwid = user_hwids.get(str(user_id))
        if current_hwid:
            await update.message.reply_text(
                f"📱 **Ваш HWID**\n\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"`{current_hwid}`\n"
                f"━━━━━━━━━━━━━━━━━━\n\n"
                f"Для изменения: /hwid <новый_код>",
                parse_mode='Markdown'
            )
        else:
            await update.message.reply_text(
                "📱 **HWID не зарегистрирован**\n\n"
                "Чтобы зарегистрировать HWID:\n"
                "1. Откройте XpertVPN\n"
                "2. Перейдите в Настройки → О приложении\n"
                "3. Скопируйте HWID\n"
                "4. Отправьте: /hwid <ваш_код>\n\n"
                "После регистрации ссылки будут привязаны к вашему устройству.",
                parse_mode='Markdown'
            )
        return
    
    new_hwid = context.args[0].strip()
    
    if len(new_hwid) < 8:
        await update.message.reply_text("❌ HWID должен быть не менее 8 символов.")
        return
    
    user_hwids[str(user_id)] = new_hwid
    save_hwids()
    
    await update.message.reply_text(
        f"✅ **HWID зарегистрирован!**\n\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"`{new_hwid}`\n"
        f"━━━━━━━━━━━━━━━━━━\n\n"
        f"Теперь ваши ссылки будут привязаны к этому устройству.\n"
        f"Для ссылки БЕЗ привязки используйте /free <ссылка>",
        parse_mode='Markdown'
    )
    
    logger.info(f"User {user_id} (@{username}) registered HWID: {new_hwid}")


async def free_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Создать ссылку БЕЗ привязки к HWID"""
    user_id = update.effective_user.id
    username = update.effective_user.username
    
    if not context.args:
        await update.message.reply_text(
            "📝 **Использование:**\n"
            "/free <ссылка>\n\n"
            "Создает зашифрованную ссылку БЕЗ привязки к устройству.",
            parse_mode='Markdown'
        )
        return
    
    url = ' '.join(context.args)
    
    if not (url.startswith('http://') or url.startswith('https://') or 
            url.startswith('vless://') or url.startswith('vmess://') or
            url.startswith('ss://') or url.startswith('trojan://')):
        await update.message.reply_text("❌ Неверный формат ссылки.")
        return
    
    try:
        await update.message.chat.send_action("typing")
        
        crypto_link = crypto.encrypt_url(
            url,
            hwid=None,  # Без привязки к HWID
            metadata={
                "encrypted_by": "XpertVPN Bot v2",
                "timestamp": datetime.now().isoformat()
            }
        )
        
        add_to_history(url, crypto_link, user_id, username, hwid=None)
        
        response = f"""
✅ **Ссылка зашифрована (без привязки)**

━━━━━━━━━━━━━━━━━━
`{crypto_link}`
━━━━━━━━━━━━━━━━━━

🔓 Без привязки к устройству
📱 Можно использовать на любом устройстве
"""
        
        await update.message.reply_text(response, parse_mode='Markdown')
        
    except Exception as e:
        logger.error(f"Error encrypting link: {e}")
        await update.message.reply_text(f"❌ Ошибка: {str(e)}")


async def bind_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Создать ссылку С привязкой к HWID"""
    user_id = update.effective_user.id
    username = update.effective_user.username
    
    if not context.args:
        await update.message.reply_text(
            "📝 **Использование:**\n"
            "/bind <hwid> <ссылка>\n\n"
            "Создает зашифрованную ссылку С привязкой к указанному HWID.\n\n"
            "Пример:\n"
            "/bind abc12345 vless://...",
            parse_mode='Markdown'
        )
        return
    
    if len(context.args) < 2:
        await update.message.reply_text("❌ Укажите HWID и ссылку.")
        return
    
    hwid = context.args[0]
    url = ' '.join(context.args[1:])
    
    if not (url.startswith('http://') or url.startswith('https://') or 
            url.startswith('vless://') or url.startswith('vmess://') or
            url.startswith('ss://') or url.startswith('trojan://')):
        await update.message.reply_text("❌ Неверный формат ссылки.")
        return
    
    try:
        await update.message.chat.send_action("typing")
        
        crypto_link = crypto.encrypt_url(
            url,
            hwid=hwid,  # С привязкой к HWID
            metadata={
                "encrypted_by": "XpertVPN Bot v2",
                "timestamp": datetime.now().isoformat()
            }
        )
        
        add_to_history(url, crypto_link, user_id, username, hwid=hwid)
        
        response = f"""
✅ **Ссылка зашифрована (с привязкой)**

━━━━━━━━━━━━━━━━━━
`{crypto_link}`
━━━━━━━━━━━━━━━━━━

🔐 Привязано к HWID: `{hwid}`
📱 Работает ТОЛЬКО на этом устройстве
"""
        
        await update.message.reply_text(response, parse_mode='Markdown')
        
    except Exception as e:
        logger.error(f"Error encrypting link: {e}")
        await update.message.reply_text(f"❌ Ошибка: {str(e)}")


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обработчик текстовых сообщений"""
    user_id = update.effective_user.id
    username = update.effective_user.username
    text = update.message.text
    str_user_id = str(user_id)
    
    # Обработка кнопок
    if text == "📊 Статистика":
        await stats_command(update, context)
        return
    elif text == "📜 История ссылок":
        await history_command(update, context)
        return
    elif text == "🔑 Секретный ключ":
        await secretkey_command(update, context)
        return
    elif text == "📱 HWID список":
        await hwid_list_command(update, context)
        return
    elif text == "ℹ️ Помощь":
        await help_command(update, context)
        return
    
    # Кнопка "Без HWID" - режим без привязки
    elif text == "🔓 Без HWID":
        user_mode[str_user_id] = "free"
        pending_hwid.pop(str_user_id, None)
        await update.message.reply_text(
            "🔓 **Режим: Без привязки**\n\n"
            "Теперь отправьте ссылку для шифрования.\n"
            "Ссылка будет работать на ЛЮБОМ устройстве.",
            parse_mode='Markdown'
        )
        return
    
    # Кнопка "С HWID" - режим с привязкой
    elif text == "🔐 С HWID":
        user_mode[str_user_id] = "hwid"
        pending_hwid[str_user_id] = True
        await update.message.reply_text(
            "🔐 **Режим: С привязкой к HWID**\n\n"
            "Сначала отправьте HWID устройства (16 символов).\n"
            "Его можно скопировать в XpertVPN:\n"
            "Настройки → О приложении → HWID",
            parse_mode='Markdown'
        )
        return
    
    # Кнопка "Мой HWID" - показать сохраненный HWID
    elif text == "📱 Мой HWID":
        current_hwid = user_hwids.get(str_user_id)
        if current_hwid:
            await update.message.reply_text(
                f"📱 **Ваш сохраненный HWID:**\n\n"
                f"`{current_hwid}`\n\n"
                f"Этот HWID будет использоваться для привязки.",
                parse_mode='Markdown'
            )
        else:
            await update.message.reply_text(
                "📱 У вас нет сохраненного HWID.\n\n"
                "Нажмите 🔐 С HWID и введите HWID устройства.",
                parse_mode='Markdown'
            )
        return
    
    # Проверяем, ожидаем ли ввод HWID
    if pending_hwid.get(str_user_id):
        # Это должен быть HWID
        if len(text) >= 16 and not text.startswith('http') and not text.startswith('vless') and not text.startswith('vmess') and not text.startswith('ss://') and not text.startswith('trojan'):
            user_hwids[str_user_id] = text.strip()
            save_hwids()
            pending_hwid.pop(str_user_id, None)
            await update.message.reply_text(
                f"✅ **HWID сохранен!**\n\n"
                f"`{text.strip()}`\n\n"
                f"Теперь отправьте ссылку для шифрования.",
                parse_mode='Markdown'
            )
            return
        else:
            await update.message.reply_text(
                "❌ Неверный формат HWID.\n"
                "HWID должен быть минимум 16 символов.\n\n"
                "Скопируйте его в XpertVPN:\n"
                "Настройки → О приложении → HWID"
            )
            return
    
    # Проверяем формат ссылки
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
        
        # Определяем режим шифрования
        mode = user_mode.get(str_user_id, "free")  # По умолчанию без привязки
        user_hwid = user_hwids.get(str_user_id) if mode == "hwid" else None
        
        crypto_link = crypto.encrypt_url(
            text,
            hwid=user_hwid,  # Привязываем к HWID если есть
            metadata={
                "encrypted_by": "XpertVPN Bot v2",
                "timestamp": datetime.now().isoformat()
            }
        )
        
        add_to_history(text, crypto_link, user_id, username, hwid=user_hwid)
        
        if user_hwid:
            response = f"""
✅ **Ссылка зашифрована (с привязкой)**

━━━━━━━━━━━━━━━━━━
`{crypto_link}`
━━━━━━━━━━━━━━━━━━

🔐 HWID: `{user_hwid[:16]}...`
📱 Работает ТОЛЬКО на этом устройстве
"""
        else:
            response = f"""
✅ **Ссылка зашифрована (без привязки)**

━━━━━━━━━━━━━━━━━━
`{crypto_link}`
━━━━━━━━━━━━━━━━━━

🔓 Без привязки к устройству
📱 Можно использовать на любом устройстве
"""
        
        await update.message.reply_text(response, parse_mode='Markdown')
        
        logger.info(f"Encrypted link for user {user_id} (@{username}), HWID bound: {user_hwid is not None}")
        
    except Exception as e:
        logger.error(f"Error encrypting link: {e}")
        await update.message.reply_text(
            f"❌ Ошибка при шифровании ссылки:\n{str(e)}"
        )


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обработчик ошибок"""
    logger.error(f"Update {update} caused error {context.error}")


async def health_check(request):
    """Health check endpoint для Koyeb"""
    return web.Response(text="OK", status=200)


async def start_health_server():
    """Запуск HTTP сервера для health checks"""
    app = web.Application()
    app.router.add_get('/', health_check)
    app.router.add_get('/health', health_check)
    
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', 8000)
    await site.start()
    logger.info("Health check server started on port 8000")


async def run_bot():
    """Запуск бота"""
    try:
        load_history()
        load_hwids()
        
        application = Application.builder().token(BOT_TOKEN).build()
        
        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("help", help_command))
        application.add_handler(CommandHandler("stats", stats_command))
        application.add_handler(CommandHandler("history", history_command))
        application.add_handler(CommandHandler("secretkey", secretkey_command))
        application.add_handler(CommandHandler("hwid", hwid_command))
        application.add_handler(CommandHandler("free", free_command))
        application.add_handler(CommandHandler("bind", bind_command))
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
        
        application.add_error_handler(error_handler)
        
        logger.info("🚀 XpertVPN Crypto Bot v2 (AES) started!")
        logger.info(f"👑 Admin ID: {ADMIN_ID}")
        logger.info(f"🔐 Encryption: AES-256-GCM + HWID binding")
        
        await application.initialize()
        await application.start()
        await application.updater.start_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)
        
        await asyncio.Event().wait()
        
    except Exception as e:
        logger.error(f"Bot crashed: {e}")
        raise


async def main():
    """Главная функция - запускает health server и бота параллельно"""
    await asyncio.gather(
        start_health_server(),
        run_bot()
    )


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Bot stopped by user")
