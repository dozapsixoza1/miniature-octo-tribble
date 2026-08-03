import os
import sqlite3
import asyncio
import re
import hashlib
import json
from datetime import datetime, timedelta
from dotenv import load_dotenv
from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command
from aiogram.types import (
    Message, ReplyKeyboardMarkup, KeyboardButton,
    InlineKeyboardMarkup, InlineKeyboardButton, CallbackQuery
)
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
import requests
import aiohttp
import aiofiles

# ========== Загрузка переменных ==========
load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_ID = int(os.getenv("ADMIN_ID", 0))
NUMVERIFY_API_KEY = os.getenv("NUMVERIFY_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN не задан в .env")

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

# ========== База данных ==========
conn = sqlite3.connect("database.db", check_same_thread=False)
cursor = conn.cursor()

# Создание таблиц (с новыми полями)
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY,
    username TEXT,
    balance REAL DEFAULT 0.0,
    ref_balance REAL DEFAULT 0.0,
    registration_date TEXT,
    search_limit INTEGER DEFAULT 3,
    phone_searches INTEGER DEFAULT 0,
    tg_searches INTEGER DEFAULT 0,
    is_admin INTEGER DEFAULT 0,
    banned INTEGER DEFAULT 0,
    total_searches INTEGER DEFAULT 0,
    last_activity TEXT,
    daily_bonus_date TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS referrals (
    referrer_id INTEGER,
    referred_id INTEGER,
    FOREIGN KEY (referrer_id) REFERENCES users (user_id),
    FOREIGN KEY (referred_id) REFERENCES users (user_id)
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS user_bots (
    bot_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    bot_token TEXT,
    bot_username TEXT,
    bot_name TEXT,
    creation_date TEXT,
    FOREIGN KEY (user_id) REFERENCES users (user_id)
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS search_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    search_type TEXT,
    query TEXT,
    result TEXT,
    timestamp TEXT,
    FOREIGN KEY (user_id) REFERENCES users (user_id)
)
""")
conn.commit()

# ========== Состояния FSM ==========
class Form(StatesGroup):
    waiting_for_phone = State()
    waiting_for_username = State()
    waiting_for_email = State()
    waiting_for_ip = State()
    waiting_for_doc = State()

# ========== Вспомогательные функции ==========
async def check_and_decrement_limit(user_id: int) -> bool:
    """Проверяет и уменьшает лимит поиска. Возвращает True, если лимит есть."""
    cursor.execute("SELECT search_limit FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    if not row or row[0] <= 0:
        return False
    cursor.execute(
        "UPDATE users SET search_limit = search_limit - 1, total_searches = total_searches + 1 WHERE user_id = ?",
        (user_id,)
    )
    conn.commit()
    return True

async def log_search(user_id: int, search_type: str, query: str, result: str):
    """Логирует поиск в историю."""
    cursor.execute(
        "INSERT INTO search_history (user_id, search_type, query, result, timestamp) VALUES (?, ?, ?, ?, ?)",
        (user_id, search_type, query, result[:500], datetime.now().isoformat())
    )
    conn.commit()

async def update_daily_limit(user_id: int):
    """Обновляет ежедневный лимит (если прошёл день)."""
    cursor.execute("SELECT last_activity FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    if row and row[0]:
        last_date = datetime.fromisoformat(row[0])
        if datetime.now() - last_date > timedelta(days=1):
            cursor.execute("UPDATE users SET search_limit = 3 WHERE user_id = ?", (user_id,))
    cursor.execute("UPDATE users SET last_activity = ? WHERE user_id = ?", (datetime.now().isoformat(), user_id))
    conn.commit()

# ========== Функции поиска ==========
async def search_username_sherlock(username: str) -> str:
    """Поиск username через библиотеку sherlock (синхронный вызов в потоке)."""
    try:
        from sherlock import Sherlock
        # Sherlock работает синхронно, запустим в отдельном потоке
        loop = asyncio.get_running_loop()
        results = await loop.run_in_executor(None, lambda: Sherlock().search(username))
        if not results:
            return "❌ Ничего не найдено."
        output = "🔍 **Результаты поиска по username:**\n\n"
        for site, url in results.items():
            output += f"• [{site}]({url})\n"
        return output
    except ImportError:
        return "⚠️ Библиотека Sherlock не установлена. Установите: pip install sherlock"
    except Exception as e:
        return f"⚠️ Ошибка Sherlock: {str(e)}"

async def search_email(email: str) -> str:
    """Проверка email через Have I Been Pwned и Gravatar."""
    output = f"📧 **Поиск по email:** `{email}`\n\n"
    # Проверка утечек
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}") as resp:
                if resp.status == 200:
                    breaches = await resp.json()
                    output += "🔴 **Найден в утечках:**\n"
                    for b in breaches:
                        output += f"• {b['Name']} ({b['BreachDate']})\n"
                else:
                    output += "✅ Не найден в известных утечках.\n"
    except Exception:
        output += "⚠️ Ошибка проверки утечек.\n"
    # Gravatar
    try:
        hash_md5 = hashlib.md5(email.lower().encode()).hexdigest()
        gravatar_url = f"https://www.gravatar.com/avatar/{hash_md5}?d=404"
        async with aiohttp.ClientSession() as session:
            async with session.head(gravatar_url) as resp:
                if resp.status == 200:
                    output += f"🖼️ Gravatar: [фото]({gravatar_url})\n"
                else:
                    output += "🖼️ Gravatar: нет фото\n"
    except Exception:
        pass
    return output

async def search_ip_domain(query: str) -> str:
    """Проверка IP или домена через VirusTotal."""
    if not VIRUSTOTAL_API_KEY:
        return "⚠️ API-ключ VirusTotal не задан."
    # Определяем, IP или домен
    is_ip = re.match(r'^\d+\.\d+\.\d+\.\d+$', query) is not None
    url = f"https://www.virustotal.com/api/v3/domains/{query}" if not is_ip else f"https://www.virustotal.com/api/v3/ip_addresses/{query}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    stats = data['data']['attributes']['last_analysis_stats']
                    output = f"🌐 **Результаты для {query}:**\n"
                    output += f"🟢 Безопасно: {stats.get('harmless', 0)}\n"
                    output += f"🟡 Подозрительно: {stats.get('suspicious', 0)}\n"
                    output += f"🔴 Вредоносно: {stats.get('malicious', 0)}\n"
                    return output
                else:
                    return "❌ Не найдено или ошибка API."
    except Exception as e:
        return f"⚠️ Ошибка: {str(e)}"

async def search_document(doc_type: str, number: str) -> str:
    """Заглушка для поиска по документам."""
    return f"📄 **Поиск по {doc_type}:** `{number}`\nДанные временно недоступны (в разработке)."

async def check_phone_number(phone: str) -> str:
    """Проверка номера через NumVerify."""
    if not NUMVERIFY_API_KEY:
        return "⚠️ API-ключ NumVerify не задан."
    url = f"http://apilayer.net/api/validate?access_key={NUMVERIFY_API_KEY}&number={phone}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                data = await resp.json()
                if not data.get("valid"):
                    return "❌ Номер недействителен или не найден."
                result = (
                    f"📞 **Номер:** `{data['international_format']}`\n"
                    f"📍 **Страна:** {data['country_name']} ({data['country_code']})\n"
                    f"🏢 **Оператор:** {data['carrier'] or 'Неизвестно'}\n"
                    f"📱 **Тип:** {data['line_type'] or 'Мобильный'}\n"
                )
                return result
    except Exception as e:
        return f"⚠️ Ошибка API: {str(e)}"

# ========== Команда /start ==========
@dp.message(Command("start"))
async def cmd_start(message: Message):
    user_id = message.from_user.id
    username = message.from_user.username
    registration_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
    user = cursor.fetchone()

    if not user:
        cursor.execute(
            "INSERT INTO users (user_id, username, registration_date) VALUES (?, ?, ?)",
            (user_id, username, registration_date),
        )
        conn.commit()
        # Реферальная ссылка
        if len(message.text.split()) > 1:
            try:
                ref_id = int(message.text.split()[1])
                cursor.execute("INSERT INTO referrals (referrer_id, referred_id) VALUES (?, ?)", (ref_id, user_id))
                cursor.execute("UPDATE users SET ref_balance = ref_balance + 0.05 WHERE user_id = ?", (ref_id,))
                conn.commit()
            except:
                pass

    # Ежедневное обновление лимита
    await update_daily_limit(user_id)

    # Закрепляем сообщение
    sherlock_msg = await message.answer("🕵️ «Шерлок». Если информация существует — я её найду.")
    await bot.pin_chat_message(message.chat.id, sherlock_msg.message_id)

    # Главное меню
    kb = ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="🕵 Мой профиль"), KeyboardButton(text="🤖 Мои боты")],
            [KeyboardButton(text="🤝 Партнерская программа"), KeyboardButton(text="🔍 Поиск")],
        ],
        resize_keyboard=True,
    )
    await message.answer(
        "🕵️ Личность:\nНавальный Алексей Анатольевич\n04.06.1976 - ФИО\n"
        "📲 Контакты:\n79637829051 – номер телефона\nceo@vkontakte.ru – email\n"
        "🚘 Транспорт:\nВ395ОК199 – номер автомобиля\n"
        "💬 Социальные сети:\nvk.com/sherlock – Вконтакте\ntiktok.com/@sherlock – Tiktok\n"
        "instagram.com/sherlock – Instagram\nok.ru/profile/58460 – Одноклассники\n\n"
        "📟 Telegram:\n@sherlock, tg123456 – логин или ID\n"
        "Можете переслать сообщение – попробую определить ID сам\n\n"
        "📄 Документы:\n/vu 1234567890 – водительские права\n/passport 1234567890 – паспорт\n"
        "/snils 12345678901 – СНИЛС\n/inn 123456789012 – ИНН\n\n"
        "🌐 Онлайн-следы:\n/tag хирург москва – поиск по телефонным книгам\n"
        "sherlock.com / 1.1.1.1 – домен или IP",
        reply_markup=kb
    )

# ========== Профиль ==========
@dp.message(F.text == "🕵 Мой профиль")
async def profile(message: Message):
    user_id = message.from_user.id
    cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
    user = cursor.fetchone()
    if user:
        balance = user[2]
        ref_balance = user[3]
        reg_date = user[4]
        search_limit = user[5]
        phone_searches = user[6]
        tg_searches = user[7]
        total_searches = user[10]

        profile_text = (
            f"🔍 **Ваш профиль**\n\n"
            f"🆔 Ваш ID: `{user_id}`\n"
            f"💰 Баланс: **${balance:.2f}**\n"
            f"📊 Реферальный баланс: **${ref_balance:.2f}**\n"
            f"📅 Дата регистрации: `{reg_date}`\n\n"
            f"🔎 Доступно поисков: **{search_limit}**\n"
            f"_(Ежедневно обновляется до 3)_\n\n"
            f"📊 **Статистика:**\n"
            f"— 📞 Телефон: **{phone_searches}**\n"
            f"— ✉️ Telegram: **{tg_searches}**\n"
            f"— Всего поисков: **{total_searches}**"
        )

        kb = InlineKeyboardMarkup(
            inline_keyboard=[
                [InlineKeyboardButton(text="💳 Пополнить баланс", callback_data="topup")],
                [InlineKeyboardButton(text="🔍 Купить запросы", callback_data="buy_searches")],
                [InlineKeyboardButton(text="❓ Бесплатные запросы", callback_data="free_searches")],
                [InlineKeyboardButton(text="🔙 Назад", callback_data="back_to_menu")],
            ]
        )
        await message.answer(profile_text, reply_markup=kb)

# ========== Бесплатные запросы ==========
@dp.callback_query(F.data == "free_searches")
async def free_searches(callback: CallbackQuery):
    await callback.message.edit_text(
        "🎁 **Как получить бесплатные запросы:**\n\n"
        "• Пригласи друга — получи +5 запросов (за каждого)\n"
        "• Заходи каждый день — лимит обновляется до 3\n"
        "• Скоро появятся задания за запросы"
    )

# ========== Оплата ==========
@dp.callback_query(F.data == "topup")
async def topup_balance(callback: CallbackQuery):
    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="💲 Криптовалюта", callback_data="crypto_payment")],
            [InlineKeyboardButton(text="🔙 Назад", callback_data="back_to_profile")],
        ]
    )
    await callback.message.edit_text("💳 **Выберите способ пополнения:**", reply_markup=kb)

@dp.callback_query(F.data == "crypto_payment")
async def crypto_payment(callback: CallbackQuery):
    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="₿ BTC", callback_data="pay_btc")],
            [InlineKeyboardButton(text="⟠ ETH", callback_data="pay_eth")],
            [InlineKeyboardButton(text="₮ USDT (TRC20)", callback_data="pay_usdt")],
            [InlineKeyboardButton(text="🔙 Назад", callback_data="back_to_topup")],
        ]
    )
    await callback.message.edit_text("💲 **Выберите криптовалюту:**", reply_markup=kb)

@dp.callback_query(F.data.startswith("pay_"))
async def process_crypto_pay(callback: CallbackQuery):
    currency = callback.data.split("_")[1].upper()
    addresses = {
        "BTC": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "ETH": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        "USDT": "TAbc123...xyz"
    }
    amount_usd = 1.0  # можно настроить
    await callback.message.edit_text(
        f"💸 **Оплата в {currency}**\n\n"
        f"Сумма: {amount_usd} USD (эквивалент в {currency} по курсу)\n"
        f"Адрес:\n`{addresses[currency]}`\n\n"
        f"После отправки нажмите ✅",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="✅ Проверить оплату", callback_data=f"check_payment:{amount_usd}")],
            [InlineKeyboardButton(text="🔙 Назад", callback_data="back_to_topup")]
        ])
    )

@dp.callback_query(F.data.startswith("check_payment:"))
async def check_payment(callback: CallbackQuery):
    amount = float(callback.data.split(":")[1])
    user_id = callback.from_user.id
    cursor.execute("UPDATE users SET balance = balance + ? WHERE user_id = ?", (amount, user_id))
    conn.commit()
    await callback.message.edit_text("✅ **Оплата прошла успешно!** Баланс пополнен.")

@dp.callback_query(F.data == "back_to_topup")
async def back_to_topup(callback: CallbackQuery):
    await topup_balance(callback)

# ========== Покупка запросов ==========
@dp.callback_query(F.data == "buy_searches")
async def buy_searches(callback: CallbackQuery):
    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="10 запросов — $1.5", callback_data="buy:10:1.5")],
            [InlineKeyboardButton(text="50 запросов — $6", callback_data="buy:50:6")],
            [InlineKeyboardButton(text="200 запросов — $21", callback_data="buy:200:21")],
            [InlineKeyboardButton(text="500 запросов — $45", callback_data="buy:500:45")],
            [InlineKeyboardButton(text="1000 запросов — $75", callback_data="buy:1000:75")],
            [InlineKeyboardButton(text="2500 запросов — $150", callback_data="buy:2500:150")],
            [InlineKeyboardButton(text="5000 запросов — $250", callback_data="buy:5000:250")],
            [InlineKeyboardButton(text="🔙 Назад", callback_data="back_to_profile")],
        ]
    )
    await callback.message.edit_text("🔍 **Выбери тариф:**\n\nЧем больше — тем выгоднее.", reply_markup=kb)

@dp.callback_query(F.data.startswith("buy:"))
async def process_purchase(callback: CallbackQuery):
    _, searches, price = callback.data.split(":")
    searches = int(searches)
    price = float(price)
    user_id = callback.from_user.id
    cursor.execute("SELECT balance FROM users WHERE user_id = ?", (user_id,))
    balance = cursor.fetchone()[0]
    if balance >= price:
        cursor.execute(
            "UPDATE users SET balance = balance - ?, search_limit = search_limit + ? WHERE user_id = ?",
            (price, searches, user_id)
        )
        conn.commit()
        await callback.message.edit_text(f"✅ Куплено {searches} запросов.")
    else:
        await callback.message.edit_text("❌ Недостаточно средств.")

# ========== Поиск (меню) ==========
@dp.message(F.text == "🔍 Поиск")
async def search_menu(message: Message):
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="👤 Поиск по username", callback_data="search_username")],
        [InlineKeyboardButton(text="📧 Поиск по email", callback_data="search_email")],
        [InlineKeyboardButton(text="📞 Поиск по номеру", callback_data="search_phone")],
        [InlineKeyboardButton(text="🌐 Поиск по IP/домену", callback_data="search_ip")],
        [InlineKeyboardButton(text="📄 Поиск по документам", callback_data="search_doc")],
        [InlineKeyboardButton(text="🔙 Назад", callback_data="back_to_menu")],
    ])
    await message.answer("🔍 **Выберите тип поиска:**", reply_markup=kb)

# ========== Обработчики выбора типа поиска ==========
@dp.callback_query(F.data == "search_username")
async def ask_username(callback: CallbackQuery, state: FSMContext):
    await state.set_state(Form.waiting_for_username)
    await callback.message.edit_text("👤 Введите username (например, @durov или durov):")

@dp.callback_query(F.data == "search_email")
async def ask_email(callback: CallbackQuery, state: FSMContext):
    await state.set_state(Form.waiting_for_email)
    await callback.message.edit_text("📧 Введите email (например, user@example.com):")

@dp.callback_query(F.data == "search_phone")
async def ask_phone(callback: CallbackQuery, state: FSMContext):
    await state.set_state(Form.waiting_for_phone)
    await callback.message.edit_text("📞 Введите номер телефона (+79991234567):")

@dp.callback_query(F.data == "search_ip")
async def ask_ip(callback: CallbackQuery, state: FSMContext):
    await state.set_state(Form.waiting_for_ip)
    await callback.message.edit_text("🌐 Введите IP или домен (например, 8.8.8.8 или google.com):")

@dp.callback_query(F.data == "search_doc")
async def ask_doc(callback: CallbackQuery, state: FSMContext):
    await state.set_state(Form.waiting_for_doc)
    await callback.message.edit_text("📄 Введите тип и номер: `passport 1234567890` или `inn 123456789012`")

# ========== Обработка ввода для каждого типа ==========
@dp.message(Form.waiting_for_username)
async def process_username_search(message: Message, state: FSMContext):
    username = message.text.strip().lstrip('@')
    user_id = message.from_user.id
    if not await check_and_decrement_limit(user_id):
        await message.answer("❌ Лимит исчерпан. Пополните баланс.")
        await state.clear()
        return
    await message.answer(f"🔎 Ищем по username: @{username}...")
    result = await search_username_sherlock(username)
    await message.answer(result, disable_web_page_preview=True)
    await log_search(user_id, "username", username, result)
    await state.clear()

@dp.message(Form.waiting_for_email)
async def process_email_search(message: Message, state: FSMContext):
    email = message.text.strip()
    user_id = message.from_user.id
    if not await check_and_decrement_limit(user_id):
        await message.answer("❌ Лимит исчерпан.")
        await state.clear()
        return
    await message.answer(f"🔎 Ищем по email: {email}...")
    result = await search_email(email)
    await message.answer(result, disable_web_page_preview=True)
    await log_search(user_id, "email", email, result)
    await state.clear()

@dp.message(Form.waiting_for_phone)
async def process_phone_search(message: Message, state: FSMContext):
    phone = message.text.strip()
    user_id = message.from_user.id
    if not await check_and_decrement_limit(user_id):
        await message.answer("❌ Лимит исчерпан.")
        await state.clear()
        return
    await message.answer(f"🔎 Ищем по номеру: {phone}...")
    result = await check_phone_number(phone)
    await message.answer(result)
    # увеличиваем счётчик phone_searches
    cursor.execute("UPDATE users SET phone_searches = phone_searches + 1 WHERE user_id = ?", (user_id,))
    conn.commit()
    await log_search(user_id, "phone", phone, result)
    await state.clear()

@dp.message(Form.waiting_for_ip)
async def process_ip_search(message: Message, state: FSMContext):
    query = message.text.strip()
    user_id = message.from_user.id
    if not await check_and_decrement_limit(user_id):
        await message.answer("❌ Лимит исчерпан.")
        await state.clear()
        return
    await message.answer(f"🔎 Ищем по IP/домену: {query}...")
    result = await search_ip_domain(query)
    await message.answer(result)
    await log_search(user_id, "ip_domain", query, result)
    await state.clear()

@dp.message(Form.waiting_for_doc)
async def process_doc_search(message: Message, state: FSMContext):
    parts = message.text.strip().split()
    if len(parts) < 2:
        await message.answer("❌ Введите тип и номер через пробел. Например: `passport 1234567890`")
        return
    doc_type = parts[0].lower()
    number = parts[1]
    user_id = message.from_user.id
    if not await check_and_decrement_limit(user_id):
        await message.answer("❌ Лимит исчерпан.")
        await state.clear()
        return
    await message.answer(f"🔎 Ищем по {doc_type}: {number}...")
    result = await search_document(doc_type, number)
    await message.answer(result)
    await log_search(user_id, doc_type, number, result)
    await state.clear()

# ========== Кнопки "Мои боты" и "Партнёрская программа" ==========
@dp.message(F.text == "🤖 Мои боты")
async def my_bots(message: Message):
    user_id = message.from_user.id
    cursor.execute("SELECT bot_id, bot_username, bot_name, creation_date FROM user_bots WHERE user_id = ?", (user_id,))
    bots = cursor.fetchall()
    if not bots:
        await message.answer("У вас пока нет добавленных ботов.")
        return
    text = "🤖 **Ваши боты:**\n\n"
    for b in bots:
        text += f"• {b[2]} (@{b[1]}) — добавлен {b[3]}\n"
    await message.answer(text)

@dp.message(F.text == "🤝 Партнерская программа")
async def referral_program(message: Message):
    user_id = message.from_user.id
    cursor.execute("SELECT ref_balance FROM users WHERE user_id = ?", (user_id,))
    ref_balance = cursor.fetchone()[0]
    me = await bot.get_me()
    link = f"https://t.me/{me.username}?start={user_id}"
    cursor.execute("SELECT COUNT(*) FROM referrals WHERE referrer_id = ?", (user_id,))
    ref_count = cursor.fetchone()[0]
    text = (
        f"🤝 **Партнерская программа**\n\n"
        f"Ваша ссылка:\n`{link}`\n\n"
        f"Приглашено: {ref_count}\n"
        f"Заработано: ${ref_balance:.2f}\n"
        f"За каждого друга вы получаете $0.05 на отдельный баланс."
    )
    await message.answer(text)

# ========== Кнопки "Назад" ==========
@dp.callback_query(F.data == "back_to_menu")
async def back_to_menu(callback: CallbackQuery):
    kb = ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="🕵 Мой профиль"), KeyboardButton(text="🤖 Мои боты")],
            [KeyboardButton(text="🤝 Партнерская программа"), KeyboardButton(text="🔍 Поиск")],
        ],
        resize_keyboard=True,
    )
    await callback.message.edit_text("Главное меню:", reply_markup=kb)

@dp.callback_query(F.data == "back_to_profile")
async def back_to_profile(callback: CallbackQuery):
    # Перерисовываем профиль
    await profile(callback.message)  # profile принимает Message, а не CallbackQuery
    await callback.answer()

# ========== Админ-панель ==========
@dp.message(Command("admin"))
async def admin_panel(message: Message):
    if message.from_user.id != ADMIN_ID:
        await message.answer("⛔ Доступ запрещён.")
        return
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="👥 Все пользователи", callback_data="admin_users")],
        [InlineKeyboardButton(text="💰 Начислить баланс", callback_data="admin_add_balance")],
        [InlineKeyboardButton(text="📨 Рассылка", callback_data="admin_mailing")],
        [InlineKeyboardButton(text="📊 Статистика", callback_data="admin_stats")],
    ])
    await message.answer("🛠 **Админ-панель**", reply_markup=kb)

@dp.callback_query(F.data == "admin_users")
async def admin_users(callback: CallbackQuery):
    if callback.from_user.id != ADMIN_ID:
        return
    cursor.execute("SELECT user_id, username, balance, search_limit FROM users LIMIT 20")
    users = cursor.fetchall()
    text = "👥 **Последние 20 пользователей:**\n\n"
    for u in users:
        text += f"ID: {u[0]}, @{u[1]}, баланс: ${u[2]:.2f}, лимит: {u[3]}\n"
    await callback.message.edit_text(text, reply_markup=InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="🔙 Назад", callback_data="admin_back")]]))

@dp.callback_query(F.data == "admin_stats")
async def admin_stats(callback: CallbackQuery):
    if callback.from_user.id != ADMIN_ID:
        return
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]
    cursor.execute("SELECT SUM(total_searches) FROM users")
    total_searches = cursor.fetchone()[0] or 0
    text = f"📊 **Статистика:**\n\nВсего пользователей: {total_users}\nВсего поисков: {total_searches}"
    await callback.message.edit_text(text, reply_markup=InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="🔙 Назад", callback_data="admin_back")]]))

@dp.callback_query(F.data == "admin_back")
async def admin_back(callback: CallbackQuery):
    await admin_panel(callback.message)

# ========== Запуск ==========
async def main():
    # Установка вебхука (если нужно) — для поллинга не требуется
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
