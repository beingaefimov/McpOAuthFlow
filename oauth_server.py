""" OAuth 2.0 Authorization Server.
Реализует Authorization Code Flow (RFC 6749), например его ожидает MCP Inspector.
Implements Authorization Code Flow (RFC 6749), as expected by MCP Inspector.

Конфигурация через переменные окружения:
Configuration via environment variables:
OAUTH_SECRET_KEY - секрет для подписи JWT (обязательно, >= 32 символов).
                   Secret for signing JWT (required, >= 32 characters).
                Секрет должен совпадать с аналогичным, передаваемым при запуске
                MCP сервера. Внимание! Если при запуске MCP сервера вовсе не указать
                аналогичный секрет, что возможно в нём в целях локального тестирования,
                то станет возможным вход на него без авторизации здесь.
                Это осознанно не обрабатывается здесь как лишнее усложнение.
                The secret must match the one passed when starting the MCP server.
                Warning! If the MCP server is started without a matching secret
                (possible for local testing), login without authorization here becomes
                possible. This is intentionally not handled here to avoid overcomplication.
OAUTH_HOST - публичный домен этого сервера (по типу https://mcp.example.com)
             Public domain of this server (e.g. https://mcp.example.com)
OAUTH_PORT - порт этого сервера (по умолчанию 9002)
             Port of this server (default 9002)
OAUTH_BIND_HOST - адрес, на котором слушает uvicorn (по умолчанию 127.0.0.1).
                  Address uvicorn listens on (default 127.0.0.1).
                В Docker нужно выставить 0.0.0.0
                In Docker, set to 0.0.0.0
MCP_SERVER_URL - URL MCP-сервера (по умолчанию http://localhost:6339/mcp)
                 URL of the MCP server (default http://localhost:6339/mcp)
OAUTH_DB - путь к SQLite-базе (по умолчанию oauth_users.db)
           Path to the SQLite database (default oauth_users.db)
OAUTH_CORS_ORIGINS - CORS-разрешённые origin-ы через запятую.
                     Comma-separated list of CORS-allowed origins.
                    По умолчанию http://localhost:6274,http://127.0.0.1:6274
                    (стандартные адреса MCP Inspector). Для прод-деплоя
                    выставить свой origin (или пустую строку, чтобы выключить CORS).
                    Default: http://localhost:6274,http://127.0.0.1:6274
                    (standard MCP Inspector addresses). For production,
                    set your own origin (or empty string to disable CORS).
OAUTH_RESOURCE_SERVER_SECRET - секрет для защиты эндпоинтов /oauth/revoke и
                    /oauth/token/info. Если задан, требуется заголовок
                    Authorization: Bearer <secret>. Если не задан, эндпоинты
                    остаются открытыми (в продакшене установить).
                    Не тестировался
                    Secret for protecting /oauth/revoke and /oauth/token/info endpoints.
                    If set, requires Authorization: Bearer <secret> header.
                    If not set, endpoints are open (set in production).
                    Not tested.
OAUTH_TRUSTED_PROXIES - список IP доверенных прокси через запятую. Если запрос
                    приходит с IP из этого списка, rate limiting использует
                    X-Forwarded-For для определения реального IP клиента.
                    Не тестировался
                    Comma-separated list of trusted proxy IPs. If a request arrives
                    from an IP in this list, rate limiting uses X-Forwarded-For
                    to determine the real client IP.
                    Not tested.

Управление пользователями - в CLI:
User management via CLI:
python3 oauth_server.py --add-user login password
python3 oauth_server.py --list-users
python3 oauth_server.py --remove-user login """

import argparse
import aiosqlite
import asyncio
import base64
import hashlib
import html
import json
import math
import os
import secrets
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from string import Template
from typing import Optional
from urllib.parse import urlencode, urlparse
import uvicorn
from fastapi import Cookie, Depends, FastAPI, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.exceptions import RequestValidationError
from jose import JWTError, jwt
import bcrypt as _bcrypt
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.cors import CORSMiddleware

""" Данная реализация содержит осознанные отклонения от стандартов
OAuth 2.0 (RFC 6749) и JWT (RFC 7519), необходимые для работы
с MCP Inspector (@modelcontextprotocol/inspector) v0.21.2.
This implementation contains intentional deviations from OAuth 2.0 (RFC 6749)
and JWT (RFC 7519) standards, required for compatibility with MCP Inspector
(@modelcontextprotocol/inspector) v0.21.2.

Если в будущих версиях MCP Inspector его поведение будет исправлено,
следующие участки кода можно вернуть к стандартам:
If future versions of MCP Inspector fix this behavior, the following
code sections can be reverted to standards:

1. Обработчик 422 -> 400 на /oauth/token.
   Handler 422 -> 400 on /oauth/token.
Наблюдаемое поведение: получив access_token, Inspector пытается открыть SSE-поток
(отправляет заголовок Authorization: Bearer и Accept: text/event-stream)
на эндпоинт выдачи токенов (/oauth/token) вместо целевого MCP-сервера.
FastAPI не может распарсить такой запрос как Form-данные и
возвращает 422 Unprocessable Entity. Inspector воспринимает 422 как
критическую ошибку схемы и сбрасывает state-машину авторизации,
из-за чего форма логина зацикливается.
Observed behavior: after receiving access_token, Inspector tries to open an SSE stream
(sends Authorization: Bearer and Accept: text/event-stream headers) on the token
endpoint (/oauth/token) instead of the actual MCP server. FastAPI cannot parse
such a request as form data and returns 422 Unprocessable Entity. Inspector treats
422 as a critical schema error and resets the authorization state machine,
causing the login form to loop.
Обход: кастомный обработчик `oauth_validation_exception_handler`,
который перехватывает `RequestValidationError` специально для пути
`/oauth/token` и возвращает стандартный для OAuth `400 Bad Request`.
Workaround: custom handler `oauth_validation_exception_handler` that intercepts
`RequestValidationError` specifically for `/oauth/token` path and returns
the standard OAuth `400 Bad Request`.
Как починить: удалить функцию `oauth_validation_exception_handler`
и её привязку через `app.exception_handler`.
How to fix: delete the `oauth_validation_exception_handler` function
and its binding via `app.exception_handler`.

2. Отсутствие CLIENT_ID при обновлении токена (grant_type=refresh_token).
   Missing CLIENT_ID when refreshing token (grant_type=refresh_token).
Наблюдаемое поведение: согласно RFC 6749 §6, параметр `client_id` обязателен при
запросе на обновление токена. MCP Inspector не отправляет его в этом запросе.
Observed behavior: per RFC 6749 §6, `client_id` is required when requesting
a token refresh. MCP Inspector does not send it in this request.
Обход: В `token_endpoint` параметр `client_id` сделан опциональным
(`Form("")` вместо `Form(...)`). В функции `verify_refresh_token`
проверка привязки refresh-токена к клиенту происходит только если
`client_id` был фактически передан в запросе.
Workaround: In `token_endpoint`, `client_id` is made optional (`Form("")` instead of
`Form(...)`). In `verify_refresh_token`, the client binding check happens only if
`client_id` was actually provided in the request.
Как починить: вернуть `client_id: str = Form(...)` в `token_endpoint`
и убрать условие `if client_id is not None` в `verify_refresh_token`.
How to fix: restore `client_id: str = Form(...)` in `token_endpoint`
and remove the `if client_id is not None` condition in `verify_refresh_token`.

3. Поле `aud` в нагрузке JWT.
   The `aud` field in JWT payload.
Наблюдаемое поведение: JWT предполагает наличие поля `aud`.
Однако текущий MCP-сервер (на порту 6339) отвергает токены с этим полем,
возвращая 401 Unauthorized (вероятно, из-за жесткой валидации формата
токена).
Observed behavior: JWT expects an `aud` field. However, the current MCP server
(on port 6339) rejects tokens with this field, returning 401 Unauthorized
(likely due to strict token format validation).
Обход: Из словаря `payload` в функции `create_access_token` удалена строка
`"aud": AUDIENCE`.
Workaround: The line `"aud": AUDIENCE` was removed from the `payload` dict
in `create_access_token`.
Как починить: раскомментировать строку `"aud": AUDIENCE` в функции
`create_access_token` и убедиться, что MCP-сервер пропускает этот claim.
How to fix: uncomment `"aud": AUDIENCE` in `create_access_token` and ensure
the MCP server accepts this claim """

# TODO: bcrypt имеет лимит 72 байта на пароль. Длинные
# passphrase'ы молча обрезаются. Если планируется использовать пароли
# длиннее 72 символов - переходить на argon2 или scrypt.
# bcrypt has a 72-byte password limit. Long passphrases are silently
# truncated. If passwords longer than 72 characters are expected,
# switch to argon2 or scrypt

# TODO: добавить refresh-token rotation detection. Сейчас, если токен
# утёк, его нельзя отозвать до истечения expires_at, потому что
# единственный механизм инвалидации - явный revoke через /oauth/revoke.
# В прод-деплое хранить family_id и ревокать всю цепочку при
# повторном использовании старого токена.
# Add refresh-token rotation detection. Currently, if a token is leaked,
# it cannot be revoked until expires_at because the only invalidation mechanism
# is an explicit revoke via /oauth/revoke. In production, store family_id
# and revoke the entire chain on reuse of an old token

# Единый таймаут на подключение к SQLite, чтобы CLI-команды не падали
# на "database is locked" при параллельной работе с сервером.
# Unified SQLite connection timeout so CLI commands don't fail with
# "database is locked" when the server is running concurrently
_DB_CONNECT_TIMEOUT = 30

# Глобальное соединение с БД для избежания накладных расходов на
# постоянное открытие/закрытие файлов в FastAPI (WAL позволяет
# держать одно соединение для всех запросов).
# Global DB connection to avoid overhead of constantly opening/closing files
# in FastAPI (WAL allows holding one connection for all requests)
_db_conn: Optional[aiosqlite.Connection] = None

# Блокировка для атомарных операций записи в SQLite (защита от race
# condition при параллельных запросах в рамках одного процесса).
# Lock for atomic write operations in SQLite (protection against race conditions
# with parallel requests within a single process)
_db_write_lock = asyncio.Lock()

# Отдельный лок для reconnect-логики, чтобы двойной параллельный сбой
# не привёл к двойному переподключению и утечке предыдущего соединения.
# Separate lock for reconnect logic so a double parallel failure does not
# lead to a double reconnect and leaking the previous connection
_db_reconnect_lock = asyncio.Lock()

# Флаг завершения работы: предотвращает NullPointerError при обращении
# к _db_conn во время shutdown.
# Shutdown flag: prevents NullPointerError when accessing _db_conn during shutdown
_shutting_down = False

def _validate_secret_key():
    """ Централизованная проверка секрета. Вызывается отовсюду, где
    требуется валидный SECRET_KEY, чтобы избежать тихого деградирования
    до пустой строки в os.environ.get(..., "").
    Centralized secret key validation. Called everywhere a valid SECRET_KEY
    is required, to prevent silent degradation to an empty string via
    os.environ.get(..., "") """
    if not SECRET_KEY or len(SECRET_KEY) < 32:
        raise RuntimeError(
            "OAUTH_SECRET_KEY is required and must be at least 32 chars long. "
            "Set it via environment variable before starting the server")

SECRET_KEY = os.environ.get("OAUTH_SECRET_KEY", "")
PUBLIC_HOST = os.environ.get("OAUTH_HOST", "https://mcp.example.com").rstrip("/")
_parsed_host = urlparse(PUBLIC_HOST)
if _parsed_host.scheme not in ("http", "https"):
    raise RuntimeError(
        f"OAUTH_HOST must include scheme (e.g. https://mcp.example.com), got: {PUBLIC_HOST!r}")
PORT = int(os.environ.get("OAUTH_PORT", "9002"))
BIND_HOST = os.environ.get("OAUTH_BIND_HOST", "127.0.0.1")
MCP_URL = os.environ.get("MCP_SERVER_URL", "http://localhost:6339/mcp")
DB_PATH = Path(os.environ.get("OAUTH_DB", "oauth_users.db"))
if DB_PATH.is_dir():
    raise RuntimeError(f"OAUTH_DB must be a file path, not directory: {DB_PATH}")
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
AUDIENCE = "mcp"
ALGORITHM = "HS256"

# Секрет для защиты эндпоинтов resource server (revoke / introspection).
# Secret for protecting resource server endpoints (revoke / introspection)
RESOURCE_SERVER_SECRET = os.environ.get("OAUTH_RESOURCE_SERVER_SECRET", "")

# Доверенные прокси для корректного определения IP в rate limiting.
# Trusted proxies for correct IP determination in rate limiting
_raw_proxies = os.environ.get("OAUTH_TRUSTED_PROXIES", "").strip()
TRUSTED_PROXIES = {p.strip() for p in _raw_proxies.split(",") if p.strip()} if _raw_proxies else set()

# TODO: Дефолт CORS под MCP Inspector (localhost:6274). Для прод-деплоя
# выставить OAUTH_CORS_ORIGINS в нужный origin (или пустую строку "",
# чтобы выключить CORS).
# Default CORS for MCP Inspector (localhost:6274). For production,
# set OAUTH_CORS_ORIGINS to the required origin (or empty string "" to disable CORS)
_DEFAULT_CORS_ORIGINS = "http://localhost:6274,http://127.0.0.1:6274"
_raw_cors = os.environ.get("OAUTH_CORS_ORIGINS", _DEFAULT_CORS_ORIGINS).strip()
# Если передана пустая строка, CORS будет полностью выключен (пустой список).
# If an empty string is provided, CORS will be completely disabled (empty list)
CORS_ORIGINS = [o.strip() for o in _raw_cors.split(",") if o.strip()] if _raw_cors else []

def _build_issuer() -> str:
    """ Строит issuer URL, обрабатывая разные форматы PUBLIC_HOST.
    Builds the issuer URL, handling different PUBLIC_HOST formats.
    Важно: при деплое за реверс-прокси на стандартных
    портах 80/443 переменная OAUTH_HOST должна содержать финальный публичный
    URL без нестандартного порта, например https://mcp.example.com.
    Important: when deploying behind a reverse proxy on standard ports 80/443,
    OAUTH_HOST must contain the final public URL without a non-standard port,
    e.g. https://mcp.example.com.
    Если OAUTH_HOST содержит хост без схемы и порта (например mcp.example.com),
    а OAUTH_PORT = 9002, то ISSUER получится https://mcp.example.com:9002/oauth,
    что неверно для продакшна за прокси. В этом случае явно указывать полный URL
    в OAUTH_HOST: https://mcp.example.com
    If OAUTH_HOST contains a host without scheme and port (e.g. mcp.example.com)
    and OAUTH_PORT = 9002, ISSUER will be https://mcp.example.com:9002/oauth,
    which is wrong for production behind a proxy. In that case, explicitly set the
    full URL in OAUTH_HOST: https://mcp.example.com """
    parsed = urlparse(PUBLIC_HOST)
    scheme = parsed.scheme or "https"
    host = parsed.hostname or "localhost"
    explicit_port = parsed.port
    port = explicit_port if explicit_port is not None else PORT
    base = f"{scheme}://{host}"
    if not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        base += f":{port}"
    # Сохраняем путь из PUBLIC_HOST (например /mcp), если он есть
    path = parsed.path.rstrip("/")
    return f"{base}{path}/oauth"

ISSUER = _build_issuer()

# Rate limiting
DEFAULT_RATE = "200/minute" # базовый лимит на все эндпоинты / base limit for all endpoints
LOGIN_RATE_BY_IP = "5/minute" # макс. попыток с одного IP в минуту / max attempts per IP per minute
LOGIN_RATE_BY_IP_H = "20/hour"  # макс. попыток с одного IP в час / max attempts per IP per hour
LOGIN_MAX_FAILS = 10 # макс. неудачных попыток по логину / max failed login attempts per account
LOGIN_LOCKOUT_SEC = 15 * 60 # блокировка аккаунта на 15 минут / account lockout for 15 minutes

# Rate limit для grant_type=refresh_token по username: ограничивает подбор
# refresh-токенов злоумышленником, сидящим за тем же IP, что и жертва.
# Срабатывает только если запрошенный username известен серверу, иначе
# атакующий мог бы засорять память лимитера несуществующими ключами.
# Per-username rate limit for grant_type=refresh_token: limits refresh-token
# brute-forcing by an attacker on the same IP as the victim. Only kicks in for
# known usernames, otherwise an attacker could pollute the limiter with
# unknown keys
REFRESH_RATE_BY_USER = "30/hour"

# Время жизни токенов / Token lifetimes
ACCESS_TOKEN_EXPIRE_SEC = 3600
REFRESH_TOKEN_EXPIRE_SEC = 30 * 86400
AUTH_CODE_EXPIRE_SEC = 300

# Зарегистрированный OAuth-клиент (например, MCP Inspector).
# Registered OAuth client (e.g. MCP Inspector).
# client_secret для публичных клиентов (PKCE) пустой.
# client_secret is empty for public clients (PKCE).
# redirect_uris == [] те "разрешить любой redirect_uri" (для Inspector)
# redirect_uris == [] means "allow any redirect_uri" (for Inspector).
# NOTE: client_secret намеренно не проверяется нигде в коде - все клиенты
# в текущей реализации считаются публичными (PKCE). Если понадобятся
# конфиденциальные клиенты с проверкой секрета, то добавить проверку в token_endpoint.
# client_secret is intentionally not checked anywhere - all clients in this
# implementation are treated as public (PKCE). If confidential clients with secret
# verification are needed, add the check in token_endpoint
REGISTERED_CLIENTS = {
    "mcp-inspector": {
        "client_secret": "", # публичный клиент = секрет не нужен / public client = no secret needed
        "redirect_uris": [], # пустой = разрешаем любой / empty = allow any
        "grant_types": ["authorization_code", "refresh_token"]}}

# Фиктивный хеш для выравнивания времени при timing-атаке.
# Вычисляется один раз при старте - bcrypt.hash медленный намеренно.
# Используется в login_post, когда пользователь не найден, чтобы время
# ответа не отличалось от случая "пользователь есть, но пароль неверный".
# Dummy hash for timing-attack equalization.
# Computed once at startup - bcrypt.hash is intentionally slow.
# Used in login_post when a user is not found so that response time does not
# differ from the "user exists but password is wrong" case
def hash_password(plain: str) -> str:
    return _bcrypt.hashpw(plain.encode(), _bcrypt.gensalt()).decode()
_DUMMY_HASH: str = hash_password("dummy_timing_protection_value")

# БД пользователей (SQLite) / User database (SQLite)
async def init_db(conn: aiosqlite.Connection):
    await conn.execute("PRAGMA journal_mode=WAL")
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            locked_until INTEGER DEFAULT 0
        )""")

    async with conn.execute("PRAGMA table_info(users)") as cur:
        cols = [r[1] for r in await cur.fetchall()]
    if "locked_until" not in cols:
        try:
            await conn.execute(
                "ALTER TABLE users ADD COLUMN locked_until INTEGER DEFAULT 0")
        except aiosqlite.OperationalError as e:
            if "duplicate column name" not in str(e).lower():
                raise

    await conn.execute("""
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            client_id TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            revoked INTEGER DEFAULT 0
        )""")

    async with conn.execute("PRAGMA table_info(refresh_tokens)") as cur:
        cols = [r[1] for r in await cur.fetchall()]

    if "client_id" not in cols:
        # TODO: Потенциальная гонка при одновременном старте двух инстансов
        # подавляется через timeout на connect, но в проде лучше
        # вынести в отдельный файл миграций с флагом completed.
        # Potential race on simultaneous startup of two instances is
        # suppressed via connect timeout, but in production it's better to
        # extract into a separate migrations file with a completed flag.
        try:
            await conn.execute(
                "ALTER TABLE refresh_tokens ADD COLUMN client_id TEXT NOT NULL DEFAULT ''")
        except aiosqlite.OperationalError as e:
            # Если параллельный процесс уже добавил колонку - игнорируем.
            # Пробрасываем только если ошибка не связана с дублированием колонки
            if "duplicate column name" not in str(e).lower():
                raise

    await conn.execute("""
        CREATE TABLE IF NOT EXISTS failed_logins (
            username TEXT NOT NULL,
            ip TEXT NOT NULL,
            failed_at INTEGER NOT NULL
        )""")
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_fl_username ON failed_logins(username)")
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_fl_ip ON failed_logins(ip)")
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_fl_failed_at ON failed_logins(failed_at)")

    await conn.execute("""
        CREATE TABLE IF NOT EXISTS auth_codes (
            code TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            client_id TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            code_challenge TEXT,
            code_challenge_method TEXT,
            scope TEXT NOT NULL DEFAULT 'mcp',
            expires_at INTEGER NOT NULL
        )""")

    await conn.execute("CREATE INDEX IF NOT EXISTS idx_ac_expires_at ON auth_codes(expires_at)")

    await conn.execute("""
        CREATE TABLE IF NOT EXISTS oauth_clients (
            client_id TEXT PRIMARY KEY,
            redirect_uris TEXT NOT NULL DEFAULT '[]',
            grant_types TEXT NOT NULL DEFAULT '["authorization_code"]',
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
        )""")
    await conn.commit()

async def _safe_reconnect() -> aiosqlite.Connection:
    """ Переподключает _db_conn под отдельным локом, чтобы двойной
    параллельный сбой не привёл к двойному reconnect и утечке соединения.
    Reconnects _db_conn under a separate lock so a double parallel failure
    does not lead to a double reconnect and a leaked connection. """
    global _db_conn
    async with _db_reconnect_lock:
        # Двойная проверка: пока ждали лок, другой код уже мог
        # переподключиться. Не плодим лишние соединения
        try:
            await _db_conn.execute("SELECT 1")
            # Локальная копия ссылки.
            # Между return _db_conn и моментом использования в вызывающем коде,
            # другой корутин может переприсвоить глобальный _db_conn.
            # Но вызывающий держит ссылку на старый объект.
            # Нужно возвращать локальную переменную, а не только править глобал
            conn = _db_conn
            return conn
        except Exception:
            pass
        if _shutting_down:
            raise RuntimeError("Server is shutting down")
        try:
            if _db_conn is not None:
                await _db_conn.close()
        except Exception:
            pass
        new_conn = await aiosqlite.connect(DB_PATH, timeout=_DB_CONNECT_TIMEOUT)
        new_conn.row_factory = aiosqlite.Row
        await init_db(new_conn)
        _db_conn = new_conn
        # Возвращаем локальную переменную, не _db_conn
        return new_conn

async def _db_exec(sql: str, params=None):
    """ Обертка для выполнения запросов с автоматическим переподключением,
    если глобальное соединение с SQLite оказалось разорвано (например,
    при удалении WAL-файла, таймауте или сбое на NFS).
    Reconnect защищён _db_write_lock на уровне вызывающего кода для
    операций записи. Для операций только чтения (SELECT) двойное
    переподключение в редком случае допустимо - худшее что произойдёт
    это повторный запрос.
    Wrapper for executing queries with automatic reconnection if the global
    SQLite connection was broken (e.g. due to WAL file deletion,
    timeout, or NFS failure).
    Reconnect is protected by _db_write_lock at the caller level for write
    operations. For read-only (SELECT) operations, a double reconnect in a
    rare case is acceptable - the worst that can happen is a repeated query """
    global _db_conn
    if _shutting_down or _db_conn is None:
        # Не пытаемся работать с БД во время shutdown или до старта lifespan
        raise HTTPException(
            status_code=503, detail="Service is shutting down, try again later")
    try:
        return await _db_conn.execute(sql, params)
    except aiosqlite.OperationalError as e:
        err_msg = str(e).lower()
        # Переподключаемся только если соединение закрыто/бито,
        # но не в database is locked
        if "closed" in err_msg or "connection" in err_msg:
            if _shutting_down:
                raise
            conn = await _safe_reconnect()
            return await conn.execute(sql, params)
        raise
    except (AttributeError, aiosqlite.DatabaseError):
        # _db_conn мог стать None в окне между проверкой и вызовом
        # (например, при shutdown). Делаем одну попытку reconnect
        if _shutting_down:
            raise HTTPException(
                status_code=503, detail="Service is shutting down, try again later")
        conn = await _safe_reconnect()
        return await conn.execute(sql, params)

async def get_user(username: str) -> Optional[aiosqlite.Row]:
    async with await _db_exec(
            "SELECT * FROM users WHERE username = ?", (username,)) as cur:
        return await cur.fetchone()

def verify_password(plain: str, hashed: str) -> bool:
    return _bcrypt.checkpw(plain.encode(), hashed.encode())

# JWT
def create_access_token(username: str) -> str:
    # Не позволяем подписывать токены при невалидном секрете - иначе
    # рискуем молча выпустить JWT, подписанный пустой строкой
    _validate_secret_key()
    now = int(time.time())
    payload = {
        "sub": username,
        "iss": ISSUER,
        # "aud": AUDIENCE,
        "iat": now,
        "exp": now + ACCESS_TOKEN_EXPIRE_SEC,
        "type": "access"}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

async def create_refresh_token(username: str, client_id: Optional[str]) -> str:
    async with _db_write_lock:
        token = secrets.token_urlsafe(48)
        expires_at = int(time.time()) + REFRESH_TOKEN_EXPIRE_SEC
        # В БД кладём явный NULL если client_id не передан, чтобы потом
        # не путать "клиент не передал" с "клиент передал пустую строку"
        stored_client_id = client_id if client_id else None
        await _db_exec(
            "INSERT INTO refresh_tokens "
            "(token, username, client_id, expires_at) VALUES (?, ?, ?, ?)",
            (token, username, stored_client_id, expires_at))
        await _db_conn.commit()
        return token

async def verify_refresh_token(token: str, client_id: Optional[str] = None) -> Optional[str]:
    """ Возвращает username если токен валиден.
    Если передан client_id, проверяет его привязку.
    Использует атомарный UPDATE вместо SELECT + UPDATE для предотвращения
    race condition при параллельных запросах с одним токеном.
    Returns username if the token is valid.
    If client_id is provided, verifies its binding.  
    Uses atomic UPDATE instead of SELECT + UPDATE to prevent race conditions
    when parallel requests use the same token """
    async with _db_write_lock:
        now = int(time.time())
        # Атомарно помечаем токен как использованный (revoked=1), только если
        # он ещё не отозван и не истёк. rowcount==1 означает успех
        cur = await _db_exec(
            "UPDATE refresh_tokens SET revoked = 1 "
            "WHERE token = ? AND revoked = 0 AND expires_at > ? "
            "AND (client_id IS NULL OR client_id = '' OR ? IS NULL OR client_id = ?)",
            (token, now, client_id, client_id))
        if cur.rowcount != 1:
            # Токен не найден, уже отозван или истёк
            await _db_conn.commit()
            return None
        # Читаем данные токена после успешного захвата
        async with await _db_exec(
                "SELECT username, client_id FROM refresh_tokens WHERE token = ?",
                (token,)) as sel:
            row = await sel.fetchone()
        await _db_conn.commit()
    if not row:
        return None
    return row["username"]

async def revoke_refresh_token(token: str):
    async with _db_write_lock:
        await _db_exec(
            "UPDATE refresh_tokens SET revoked = 1 WHERE token = ?", (token,))
        await _db_conn.commit()

# Auth code store
async def store_auth_code(
    code: str, username: str, client_id: str, redirect_uri: str,
    code_challenge: Optional[str], code_challenge_method: Optional[str],
    scope: str = "mcp"):
    async with _db_write_lock:
        expires_at = int(time.time()) + AUTH_CODE_EXPIRE_SEC
        try:
            await _db_exec(
                """INSERT INTO auth_codes
                (code, username, client_id, redirect_uri,
                    code_challenge, code_challenge_method, scope, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (code, username, client_id, redirect_uri, code_challenge,
                 code_challenge_method, scope, expires_at))
            await _db_conn.commit()
        except aiosqlite.IntegrityError:
            raise HTTPException(500, "Failed to generate authorization code")

async def consume_auth_code(code: str) -> Optional[aiosqlite.Row]:
    """ Возвращает запись и сразу удаляет код (одноразовый).
    Проверяет expires_at ДО удаления, чтобы не возвращать просроченную
    запись после её удаления из БД (исправление TOCTOU-уязвимости).
    Checks expires_at BEFORE deleting, so we do not return an expired record
    after it has been removed from the DB (fixes TOCTOU vulnerability).
    Returns the record and immediately deletes the code (one-time use) """
    async with _db_write_lock:
        async with await _db_exec(
                "SELECT * FROM auth_codes WHERE code = ?", (code,)) as cur:
            row = await cur.fetchone()
        if not row:
            return None
        # Проверяем срок действия ДО удаления, иначе просроченный код
        # удалялся бы из БД, но функция возвращала бы его как валидный
        if int(time.time()) > row["expires_at"]:
            # Удаляем просроченный код, чтобы не засорять БД
            await _db_exec("DELETE FROM auth_codes WHERE code = ?", (code,))
            await _db_conn.commit()
            return None
        await _db_exec("DELETE FROM auth_codes WHERE code = ?", (code,))
        await _db_conn.commit()
        return row

# PKCE RFC 7636
def verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    if method == "S256":
        digest = hashlib.sha256(code_verifier.encode()).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        return secrets.compare_digest(computed, code_challenge)
    if method == "plain":
        return secrets.compare_digest(code_verifier, code_challenge)
    return False

# Failed logins / lockout
async def record_failed_login(username: str, ip: str):
    async with _db_write_lock:
        now = int(time.time())
        await _db_exec(
            "INSERT INTO failed_logins (username, ip, failed_at) "
            "VALUES (?, ?, ?)",
            (username, ip, now))
        # Проверяем количество неудачных попыток за последнее время
        # (используем тот же интервал для определения, когда пора блокировать)
        cutoff = now - LOGIN_LOCKOUT_SEC
        async with await _db_exec(
                "SELECT COUNT(*) FROM failed_logins "
                "WHERE username = ? AND failed_at > ?",
                (username, cutoff)) as cur:
            count = (await cur.fetchone())[0]

        if count >= LOGIN_MAX_FAILS:
            # Блокируем аккаунт ровно на LOGIN_LOCKOUT_SEC с текущего момента
            locked_until = now + LOGIN_LOCKOUT_SEC
            await _db_exec(
                "UPDATE users SET locked_until = ? WHERE username = ?",
                (locked_until, username))

        await _db_conn.commit()

async def clear_failed_logins(username: str):
    async with _db_write_lock:
        await _db_exec(
            "DELETE FROM failed_logins WHERE username = ?", (username,))
        # Снимаем блокировку при успешном логине
        await _db_exec(
            "UPDATE users SET locked_until = 0 WHERE username = ?", (username,))
        await _db_conn.commit()

async def get_account_lockout(username: str) -> Optional[int]:
    """ Возвращает секунды до разблокировки, или None если не заблокирован.
    Сброс просроченной блокировки выполняется атомарно внутри _db_write_lock,
    чтобы не удалить failed_logins записи, добавленные параллельным запросом
    между SELECT и DELETE.
    Returns seconds until unlock, or None if not locked.
    Expired lockout reset is done atomically inside _db_write_lock to avoid
    deleting failed_login records added by a parallel request between SELECT and DELETE """
    async with await _db_exec(
            "SELECT locked_until FROM users WHERE username = ?",
            (username,)) as cur:
        row = await cur.fetchone()
    if not row or row["locked_until"] == 0:
        return None
    remaining = row["locked_until"] - int(time.time())
    if remaining > 0:
        return remaining
    # Если время вышло, заодно очищаем флаг и записи failed_logins,
    # чтобы не висела мета-информация и следующая же неудача не
    # заблокировала аккаунт мгновенно из-за старых записей.
    # Сброс выполняем атомарно: если между SELECT выше и этим UPDATE
    # параллельный запрос успел добавить новую failed_login запись,
    # мы её сохраним, а счётчик не обнулим
    async with _db_write_lock:
        # Повторно читаем locked_until под lock'ом чтобы не затереть
        # блокировку, которую параллельный запрос мог уже выставить заново.
        # Также фиксируем момент времени, с которым будем сравнивать
        # failed_at - все записи с failed_at > этого момента считаем
        # "свежими" и не удаляем, даже если их добавил параллельный запрос
        async with await _db_exec(
                "SELECT locked_until FROM users WHERE username = ?",
                (username,)) as cur2:
            row2 = await cur2.fetchone()
        if row2 and row2["locked_until"] != 0:
            remaining2 = row2["locked_until"] - int(time.time())
            if remaining2 > 0:
                # Параллельный запрос уже установил новую блокировку - не сбрасываем
                return remaining2
        # Фиксируем момент времени до удаления. Любая запись с
        # failed_at > moment считается свежей и сохраняется
        moment = int(time.time())
        await _db_exec(
            "UPDATE users SET locked_until = 0 WHERE username = ?", (username,))
        # Удаляем только записи, которые были до входа в этот блок.
        # Свежие failed_login от параллельного запроса (с failed_at > moment)
        # останутся и счётчик не обнулится
        await _db_exec(
            "DELETE FROM failed_logins WHERE username = ? AND failed_at <= ?",
            (username, moment))
        await _db_conn.commit()
    return None

# GC для временных таблиц / GC for temporary tables
async def cleanup_expired():
    """ Чистит просроченные/отозванные записи во временных таблицах.
    Запускается периодически из lifespan (каждые 5 минут).
    Cleans up expired/revoked records in temporary tables.
    Called periodically from lifespan (every 5 minutes) """
    async with _db_write_lock:
        now = int(time.time())
        try:
            await _db_exec("""
                DELETE FROM failed_logins
                WHERE failed_at < ?
                AND username IN (
                    SELECT username FROM users
                    WHERE locked_until = 0
                )
                AND username NOT IN (
                    SELECT username FROM failed_logins
                    WHERE failed_at >= ?
                )""",
                (now - LOGIN_LOCKOUT_SEC * 2, now - LOGIN_LOCKOUT_SEC * 2))
            await _db_exec(
                "DELETE FROM auth_codes WHERE expires_at < ?", (now,))
            # Удаляем только просроченные токены (независимо от revoked),
            # сохраняя отозванные с актуальным expires_at.
            # Это позволит в будущем реализовать rotation detection по family_id
            # без потери данных об отзыве.
            # Delete only expired tokens (regardless of revoked status),
            # keeping revoked tokens with a valid expires_at.
            # This allows future rotation detection via family_id without
            # losing revocation data
            await _db_exec(
                "DELETE FROM refresh_tokens WHERE expires_at < ?",
                (now,))
            await _db_conn.commit()
        except Exception as e:
            print(f"cleanup_expired error: {e}")

async def _gc_loop(interval_sec: int = 300):
    try:
        while True:
            await asyncio.sleep(interval_sec)
            await cleanup_expired()
    except asyncio.CancelledError:
        pass

# Redirect URI validation
def _is_valid_redirect_uri(uri: str) -> bool:
    """ Базовая валидация по RFC 6749 §3.1.2 + защита от javascript:/data:
    схем. Разрешаем http и https для любых хостов (включая loopback),
    а также кастомные схемы (app://) для нативных клиентов.
    Опасные схемы (javascript:, data:) заблокированы.
    Возвращаем False, если URI пустой или кривой.
    Basic validation per RFC 6749 §3.1.2 + protection against javascript:/data:
    schemes. Allows http and https for any host (including loopback), as well
    as custom schemes (app://) for native clients. Dangerous schemes
    (javascript:, data:) are blocked. Returns False if the URI is empty or malformed """
    if not uri or not isinstance(uri, str):
        return False
    try:
        parsed = urlparse(uri)
    except ValueError:
        return False
    if not parsed.scheme or not parsed.netloc:
        return False
    # Запрещаем опасные схемы, которые браузер может исполнить
    if parsed.scheme.lower() in ("javascript", "data", "vbscript", "file"):
        return False
    if parsed.scheme in ("http", "https"):
        return True
    # Нативные клиенты (app://, com.example://, ms-app://) - пропускаем
    return True

async def _get_client_redirect_uris(client_id: str) -> Optional[list]:
    """ Возвращает список разрешённых redirect_uri для клиента,
    или None если клиент неизвестен. [] = разрешить любой (только для
    hardcoded REGISTERED_CLIENTS). Для динамически зарегистрированных
    клиентов возвращает их объявленный список.
    Returns the list of allowed redirect_uris for a client, or None if
    the client is unknown. [] = allow any (only for hardcoded REGISTERED_CLIENTS).
    For dynamically registered clients, returns their declared list """
    if client_id in REGISTERED_CLIENTS:
        return REGISTERED_CLIENTS[client_id].get("redirect_uris", [])
    async with await _db_exec(
            "SELECT redirect_uris FROM oauth_clients WHERE client_id = ?",
            (client_id,)) as cur:
        row = await cur.fetchone()
    if row:
        try:
            return json.loads(row[0])
        except (json.JSONDecodeError, TypeError):
            return []
    return None

async def _is_redirect_uri_allowed(client_id: str, redirect_uri: str) -> bool:
    uris = await _get_client_redirect_uris(client_id)
    if uris is None:
        return False
    if not uris: # пустой = разрешить любой (только для REGISTERED_CLIENTS)
        return True
    return redirect_uri in uris

# Безопасный рендеринг шаблона: html.escape прогоняет все подставляемые
# значения автоматически, плюс мы используем ${...} разделитель вместо
# $... чтобы Template не путал $ в потенциально опасных значениях
# (например, в state/redirect_uri) с собственными identifier-ами.
# Кроме того, переход с safe_substitute на substitute с предварительным
# экранированием закрывает XSS: даже если значение содержит "<script>",
# оно будет выведено как &lt;script&gt;.
# Safe template rendering: html.escape is applied to all substituted values
# automatically, and we use ${...} separators instead of $... so Template
# does not confuse $ in potentially dangerous values (e.g. in
# state/redirect_uri) with its own identifiers.
# Switching from safe_substitute to substitute with pre-escaping closes XSS:
# even if a value contains "<script>", it is rendered as &lt;script&gt;
def _render_login_html(
    state: str, client_id: str, redirect_uri: str,
    code_challenge: str, code_challenge_method: str,
    error_block_html: str = "",
    subtitle: str = "Sign in to your MCP server account") -> str:
    """ Рендерит LOGIN_HTML с предварительным экранированием всех
    интерполируемых значений. error_block_html уже должен быть готовым
    фрагментом HTML (с экранированным текстом внутри) - параметр
    называется _html нарочно, чтобы подчеркнуть, что экранирование
    лежит на вызывающем коде.
    Renders LOGIN_HTML with pre-escaping of all interpolated values.
    error_block_html must be a ready HTML fragment (with escaped text inside)
    - the _html suffix emphasizes that escaping is the caller's responsibility """
    return LOGIN_HTML.substitute(
        state=html.escape(state, quote=True),
        client_id=html.escape(client_id, quote=True),
        redirect_uri=html.escape(redirect_uri, quote=True),
        code_challenge=html.escape(code_challenge, quote=True),
        code_challenge_method=html.escape(code_challenge_method, quote=True),
        error_block=error_block_html,
        subtitle=html.escape(subtitle, quote=True))

# Шаблон использует string.Template, поэтому ВСЕ подставляемые значения
# прогоняются через html.escape. Это закрывает XSS в error_block и
# защищает от KeyError/ValueError, если в client_id/state/redirect_uri
# пришли символы $ или слеш.
# Используем ${name}: даже если значение содержит $, оно не будет
# воспринято как следующая подстановка.
# The template uses string.Template, so ALL substituted values are passed
# through html.escape. This closes XSS in error_block and protects against
# KeyError/ValueError if client_id/state/redirect_uri contain $ or slashes.
# ${name} in action: even if a value contains $, it will not
# be interpreted as the next substitution
LOGIN_HTML = Template("""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MCP Server Login</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #0f172a;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: #e2e8f0;
    }
    .card {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 12px;
      padding: 2.5rem 2rem;
      width: 100%;
      max-width: 380px;
      box-shadow: 0 20px 60px rgba(0,0,0,.5);
    }
    .logo { text-align: center; margin-bottom: 1.5rem; }
    .logo svg { width: 48px; height: 48px; }
    h1 { font-size: 1.25rem; font-weight: 600; text-align: center; margin-bottom: 0.25rem; }
    .subtitle { text-align: center; font-size: 0.85rem; color: #94a3b8; margin-bottom: 2rem; }
    label {
      display: block; font-size: 0.8rem; font-weight: 500;
      color: #94a3b8; margin-bottom: 0.35rem; margin-top: 1rem;
    }
    input[type=text], input[type=password] {
      width: 100%;
      padding: 0.6rem 0.75rem;
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 8px;
      color: #e2e8f0;
      font-size: 0.95rem;
      outline: none;
      transition: border-color .15s;
    }
    input:focus { border-color: #6366f1; }
    .error {
      background: #450a0a; border: 1px solid #7f1d1d; color: #fca5a5;
      border-radius: 8px; padding: 0.6rem 0.75rem;
      font-size: 0.85rem; margin-top: 1rem;
    }
    button {
      width: 100%; margin-top: 1.5rem; padding: 0.7rem;
      background: #6366f1; border: none; border-radius: 8px;
      color: #fff; font-size: 0.95rem; font-weight: 600;
      cursor: pointer; transition: background .15s;
    }
    button:hover { background: #4f46e5; }
    .footer { text-align: center; margin-top: 1.5rem; font-size: 0.75rem; color: #475569; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">
    <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 48 48">
    <title>Mcp Icon</title>
    <g fill="currentColor" transform="scale(3) translate(0, 0)">
    <path d="M5.85 1.24a3.263 3.263 0 0 1 5.534 2.654a3.262 3.262 0 0 1 2.568 5.574L9.117 14.23l.208.212a.75.75 0 0 1-1.07 1.053l-.734-.746a.75.75 0 0 1 .01-1.061l5.37-5.288a1.762 1.762 0 0 0-2.473-2.51L7.445 8.825a.751.751 0 0 1-1.22-.823a.8.8 0 0 1 .167-.246L9.376 4.82a1.763 1.763 0 0 0-2.473-2.512l-5.37 5.287A.75.75 0 0 1 .48 6.527z"/>
    <path d="M7.22 3.467a.751.751 0 0 1 1.052 1.07L5.6 7.167A1.743 1.743 0 0 0 8.045 9.65l2.673-2.63a.75.75 0 0 1 1.052 1.07l-2.672 2.63a3.243 3.243 0 0 1-4.55-4.622z"/>
    </g>
    </svg>
    </div>
    <h1>MCP Server Login</h1>
    <p class="subtitle">${subtitle}</p>
    ${error_block}
    <form method="post" action="/oauth/login">
      <input type="hidden" name="state" value="${state}">
      <input type="hidden" name="client_id" value="${client_id}">
      <input type="hidden" name="redirect_uri" value="${redirect_uri}">
      <input type="hidden" name="code_challenge" value="${code_challenge}">
      <input type="hidden" name="code_challenge_method" value="${code_challenge_method}">
      <label for="username">Account</label>
      <input id="username" type="text" name="username"
        autocomplete="username" autofocus required>
      <label for="password">Password</label>
      <input id="password" type="password" name="password"
        autocomplete="current-password" required>
      <button type="submit">Login</button>
    </form>
    <p class="footer">MCP OAuth 2.0 · Authorization Code + PKCE</p>
  </div>
</body>
</html>""")

def _make_lockout_html(
    state: str, client_id: str, redirect_uri: str,
    code_challenge: str, code_challenge_method: str,
    seconds: int) -> str:
    if seconds < 60:
        msg = f"Too many attempts. Try again in {seconds} sec"
    else:
        msg = f"Too many attempts. Blocked for {math.ceil(seconds / 60)} min"
    # Текст сообщения экранируем до сборки HTML-фрагмента, чтобы он
    # не мог сломать вёрстку или прокинуть XSS даже при экзотическом
    # содержимом
    error_block = f'<div class="error">{html.escape(msg)}</div>'
    return _render_login_html(
        state=state, client_id=client_id, redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        error_block_html=error_block,
        subtitle="Too many failed attempts")

# FastAPI
@asynccontextmanager
async def lifespan(app: FastAPI):
    global _db_conn, _shutting_down
    _validate_secret_key()
    _db_conn = await aiosqlite.connect(DB_PATH, timeout=_DB_CONNECT_TIMEOUT)
    # Устанавливаем row_factory один раз для всего глобального соединения
    _db_conn.row_factory = aiosqlite.Row
    await init_db(_db_conn)
    print(f"OAuth server issuer: {ISSUER}")
    print(f"MCP endpoint: {MCP_URL}")
    if not RESOURCE_SERVER_SECRET:
        print("WARNING: OAUTH_RESOURCE_SERVER_SECRET is not set. "
              "/oauth/revoke and /oauth/token/info are open to anyone")
    if TRUSTED_PROXIES:
        print(f"Trusted proxies for X-Forwarded-For: {TRUSTED_PROXIES}")
    # Периодический GC просроченных записей / Periodic GC of expired records.
    task = asyncio.create_task(_gc_loop(interval_sec=300))
    try:
        yield
    finally:
        # Ставим флаг до отмены GC и закрытия соединения, чтобы любой
        # in-flight запрос получил 503 из _db_exec, а не AttributeError
        _shutting_down = True
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        # Дожидаемся снятия всех текущих _db_write_lock и _db_reconnect_lock
        # холдеров, чтобы не закрыть соединение под активной транзакцией
        for lock in (_db_write_lock, _db_reconnect_lock):
            async with lock:
                pass
        if _db_conn:
            await _db_conn.close()
            _db_conn = None

# Rate limiting: определение IP за reverse proxy.
# Rate limiting: IP determination behind a reverse proxy
def get_remote_address_trusted(request: Request) -> str:
    """ Возвращает IP клиента. Если прямой клиент, это доверенный прокси,
    то использует X-Forwarded-For для определения реального IP.
    Returns the client IP. If the direct client is a trusted proxy,
    uses X-Forwarded-For to determine the real IP """
    client_host = request.client.host if request.client else "127.0.0.1"
    if not TRUSTED_PROXIES or client_host not in TRUSTED_PROXIES:
        return client_host
    xff = request.headers.get("X-Forwarded-For")
    if not xff:
        return client_host
    ips = [ip.strip() for ip in xff.split(",")]
    # Идём с конца цепочки, пропуская доверенные прокси
    for ip in reversed(ips):
        if ip not in TRUSTED_PROXIES:
            return ip
    return client_host

# Ключ для refresh-rate-limit: используется только когда username известен
# серверу, иначе атакующий может засорять память лимитера фейковыми ключами.
# Key for refresh-rate-limit: only used when the username is known to the
# server, otherwise an attacker can pollute the limiter with fake keys
def _refresh_rate_key(request: Request) -> str:
    """ Возвращает ключ для rate limit на /oauth/token при grant_type=refresh_token.
    Если username отсутствует или пустой, ключом становится IP клиента -
    fallback на глобальный лимит.
    Returns the key for rate limiting /oauth/token for grant_type=refresh_token.
    If username is missing or empty, falls back to the client IP - a global limit kicks in """
    # TODO: request.scope["form"] - незадокументированное поведение FastAPI,
    # в реальности похоже там пусто, поэтому rate limit по username никогда не
    # срабатывает и всегда используется IP.
    # Варианты исправления:
    # 1. Middleware: парсить тело до роутера, класть username в request.state.
    # 2. Dependency: принять username как Form-параметр в token_endpoint,
    #    вызвать refresh_limiter.check(...) внутри самой функции уже после
    #    парсинга формы, убрав декоратор @refresh_limiter.limit.
    # 3. Переключиться на библиотеку, поддерживающую async key_func.
    # request.scope["form"] is undocumented FastAPI behavior and looks like is 
    # always empty, so rate limiting by username never works - IP is always used.
    # Fix options:
    # 1. Middleware: parse the body before routing, put username into request.state.
    # 2. Dependency: accept username as a Form parameter in token_endpoint,
    #    call refresh_limiter.check(...) inside the function after form parsing,
    #    removing the @refresh_limiter.limit decorator.
    # 3. Switch to a library that supports async key_func.
    form_data = request.scope.get("form") or {}
    username = form_data.get("username")
    if username:
        return f"refresh:{username}"
    return get_remote_address_trusted(request)

# Второй лимитер специально для refresh - имеет собственный key_func
# (по username, если он есть) и более жёсткий лимит.
# Second limiter specifically for refresh - has its own key_func (by username
# if present) and a tighter limit
refresh_limiter = Limiter(key_func=_refresh_rate_key)

limiter = Limiter(key_func=get_remote_address_trusted, default_limits=[DEFAULT_RATE])
app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)
# TODO: Разрешаем конкретные origins из переменной, но оставляем возможность
# для методов и заголовков (иначе MCP Inspector ломается на preflight запросах).
# Allowing specific origins from the variable, but keeping open methods and
# headers (otherwise MCP Inspector breaks on preflight requests)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False,
    expose_headers=["*"],
)
app.state.limiter = limiter
app.state.refresh_limiter = refresh_limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.exception_handler(RequestValidationError)
async def oauth_validation_exception_handler(request: Request, exc: RequestValidationError):
    """ Перехватываем 422 ошибку валидации формы на /oauth/token.
    MCP Inspector после получения токена не нормально пытается открыть
    SSE-поток на этом эндпоинте. Строгий 422 ответ крашит его state-машину
    и заставляет заново запрашивать логин. Меняем на стандартный 400.
    Intercept the 422 form validation error on /oauth/token.
    After receiving a token, MCP Inspector incorrectly tries to open an SSE stream
    on this endpoint. The strict 422 response crashes its state machine and forces
    re-login. We change it to a standard 400.
    Но возвращаем 400 только если Content-Type не является
    application/x-www-form-urlencoded. Это позволяет сохранить корректную
    обработку реальных ошибок валидации формы (например, попытки эксплуатации),
    которые иначе маскировались бы под безобидный 400 invalid_request.
    But return 400 only if Content-Type is not application/x-www-form-urlencoded.
    This preserves correct handling of real form validation errors (e.g. exploitation
    attempts) that would otherwise be masked by a harmless 400 invalid_request """
    if request.url.path == "/oauth/token":
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "Malformed request"})
    # Для остальных роутов (и для form-запросов на /oauth/token) оставляем
    # стандартный ответ FastAPI
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors()})

@app.get("/.well-known/oauth-authorization-server")
async def oauth_metadata():
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "revocation_endpoint": f"{ISSUER}/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["mcp"],
        "registration_endpoint": f"{ISSUER}/register"}

# Защита эндпоинтов resource server (revoke / introspection).
# Protection of resource server endpoints (revoke / introspection)
def require_resource_server_auth(request: Request):
    """ Если OAUTH_RESOURCE_SERVER_SECRET задан, требует Bearer-токен.
    If OAUTH_RESOURCE_SERVER_SECRET is set, requires a Bearer token """
    if not RESOURCE_SERVER_SECRET:
        return
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = auth[7:]
    if not secrets.compare_digest(token, RESOURCE_SERVER_SECRET):
        raise HTTPException(status_code=401, detail="Unauthorized")

# Начало флоу, показываем форму логина.
# Start of the flow: display the login form
@app.get("/oauth/authorize", response_class=HTMLResponse)
async def authorize_get(
    response_type: str,
    client_id: str,
    redirect_uri: str,
    state: str = "",
    code_challenge: str = "",
    code_challenge_method: str = "S256",
    scope: str = "mcp"):
    _MAX_PARAM = 2048
    for _name, _val in [
            ("state", state), ("redirect_uri", redirect_uri),
            ("code_challenge", code_challenge), ("client_id", client_id)]:
        if len(_val) > _MAX_PARAM:
            raise HTTPException(400, f"{_name} is too long")
    if response_type != "code":
        raise HTTPException(400, "response_type=code only supported")
    if await _get_client_redirect_uris(client_id) is None:
        raise HTTPException(400, f"Unknown client_id: {client_id}")
    if not _is_valid_redirect_uri(redirect_uri):
        raise HTTPException(400, "redirect_uri is not a valid URI")
    if not await _is_redirect_uri_allowed(client_id, redirect_uri):
        raise HTTPException(400, "redirect_uri not allowed for this client")
    # Параметр scope сохраняем в auth_code и прокидывается до
    # token_endpoint, где попадает в ответ. По умолчанию - "mcp".
    # The scope parameter goes to auth_code and propagated to
    # token_endpoint, where it ends up in the response. Default is "mcp".
    # Никакой логики отсечения неразрешённых scope нет - если в
    # будущем потребуется, добавить валидацию против scopes_supported из
    # oauth_metadata здесь.
    # There's no "disallowed scope" logic - if needed in the future,
    # add validation against scopes_supported from oauth_metadata here
    response_html = _render_login_html(
        state=state, client_id=client_id, redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        error_block_html="",
        subtitle="Sign in to your MCP server account")
    response = HTMLResponse(response_html)
    # CSRF-защита: сохраняем state в HttpOnly cookie, чтобы сверить при POST
    # CSRF protection: store state in an HttpOnly cookie to verify on POST.
    if state:
        response.set_cookie(
            key="oauth_state",
            value=state,
            httponly=True,
            secure=PUBLIC_HOST.startswith("https"),
            samesite="lax",
            path="/oauth",
            max_age=AUTH_CODE_EXPIRE_SEC)
    return response

@app.post("/oauth/register")
@limiter.limit("10/hour")
async def register_client(request: Request):
    """ RFC 7591 Dynamic Client Registration """
    body = await request.json()
    client_id = body.get("client_id") or secrets.token_urlsafe(16)
    # Защита от подмены зарезервированных client_id
    if client_id in REGISTERED_CLIENTS:
        raise HTTPException(409, "Reserved client_id")
    redirect_uris = body.get("redirect_uris", [])
    if not isinstance(redirect_uris, list) or not redirect_uris:
        raise HTTPException(400, "redirect_uris must be a non-empty array")
    # Валидация и фильтрация grant_types
    ALLOWED_GRANT_TYPES = {"authorization_code", "refresh_token"}
    raw_grants = body.get("grant_types", ["authorization_code"])
    if not isinstance(raw_grants, list) or not raw_grants:
        raise HTTPException(400, "grant_types must be a non-empty array")
    grant_types = [g for g in raw_grants if g in ALLOWED_GRANT_TYPES]
    if not grant_types:
        raise HTTPException(400, f"Unsupported grant_types. Allowed: {ALLOWED_GRANT_TYPES}")
    # Валидируем каждую URI: защита от javascript:/data: и прочих
    # опасных схем, которые могут использоваться для кражи code
    for uri in redirect_uris:
        if not _is_valid_redirect_uri(uri):
            raise HTTPException(400, f"Invalid redirect_uri: {uri}")
    try:
        async with _db_write_lock:
            await _db_exec(
                "INSERT INTO oauth_clients (client_id, redirect_uris, grant_types) VALUES (?, ?, ?)",
                (client_id, json.dumps(redirect_uris), json.dumps(grant_types)))
            await _db_conn.commit()
    except aiosqlite.IntegrityError:
        raise HTTPException(409, "Client already registered")
    response_types = ["code"] if "authorization_code" in grant_types else []
    return JSONResponse({
        "client_id": client_id,
        # client_secret намеренно не возвращаем: token_endpoint_auth_method=none
        # означает публичный клиент, у которого секрета нет в принципе
        "redirect_uris": redirect_uris,
        "grant_types": grant_types,
        "response_types": response_types,
        "token_endpoint_auth_method": "none"})

@app.post("/oauth/login")
@limiter.limit(LOGIN_RATE_BY_IP)
@limiter.limit(LOGIN_RATE_BY_IP_H)
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    state: str = Form(""),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    code_challenge: str = Form(""),
    code_challenge_method: str = Form("S256"),
    oauth_state: Optional[str] = Cookie(None)):
    _MAX_PARAM = 2048
    for _name, _val in [
            ("state", state), ("redirect_uri", redirect_uri),
            ("code_challenge", code_challenge), ("client_id", client_id)]:
        if len(_val) > _MAX_PARAM:
            raise HTTPException(400, f"{_name} is too long")
    if len(username.encode()) > 256 or len(password.encode()) > 256:
        raise HTTPException(400, "username or password is too long")
    ip = get_remote_address_trusted(request)
    # CSRF-защита: если при авторизации был установлен oauth_state cookie,
    # обязательно сверяем с state из формы
    if state and oauth_state != state:
        raise HTTPException(400, "Invalid state")
    # Сначала валидируем клиент/redirect_uri: любые 400-ошибки должны быть
    # видны без раскрытия существования пользователя
    if await _get_client_redirect_uris(client_id) is None:
        raise HTTPException(400, f"Unknown client_id: {client_id}")
    if not _is_valid_redirect_uri(redirect_uri):
        raise HTTPException(400, "redirect_uri is not a valid URI")
    if not await _is_redirect_uri_allowed(client_id, redirect_uri):
        raise HTTPException(400, "redirect_uri not allowed for this client")
    # Lockout проверяем только для существующих пользователей: иначе атакующий
    # может заспамить failed_logins фейковыми username'ами и забить БД
    user = await get_user(username)
    if user is not None:
        lockout_sec = await get_account_lockout(username)
        if lockout_sec:
            response_html = _make_lockout_html(
                state, client_id, redirect_uri,
                code_challenge, code_challenge_method, lockout_sec)
            return HTMLResponse(response_html, status_code=429)
    # Защита от timing-атаки. Если пользователь не найден, verify_password
    # всё равно эмулируем, чтобы ответ не возвращался заметно быстрее, чем
    # если бы пользователь был обнаружен.
    # Вынесено в поток, чтобы не блокировать Event Loop
    hashed = user["hashed_password"] if user else _DUMMY_HASH
    password_ok = await asyncio.to_thread(verify_password, password, hashed)
    if not user or not password_ok:
        if user is not None:
            # Записываем failed_login только для существующих пользователей
            await record_failed_login(username, ip)
        # Один и тот же ответ для "юзера нет" и "пароль неверный" - чтобы
        # не показывать существование пользователя через тайминги/сообщения
        error_block = f'<div class="error">{html.escape("Unauthorized")}</div>'
        response_html = _render_login_html(
            state=state, client_id=client_id, redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            error_block_html=error_block,
            subtitle="Sign in to your MCP server account")
        return HTMLResponse(response_html, status_code=401)
    await clear_failed_logins(username)
    code = secrets.token_urlsafe(32)
    await store_auth_code(
        code=code,
        username=username,
        client_id=client_id,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge or None,
        code_challenge_method=code_challenge_method or None)
    params = {"code": code}
    if state:
        params["state"] = state
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(
        f"{redirect_uri}{sep}{urlencode(params)}",
        status_code=302)
    """
    # Задел: более правильный способ, не подогнанный под наблюдаемое поведение
    # MCP Inspector. Генерируем новый state для редиректа, чтобы предотвратить
    # Session Fixation, даже несмотря на защиту PKCE
    final_state = secrets.token_urlsafe(32)
    params = {"code": code, "state": final_state}
    sep = "&" if "?" in redirect_uri else "?"
    response = RedirectResponse(
        f"{redirect_uri}{sep}{urlencode(params)}",
        status_code=302)
    # Инвалидируем старую куку, чтобы её нельзя было переиспользовать
    response.delete_cookie("oauth_state", path="/oauth")
    return response """

@app.post("/oauth/token")
@limiter.limit(LOGIN_RATE_BY_IP_H)
async def token_endpoint(
    request: Request,
    grant_type: str = Form(...),
    # Обязателен по RFC 6749 §4.1.3, но MCP инспектор может не слать
    client_id: str = Form(""),
    # По RFC 6749 §4.1.3, если redirect_uri присутствовал в запросе
    # авторизации - он должен быть и здесь. Параметр оставлен опциональным
    # для совместимости с Inspector, но при наличии проверяется строго
    redirect_uri: str = Form(""),
    code: str = Form(""),
    code_verifier: str = Form(""),
    refresh_token: str = Form("")):
    if grant_type == "authorization_code":
        # Проверяем client_id только для получения кода
        if not client_id:
            raise HTTPException(400, "client_id required")
        if await _get_client_redirect_uris(client_id) is None:
            raise HTTPException(400, f"Unknown client_id: {client_id}")
        if not code:
            raise HTTPException(400, "code required")
        record = await consume_auth_code(code)
        if not record:
            raise HTTPException(400, "code is invalid or has expired")
        if record["client_id"] != client_id:
            raise HTTPException(400, "client_id does not match")
        if not await _is_redirect_uri_allowed(client_id, record["redirect_uri"]):
            raise HTTPException(400, "stored redirect_uri is not allowed")
        # Если redirect_uri пришёл в запросе, то проверяем строго;
        # если не пришёл - принимаем как есть
        if redirect_uri and redirect_uri != record["redirect_uri"]:
            raise HTTPException(400, "redirect_uri does not match the authorization request")
        if record["code_challenge"]:
            if not code_verifier:
                raise HTTPException(400, "code_verifier required (PKCE)")
            if not verify_pkce(
                code_verifier, record["code_challenge"],
                record["code_challenge_method"] or "S256"):
                raise HTTPException(400, "Incorrect code_verifier")
        # Берём scope из auth_code (если там None или пустая строка, то
        # fallback на дефолт "mcp", чтобы ответ всегда содержал
        # непустое поле scope).
        # Read scope from auth_code (if it's None or empty there, fall back
        # to the default "mcp" so the response always contains a non-empty
        # scope field)
        issued_scope = record["scope"] if record["scope"] else "mcp"
        access = create_access_token(record["username"])
        refresh = await create_refresh_token(record["username"], client_id or None)
        return JSONResponse({
            "access_token": access,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_SEC,
            "refresh_token": refresh,
            "scope": issued_scope})
    if grant_type == "refresh_token":
        if not refresh_token:
            raise HTTPException(400, "refresh_token required")
        # Per-username rate limit на случай, если злоумышленник за тем же
        # IP, что и жертва, перебирает её refresh-токены. Срабатывает
        # благодаря refresh_limiter, у которого key_func читает username
        # из request.scope["form"] (FastAPI кладёт туда распарсенную форму).
        # Per-username rate limit in case an attacker on the same IP as
        # the victim brute-forces her refresh tokens. Triggered by
        # refresh_limiter, whose key_func reads username from
        # request.scope["form"] (FastAPI puts the parsed form there).
        # Если username не удалось достать (форма не распарсилась / не
        # передан), _refresh_rate_key вернёт IP и сработает общий
        # LOGIN_RATE_BY_IP_H.
        # If username cannot be extracted (form not parsed / not sent),
        # _refresh_rate_key falls back to IP and the general
        # LOGIN_RATE_BY_IP_H kicks in.
        await refresh_limiter.check(request, dynamic_limit=REFRESH_RATE_BY_USER)
        # Передаем client_id только если он реально был передан инспектором.
        # verify_refresh_token атомарно отзывает токен внутри себя -
        # не вызываем revoke_refresh_token отдельно
        username = await verify_refresh_token(
            refresh_token,
            client_id if client_id else None)
        if not username:
            raise HTTPException(400, "refresh_token is invalid or has expired")
        # Создаем новый токен. verify_refresh_token уже отозвал старый атомарно,
        # поэтому здесь нет риска потерять сессию при сбое между revoke и issue
        new_refresh = await create_refresh_token(username, client_id or None)
        access = create_access_token(username)
        return JSONResponse({
            "access_token": access,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_SEC,
            "refresh_token": new_refresh,
            "scope": "mcp"})
    raise HTTPException(400, f"Unsupported grant_type: {grant_type}")

@app.post("/oauth/revoke")
async def revoke_endpoint(
    token: str = Form(...),
    _=Depends(require_resource_server_auth)):
    await revoke_refresh_token(token)
    return Response(status_code=200)

# Интроспекция по RFC 7662. POST - иначе токен утекает в
# access-логи и referer'ы.
# Introspection per RFC 7662. POST - otherwise the token leaks into
# access logs and referrer headers.
# TODO: В текущей реализации payload JWT не содержит client_id (aud),
# поэтому эндпоинт не может проверить, предназначался ли токен
# конкретному resource server'у. Если будет несколько MCP-серверов,
# необходимо добавить client_id в payload при создании access_token
# и проверять его здесь.
# До того в прод-деплое защищать через OAUTH_RESOURCE_SERVER_SECRET.
# he current JWT payload does not contain client_id (aud), so this endpoint
# cannot verify whether the token was intended for a specific resource server.
# If there are multiple MCP servers, add client_id to the payload in create_access_token
# and validate it here.
# Until then, protect via OAUTH_RESOURCE_SERVER_SECRET in production.
@app.post("/oauth/token/info")
async def token_info_post(
    request: Request,
    token: str = Form(...),
    _=Depends(require_resource_server_auth)):
    # Сначала валидируем секрет - иначе jwt.decode может крашнуться
    # на пустой строке или вести себя непредсказуемо
    try:
        _validate_secret_key()
    except RuntimeError:
        return {"active": False}
    try:
        # Без `audience=` потому что access_token выпускается без `aud`
        # (см. отклонение №3)
        payload = jwt.decode(
            token, SECRET_KEY, algorithms=[ALGORITHM])
        # Защита от confused deputy: убеждаемся, что это именно
        # наш access-токен, а не другой JWT, подписанный тем же ключом
        if payload.get("type") != "access" or payload.get("iss") != ISSUER:
            return {"active": False}
        return {"active": True, "sub": payload["sub"], "exp": payload["exp"]}
    except JWTError:
        return {"active": False}

# CLI
async def _cli_add_user(username: str, password: str):
    if len(password.encode("utf-8")) > 72:
        print(
            "WARNING: bcrypt silently truncates passwords longer than 72 bytes. "
            "The password will be stored, but only the first 72 bytes will be used "
            "for verification. Consider using argon2 or scrypt for long passphrases")
    global _db_conn
    _db_conn = await aiosqlite.connect(DB_PATH, timeout=_DB_CONNECT_TIMEOUT)
    _db_conn.row_factory = aiosqlite.Row
    try:
        await init_db(_db_conn)
        # Выносим в поток, чтобы не блокировать Event Loop CLI на время хеширования
        hashed = await asyncio.to_thread(hash_password, password)
        await _db_conn.execute(
            "INSERT INTO users (username, hashed_password) VALUES (?, ?)",
            (username, hashed))
        await _db_conn.commit()
        print(f"User '{username}' has been added")
    finally:
        await _db_conn.close()
        _db_conn = None

async def _cli_list_users():
    global _db_conn
    _db_conn = await aiosqlite.connect(DB_PATH, timeout=_DB_CONNECT_TIMEOUT)
    _db_conn.row_factory = aiosqlite.Row
    try:
        await init_db(_db_conn)
        async with _db_conn.execute("SELECT username, created_at FROM users") as cur:
            rows = await cur.fetchall()
        if not rows:
            print("No users")
            return
        for r in rows:
            print(f"  {r['username']}  (created at: {r['created_at']})")
    finally:
        await _db_conn.close()
        _db_conn = None

async def _cli_remove_user(username: str):
    global _db_conn
    _db_conn = await aiosqlite.connect(DB_PATH, timeout=_DB_CONNECT_TIMEOUT)
    _db_conn.row_factory = aiosqlite.Row
    try:
        await init_db(_db_conn)
        cur = await _db_conn.execute(
            "DELETE FROM users WHERE username = ?", (username,))
        await _db_conn.commit()
        if cur.rowcount:
            print(f"User '{username}' has been deleted")
        else:
            print(f"User '{username}' not found")
    finally:
        await _db_conn.close()
        _db_conn = None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OAuth server for MCP")
    parser.add_argument("--add-user", nargs=2, metavar=("LOGIN", "PASSWORD"))
    parser.add_argument("--list-users", action="store_true")
    parser.add_argument("--remove-user", metavar="LOGIN")
    args = parser.parse_args()

    if args.add_user:
        asyncio.run(_cli_add_user(*args.add_user))
    elif args.list_users:
        asyncio.run(_cli_list_users())
    elif args.remove_user:
        asyncio.run(_cli_remove_user(args.remove_user))
    else:
        if not SECRET_KEY or len(SECRET_KEY) < 32:
            print(
                "ERROR: OAUTH_SECRET_KEY is required and must be at least 32 chars. "
                "Set it via environment variable before starting the server",
                flush=True)
            sys.exit(2)
        uvicorn.run(
            "oauth_server:app",
            host=BIND_HOST,
            port=PORT,
            log_level="info")
