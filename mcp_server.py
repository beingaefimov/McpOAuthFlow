""" Наивный MCP Server (FastMCP, streamable-http транспорт) - коннектор для поиска ответов
на вопросы по программированию в интернете со встроенным GUI тестировщиком.

Инструменты сервера представляются LLM как предназначенные для поиска информации,
связанной с программированием, разработкой ПО, компьютерными науками
и смежными техническими дисциплинами
(определяется description инструментов и instructions сервера,
а так же перечнем авторитетных источников).

Источники поиска:
Приоритет отдаётся авторитетным и современным источникам:
- Stack Overflow, Stack Exchange
- Официальная документация (MDN, Python docs, Rust docs, Go docs и т.д.)
- GitHub (issues, discussions, README)
- Технические блоги и учебные ресурсы (Real Python, JavaScript.info и др.)

Авторизация:
Сервер принимает JWT access_token, выданный oauth_server.py.
Токен передаётся клиентом автоматически после OAuth-флоу.
Переменные окружения:
OAUTH_SECRET_KEY - должен совпадать с тем же ключом в oauth_server.py
OAUTH_ISSUER - публичный URL OAuth-сервера (например https://mcp.example.com/oauth)

Для локального тестирования во встроенном GUI - запускать без OAUTH_SECRET_KEY """

# TODO: Добавить специальные обработчики для:
# 1. go.dev / pkg.go.dev (вес 95)
#    Основной контент на pkg.go.dev находится в теге main#doc-content 
#    или section.Documentation. На go.dev/blog - в теге article.
#    Необходимо удалить мусор: nav.Header, div.go-Search, div.DetailsHeader.
#    Подход: Улучшенный HTML-парсинг (аналогично _fetch_python_docs_via_html)
#
# 2. Microsoft Learn / docs.microsoft.com (вес 85)
#    Огромный объем документации (.NET, C#, Azure, PowerShell).
#    Основной контент: main#main, div.content.
#    Необходимо удалить обвес: div#left-nav, div#right-nav, div.breadcrumb,
#    div.affixed-top, div.feedback-panel, div.theme-selector.
#    Подход: Улучшенный HTML-парсинг. Сложность в том, что структура страниц
#    может немного отличаться в зависимости от раздела (Azure vs .NET)

# TODO: Принудительное перенаправление на сайты.
# Почти всегда "Search & Fetch Top Result" будет выбиирать результат от Stack Overflow.
# Рассчитывать, что если установлено "глубокое размышление", или делается не первая
# итерация по требованию недовольного пользователя, то можно принудительно
# перенаправлять поиск на сайт (из списка авторитетных),
# добавляя его к запросу к "Search & Fetch Top Result", таким образом (те после site:):
# fastapi websocket connection site:github.com
# python requests site:pypi.org
# express site:npmjs.com
# serde site:crates.io
# DuckDuckGo поймёт этот оператор, ограничит выдачу нужным доменом,
# и тогда "Search & Fetch" автоматически передаст URL в новые API-обработчики

import anyio
import asyncio
from starlette.middleware.cors import CORSMiddleware
import json
import logging
import re
import threading
import time
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from typing import Any, Dict, List, Optional
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from urllib.parse import urlparse, unquote, parse_qs, quote
import os
import secrets
import httpx
import html as html_module
import uvicorn
from bs4 import BeautifulSoup
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.middleware.cors import CORSMiddleware
from jose import JWTError, jwt as jose_jwt
# Не используем duckduckgo_search
from ddgs import DDGS
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.fastmcp import FastMCP, Context
from mcp.types import CallToolResult, TextContent, TextResourceContents
from pydantic import BaseModel, Field

# Включаем отладочное логирование. Намеренно не удалено, тк ожидается много доработок и отладки
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")

_version = '1.0.1'
_name = 'MCP Programming Search Connector'

MCP_PROTOCOL = 'http://'
MCP_HOST = '0.0.0.0'
MCP_PORT = 6339
MCP_STREAM = '/mcp'
MCP_HOST_TIMEOUT_SEC = 60

# JWT-настройки: должны совпадать с oauth_server.py
OAUTH_SECRET_KEY: str = os.environ.get("OAUTH_SECRET_KEY", "")
OAUTH_ISSUER: str = os.environ.get("OAUTH_ISSUER", "")
OAUTH_ALGORITHM = "HS256"

if not OAUTH_ISSUER:
    print("OAUTH_ISSUER не задан! Работа только с локальным GUI")

if not OAUTH_SECRET_KEY:
    print("OAUTH_SECRET_KEY не задан! MCP-сервер не сможет проверять JWT, локальный GUI не будет проверять JWT")

GUI_MCP_BASE = f'{MCP_PROTOCOL}localhost:{MCP_PORT}{MCP_STREAM}'
GUI_QUERY_DEFAULT = 'How to implement async semaphore in Python?'

# Доменные источники
DOMAIN_AUTHORITY = {
    "stackoverflow.com": 100,
    "stackexchange.com": 90,
    "superuser.com": 70,
    "serverfault.com": 75,
    "askubuntu.com": 65,
    "developer.mozilla.org": 95,
    "docs.python.org": 95,
    "docs.ros.org": 85,
    "docs.rs": 90,
    "doc.rust-lang.org": 95,
    "go.dev": 95,
    "docs.golang.org": 95,
    "kotlinlang.org": 90,
    "docs.oracle.com": 90,
    "docs.spring.io": 85,
    "docs.microsoft.com": 85,
    "learn.microsoft.com": 85,
    "developer.android.com": 90,
    "react.dev": 90,
    "vuejs.org": 90,
    "angular.dev": 90,
    "nextjs.org": 85,
    "svelte.dev": 85,
    "nuxt.com": 85,
    "tailwindcss.com": 85,
    "typescriptlang.org": 90,
    "nodejs.org": 90,
    "deno.land": 80,
    "expressjs.com": 85,
    "fastapi.tiangolo.com": 85,
    "django.readthedocs.io": 85,
    "flask.palletsprojects.com": 85,
    "docs.sqlalchemy.org": 85,
    "nginx.org": 85,
    "kubernetes.io": 90,
    "docs.docker.com": 90,
    "postgresql.org": 90,
    "redis.io": 85,
    "mongodb.com": 80,
    "elastic.co": 85,
    "grafana.com": 80,
    "prometheus.io": 85,
    "llvm.org": 85,
    "gcc.gnu.org": 85,
    "docs.julialang.org": 85,
    "hexdocs.pm": 80,
    "crystal-lang.org": 80,
    "ziglang.org": 80,
    "vlang.io": 75,
    "github.com": 80,
    "gitlab.com": 75,
    "bitbucket.org": 65,
    "realpython.com": 85,
    "javascript.info": 85,
    "python.org": 90,
    "pypi.org": 75,
    "crates.io": 75,
    "npmjs.com": 75,
    "arxiv.org": 80,
    "habr.com": 70,
    "dev.to": 70,
    "medium.com": 50,
    "hackernoon.com": 60,
    "freecodecamp.org": 75,
    "codeforces.com": 75,
    "leetcode.com": 75,
    "aws.amazon.com": 80,
    "cloud.google.com": 80,
    "azure.microsoft.com": 75,
    "en.wikipedia.org": 60,
    "ru.wikipedia.org": 55}

# Доменные утилиты
def get_domain_authority(url: str) -> int:
    """ Возвращает вес авторитетности источника из URL """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
        if ':' in domain:
            domain = domain.split(':')[0]
        if domain in DOMAIN_AUTHORITY:
            return DOMAIN_AUTHORITY[domain]
        for auth_domain, weight in DOMAIN_AUTHORITY.items():
            if domain == auth_domain or domain.endswith('.' + auth_domain):
                return max(weight - 5, 10)
        return 10
    except Exception:
        return 10

def extract_domain(url: str) -> str:
    """ Извлекает источник из URL """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
        if ':' in domain:
            domain = domain.split(':')[0]
        return domain
    except Exception:
        return ""

def rank_results(results: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """ Ранжирует результаты поиска по авторитетности источника """
    for r in results:
        r['_authority'] = get_domain_authority(r.get('href', ''))
    results.sort(key=lambda x: x.get('_authority', 0), reverse=True)
    for r in results:
        r.pop('_authority', None)
    return results

async def perform_search(
    query: str,
    max_results: int = 5,
    timelimit: Optional[str] = "y",
) -> List[Dict[str, str]]:
    """ Выполняет поиск через DuckDuckGo (ddgs) и возвращает ранжированные результаты """
    loop = asyncio.get_event_loop()
    def _search_sync() -> List[Dict]:
        ddgs = DDGS()
        last_error: Exception = RuntimeError("No attempts made")
        for attempt in range(3):
            try:
                raw_results = ddgs.text(
                    query,
                    region="us-en",
                    # С запасом для ранжирования
                    max_results=max_results * 3,
                    safesearch="moderate",
                    timelimit=timelimit)
                return raw_results or []
            except Exception as e:
                last_error = e
                logging.warning(f"Попытка {attempt + 1}/3 DuckDuckGo: {e}")
                if attempt < 2:
                    time.sleep(2)
        logging.error(f"Все попытки DuckDuckGo исчерпаны: {last_error}")
        return []
    raw_results = await loop.run_in_executor(None, _search_sync)
    formatted = []
    for r in raw_results:
        href = r.get("href", r.get("url", ""))
        body = r.get("body", r.get("description", r.get("snippet", "")))
        formatted.append({
            "title": r.get("title", ""),
            "href": href,
            "body": body,
            "domain": extract_domain(href)})
    formatted = rank_results(formatted)
    return formatted[:max_results]

def _extract_so_question_id(url: str) -> Optional[str]:
    """ Извлекает числовой ID вопроса из URL Stack Overflow / Stack Exchange """
    match = re.search(r'/questions/(\d+)', url)
    return match.group(1) if match else None

def _get_se_site(url: str) -> str:
    """ Определяет имя сайта для Stack Exchange API по URL """
    domain = extract_domain(url)
    mapping = {
        "stackoverflow.com": "stackoverflow",
        "askubuntu.com": "askubuntu",
        "superuser.com": "superuser",
        "serverfault.com": "serverfault",
        "codereview.stackexchange.com": "codereview",
        "unix.stackexchange.com": "unix",
        "math.stackexchange.com": "math",
        "cs.stackexchange.com": "cs",
        "softwareengineering.stackexchange.com": "softwareengineering",
        "dba.stackexchange.com": "dba"}
    if domain in mapping:
        return mapping[domain]
    # Локализованные Stack Overflow: ru.stackoverflow.com -> "ru.stackoverflow"
    m = re.match(r'^([a-z]{2})\.stackoverflow\.com$', domain)
    if m:
        return f"{m.group(1)}.stackoverflow"
    # *.stackexchange.com -> берём поддомен
    m = re.match(r'^(.+)\.stackexchange\.com$', domain)
    if m:
        return m.group(1)
    return "stackoverflow"

async def _fetch_via_se_api(question_id: str, site: str, max_chars: int) -> str:
    """ Получает вопрос и ответы через Stack Exchange API v2.3 """
    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=httpx.Timeout(connect=10.0, read=20.0, write=5.0, pool=5.0),
    ) as client:
        q_url = (
            f"https://api.stackexchange.com/2.3/questions/{question_id}"
            f"?site={site}&filter=withbody&key=")
        qr = await client.get(q_url)
        qr.raise_for_status()
        q_data = qr.json()
        parts = []
        if q_data.get("items"):
            q = q_data["items"][0]
            title = html_module.unescape(q.get("title", ""))
            body_html = q.get("body", "")
            body_text = BeautifulSoup(body_html, "html.parser").get_text(separator='\n', strip=True)
            tags = ", ".join(q.get("tags", []))
            score = q.get("score", 0)
            parts.append(f"# {title}")
            parts.append(f"Теги: {tags} | Оценка: {score}")
            parts.append("")
            parts.append("## Вопрос")
            parts.append(body_text)
            parts.append("")
        a_url = (
            f"https://api.stackexchange.com/2.3/questions/{question_id}/answers"
            f"?site={site}&filter=withbody&sort=votes&order=desc&pagesize=3&key=")
        ar = await client.get(a_url)
        ar.raise_for_status()
        a_data = ar.json()
        answers = a_data.get("items", [])
        if answers:
            parts.append(f"## Ответы ({len(answers)} из лучших)")
            for i, ans in enumerate(answers, 1):
                score = ans.get("score", 0)
                accepted = " ✓ [принятый]" if ans.get("is_accepted") else ""
                body_html = ans.get("body", "")
                body_text = BeautifulSoup(body_html, "html.parser").get_text(separator='\n', strip=True)
                parts.append(f"\n### Ответ {i}{accepted} (оценка: {score})")
                parts.append(body_text)
        else:
            parts.append("## Ответы не найдены")
    text = '\n'.join(parts)
    lines = [l for l in text.splitlines() if l.strip() or l == ""]
    result_lines = []
    blank_count = 0
    for line in lines:
        if line.strip() == "":
            blank_count += 1
            if blank_count <= 1:
                result_lines.append(line)
        else:
            blank_count = 0
            result_lines.append(line)
    text = '\n'.join(result_lines)
    if len(text) > max_chars:
        text = text[:max_chars] + f"\n\n... [обрезано, всего символов: {len(text)}]"
    return text

async def _fetch_wikipedia_via_api(url: str, max_chars: int) -> Optional[str]:
    """ Получает полное содержимое статьи Wikipedia через REST API (html-эндпоинт).
    Возвращает None, если URL не подходит для обработки через API или все попытки исчерпаны.

    Эндпоинт /page/html/ возвращает только содержимое статьи без обвеса сайта """
    domain = extract_domain(url)
    if not domain.endswith("wikipedia.org"):
        return None
    # Извлекаем заголовок статьи из пути /wiki/...
    path = urlparse(url).path
    match = re.search(r'/wiki/([^/#?]+)', path)
    if not match:
        return None
    title = unquote(match.group(1))
    # Определяем язык по поддомену
    lang = "en"
    if domain != "wikipedia.org":
        lang_match = re.match(r'^([a-z]{2,3})\.wikipedia\.org$', domain)
        if lang_match:
            lang = lang_match.group(1)
    api_title = title.replace(" ", "_")
    # Сначала пробуем язык оригинала, затем английский как fallback
    languages_to_try = [lang]
    if lang != "en":
        languages_to_try.append("en")
    headers = {
        "User-Agent": "MCP-Programming-Search/1.0 (https://github.com/your-username/mcp-search; contact@example.com)",
        "Accept": "text/html; charset=utf-8; profile=\"https://www.mediawiki.org/wiki/Specs/HTML/2.5.0\""}
    for try_lang in languages_to_try:
        # HTML-эндпоинт возвращает полную статью без обвеса сайта
        api_url = f"https://{try_lang}.wikipedia.org/api/rest_v1/page/html/{api_title}"
        for attempt in range(3):
            try:
                async with httpx.AsyncClient(timeout=25.0) as client:
                    resp = await client.get(
                        api_url,
                        headers=headers,
                        follow_redirects=True)
                    if resp.status_code == 429:
                        retry_after = int(resp.headers.get("retry-after", "5"))
                        wait_time = min(retry_after, 5)
                        logging.warning(
                            f"[Wikipedia API] 429 для {api_url}, "
                            f"ожидание {wait_time}с (попытка {attempt + 1}/3)"
                        )
                        if attempt < 2:
                            await asyncio.sleep(wait_time)
                            continue
                        else:
                            logging.warning(
                                f"[Wikipedia API] Все 3 попытки исчерпаны для языка '{try_lang}'")
                            break
                    if resp.status_code == 404:
                        logging.debug(f"[Wikipedia API] 404 - статья не найдена: {api_url}")
                        break  # Статьи нет в этом языке, пробуем следующий
                    if resp.status_code != 200:
                        logging.debug(
                            f"[Wikipedia API] {resp.status_code} для {api_url}: "
                            f"{resp.text[:200]}")
                        break
                    # Парсим HTML статьи
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    for tag in soup([
                        "script", "style", "noscript",
                        # Сноски и примечания внизу статьи
                        "div[class*='reflist']", "div[class*='references']",
                        "ol[class*='references']", "div[class*='refbegin']",
                        # Внешние ссылки внизу
                        "div[class*='external']", "div[id='external-links']",
                        # Списки литературы
                        "div[class*='bibliography']",
                        # Навигационные шаблоны-врезки
                        "table[class*='navbox']", "table[id*='navbox']",
                        "div[class*='navbox']",
                        # Инфобоксы (таблицы справа) - обычно дублируют текст
                        "table[class*='infobox']", "table[class*='metadata']",
                        # Категории
                        "div[id='catlinks']", "div[class*='catlinks']",
                        # Межъязыковые ссылки
                        "div[id='p-lang']", "div[class*='interwiki']",
                        # Предупреждения
                        "div[class*='ambox']", "div[class*='tmbox']",
                        # «Эта статья о…»
                        "div[class*='hatnote']", "div[class*='dablink']",
                        "div[class*='retrans']"]):
                        tag.decompose()
                    # Извлекаем текст
                    text_content = soup.get_text(separator='\n', strip=True)
                    # Очищаем от лишних пустых строк
                    lines = [line.strip() for line in text_content.splitlines() if line.strip()]
                    text = '\n'.join(lines)
                    # Схлопываем повторяющиеся пустые строки (на всякий случай)
                    while '\n\n\n' in text:
                        text = text.replace('\n\n\n', '\n\n')
                    if not text.strip():
                        logging.debug(f"[Wikipedia API] Пустой текст после парсинга: {api_url}")
                        break
                    # Добавляем заголовок с указанием языка
                    lang_label = try_lang.upper()
                    text = f"[Язык: {lang_label}]\n\n{text}"
                    if len(text) > max_chars:
                        text = text[:max_chars] + f"\n\n... [обрезано, всего символов: {len(text)}]"
                    return text
            except Exception as e:
                logging.warning(f"Wikipedia API error for {api_url}: {e}")
                break
    return None

async def _fetch_wikipedia_via_curl_cffi(url: str, max_chars: int) -> Optional[str]:
    """ Fallback-загрузка полной статьи Wikipedia через curl_cffi для обхода
    TLS-fingerprinting (403 Forbidden от HAProxy при прямом HTTP-доступе).
    curl_cffi уже установлен как транзитивная зависимость ddgs.
    Используем sync-версию в executor для избежания конфликтов event loop """
    try:
        from curl_cffi import requests as cffi_requests
    except ImportError:
        logging.debug("[Wikipedia curl_cffi] curl_cffi не доступен")
        return None

    def _fetch_sync() -> Optional[str]:
        try:
            resp = cffi_requests.get(
                url,
                impersonate="chrome",
                timeout=25,
                headers={
                    "User-Agent": "MCP-Programming-Search/1.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9,ru;q=0.8",})
            if resp.status_code != 200:
                logging.debug(f"[Wikipedia curl_cffi] {resp.status_code} для {url}")
                return None
            soup = BeautifulSoup(resp.text, 'html.parser')
            # На mw-content-text завязана основная статья
            main_content = (
                soup.find("div", id="mw-content-text")
                or soup.find("main")
                or soup.find(id="content")
                or soup.find("article"))
            if not main_content:
                logging.debug("[Wikipedia curl_cffi] Не найден основной контент")
                return None
            for tag in main_content([
                "script", "style", "noscript", "svg", "iframe",
                "div[class*='reflist']", "div[class*='references']",
                "ol[class*='references']", "div[class*='refbegin']",
                "div[class*='external']", "div[id='external-links']",
                "div[class*='bibliography']",
                "table[class*='navbox']", "table[id*='navbox']",
                "div[class*='navbox']",
                "table[class*='infobox']", "table[class*='metadata']",
                "div[id='catlinks']", "div[class*='catlinks']",
                "div[id='p-lang']", "div[class*='interwiki']",
                "div[class*='ambox']", "div[class*='tmbox']",
                "div[class*='hatnote']", "div[class*='dablink']",
                "div[class*='retrans']",
                "div[class*='toc']", "div[id='toc']"]):
                tag.decompose()
            text = main_content.get_text(separator='\n', strip=True)
            lines = [line.strip() for line in text.splitlines() if line.strip()]
            text = '\n'.join(lines)
            while '\n\n\n' in text:
                text = text.replace('\n\n\n', '\n\n')
            if not text.strip():
                return None
            if len(text) > max_chars:
                text = text[:max_chars] + f"\n\n... [обрезано, всего символов: {len(text)}]"
            return text
        except Exception as e:
            logging.warning(f"[Wikipedia curl_cffi] Ошибка: {type(e).__name__}: {e}")
            return None
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _fetch_sync)

async def _fetch_mdn_via_api(url: str, max_chars: int) -> Optional[str]:
    """ Получает содержимое страницы MDN через официальный JSON API """
    try:
        domain = extract_domain(url)
        if domain != "developer.mozilla.org":
            return None
        path = urlparse(url).path
        if "/docs/" not in path:
            return None
        locale = "en-US"
        locale_match = re.match(r'^/([a-z]{2}(?:-[A-Z]{2})?)/docs/', path)
        if locale_match:
            locale = locale_match.group(1)
            slug = path.split(f'/{locale}/docs/', 1)[-1].rstrip('/')
        else:
            slug = path.split('/docs/', 1)[-1].rstrip('/')
        if not slug:
            return None
        api_url = f"https://developer.mozilla.org/{locale}/docs/{slug}/index.json"
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(api_url, headers={"User-Agent": "MCP-Connector/1.0"}, follow_redirects=True)
            if resp.status_code == 404 or resp.status_code != 200:
                return None
            data = resp.json()
            doc = data.get('doc', {})
            if not doc:
                return None
            parts = []
            title = doc.get('title', '')
            summary = doc.get('summary', '')
            if title: parts.append(f"# {title}")
            if summary: parts.append(f"{summary}\n")
            body = doc.get('body', '')
            if body:
                soup = BeautifulSoup(body, 'html.parser')
                for tag in soup(["script", "style", "nav", "footer", "header", "aside", "iframe"]):
                    tag.decompose()
                text_content = soup.get_text(separator='\n', strip=True)
                if text_content:
                    parts.append("## Документация\n")
                    parts.append(text_content)
            text = "\n".join(parts).strip()
            return text[:max_chars] + ("..." if len(text) > max_chars else "")
    except Exception as e:
        logging.warning(f"[MDN API] Ошибка: {type(e).__name__}: {e}")
        return None

async def _fetch_python_docs_via_html(url: str, max_chars: int) -> Optional[str]:
    """ Получает содержимое страницы Python docs с улучшенным парсингом """
    try:
        domain = extract_domain(url)
        if domain != "docs.python.org":
            return None
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
        async with httpx.AsyncClient(headers=headers, timeout=20.0, follow_redirects=True) as client:
            resp = await client.get(url)
            if resp.status_code == 404: return None
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, 'html.parser')
            main = soup.find("div", class_="body") or soup.find(role="main") or soup.find("main")
            if not main: return None
            for tag in main(["script", "style", "nav", "footer", "header", "aside", 
                            "div[class*='navigation']", "div[class*='sidebar']", 
                            "div[class*='related']", "div[class*='bottomnav']"]):
                tag.decompose()
            title_tag = main.find("h1")
            title = title_tag.get_text(strip=True) if title_tag else ""
            text_content = main.get_text(separator='\n', strip=True)
            parts = []
            if title: parts.append(f"# {title}\n")
            parts.append("## Документация\n")
            parts.append(text_content)
            text = "\n".join(parts).strip()
            lines = [l for l in text.splitlines() if l.strip() or l == ""]
            result_lines, blank_count = [], 0
            for line in lines:
                if line.strip() == "":
                    blank_count += 1
                    if blank_count <= 1: result_lines.append(line)
                else:
                    blank_count = 0
                    result_lines.append(line)
            text = "\n".join(result_lines)
            return text[:max_chars] + ("..." if len(text) > max_chars else "")
    except Exception as e:
        logging.warning(f"[Python docs] Ошибка: {type(e).__name__}: {e}")
        return None

async def _fetch_github_via_api(url: str, max_chars: int) -> Optional[str]:
    """ Получает содержимое GitHub (README, Issues, PRs) через REST API """
    try:
        domain = extract_domain(url)
        if domain != "github.com":
            return None
        path = urlparse(url).path.strip('/')
        # Извлекаем owner/repo и опционально тип и номер
        m_repo = re.match(r'^([^/]+)/([^/]+?)(?:\.git)?$', path)
        m_issue = re.match(r'^([^/]+)/([^/]+)/issues/(\d+)$', path)
        m_pr = re.match(r'^([^/]+)/([^/]+)/pull/(\d+)$', path)
        headers = {
            "User-Agent": "MCP-Programming-Search/1.0",
            "Accept": "application/vnd.github.v3+json"}
        async with httpx.AsyncClient(timeout=15.0) as client:
            if m_issue:
                owner, repo, num = m_issue.groups()
                api_url = f"https://api.github.com/repos/{owner}/{repo}/issues/{num}"
                resp = await client.get(api_url, headers=headers)
                if resp.status_code != 200: return None
                data = resp.json()
                parts = [f"# {data.get('title', 'Issue')}\n"]
                parts.append(f"Автор: {data.get('user', {}).get('login', 'N/A')} | Статус: {data.get('state', 'N/A')} | Оценка: {data.get('score', 0)}\n")
                body = data.get('body', '') or ''
                parts.append("## Описание\n")
                parts.append(body)
                # Запросим топ комментариев
                comments_url = f"https://api.github.com/repos/{owner}/{repo}/issues/{num}/comments?sort=votes&per_page=3"
                c_resp = await client.get(comments_url, headers=headers)
                if c_resp.status_code == 200 and c_resp.json():
                    parts.append("\n## Лучшие комментарии")
                    for c in c_resp.json():
                        parts.append(f"\n### @{c.get('user', {}).get('login', 'N/A')} (оценка: {c.get('reactions', {}).get('+1', 0)})")
                        parts.append(c.get('body', ''))
                text = "\n".join(parts)
            elif m_pr:
                owner, repo, num = m_pr.groups()
                api_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{num}"
                resp = await client.get(api_url, headers=headers)
                if resp.status_code != 200: return None
                data = resp.json()
                parts = [f"# {data.get('title', 'PR')}\n"]
                parts.append(f"Автор: {data.get('user', {}).get('login', 'N/A')} | Статус: {data.get('state', 'N/A')}\n")
                body = data.get('body', '') or ''
                parts.append("## Описание\n")
                parts.append(body)
                text = "\n".join(parts)
            elif m_repo:
                owner, repo = m_repo.groups()
                api_url = f"https://api.github.com/repos/{owner}/{repo}/readme"
                # raw формат возвращает текст сразу, без base64
                headers_raw = {**headers, "Accept": "application/vnd.github.v3.raw"}
                resp = await client.get(api_url, headers=headers_raw)
                if resp.status_code != 200: return None
                repo_info_url = f"https://api.github.com/repos/{owner}/{repo}"
                r_resp = await client.get(repo_info_url, headers=headers)
                desc = ""
                if r_resp.status_code == 200:
                    desc = r_resp.json().get('description', '')
                parts = []
                if desc: parts.append(f"**Описание:** {desc}\n")
                parts.append(resp.text)
                text = "\n".join(parts)
            else:
                return None
            if len(text) > max_chars:
                text = text[:max_chars] + f"\n\n... [обрезано, всего символов: {len(text)}]"
            return text
    except Exception as e:
        logging.warning(f"[GitHub API] Ошибка: {type(e).__name__}: {e}")
        return None

async def _fetch_pypi_via_api(url: str, max_chars: int) -> Optional[str]:
    """ Получает описание пакета и README через PyPI JSON API """
    try:
        domain = extract_domain(url)
        if domain != "pypi.org":
            return None
        m = re.search(r'pypi\.org/project/([^/]+)', url)
        if not m:
            return None
        package = m.group(1)
        api_url = f"https://pypi.org/pypi/{package}/json"
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(api_url, headers={"User-Agent": "MCP-Connector/1.0"})
            if resp.status_code != 200:
                return None
            data = resp.json()
            info = data.get('info', {})
            parts = [f"# {info.get('name', package)}"]
            parts.append(f"**Версия:** {data.get('info', {}).get('version', 'N/A')} | **Автор:** {info.get('author', 'N/A')}\n")
            parts.append(f"**Кратко:** {info.get('summary', 'N/A')}\n")
            description = info.get('description', '')
            if description:
                # Если описание в HTML (часто бывает для старых пакетов или при конвертации RST)
                if description.strip().startswith("<"):
                    soup = BeautifulSoup(description, 'html.parser')
                    for tag in soup(["script", "style"]): tag.decompose()
                    description = soup.get_text(separator='\n', strip=True)
                parts.append("## Описание (README)\n")
                parts.append(description)
            text = "\n".join(parts)
            if len(text) > max_chars:
                text = text[:max_chars] + f"\n\n... [обрезано, всего символов: {len(text)}]"
            return text
    except Exception as e:
        logging.warning(f"[PyPI API] Ошибка: {type(e).__name__}: {e}")
        return None

async def _fetch_npm_via_api(url: str, max_chars: int) -> Optional[str]:
    """ Получает описание пакета и README через npm Registry API """
    try:
        domain = extract_domain(url)
        if domain != "npmjs.com":
            return None
        m = re.search(r'npmjs\.com/package/([^/]+)', url)
        if not m:
            return None
        package = m.group(1)
        # Используем /latest для быстрого получения только последней версии без всей истории
        api_url = f"https://registry.npmjs.org/{package}/latest"
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(api_url, headers={"User-Agent": "MCP-Connector/1.0"})
            if resp.status_code != 200:
                return None
            data = resp.json()
            parts = [f"# {data.get('name', package)}"]
            parts.append(f"**Версия:** {data.get('version', 'N/A')} | **Автор:** {data.get('author', {}).get('name', 'N/A') if isinstance(data.get('author'), dict) else data.get('author', 'N/A')}\n")
            parts.append(f"**Кратко:** {data.get('description', 'N/A')}\n")
            readme = data.get('readme', '')
            if readme:
                parts.append("## README\n")
                parts.append(readme)  
            text = "\n".join(parts)
            if len(text) > max_chars:
                text = text[:max_chars] + f"\n\n... [обрезано, всего символов: {len(text)}]"
            return text
    except Exception as e:
        logging.warning(f"[npm API] Ошибка: {type(e).__name__}: {e}")
        return None

async def _fetch_crates_via_api(url: str, max_chars: int) -> Optional[str]:
    """ Получает описание крейта и README через crates.io API """
    try:
        domain = extract_domain(url)
        if domain != "crates.io":
            return None
        m = re.search(r'crates\.io/crates/([^/]+)', url)
        if not m:
            return None
        crate = m.group(1)
        api_url = f"https://crates.io/api/v1/crates/{crate}"
        async with httpx.AsyncClient(timeout=15.0) as client:
            # crates.io требует User-Agent
            resp = await client.get(api_url, headers={"User-Agent": "MCP-Programming-Search/1.0 (contact@example.com)"})
            if resp.status_code != 200:
                return None
            data = resp.json()
            crate_data = data.get('crate', {})
            parts = [f"# {crate_data.get('name', crate)}"]
            parts.append(f"**Версия:** {crate_data.get('newest_version', 'N/A')} | **Загрузки:** {crate_data.get('downloads', 0)}\n")
            parts.append(f"**Кратко:** {crate_data.get('description', 'N/A')}\n")
            readme = data.get('readme', '')
            if readme:
                parts.append("## README\n")
                parts.append(readme)
            text = "\n".join(parts)
            if len(text) > max_chars:
                text = text[:max_chars] + f"\n\n... [обрезано, всего символов: {len(text)}]"
            return text
    except Exception as e:
        logging.warning(f"[crates.io API] Ошибка: {type(e).__name__}: {e}")
        return None

async def _fetch_docs_rs_via_html(url: str, max_chars: int) -> Optional[str]:
    """ Улучшенный парсинг для документации Rust на docs.rs """
    try:
        domain = extract_domain(url)
        if domain != "docs.rs":
            return None
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
        async with httpx.AsyncClient(headers=headers, timeout=20.0, follow_redirects=True) as client:
            resp = await client.get(url)
            if resp.status_code == 404: return None
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, 'html.parser')
            # На docs.rs основной контент обёрнут в специфичные классы Rustdoc
            main = soup.find("div", class_="docblock") or soup.find("main", class_="rustdoc") or soup.find("main")
            if not main:
                return None
            # Удаляем боковую панель с модулями и навигацией
            for tag in soup(["nav", "script", "style", "header", "footer"]):
                tag.decompose()
            for tag in main.find_all(["details", "aside"]):
                if "rustdoc-toggle" in tag.get("class", []) or "sidebar" in tag.get("class", []):
                    tag.decompose()
            # Оставляем блоки кода (pre.rust) без изменений
            text_content = main.get_text(separator='\n', strip=True)
            # Извлекаем заголовок из h1 или fqn
            title = ""
            fqn = soup.find("span", class_="fqn")
            if fqn:
                title = fqn.get_text(strip=True).replace("::", " :: ")
            if not title:
                h1 = main.find("h1")
                if h1: title = h1.get_text(strip=True)
            parts = []
            if title: parts.append(f"# {title}\n")
            parts.append(text_content)
            text = "\n".join(parts).strip()
            lines = [l for l in text.splitlines() if l.strip() or l == ""]
            result_lines, blank_count = [], 0
            for line in lines:
                if line.strip() == "":
                    blank_count += 1
                    if blank_count <= 1: result_lines.append(line)
                else:
                    blank_count = 0
                    result_lines.append(line)
            text = "\n".join(result_lines)
            return text[:max_chars] + ("..." if len(text) > max_chars else "")
    except Exception as e:
        logging.warning(f"[docs.rs] Ошибка: {type(e).__name__}: {e}")
        return None

async def fetch_page_text(url: str, max_chars: int = 15000) -> str:
    """ Загружает страницу и извлекает текстовое содержимое.
    Приоритет: SE API -> Wikipedia -> MDN -> Python -> GitHub -> PyPI -> npm -> 
               crates.io -> docs.rs -> общий HTTP """
    domain = extract_domain(url)
    # Stack Overflow / Stack Exchange -> API
    is_se_site = (
        domain in ("stackoverflow.com", "askubuntu.com", "superuser.com", "serverfault.com")
        or domain.endswith(".stackexchange.com")
        or domain.endswith(".stackoverflow.com"))
    if is_se_site:
        question_id = _extract_so_question_id(url)
        if question_id:
            try:
                site = _get_se_site(url)
                return await _fetch_via_se_api(question_id, site, max_chars)
            except Exception as e:
                logging.warning(f"SE API упал, пробуем прямой запрос: {e}")
    # Wikipedia -> REST API (полная статья, html-эндпоинт) -> curl_cffi fallback
    if domain.endswith("wikipedia.org"):
        # 1. REST API - полная статья без обвеса сайта
        # Ретрай при 429, fallback на английскую Wikipedia
        try:
            wp_content = await _fetch_wikipedia_via_api(url, max_chars)
            if wp_content is not None:
                return wp_content
        except Exception as e:
            logging.warning(f"Wikipedia API обработка не удалась: {e}")
        # 2. Fallback: curl_cffi - обход блокировки по TLS-отпечатку (403 int-tls)
        try:
            wp_content = await _fetch_wikipedia_via_curl_cffi(url, max_chars)
            if wp_content is not None:
                return wp_content
        except Exception as e:
            logging.warning(f"Wikipedia curl_cffi fallback не удался: {e}")
        # 3. Все методы исчерпаны - информативное сообщение вместо сырой ошибки
        return (
            f"[Не удалось загрузить содержимое Wikipedia. "
            f"Возможные причины: превышен лимит запросов API (429) "
            f"или блокировка по TLS-отпечатку при прямом доступе (403). "
            f"Попробуйте повторить запрос через 30–60 секунд. "
            f"URL: {url}]")
    # MDN -> JSON API
    if domain == "developer.mozilla.org":
        try:
            mdn_content = await _fetch_mdn_via_api(url, max_chars)
            if mdn_content is not None: return mdn_content
        except Exception as e:
            logging.warning(f"[fetch_page_text] Ошибка при вызове MDN API: {e}")
    # Python docs -> улучшенный HTML-парсинг
    if domain == "docs.python.org":
        try:
            py_content = await _fetch_python_docs_via_html(url, max_chars)
            if py_content is not None: return py_content
        except Exception as e:
            logging.warning(f"[fetch_page_text] Ошибка при парсинге Python docs: {e}")
    # GitHub -> API (Issues, PRs, Readme)
    if domain == "github.com":
        try:
            gh_content = await _fetch_github_via_api(url, max_chars)
            if gh_content is not None: return gh_content
        except Exception as e:
            logging.warning(f"[fetch_page_text] Ошибка при вызове GitHub API: {e}")
    # PyPI -> JSON API
    if domain == "pypi.org":
        try:
            pypi_content = await _fetch_pypi_via_api(url, max_chars)
            if pypi_content is not None: return pypi_content
        except Exception as e:
            logging.warning(f"[fetch_page_text] Ошибка при вызове PyPI API: {e}")
    # npmjs -> Registry API
    if domain == "npmjs.com":
        try:
            npm_content = await _fetch_npm_via_api(url, max_chars)
            if npm_content is not None: return npm_content
        except Exception as e:
            logging.warning(f"[fetch_page_text] Ошибка при вызове npm API: {e}")
    # crates.io -> API
    if domain == "crates.io":
        try:
            crates_content = await _fetch_crates_via_api(url, max_chars)
            if crates_content is not None: return crates_content
        except Exception as e:
            logging.warning(f"[fetch_page_text] Ошибка при вызове crates.io API: {e}")
    # docs.rs -> Улучшенный парсинг
    if domain == "docs.rs":
        try:
            docs_content = await _fetch_docs_rs_via_html(url, max_chars)
            if docs_content is not None: return docs_content
        except Exception as e:
            logging.warning(f"[fetch_page_text] Ошибка при парсинге docs.rs: {e}")
    # Общий путь: прямой HTTP-запрос
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,ru;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="131", "Google Chrome";v="131"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Referer": "https://www.google.com/",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }
        # Ретрай-логика для 403
        response = None
        last_error = None
        for attempt in range(2):
            try:
                await asyncio.sleep(0.3 + (time.time() % 0.4))
                async with httpx.AsyncClient(
                    headers=headers, follow_redirects=True,
                    timeout=httpx.Timeout(connect=10.0, read=30.0, write=5.0, pool=5.0),
                ) as client:
                    response = await client.get(url)
                    if response.status_code == 403 and attempt == 0:
                        await asyncio.sleep(1.5)
                        continue
                    response.raise_for_status()
                    break
            except httpx.TimeoutException as e:
                last_error = e
                if attempt == 1: return f"[Ошибка: таймаут при загрузке {url}]"
                await asyncio.sleep(1.0)
            except httpx.HTTPStatusError as e:
                last_error = e
                if attempt == 1: return f"[Ошибка HTTP {e.response.status_code} при загрузке {url}]"
                await asyncio.sleep(1.0)
            except Exception as e:
                last_error = e
                if attempt == 1: return f"[Ошибка при загрузке {url}: {type(e).__name__}: {e}]"
                await asyncio.sleep(1.0)
        if response is None:
            return f"[Не удалось загрузить {url}: {last_error}]"
        soup = BeautifulSoup(response.text, 'html.parser')
        for tag in soup(["script", "style", "nav", "footer", "header", "aside", "iframe", "noscript", "svg", "form"]):
            tag.decompose()
        main_content = (
            soup.find("main") or soup.find("article") or soup.find(id="content") or
            soup.find(id="main-content") or soup.find(class_="content") or
            soup.find(class_="post-content") or soup.find(class_="entry-content") or
            soup.find(class_="article-body"))
        text = (main_content or soup).get_text(separator='\n', strip=True)
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        text = '\n'.join(lines)
        if len(text) > max_chars:
            text = text[:max_chars] + f"\n\n... [обрезано, всего символов: {len(text)}]"
        return text
    except Exception as e:
        return f"[Ошибка при загрузке {url}: {type(e).__name__}: {e}]"

def format_search_results(results: List[Dict[str, str]]) -> str:
    """ Форматирует результаты поиска в читаемый текст """
    if not results:
        return "Результаты не найдены"
    parts = []
    for i, r in enumerate(results, 1):
        parts.append(f"--- Результат {i} ---")
        parts.append(f"Заголовок: {r.get('title', 'N/A')}")
        parts.append(f"URL: {r.get('href', 'N/A')}")
        parts.append(f"Домен: {r.get('domain', 'N/A')}")
        parts.append(f"Сниппет: {r.get('body', 'N/A')}")
        parts.append("")
    return "\n".join(parts)

# Bearer-token middleware
class JWTAuthMiddleware(BaseHTTPMiddleware):
    """ Проверяет JWT access_token, выданный oauth_server.py.
    Пропускает без проверки:
    - OPTIONS-запросы (CORS preflight)
    - GET /health 
    Все остальные запросы должны содержать:
      Authorization: Bearer <jwt_access_token>
    При ошибке возвращает 401 с заголовком:
      WWW-Authenticate: Bearer resource_metadata="/.well-known/oauth-authorization-server"
    Это сигнал клиенту (например MCP Inspector) начать OAuth-флоу """
    async def dispatch(self, request: Request, call_next):
        if request.method == "OPTIONS":
            return await call_next(request)
        if request.url.path in ("/health", "/mcp/health") \
            or request.url.path.startswith("/.well-known/") \
            or request.url.path == "/register":
            return await call_next(request)
        # Без OAUTH_SECRET_KEY, GUI-клиент подключается локально - пропускаем без JWT
        if (not OAUTH_SECRET_KEY) and request.client and request.client.host in ("127.0.0.1", "::1", "localhost"):
            return await call_next(request)
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"error": "Unauthorized", "detail": "Bearer JWT required"},
                headers={
                    "WWW-Authenticate": (
                        f'Bearer resource_metadata="{OAUTH_ISSUER[: OAUTH_ISSUER.rfind("/oauth")]}' 
                        f'/.well-known/oauth-authorization-server"')})
        token = auth_header[7:]
        if not OAUTH_SECRET_KEY:
            return JSONResponse(
                status_code=503,
                content={"error": "Server misconfigured", "detail": "OAUTH_SECRET_KEY not set"})
        try:
            jose_jwt.decode(
                token,
                OAUTH_SECRET_KEY,
                algorithms=[OAUTH_ALGORITHM],
                options={"verify_iss": False})
            payload = jose_jwt.get_unverified_claims(token)
            if payload.get("iss") != OAUTH_ISSUER:
                raise JWTError("Wrong issuer")
            if payload.get("type") != "access":
                raise JWTError("Not an access token")
        except JWTError as e:
            return JSONResponse(
                status_code=401,
                content={"error": "Unauthorized", "detail": f"Invalid JWT: {e}"},
                headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""})
        return await call_next(request)

# LIFESPAN
@asynccontextmanager
async def app_lifespan(server: FastMCP):
    """ Жизненный цикл MCP сервера """
    print(f"[{_name}] Сервер запускается...")
    yield {}
    print(f"[{_name}] Сервер останавливается...")

# MCP сервер
mcp = FastMCP(
    _name,
    instructions=(
        "MCP сервер для поиска ответов на вопросы по программированию в интернете. "
        "Предоставляет инструменты для поиска технической информации с приоритетом "
        "авторитетных источников: Stack Overflow, официальная документация языков "
        "и фреймворков, GitHub, проверенные технические блоги и учебные ресурсы. "
        "Инструменты предназначены ИСКЛЮЧИТЕЛЬНО для тем, связанных с "
        "программированием, разработкой ПО и компьютерными науками. "
    ),
    lifespan=app_lifespan,
    host=MCP_HOST,
    port=MCP_PORT,
    streamable_http_path=MCP_STREAM,
    stateless_http=True,
    json_response=True)

@mcp.resource("prog-search://trusted-sources")
def trusted_sources() -> str:
    """Список авторитетных источников для программирования с весами."""
    lines = ["Домен | Вес авторитетности", "--- | ---"]
    for domain, weight in sorted(DOMAIN_AUTHORITY.items(), key=lambda x: -x[1]):
        lines.append(f"{domain} | {weight}")
    return "\n".join(lines)

@mcp.prompt(title="answer_programming_question")
def answer_programming_question_prompt(question: str, search_results: str) -> str:
    """Генерирует промпт для ответа на вопрос по программированию."""
    return f'''Ты — опытный программист и технический эксперт. Ответь на вопрос
по программированию, используя приведённые ниже результаты поиска
из авторитетных источников.

Правила:
1. Ответ должен быть точным, конкретным и содержать примеры кода, если уместно.
2. Указывай источники (URL), из которых взята информация.
3. Если результаты противоречивы, укажи это и дай своё экспертное мнение.
4. Если информации недостаточно, так и скажи — не выдумывай.
5. Отвечай на том же языке, на котором задан вопрос.
6. Предпочитай современные подходы и практики.

Вопрос: {question}

Результаты поиска:
{search_results}
'''

@mcp.tool(name="search_programming_answers", annotations={"readOnlyHint": True})
async def search_programming_answers(
    ctx: Context,
    query: str = Field(
        ...,
        description=(
            "Вопрос по программированию на любом языке. "
            "Примеры: 'How to handle async exceptions in Python?', "
            "'React useEffect cleanup function example', "
            "'Разница между JOIN и LEFT JOIN в SQL', "
            "'How to implement binary search in C++?'"
        ),
        min_length=3,
    ),
    max_results: int = Field(
        default=5,
        description="Максимальное количество результатов поиска (от 1 до 10).",
        ge=1,
        le=10,
    ),
    time_range: str = Field(
        default="year",
        description=(
            "Временной диапазон: 'day', 'week', 'month', 'year' (рекомендуется), 'any'."
        ),
    ),
) -> CallToolResult:
    """Ищет ответы на вопросы по программированию в интернете."""
    timelimit_map = {
        "day": "d", "week": "w", "month": "m", "year": "y", "any": None,}
    timelimit = timelimit_map.get(time_range.lower(), "y")
    try:
        results = await perform_search(
            query=query, max_results=max_results, timelimit=timelimit,)
        if not results:
            return CallToolResult(
                content=[TextContent(
                    type="text",
                    text=(
                        f"По запросу «{query}» не найдено результатов. "
                        "Попробуйте переформулировать вопрос, использовать "
                        "английский язык или расширить временной диапазон."))],
                _meta={"query": query, "results_count": 0})
        formatted = format_search_results(results)
        # Встраиваем JSON с данными в конец текста - GUI его распарсит,
        # а LLM-клиент просто увидит читаемый текст + JSON-блок
        payload = json.dumps({
            "status": "success",
            "query": query,
            "time_range": time_range,
            "results_count": len(results),
            "results": results}, ensure_ascii=False)
        full_text = f"{formatted}\n\n__JSON_PAYLOAD__\n{payload}"
        return CallToolResult(
            content=[TextContent(type="text", text=full_text)],
            _meta={
                "query": query,
                "results_count": len(results),
                "sources": [r.get("domain") for r in results]})
    except Exception as e:
        logging.error(f"Ошибка в search_programming_answers: {e}")
        return CallToolResult(
            content=[TextContent(
                type="text",
                text=f"Произошла ошибка при поиске: {type(e).__name__}: {e}")],
            _meta={"status": "error", "error": str(e)})

@mcp.tool(name="fetch_webpage_content", annotations={"readOnlyHint": True})
async def fetch_webpage_content(
    ctx: Context,
    url: str = Field(
        ...,
        description=(
            "URL веб-страницы для загрузки текстового содержимого. "
            "Пример: 'https://stackoverflow.com/questions/12345/...'"
        ),
    ),
    max_chars: int = Field(
        default=15000,
        description="Максимальное количество символов (от 1000 до 50000).",
        ge=1000,
        le=50000,
    ),
) -> CallToolResult:
    """Загружает и извлекает текстовое содержимое веб-страницы."""
    if not url.startswith(("http://", "https://")):
        return CallToolResult(
            content=[TextContent(
                type="text",
                text=f"Некорректный URL: {url}. URL должен начинаться с http:// или https://")],
            _meta={"status": "error", "reason": "invalid_url"},)
    try:
        text = await fetch_page_text(url, max_chars=max_chars)
        return CallToolResult(
            content=[TextContent(type="text", text=text)],
            _meta={"url": url, "chars": len(text)})
    except Exception as e:
        logging.error(f"Ошибка в fetch_webpage_content: {e}")
        return CallToolResult(
            content=[TextContent(
                type="text",
                text=f"Ошибка при загрузке страницы: {type(e).__name__}: {e}"
            )],
            _meta={"status": "error", "error": str(e)},)

# GUI тестировщик
class MCPTestGUIClient:
    """ Тестовый GUI-клиент """
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{_name} ({MCP_PROTOCOL}{MCP_HOST}:{MCP_PORT}{MCP_STREAM}) & Test Client")
        self.chars_var = tk.StringVar(value="Chars: 0")
        self.status_var = tk.StringVar(value="Ready")
        self.setup_ui()

    def setup_ui(self):
        main = ttk.Frame(self.root, padding=10)
        main.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        search_frame = ttk.LabelFrame(main, text="Search Programming Answers", padding=5)
        search_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        ttk.Label(search_frame, text="Query:").grid(row=0, column=0, sticky="w")
        self.query_ent = ttk.Entry(search_frame, width=70)
        self.query_ent.insert(0, GUI_QUERY_DEFAULT)
        self.query_ent.grid(row=0, column=1, padx=(5, 0), sticky="ew")
        params_row = ttk.Frame(search_frame)
        params_row.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(5, 0))
        ttk.Label(params_row, text="Max results:").grid(row=0, column=0, sticky="w")
        self.max_results_ent = ttk.Entry(params_row, width=5)
        self.max_results_ent.insert(0, "5")
        self.max_results_ent.grid(row=0, column=1, sticky="w", padx=(5, 0))
        ttk.Label(params_row, text="Time range:").grid(row=0, column=2, sticky="w", padx=(15, 0))
        self.time_range_var = tk.StringVar(value="year")
        time_combo = ttk.Combobox(params_row, textvariable=self.time_range_var, values=["day", "week", "month", "year", "any"], width=8, state="readonly")
        time_combo.grid(row=0, column=3, sticky="w", padx=(5, 0))
        btn_row = ttk.Frame(search_frame)
        btn_row.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(5, 0))
        ttk.Button(btn_row, text="Search", command=self.search_cmd).grid(row=0, column=0, sticky="ew", padx=2)
        ttk.Button(btn_row, text="Search & Fetch Top Result", command=self.search_and_fetch_cmd).grid(row=0, column=1, sticky="ew", padx=2)
        search_frame.columnconfigure(1, weight=1)

        fetch_frame = ttk.LabelFrame(main, text="Fetch Webpage Content", padding=5)
        fetch_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        ttk.Label(fetch_frame, text="URL:").grid(row=0, column=0, sticky="w")
        self.url_ent = ttk.Entry(fetch_frame, width=70)
        self.url_ent.grid(row=0, column=1, padx=(5, 0), sticky="ew")
        ttk.Button(fetch_frame, text="Fetch Page", command=self.fetch_cmd).grid(row=0, column=2, padx=(5, 0))
        fetch_frame.columnconfigure(1, weight=1)

        extra_frame = ttk.Frame(main)
        extra_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        ttk.Button(extra_frame, text="List Tools", command=self.list_tools_cmd).grid(row=0, column=0, sticky="ew", padx=2, pady=2)
        ttk.Button(extra_frame, text="MCP Session Info", command=self.get_mcp_info_cmd).grid(row=0, column=1, sticky="ew", padx=2, pady=2)
        ttk.Button(extra_frame, text="Trusted Sources", command=self.get_trusted_sources_cmd).grid(row=0, column=2, sticky="ew", padx=2, pady=2)
        ttk.Button(extra_frame, text="Prompt Sample", command=self.get_prompt_cmd).grid(row=0, column=3, sticky="ew", padx=2, pady=2)

        status_frame = ttk.Frame(main)
        status_frame.grid(row=3, column=0, columnspan=2, sticky="ew")
        ttk.Label(status_frame, textvariable=self.status_var, foreground="gray").grid(row=0, column=0, sticky="w")
        ttk.Label(status_frame, textvariable=self.chars_var).grid(row=0, column=1, sticky="e")
        self.out = scrolledtext.ScrolledText(main, wrap=tk.WORD, width=90, height=30)
        self.out.grid(row=4, column=0, columnspan=2, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=1)
        main.rowconfigure(4, weight=1)
        self._setup_clipboard_bindings()

    def _setup_clipboard_bindings(self):
        """ Настраивает копипаст для всех виджетов ввода """
        def make_copy(widget):
            def _copy(event=None):
                try:
                    if isinstance(widget, (tk.Entry, ttk.Entry)):
                        if widget.selection_present(): text = widget.selection_get()
                        else: return "break"
                    else: text = widget.get("sel.first", "sel.last")
                    widget.clipboard_clear(); widget.clipboard_append(text)
                except tk.TclError: pass
                return "break"
            return _copy

        def make_cut(widget):
            def _cut(event=None):
                try:
                    if isinstance(widget, (tk.Entry, ttk.Entry)):
                        if widget.selection_present():
                            text = widget.selection_get()
                            widget.clipboard_clear(); widget.clipboard_append(text); widget.delete("sel.first", "sel.last")
                    else:
                        text = widget.get("sel.first", "sel.last")
                        widget.clipboard_clear(); widget.clipboard_append(text); widget.delete("sel.first", "sel.last")
                except tk.TclError: pass
                return "break"
            return _cut

        def make_paste(widget):
            def _paste(event=None):
                try:
                    text = widget.clipboard_get()
                    if isinstance(widget, (tk.Entry, ttk.Entry)):
                        try: widget.delete("sel.first", "sel.last")
                        except tk.TclError: pass
                        widget.insert(tk.INSERT, text)
                    else:
                        try: widget.delete("sel.first", "sel.last")
                        except tk.TclError: pass
                        widget.insert(tk.INSERT, text)
                except tk.TclError: pass
                return "break"
            return _paste

        def make_select_all(widget):
            def _select_all(event=None):
                try:
                    if isinstance(widget, (tk.Entry, ttk.Entry)): widget.select_range(0, tk.END); widget.icursor(tk.END)
                    else: widget.tag_add(tk.SEL, "1.0", tk.END); widget.mark_set(tk.INSERT, tk.END)
                except tk.TclError: pass
                return "break"
            return _select_all

        editable_widgets = [self.query_ent, self.url_ent, self.max_results_ent, self.out]
        for w in editable_widgets:
            for key in ("<Control-c>", "<Control-C>"): w.bind(key, make_copy(w))
            for key in ("<Control-x>", "<Control-X>"): w.bind(key, make_cut(w))
            for key in ("<Control-v>", "<Control-V>"): w.bind(key, make_paste(w))
            for key in ("<Control-a>", "<Control-A>"): w.bind(key, make_select_all(w))
    
    def run_async_task(self, coro, callback=None):
        def run_in_thread():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(coro)
                if callback: self.root.after(0, callback, result)
            except Exception as e: self.root.after(0, self._show_error, str(e))
            finally: loop.close()
        thread = threading.Thread(target=run_in_thread, daemon=True)
        thread.start()

    def _show_error(self, msg: str):
        self.out.delete("1.0", tk.END); self.out.insert(tk.END, f"Error: {msg}\n"); self.status_var.set("Error")

    def _show_result(self, title: str, result: Any):
        try:
            text = result if isinstance(result, str) else json.dumps(result, indent=2, ensure_ascii=False)
            self.out.delete("1.0", tk.END); self.out.insert(tk.END, f"=== {title} ===\n\n{text}")
            self.chars_var.set(f"Chars: {len(text)}"); self.status_var.set("Done")
        except Exception as e: self._show_error(str(e))

    async def _call_mcp_tool(self, tool_name: str, arguments: dict) -> Any:
        async with streamable_http_client(GUI_MCP_BASE) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return await session.call_tool(tool_name, arguments)

    def search_cmd(self):
        query = self.query_ent.get().strip()
        if not query: messagebox.showerror("Error", "Enter a search query"); return
        max_results = int(self.max_results_ent.get().strip() or "5")
        time_range = self.time_range_var.get()
        self.out.delete("1.0", tk.END); self.out.insert(tk.END, "Searching..."); self.status_var.set("Searching..."); self.root.update_idletasks()
        async def task():
            result = await self._call_mcp_tool("search_programming_answers", {"query": query, "max_results": max_results, "time_range": time_range})
            text = result.content[0].text if result.content else "No data"
            if "__JSON_PAYLOAD__\n" in text:
                parts = text.split("__JSON_PAYLOAD__\n", 1)
                try: return json.loads(parts[1])
                except Exception: pass
            return text
        self.run_async_task(task(), lambda r: self._show_result("Search Results", r))

    def search_and_fetch_cmd(self):
        query = self.query_ent.get().strip()
        if not query: messagebox.showerror("Error", "Enter a search query"); return
        max_results = int(self.max_results_ent.get().strip() or "5")
        time_range = self.time_range_var.get()
        self.out.delete("1.0", tk.END); self.out.insert(tk.END, "Searching & fetching top result..."); self.status_var.set("Searching..."); self.root.update_idletasks()
        async def task():
            parts = []
            result = await self._call_mcp_tool("search_programming_answers", {"query": query, "max_results": max_results, "time_range": time_range})
            text = result.content[0].text if result.content else ""
            search_results = []
            if "__JSON_PAYLOAD__\n" in text:
                raw_text, payload_str = text.split("__JSON_PAYLOAD__\n", 1)
                try: payload = json.loads(payload_str); search_results = payload.get("results", [])
                except Exception: pass
                parts.append("=== SEARCH RESULTS ===\n"); parts.append(raw_text.strip())
            else: return text
            if search_results:
                top_url = search_results[0].get("href", "")
                if top_url:
                    parts.append(f"\n=== FETCHING TOP RESULT: {top_url} ===\n")
                    fetch_result = await self._call_mcp_tool("fetch_webpage_content", {"url": top_url, "max_chars": 30000})
                    if fetch_result.content: parts.append(fetch_result.content[0].text)
            return "\n".join(parts)
        self.run_async_task(task(), lambda r: self._show_result("Search + Fetch", r))

    def fetch_cmd(self):
        url = self.url_ent.get().strip()
        if not url: messagebox.showerror("Error", "Enter a URL"); return
        self.out.delete("1.0", tk.END); self.out.insert(tk.END, "Fetching page..."); self.status_var.set("Fetching..."); self.root.update_idletasks()
        async def task():
            result = await self._call_mcp_tool("fetch_webpage_content", {"url": url, "max_chars": 15000})
            return result.content[0].text if result.content else "No data"
        self.run_async_task(task(), lambda r: self._show_result("Page Content", r))

    def list_tools_cmd(self):
        async def task():
            async with streamable_http_client(GUI_MCP_BASE) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    return [{"name": t.name, "description": t.description} for t in tools.tools]
        self.run_async_task(task(), lambda r: self._show_result("Tools", r))

    def get_mcp_info_cmd(self):
        async def task():
            async with streamable_http_client(GUI_MCP_BASE) as (read, write, _):
                async with ClientSession(read, write) as session:
                    result = await session.initialize()
                    return json.dumps(result.model_dump(), indent=2, ensure_ascii=False)
        self.run_async_task(task(), lambda r: self._show_result("MCP Session Info", r))

    def get_trusted_sources_cmd(self):
        async def task():
            async with streamable_http_client(GUI_MCP_BASE) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    resources = await session.list_resources()
                    if resources.resources:
                        rc = await session.read_resource(resources.resources[0].uri)
                        if rc.contents and isinstance(rc.contents[0], TextResourceContents): return rc.contents[0].text
                    return "No resources found"
        self.run_async_task(task(), lambda r: self._show_result("Trusted Sources", r))

    def get_prompt_cmd(self):
        async def task():
            async with streamable_http_client(GUI_MCP_BASE) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    prompts = await session.list_prompts()
                    if prompts.prompts:
                        pc = await session.get_prompt(prompts.prompts[0].name, arguments={"question": "How to parse JSON in Python?", "search_results": "Stack Overflow: use json.loads()"})
                        if pc.messages:
                            content = pc.messages[0].content
                            if hasattr(content, "text"): return content.text
                            return str(content)
                    return "No prompts found"
        self.run_async_task(task(), lambda r: self._show_result("Prompt Sample", r))

# Запуск
def run_mcp_server():
    """ Запуск MCP сервера в отдельном потоке """
    oauth_base = OAUTH_ISSUER.rsplit("/oauth", 1)[0]

    async def well_known_oauth(request):
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{oauth_base}/.well-known/oauth-authorization-server")
        return JSONResponse(resp.json())

    async def well_known_openid(request):
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{oauth_base}/.well-known/oauth-authorization-server")
        return JSONResponse(resp.json())

    async def register_endpoint(request):
        body = await request.json()
        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{OAUTH_ISSUER}/register", json=body)
        return JSONResponse(resp.json(), status_code=resp.status_code)

    async def run_with_auth():
        starlette_app = mcp.streamable_http_app()
        starlette_app.routes.insert(0, Route("/.well-known/oauth-authorization-server", well_known_oauth))
        starlette_app.routes.insert(0, Route("/.well-known/openid-configuration", well_known_openid))
        starlette_app.routes.insert(0, Route("/register", register_endpoint, methods=["POST"]))
        starlette_app.routes.insert(0, Route("/.well-known/oauth-protected-resource", protected_resource))
        starlette_app.routes.insert(0, Route("/.well-known/oauth-protected-resource/mcp", protected_resource))
        starlette_app.add_middleware(JWTAuthMiddleware)
        starlette_app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_methods=["*"],
            allow_headers=["*"],
            expose_headers=["*"])
        config = uvicorn.Config(
            starlette_app,
            host=mcp.settings.host,
            port=mcp.settings.port,
            log_level=mcp.settings.log_level.lower())
        server = uvicorn.Server(config)
        await server.serve()

    async def protected_resource(request):
        return JSONResponse({
            "resource": f"http://127.0.0.1:{mcp.settings.port}/mcp",
            "authorization_servers": [OAUTH_ISSUER.rsplit("/oauth", 1)[0]],
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["mcp"]})

    anyio.run(run_with_auth)

def run_gui():
    root = tk.Tk()
    root.geometry("1100x750")
    MCPTestGUIClient(root)
    root.mainloop()

if __name__ == "__main__":
    server_thread = threading.Thread(target=run_mcp_server, daemon=True)
    server_thread.start()
    time.sleep(2)
    run_gui()