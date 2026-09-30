#!/usr/bin/env python3
# SourceHub backend: standard-library only.
# Works in Pydroid 3 without FastAPI/Uvicorn/python-telegram-bot.

import os
import re
import json
import time
import uuid
import hmac
import shutil
import hashlib
import secrets
import sqlite3
import threading
import mimetypes
from pathlib import Path
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from urllib.request import Request as UrlRequest, urlopen
from urllib.error import HTTPError, URLError

BASE = Path(__file__).resolve().parent
DB_PATH = BASE / "sourcehub.sqlite3"
UPLOADS = BASE / "uploads"
UPLOADS.mkdir(exist_ok=True)

HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8080"))
ADMIN_UID = "b4174ad4-6dd0-47ff-8e38-2d0a7986a3e0"
RESERVED_USERNAME = "bogMurphy"
# Pydroid config: no environment variables are required.
CONFIG_FILE = BASE / "pydroid_config.json"
SECRET_FILE = BASE / "sourcehub_secret.txt"

def load_bot_config():
    token = ""
    username = ""
    if CONFIG_FILE.exists():
        try:
            data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            token = str(data.get("bot_token", "")).strip()
            username = str(data.get("bot_username", "")).strip().lstrip("@")
        except Exception:
            pass
    if not token:
        try:
            import config as _config
            token = str(getattr(_config, "BOT_TOKEN", "")).strip()
            username = str(getattr(_config, "BOT_USERNAME", username)).strip().lstrip("@")
        except Exception:
            pass
    return token, username

BOT_TOKEN, BOT_USERNAME = load_bot_config()

def load_server_secret():
    # Stable across restarts. The previous build generated a new secret on
    # every launch, which made existing permanent Telegram codes unverifiable.
    try:
        if SECRET_FILE.exists():
            value = SECRET_FILE.read_text(encoding="utf-8").strip()
            if len(value) >= 32:
                return value
        value = secrets.token_hex(32)
        SECRET_FILE.write_text(value, encoding="utf-8")
        return value
    except Exception:
        # Last-resort process secret; normal Pydroid installs use SECRET_FILE.
        return secrets.token_hex(32)

CORS_ORIGINS = [x.strip() for x in os.getenv("CORS_ORIGINS", "*").split(",") if x.strip()]
SERVER_SECRET = os.getenv("SOURCEHUB_SECRET", "").strip() or load_server_secret()
MAX_ZIP = 100 * 1024 * 1024
MAX_IMAGE = 10 * 1024 * 1024

print("SourceHub Pydroid backend")
print(f"Listening: http://{HOST}:{PORT}")

def setup_bot_if_needed():
    global BOT_TOKEN, BOT_USERNAME
    if not BOT_TOKEN:
        print("Telegram bot token is not configured.")
        print("Paste the NEW token from @BotFather and press Enter.")
        try:
            BOT_TOKEN = input("BOT TOKEN: ").strip()
        except (EOFError, KeyboardInterrupt):
            BOT_TOKEN = ""
        if BOT_TOKEN:
            try:
                CONFIG_FILE.write_text(json.dumps({"bot_token": BOT_TOKEN, "bot_username": BOT_USERNAME}, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception as e:
                print("Cannot save local config:", e)
    if BOT_TOKEN and not BOT_USERNAME:
        try:
            result = tg_call("getMe", {})
            if result.get("ok"):
                BOT_USERNAME = str(result["result"].get("username", "")).strip().lstrip("@")
                CONFIG_FILE.write_text(json.dumps({"bot_token": BOT_TOKEN, "bot_username": BOT_USERNAME}, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as e:
            print("Telegram connection failed:", e)


def now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.isoformat()


def db():
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    con = db()
    con.executescript("""
    PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      telegram_id TEXT UNIQUE NOT NULL,
      telegram_username TEXT DEFAULT '',
      username TEXT UNIQUE NOT NULL,
      bio TEXT NOT NULL DEFAULT 'Автор SourceHub',
      telegram TEXT NOT NULL DEFAULT '',
      avatar_path TEXT,
      badge TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS auth_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      telegram_id TEXT NOT NULL,
      code_hash TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_auth_codes_hash ON auth_codes(code_hash, used, expires_at);
    -- Permanent one-code-per-Telegram mapping. The same Telegram account always gets the same code.
    CREATE TABLE IF NOT EXISTS telegram_auth (
      telegram_id TEXT PRIMARY KEY,
      code TEXT NOT NULL UNIQUE,
      code_hash TEXT NOT NULL UNIQUE,
      telegram_username TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sources (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      title TEXT NOT NULL,
      game TEXT NOT NULL,
      version TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      author TEXT NOT NULL,
      file_name TEXT NOT NULL,
      file_size INTEGER NOT NULL,
      zip_path TEXT NOT NULL,
      image_path TEXT,
      likes INTEGER NOT NULL DEFAULT 0,
      downloads INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS likes (
      user_id TEXT NOT NULL,
      source_id TEXT NOT NULL,
      PRIMARY KEY(user_id, source_id)
    );
    """)
    # Migrate older databases created before avatars/badges/moderation.
    for stmt in (
        "ALTER TABLE users ADD COLUMN avatar_path TEXT",
        "ALTER TABLE users ADD COLUMN badge TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE sources ADD COLUMN status TEXT NOT NULL DEFAULT 'approved'",
        "ALTER TABLE sources ADD COLUMN moderation_note TEXT NOT NULL DEFAULT ''"
    ):
        try:
            con.execute(stmt)
        except sqlite3.OperationalError:
            pass
    # Repair hashes created by older builds. Those builds stored the permanent
    # 6-digit code but used a random process secret, so a restart broke login.
    # The code itself is retained locally in telegram_auth; rebuild only hashes.
    rows = con.execute("SELECT telegram_id, code FROM telegram_auth").fetchall()
    for row in rows:
        stable_hash = hmac.new(SERVER_SECRET.encode(), str(row["code"]).encode(), hashlib.sha256).hexdigest()
        con.execute("UPDATE telegram_auth SET code_hash=? WHERE telegram_id=?",
                    (stable_hash, str(row["telegram_id"])))
    con.commit()
    con.close()


def sha256(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def code_hash(code):
    return hmac.new(SERVER_SECRET.encode(), code.encode(), hashlib.sha256).hexdigest()


def json_bytes(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def make_session(user_id):
    token = secrets.token_urlsafe(48)
    con = db()
    con.execute("DELETE FROM sessions WHERE expires_at < ?", (iso(now()),))
    con.execute("INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)",
                (sha256(token), user_id, iso(now() + timedelta(days=365)), iso(now())))
    con.commit()
    con.close()
    return token


def auth_user(handler):
    value = handler.headers.get("Authorization", "")
    if not value.lower().startswith("bearer "):
        return None
    token = value.split(" ", 1)[1].strip()
    if not token:
        return None
    con = db()
    row = con.execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?",
                      (sha256(token), iso(now()))).fetchone()
    con.close()
    return row


def is_admin(user):
    return bool(user and str(user["id"]) == ADMIN_UID)

def normalize_username(name):
    return str(name or "").strip().lstrip("@").strip()

def valid_username(name):
    # Latin/Cyrillic nicknames, spaces, digits, underscore and hyphen.
    return bool(re.fullmatch(r"[A-Za-zА-Яа-яЁё0-9_ -]{3,30}", name))

def badge_json(user):
    return str(user["badge"] or "") if user else ""

def clean_name(name, fallback):
    name = os.path.basename(name or fallback)
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return name[:100] or fallback


def source_json(row):
    created = datetime.fromisoformat(row["created_at"]).timestamp() * 1000
    return {
        "id": row["id"], "userId": row["user_id"], "title": row["title"],
        "game": row["game"], "version": row["version"], "description": row["description"],
        "author": row["author"], "authorBadge": row["author_badge"] if "author_badge" in row.keys() else "", "fileName": row["file_name"], "size": row["file_size"],
        "zipPath": row["zip_path"], "zipUrl": f"/api/sources/{row['id']}/download",
        "image": f"/uploads/{row['image_path']}" if row["image_path"] else "",
        "likes": row["likes"], "downloads": row["downloads"], "created": int(created),
        "status": row["status"] if "status" in row.keys() else "approved"
    }


def telegram_api(method, payload=None, timeout=65):
    if not BOT_TOKEN:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is not configured")
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/{method}"
    data = json_bytes(payload or {})
    req = UrlRequest(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def issue_code(tg_user):
    """Return one permanent 6-digit code for this Telegram account.

    /start never rotates the code. A Telegram ID is mapped to exactly one
    code, and a code is globally unique across SourceHub accounts.
    """
    tg_id = str(tg_user["id"])
    tg_username = str(tg_user.get("username", "") or "")
    con = db()
    row = con.execute(
        "SELECT code FROM telegram_auth WHERE telegram_id=?", (tg_id,)
    ).fetchone()
    if row:
        con.execute(
            "UPDATE telegram_auth SET telegram_username=? WHERE telegram_id=?",
            (tg_username, tg_id)
        )
        con.execute(
            "UPDATE users SET telegram_username=? WHERE telegram_id=?",
            (tg_username, tg_id)
        )
        con.commit()
        con.close()
        return row["code"]

    # Generate until the six-digit code is unique globally.
    while True:
        code = f"{secrets.randbelow(1_000_000):06d}"
        if not con.execute("SELECT 1 FROM telegram_auth WHERE code=?", (code,)).fetchone():
            break

    con.execute(
        "INSERT INTO telegram_auth(telegram_id,code,code_hash,telegram_username,created_at) VALUES(?,?,?,?,?)",
        (tg_id, code, code_hash(code), tg_username, iso(now()))
    )
    con.execute(
        "UPDATE users SET telegram_username=? WHERE telegram_id=?",
        (tg_username, tg_id)
    )
    con.commit()
    con.close()
    return code


def telegram_loop():
    if not BOT_TOKEN:
        return
    offset = 0
    while True:
        try:
            result = telegram_api("getUpdates", {"timeout": 50, "offset": offset}, timeout=65)
            if not result.get("ok"):
                time.sleep(3)
                continue
            for update in result.get("result", []):
                offset = max(offset, int(update["update_id"]) + 1)
                msg = update.get("message") or {}
                text = (msg.get("text") or "").strip()
                user = msg.get("from") or {}
                chat = msg.get("chat") or {}
                if not user or not chat:
                    continue
                if text.startswith("/start"):
                    code = issue_code(user)
                    reply = ("SourceHub\n\nТвой постоянный код аккаунта:\n\n"
                             f"{code}\n\nЭтот 6-значный код навсегда привязан к этому Telegram-аккаунту.\n"
                             "Используй его для входа на сайте SourceHub. Не передавай код другим людям.")
                    telegram_api("sendMessage", {"chat_id": chat["id"], "text": reply}, timeout=15)
                elif text.startswith("/help"):
                    telegram_api("sendMessage", {"chat_id": chat["id"],
                                                  "text": "Для входа в SourceHub отправь /start. Бот покажет твой постоянный 6-значный код, привязанный к этому Telegram-аккаунту."}, timeout=15)
        except (HTTPError, URLError, TimeoutError, OSError, RuntimeError, ValueError) as exc:
            print("Telegram polling error:", exc)
            time.sleep(4)
        except Exception as exc:
            print("Telegram error:", exc)
            time.sleep(4)


# Minimal multipart/form-data parser. It stores each part in memory; the ZIP is capped at 100 MB.
def parse_multipart(handler, body):
    ctype = handler.headers.get("Content-Type", "")
    m = re.search(r'boundary=(?:"([^"]+)"|([^;]+))', ctype, re.I)
    if not m:
        raise ValueError("multipart boundary missing")
    boundary = (m.group(1) or m.group(2)).encode("utf-8")
    delimiter = b"--" + boundary
    fields = {}
    files = {}
    for chunk in body.split(delimiter)[1:]:
        if chunk.startswith(b"--"):
            break
        chunk = chunk.lstrip(b"\r\n")
        if not chunk:
            continue
        head, sep, data = chunk.partition(b"\r\n\r\n")
        if not sep:
            continue
        data = data.rstrip(b"\r\n")
        headers = {}
        for line in head.decode("utf-8", "replace").split("\r\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.lower().strip()] = v.strip()
        cd = headers.get("content-disposition", "")
        nm = re.search(r'name="([^"]+)"', cd)
        if not nm:
            continue
        name = nm.group(1)
        fm = re.search(r'filename="([^"]*)"', cd)
        if fm:
            files[name] = {"filename": fm.group(1), "content": data, "content_type": headers.get("content-type", "")}
        else:
            fields[name] = data.decode("utf-8", "replace")
    return fields, files


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print(f"[{self.address_string()}] {fmt % args}")

    def cors_origin(self):
        origin = self.headers.get("Origin")
        if "*" in CORS_ORIGINS:
            return "*"
        if origin in CORS_ORIGINS:
            return origin
        return CORS_ORIGINS[0] if CORS_ORIGINS else "*"

    def send_json(self, status, obj):
        data = json_bytes(obj)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", self.cors_origin())
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def error(self, status, message):
        self.send_json(status, {"detail": message})

    def read_body(self, max_bytes=None):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("Invalid Content-Length")
        if max_bytes is not None and length > max_bytes:
            raise OverflowError("request too large")
        return self.rfile.read(length)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", self.cors_origin())
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
        self.send_header("Access-Control-Max-Age", "86400")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        try:
            if path == "/health":
                return self.send_json(200, {"ok": True, "telegram_bot": bool(BOT_TOKEN), "service": "SourceHub", "backend": "stdlib"})
            if path == "/api/config":
                return self.send_json(200, {"botUsername": BOT_USERNAME, "registration": bool(BOT_TOKEN), "backend": "pydroid-stdlib"})
            if path == "/api/sources":
                con = db()
                rows = con.execute("SELECT s.*, COALESCE(u.badge,'') AS author_badge FROM sources s LEFT JOIN users u ON u.id=s.user_id WHERE COALESCE(s.status,'approved')='approved' ORDER BY s.created_at DESC LIMIT 500").fetchall()
                con.close()
                return self.send_json(200, [source_json(r) for r in rows])
            if path == "/api/profile/me":
                user = auth_user(self)
                if not user: return self.error(401, "Не авторизован")
                return self.send_json(200, {"id": user["id"], "username": user["username"], "bio": user["bio"], "telegram": user["telegram"], "avatar": f"/uploads/{user["avatar_path"]}" if user["avatar_path"] else "", "badge": user["badge"] or "", "admin": is_admin(user)})
            m = re.fullmatch(r"/api/sources/([^/]+)/download", path)
            if m:
                return self.download_source(m.group(1))
            if path == "/":
                return self.serve_file(BASE / "index.html", "text/html; charset=utf-8")
            if path.startswith("/uploads/"):
                rel = path[len("/uploads/"):]
                target = (UPLOADS / rel).resolve()
                if not str(target).startswith(str(UPLOADS.resolve()) + os.sep):
                    return self.error(403, "Forbidden")
                if not target.is_file(): return self.error(404, "Файл не найден")
                return self.serve_file(target, mimetypes.guess_type(str(target))[0] or "application/octet-stream")
            return self.error(404, "Не найдено")
        except Exception as exc:
            print("GET error:", exc)
            return self.error(500, "Ошибка сервера")

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            if path == "/api/auth/verify":
                return self.verify_auth()
            if path == "/api/profile/avatar":
                return self.upload_avatar()
            if path == "/api/auth/logout":
                value = self.headers.get("Authorization", "")
                if value.lower().startswith("bearer "):
                    con = db(); con.execute("DELETE FROM sessions WHERE token_hash=?", (sha256(value.split(" ",1)[1].strip()),)); con.commit(); con.close()
                return self.send_json(200, {"ok": True})
            if path == "/api/sources":
                return self.create_source()
            if path == "/api/admin/moderation":
                return self.admin_moderation()
            m = re.fullmatch(r"/api/admin/sources/([^/]+)/moderate", path)
            if m:
                return self.admin_moderate_source(m.group(1))
            m = re.fullmatch(r"/api/admin/users/([^/]+)/badge", path)
            if m:
                return self.admin_set_badge(m.group(1))
            m = re.fullmatch(r"/api/sources/([^/]+)/like", path)
            if m:
                return self.like_source(m.group(1))
            return self.error(404, "Не найдено")
        except OverflowError:
            return self.error(413, "Файл слишком большой")
        except ValueError as exc:
            return self.error(400, str(exc))
        except Exception as exc:
            print("POST error:", exc)
            return self.error(500, "Ошибка сервера")

    def do_PATCH(self):
        if urlparse(self.path).path != "/api/profile":
            return self.error(404, "Не найдено")
        try:
            user = auth_user(self)
            if not user: return self.error(401, "Не авторизован")
            body = json.loads(self.read_body(256 * 1024).decode("utf-8"))
            username = normalize_username(body.get("username", ""))
            bio = str(body.get("bio", "Автор SourceHub"))[:500]
            telegram = str(body.get("telegram", ""))[:100]
            if not valid_username(username):
                return self.error(400, "Ник: 3–30 символов, 3–30 знаков. Разрешены русские/латинские буквы, цифры, пробел, _ и -.")
            if username.lower() == RESERVED_USERNAME.lower() and user["id"] != ADMIN_UID:
                return self.error(403, "Этот ник зарезервирован.")
            con = db()
            dup = con.execute("SELECT 1 FROM users WHERE lower(username)=lower(?) AND id<>?", (username, user["id"])).fetchone()
            if dup:
                con.close(); return self.error(409, "Этот ник уже занят.")
            con.execute("UPDATE users SET username=?,bio=?,telegram=? WHERE id=?", (username,bio,telegram,user["id"]))
            con.commit(); con.close()
            return self.send_json(200, {"id": user["id"], "username": username, "bio": bio, "telegram": telegram})
        except Exception as exc:
            print("PATCH error:", exc)
            return self.error(400, "Некорректные данные")

    def do_DELETE(self):
        path = urlparse(self.path).path
        m = re.fullmatch(r"/api/sources/([^/]+)", path)
        if not m: return self.error(404, "Не найдено")
        try:
            user = auth_user(self)
            if not user: return self.error(401, "Не авторизован")
            sid = m.group(1)
            con = db(); row = con.execute("SELECT * FROM sources WHERE id=?", (sid,)).fetchone()
            if not row:
                con.close(); return self.error(404, "Сорс не найден")
            if row["user_id"] != user["id"]:
                con.close(); return self.error(403, "Нет доступа")
            con.execute("DELETE FROM likes WHERE source_id=?", (sid,))
            con.execute("DELETE FROM sources WHERE id=?", (sid,))
            con.commit(); con.close()
            shutil.rmtree(UPLOADS / sid, ignore_errors=True)
            return self.send_json(200, {"ok": True})
        except Exception as exc:
            print("DELETE error:", exc)
            return self.error(500, "Ошибка сервера")

    def verify_auth(self):
        try:
            body = json.loads(self.read_body(32 * 1024).decode("utf-8"))
        except Exception:
            return self.error(400, "Некорректный JSON")
        code = str(body.get("code", "")).strip()
        username = normalize_username(body.get("username", "") or "")
        mode = str(body.get("mode", "login"))
        if not re.fullmatch(r"\d{6}", code):
            return self.error(400, "Код должен содержать 6 цифр.")
        if mode not in ("login", "register"):
            return self.error(400, "Некорректный режим.")
        con = db()
        # Permanent mapping: the same six-digit code can be used again for the
        # same Telegram account and never changes after /start.
        # Primary lookup uses the stable hash. Fallback to the stored permanent
        # code keeps accounts created by older builds working after migration.
        row = con.execute(
            "SELECT telegram_id, code FROM telegram_auth WHERE code_hash=? LIMIT 1",
            (code_hash(code),)
        ).fetchone()
        if not row:
            row = con.execute(
                "SELECT telegram_id, code FROM telegram_auth WHERE code=? LIMIT 1",
                (code,)
            ).fetchone()
            if row:
                con.execute("UPDATE telegram_auth SET code_hash=? WHERE telegram_id=?",
                            (code_hash(code), row["telegram_id"]))
        if not row:
            con.close(); return self.error(401, "Неверный 6-значный код.")
        tg_id = row["telegram_id"]
        user = con.execute("SELECT * FROM users WHERE telegram_id=?", (tg_id,)).fetchone()
        if user is None:
            if mode != "register":
                con.rollback(); con.close(); return self.error(404, "Аккаунт не найден. Выбери регистрацию.")
            if not valid_username(username):
                con.rollback(); con.close(); return self.error(400, "Ник: 3–30 символов. Разрешены русские/латинские буквы, цифры, пробел, _ и -.")
            if username.lower() == RESERVED_USERNAME.lower():
                con.rollback(); con.close(); return self.error(403, "Этот ник зарезервирован для администратора.")
            if con.execute("SELECT 1 FROM users WHERE lower(username)=lower(?)", (username,)).fetchone():
                con.rollback(); con.close(); return self.error(409, "Этот ник уже занят.")
            uid = str(uuid.uuid4())
            tg_name = con.execute("SELECT telegram_username FROM telegram_auth WHERE telegram_id=?", (tg_id,)).fetchone()
            tg_username = str(tg_name["telegram_username"] if tg_name else "")
            con.execute("INSERT INTO users(id,telegram_id,telegram_username,username,created_at) VALUES(?,?,?,?,?)",
                        (uid,tg_id,tg_username,username,iso(now())))
            user = con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        elif mode == "register":
            con.rollback(); con.close(); return self.error(409, "Этот Telegram уже привязан к аккаунту.")
        con.commit(); con.close()
        token = make_session(user["id"])
        return self.send_json(200, {"token": token, "user": {"id": user["id"], "username": user["username"]}})

    def admin_moderation(self):
        user = auth_user(self)
        if not is_admin(user): return self.error(403, "Только администратор")
        con = db()
        rows = con.execute("SELECT s.*, u.username AS author_username, COALESCE(u.badge,'') AS author_badge FROM sources s LEFT JOIN users u ON u.id=s.user_id WHERE s.status='pending' ORDER BY s.created_at ASC").fetchall()
        con.close()
        return self.send_json(200, [source_json(r) | {"author": r["author_username"], "authorBadge": r["author_badge"], "status": r["status"], "moderationNote": r["moderation_note"]} for r in rows])

    def admin_moderate_source(self, sid):
        user = auth_user(self)
        if not is_admin(user): return self.error(403, "Только администратор")
        try:
            body=json.loads(self.read_body(16*1024).decode("utf-8"))
        except Exception:
            return self.error(400,"Некорректный JSON")
        status=str(body.get("status","")).strip().lower()
        note=str(body.get("note","")).strip()[:500]
        if status not in ("approved","rejected"):
            return self.error(400,"Статус: approved или rejected")
        con=db(); row=con.execute("SELECT id FROM sources WHERE id=?",(sid,)).fetchone()
        if not row:
            con.close(); return self.error(404,"Сорс не найден")
        con.execute("UPDATE sources SET status=?, moderation_note=? WHERE id=?",(status,note,sid)); con.commit(); con.close()
        return self.send_json(200,{"ok":True,"status":status})

    def admin_set_badge(self, uid):
        user=auth_user(self)
        if not is_admin(user): return self.error(403,"Только администратор")
        try:
            body=json.loads(self.read_body(8*1024).decode("utf-8"))
        except Exception:
            return self.error(400,"Некорректный JSON")
        badge=str(body.get("badge","")).strip().lower()
        if badge not in ("gold","white",""):
            return self.error(400,"Галочка: gold, white или пусто")
        con=db(); target=con.execute("SELECT id,username FROM users WHERE id=?",(uid,)).fetchone()
        if not target:
            con.close(); return self.error(404,"Пользователь не найден")
        con.execute("UPDATE users SET badge=? WHERE id=?",(badge,uid)); con.commit(); con.close()
        return self.send_json(200,{"ok":True,"uid":uid,"badge":badge})

    def upload_avatar(self):
        user=auth_user(self)
        if not user: return self.error(401,"Не авторизован")
        length=int(self.headers.get("Content-Length","0"))
        if length>MAX_IMAGE+1024*1024: return self.error(413,"Аватар слишком большой")
        body=self.read_body(MAX_IMAGE+1024*1024); fields,files=parse_multipart(self,body)
        f=files.get("avatar")
        if not f or not f["content"]: return self.error(400,"Нужен файл аватара")
        if len(f["content"])>MAX_IMAGE: return self.error(413,"Аватар должен быть не больше 10 MB")
        ext=Path(f["filename"] or "avatar.jpg").suffix.lower()
        if ext not in (".jpg",".jpeg",".png",".webp",".gif"): ext=".jpg"
        rel=f"avatars/{user['id']}{ext}"; path=UPLOADS/rel; path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(f["content"])
        con=db(); con.execute("UPDATE users SET avatar_path=? WHERE id=?",(rel,user["id"])); con.commit(); con.close()
        return self.send_json(200,{"avatar":f"/uploads/{rel}"})

    def create_source(self):
        user = auth_user(self)
        if not user: return self.error(401, "Сначала войдите через Telegram")
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_ZIP + MAX_IMAGE + 2 * 1024 * 1024:
            return self.error(413, "Запрос слишком большой")
        body = self.read_body(MAX_ZIP + MAX_IMAGE + 2 * 1024 * 1024)
        fields, files = parse_multipart(self, body)
        z = files.get("zip")
        if not z: return self.error(400, "Нужен ZIP-файл")
        if not z["filename"].lower().endswith(".zip"): return self.error(400, "Нужен ZIP-файл")
        if len(z["content"]) > MAX_ZIP: return self.error(413, "ZIP должен быть не больше 100 MB")
        image = files.get("image")
        if image and len(image["content"]) > MAX_IMAGE: return self.error(413, "Обложка должна быть не больше 10 MB")
        sid = str(uuid.uuid4())
        folder = UPLOADS / sid
        folder.mkdir(parents=True, exist_ok=False)
        zip_name = clean_name(z["filename"], "source.zip")
        (folder / zip_name).write_bytes(z["content"])
        image_rel = None
        if image and image["content"]:
            image_name = clean_name(image["filename"], "cover")
            (folder / image_name).write_bytes(image["content"])
            image_rel = f"{sid}/{image_name}"
        zip_rel = f"{sid}/{zip_name}"
        title = fields.get("title", "").strip()[:120]
        game = fields.get("game", "").strip()[:80]
        version = fields.get("version", "1.0.0").strip()[:30] or "1.0.0"
        description = fields.get("description", "").strip()[:5000]
        if not title or not game:
            shutil.rmtree(folder, ignore_errors=True)
            return self.error(400, "Название и игра обязательны")
        con = db()
        status = "approved" if is_admin(user) else "pending"
        con.execute("INSERT INTO sources(id,user_id,title,game,version,description,author,file_name,file_size,zip_path,image_path,status,moderation_note,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (sid,user["id"],title,game,version,description,user["username"],z["filename"],len(z["content"]),zip_rel,image_rel,status,"",iso(now())))
        con.commit()
        row = con.execute("SELECT * FROM sources WHERE id=?", (sid,)).fetchone()
        con.close()
        return self.send_json(200, source_json(row))

    def like_source(self, sid):
        user = auth_user(self)
        if not user: return self.error(401, "Не авторизован")
        con = db()
        if not con.execute("SELECT id FROM sources WHERE id=?", (sid,)).fetchone():
            con.close(); return self.error(404, "Сорс не найден")
        exists = con.execute("SELECT 1 FROM likes WHERE user_id=? AND source_id=?", (user["id"],sid)).fetchone()
        if exists:
            con.execute("DELETE FROM likes WHERE user_id=? AND source_id=?", (user["id"],sid))
            con.execute("UPDATE sources SET likes=MAX(0,likes-1) WHERE id=?", (sid,))
            liked = False
        else:
            con.execute("INSERT INTO likes(user_id,source_id) VALUES(?,?)", (user["id"],sid))
            con.execute("UPDATE sources SET likes=likes+1 WHERE id=?", (sid,))
            liked = True
        con.commit(); con.close()
        return self.send_json(200, {"liked": liked})

    def download_source(self, sid):
        con = db(); row = con.execute("SELECT * FROM sources WHERE id=? AND COALESCE(status,'approved')='approved'", (sid,)).fetchone()
        if not row:
            con.close(); return self.error(404, "Сорс не найден")
        con.execute("UPDATE sources SET downloads=downloads+1 WHERE id=?", (sid,)); con.commit(); con.close()
        path = (UPLOADS / row["zip_path"]).resolve()
        if not str(path).startswith(str(UPLOADS.resolve()) + os.sep) or not path.is_file():
            return self.error(404, "ZIP-файл отсутствует")
        return self.serve_file(path, "application/zip", download_name=row["file_name"])

    def serve_file(self, path, content_type, download_name=None):
        size = path.stat().st_size
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(size))
        self.send_header("Access-Control-Allow-Origin", self.cors_origin())
        if download_name:
            safe = clean_name(download_name, "download.zip")
            self.send_header("Content-Disposition", f'attachment; filename="{safe}"')
        else:
            self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        with path.open("rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk: break
                self.wfile.write(chunk)


def main():
    init_db()
    setup_bot_if_needed()
    if BOT_TOKEN:
        t = threading.Thread(target=telegram_loop, name="telegram-polling", daemon=True)
        t.start()
        print(f"Telegram bot: @{BOT_USERNAME or 'configured'}")
        print("Registration: ON - send /start to the bot to receive a 6-digit code.")
    else:
        print("Telegram bot: OFF - no token entered.")
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
