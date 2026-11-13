"""Autentikasi: user di users.db (password di-hash PBKDF2), sesi di memori dengan idle timeout."""
import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path

USERS_DB = os.environ.get("USERS_DB", str(Path(__file__).parent / "users.db"))
IDLE_SECONDS = 10 * 60      # tidak ada aktivitas 10 menit -> login ulang
COOKIE = "msisdn_session"
ITER = 200_000
LOCK_SECONDS = 5 * 60       # lama blokir setelah terlalu banyak gagal login
LIMIT_USER = 5              # gagal per (IP + username)
LIMIT_IP = 20               # gagal per IP
_DUMMY_SALT = b"\x00" * 16


def _conn():
    c = sqlite3.connect(USERS_DB)
    c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, salt BLOB, hash BLOB, iter INTEGER)")
    cols = {r[1] for r in c.execute("PRAGMA table_info(users)")}
    if "phone" not in cols:
        c.execute("ALTER TABLE users ADD COLUMN phone TEXT")
    if "must_change" not in cols:
        c.execute("ALTER TABLE users ADD COLUMN must_change INTEGER DEFAULT 0")
    # password awal (default) disimpan sebagai hash saja, bukan teks asli
    c.execute("CREATE TABLE IF NOT EXISTS default_pw (id INTEGER PRIMARY KEY CHECK (id=1), salt BLOB, hash BLOB, iter INTEGER)")
    return c


def _hash(password, salt, it=ITER):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, it)


def _norm(username):
    return (username or "").strip().lower()


def set_user(username, password, must_change=False):
    salt = secrets.token_bytes(16)
    with _conn() as c:
        c.execute(
            "INSERT INTO users (username, salt, hash, iter, must_change) VALUES (?,?,?,?,?) "
            "ON CONFLICT(username) DO UPDATE SET salt=excluded.salt, hash=excluded.hash, "
            "iter=excluded.iter, must_change=excluded.must_change",
            (_norm(username), salt, _hash(password, salt), ITER, 1 if must_change else 0),
        )  # nomor WhatsApp tidak ikut tertimpa


def must_change(username):
    with _conn() as c:
        row = c.execute("SELECT must_change FROM users WHERE username=?", (_norm(username),)).fetchone()
    return bool(row and row[0])


def set_must_change(username, flag=True):
    """username=None -> semua user. Return jumlah user yang diubah."""
    with _conn() as c:
        if username is None:
            return c.execute("UPDATE users SET must_change=?", (1 if flag else 0,)).rowcount
        return c.execute("UPDATE users SET must_change=? WHERE username=?", (1 if flag else 0, _norm(username))).rowcount


# ---------- password awal (default) ----------
def set_default(password):
    salt = secrets.token_bytes(16)
    with _conn() as c:
        c.execute("INSERT OR REPLACE INTO default_pw VALUES (1,?,?,?)", (salt, _hash(password, salt), ITER))


def has_default():
    with _conn() as c:
        return c.execute("SELECT 1 FROM default_pw").fetchone() is not None


def is_default_password(password):
    with _conn() as c:
        row = c.execute("SELECT salt, hash, iter FROM default_pw").fetchone()
    return bool(row) and hmac.compare_digest(_hash(password or "", row[0], row[2]), row[1])


def apply_default(username):
    """Kembalikan password user ke password awal (salin hash default) dan wajibkan ganti password."""
    with _conn() as c:
        row = c.execute("SELECT salt, hash, iter FROM default_pw").fetchone()
        if not row:
            raise RuntimeError("Password awal belum diatur. Jalankan: python manage_users.py setdefault")
        c.execute(
            "INSERT INTO users (username, salt, hash, iter, must_change) VALUES (?,?,?,?,1) "
            "ON CONFLICT(username) DO UPDATE SET salt=excluded.salt, hash=excluded.hash, "
            "iter=excluded.iter, must_change=1",
            (_norm(username), *row),
        )


def check_policy(password, username=None, current=None):
    """Return pesan error (str) jika password tidak memenuhi syarat, atau None jika lolos."""
    if len(password) < 8:
        return "Password minimal 8 karakter."
    if len(password) > 128:
        return "Password maksimal 128 karakter."
    if not (any(ch.isalpha() for ch in password) and any(ch.isdigit() for ch in password)):
        return "Password harus mengandung huruf dan angka."
    if username and password.lower() == _norm(username):
        return "Password tidak boleh sama dengan username."
    if is_default_password(password):
        return "Password tidak boleh sama dengan password awal (default)."
    if current is not None and password == current:
        return "Password baru tidak boleh sama dengan password lama."
    return None


def set_phone(username, phone):
    with _conn() as c:
        return c.execute("UPDATE users SET phone=? WHERE username=?", (phone, _norm(username))).rowcount


def get_phone(username):
    with _conn() as c:
        row = c.execute("SELECT phone FROM users WHERE username=?", (_norm(username),)).fetchone()
    return row[0] if row and row[0] else None


def mask_phone(phone):
    return phone[:5] + "*" * max(0, len(phone) - 8) + phone[-3:] if phone else "-"


def delete_user(username):
    with _conn() as c:
        return c.execute("DELETE FROM users WHERE username=?", (_norm(username),)).rowcount


def list_users():
    with _conn() as c:
        return [r[0] for r in c.execute("SELECT username FROM users ORDER BY username")]


def list_users_detail():
    with _conn() as c:
        return c.execute("SELECT username, phone FROM users ORDER BY username").fetchall()


def user_exists(username):
    with _conn() as c:
        return c.execute("SELECT 1 FROM users WHERE username=?", (_norm(username),)).fetchone() is not None


def verify(username, password):
    with _conn() as c:
        row = c.execute("SELECT salt, hash, iter FROM users WHERE username=?", (_norm(username),)).fetchone()
    if not row:
        _hash(password or "", _DUMMY_SALT)  # samakan waktu proses agar username tidak bisa ditebak
        return False
    return hmac.compare_digest(_hash(password or "", row[0], row[2]), row[1])


# ---------- sesi ----------
_sessions = {}
_lock = threading.Lock()


def create_session(username):
    token = secrets.token_urlsafe(32)
    with _lock:
        _sessions[token] = [_norm(username), time.time()]
    return token


def get_session(token, touch=True):
    """Return username jika sesi valid; sesi idle > IDLE_SECONDS dihapus."""
    if not token:
        return None
    now = time.time()
    with _lock:
        for t in [t for t, s in _sessions.items() if now - s[1] > IDLE_SECONDS]:
            del _sessions[t]
        s = _sessions.get(token)
        if not s:
            return None
        if touch:
            s[1] = now
        return s[0]


def drop_user_sessions(username, keep_token=None):
    """Hapus semua sesi user (kecuali keep_token), mis. setelah password diganti."""
    u = _norm(username)
    with _lock:
        for t in [t for t, v in _sessions.items() if v[0] == u and t != keep_token]:
            del _sessions[t]


def drop_session(token):
    with _lock:
        _sessions.pop(token, None)


# ---------- pembatasan percobaan login ----------
_fails = {}  # key -> [jumlah gagal, waktu gagal pertama]


def locked_for(*keys_limits):
    """keys_limits: (key, limit). Return sisa detik blokir (0 jika tidak diblokir)."""
    now = time.time()
    worst = 0
    with _lock:
        for key, limit in keys_limits:
            rec = _fails.get(key)
            if not rec:
                continue
            if now - rec[1] > LOCK_SECONDS:
                del _fails[key]
            elif rec[0] >= limit:
                worst = max(worst, int(LOCK_SECONDS - (now - rec[1])) + 1)
    return worst


def register_fail(*keys):
    now = time.time()
    with _lock:
        for key in keys:
            rec = _fails.get(key)
            if not rec or now - rec[1] > LOCK_SECONDS:
                _fails[key] = [1, now]
            else:
                rec[0] += 1


def clear_fails(*keys):
    with _lock:
        for k in keys:
            _fails.pop(k, None)
