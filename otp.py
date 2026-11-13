"""OTP 6 digit: disimpan sebagai HMAC (bukan teks asli), berlaku 5 menit, sekali pakai, dibatasi percobaannya."""
import hashlib
import hmac
import secrets
import threading
import time

LENGTH = 6
TTL = 300                 # masa berlaku OTP (detik)
MAX_TRIES = 5             # salah memasukkan OTP -> harus login ulang
RESEND_COOLDOWN = 60      # jeda minimal kirim ulang (detik)
MAX_SENDS_PER_LOGIN = 3   # kirim ulang maksimal per sesi login
MAX_SENDS_PER_HOUR = 5    # per user, agar nomor WA tidak dibanjiri pesan

_key = secrets.token_bytes(32)
_pending = {}
_hourly = {}
_lock = threading.Lock()


class RateLimited(Exception):
    def __init__(self, wait):
        super().__init__(wait)
        self.wait = wait


def _digest(pid, code):
    return hmac.new(_key, f"{pid}:{code}".encode(), hashlib.sha256).digest()


def _gc(now):
    for k in [k for k, v in _pending.items() if v["exp"] < now]:
        del _pending[k]
    for u in list(_hourly):
        _hourly[u] = [t for t in _hourly[u] if now - t < 3600]
        if not _hourly[u]:
            del _hourly[u]


def _new_code(pid, rec, now):
    code = "".join(secrets.choice("0123456789") for _ in range(LENGTH))
    rec["hash"], rec["exp"], rec["last"] = _digest(pid, code), now + TTL, now
    rec["sends"] += 1
    rec["tries"] = 0
    return code


def _hour_check(user, now):
    hist = _hourly.get(user, [])
    if len(hist) >= MAX_SENDS_PER_HOUR:
        raise RateLimited(int(3600 - (now - hist[0])) + 1)


def start(user, ip):
    """Buat OTP baru. Return (pending_id, code). RateLimited jika terlalu sering."""
    now = time.time()
    with _lock:
        _gc(now)
        _hour_check(user, now)
        pid = secrets.token_urlsafe(24)
        rec = {"user": user, "ip": ip, "sends": 0}
        code = _new_code(pid, rec, now)
        _pending[pid] = rec
        _hourly.setdefault(user, []).append(now)
        return pid, code


def resend(pid, ip):
    """Return (status, code_or_wait). status: ok | expired | cooldown | limit | hourly"""
    now = time.time()
    with _lock:
        _gc(now)
        rec = _pending.get(pid)
        if not rec or rec["ip"] != ip:
            return "expired", None
        if rec["sends"] >= MAX_SENDS_PER_LOGIN:
            return "limit", None
        wait = int(RESEND_COOLDOWN - (now - rec["last"]))
        if wait > 0:
            return "cooldown", wait
        try:
            _hour_check(rec["user"], now)
        except RateLimited as e:
            return "hourly", e.wait
        code = _new_code(pid, rec, now)
        _hourly.setdefault(rec["user"], []).append(now)
        return "ok", code


def user_of(pid):
    with _lock:
        rec = _pending.get(pid or "")
        return rec["user"] if rec else None


def cancel(pid):
    with _lock:
        _pending.pop(pid, None)


def verify(pid, code, ip):
    """Return (status, value). status: ok(value=username) | wrong(value=sisa percobaan) | expired | locked"""
    now = time.time()
    with _lock:
        _gc(now)
        rec = _pending.get(pid or "")
        if not rec or rec["ip"] != ip:
            return "expired", None
        if hmac.compare_digest(rec["hash"], _digest(pid, (code or "").strip())):
            del _pending[pid]  # sekali pakai
            return "ok", rec["user"]
        rec["tries"] += 1
        left = MAX_TRIES - rec["tries"]
        if left <= 0:
            del _pending[pid]
            return "locked", None
        return "wrong", left
