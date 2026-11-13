"""
Log aktivitas (disimpan di activity.db):
  events           : login berhasil/gagal, logout, ganti password, unduh hasil
  submissions      : tiap pengecekan MSISDN (siapa, dari IP mana, jam berapa, sumber, jumlah)
  submission_msisdn: daftar lengkap MSISDN yang disubmit pada tiap pengecekan + ditemukan atau tidak

Kegagalan menulis log tidak boleh mengganggu aplikasi, jadi semua fungsi di sini menelan error (dicetak saja).
"""
import os
import sqlite3
import time
from pathlib import Path

ACTIVITY_DB = os.environ.get("ACTIVITY_DB", str(Path(__file__).parent / "activity.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, epoch REAL,
    username TEXT, ip TEXT, ua TEXT, event TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS idx_ev_epoch ON events(epoch);
CREATE INDEX IF NOT EXISTS idx_ev_user ON events(username);

CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, epoch REAL,
    username TEXT, ip TEXT, ua TEXT, source TEXT,
    n_input INTEGER, n_unique INTEGER, n_invalid INTEGER, n_found INTEGER, n_not_found INTEGER);
CREATE INDEX IF NOT EXISTS idx_sub_epoch ON submissions(epoch);
CREATE INDEX IF NOT EXISTS idx_sub_user ON submissions(username);

CREATE TABLE IF NOT EXISTS submission_msisdn (
    submission_id INTEGER, msisdn TEXT, found INTEGER);
CREATE INDEX IF NOT EXISTS idx_sm_sub ON submission_msisdn(submission_id);
CREATE INDEX IF NOT EXISTS idx_sm_msisdn ON submission_msisdn(msisdn);
"""


def connect():
    c = sqlite3.connect(ACTIVITY_DB, timeout=15)
    c.execute("PRAGMA journal_mode=WAL")
    c.executescript(SCHEMA)
    return c


def _now():
    t = time.time()
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)), t


def _cut(v, n):
    return (v or "")[:n]


def log_event(username, ip, ua, event, detail=""):
    try:
        ts, t = _now()
        with connect() as c:
            c.execute(
                "INSERT INTO events (ts, epoch, username, ip, ua, event, detail) VALUES (?,?,?,?,?,?,?)",
                (ts, t, _cut(username, 64), _cut(ip, 64), _cut(ua, 200), event, _cut(detail, 300)),
            )
    except Exception as e:
        print(f"[ACTIVITY] gagal menulis log event: {e}")


def log_submission(username, ip, ua, source, msisdns, found_set, n_input, n_invalid):
    """msisdns: daftar MSISDN unik yang disubmit; found_set: yang ditemukan di database."""
    try:
        ts, t = _now()
        n_found = sum(1 for m in msisdns if m in found_set)
        with connect() as c:
            cur = c.execute(
                "INSERT INTO submissions (ts, epoch, username, ip, ua, source, n_input, n_unique, n_invalid, n_found, n_not_found) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (ts, t, _cut(username, 64), _cut(ip, 64), _cut(ua, 200), _cut(source, 300),
                 n_input, len(msisdns), n_invalid, n_found, len(msisdns) - n_found),
            )
            sid = cur.lastrowid
            c.executemany(
                "INSERT INTO submission_msisdn (submission_id, msisdn, found) VALUES (?,?,?)",
                ((sid, m, 1 if m in found_set else 0) for m in msisdns),
            )
        return sid
    except Exception as e:
        print(f"[ACTIVITY] gagal menulis log submission: {e}")
        return None
