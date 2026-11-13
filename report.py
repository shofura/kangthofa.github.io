"""
Laporan aktivitas dari activity.db.

    python report.py summary [--days 30]                 # ringkasan: login berhasil, MSISDN disubmit, per user
    python report.py logins  [--days 7] [--user budi] [--all]   # daftar login (default hanya yang berhasil; --all = semua kejadian)
    python report.py submissions [--days 7] [--user budi]       # daftar pengecekan
    python report.py export submissions hasil.csv [--days 30] [--user budi]   # rincian per MSISDN
    python report.py export events kejadian.csv [--days 30]
    python report.py find 0812xxxxxxx                    # siapa saja yang pernah mengecek nomor ini
    python report.py purge --days 90                     # hapus log lebih lama dari 90 hari
"""
import argparse
import csv
import sqlite3
import sys
import time

import activity
from common import norm_msisdn


def db():
    return activity.connect()


def since(days):
    return time.time() - days * 86400 if days else 0


def table(rows, headers):
    if not rows:
        print("(tidak ada data)")
        return
    rows = [[("" if v is None else str(v)) for v in r] for r in rows]
    w = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    print("  ".join(h.ljust(w[i]) for i, h in enumerate(headers)))
    print("  ".join("-" * x for x in w))
    for r in rows:
        print("  ".join(r[i].ljust(w[i]) for i in range(len(headers))))


def cmd_summary(a):
    c, t0 = db(), since(a.days)
    label = f"{a.days} hari terakhir" if a.days else "semua waktu"
    print(f"=== RINGKASAN AKTIVITAS ({label}) ===\n")
    ok, users = c.execute("SELECT COUNT(*), COUNT(DISTINCT username) FROM events WHERE event='login_success' AND epoch>=?", (t0,)).fetchone()
    fail = c.execute("SELECT COUNT(*) FROM events WHERE event IN ('password_fail','captcha_fail','otp_fail','otp_locked','locked') AND epoch>=?", (t0,)).fetchone()[0]
    print(f"Login berhasil          : {ok:,} kali oleh {users:,} user")
    print(f"Percobaan login gagal   : {fail:,}")
    n_sub, n_in, n_uniq, n_found = c.execute(
        "SELECT COUNT(*), COALESCE(SUM(n_input),0), COALESCE(SUM(n_unique),0), COALESCE(SUM(n_found),0) FROM submissions WHERE epoch>=?", (t0,)).fetchone()
    distinct = c.execute(
        "SELECT COUNT(DISTINCT sm.msisdn) FROM submission_msisdn sm JOIN submissions s ON s.id=sm.submission_id WHERE s.epoch>=?", (t0,)).fetchone()[0]
    print(f"Pengecekan (submit)     : {n_sub:,} kali")
    print(f"MSISDN disubmit         : {n_in:,} baris input, {n_uniq:,} unik per submit, {distinct:,} nomor berbeda")
    print(f"  ditemukan GA/Biometrik: {n_found:,}  | tidak ditemukan: {n_uniq - n_found:,}")

    print("\n--- Login berhasil per hari ---")
    table(c.execute("SELECT substr(ts,1,10), COUNT(*), COUNT(DISTINCT username) FROM events WHERE event='login_success' AND epoch>=? "
                    "GROUP BY 1 ORDER BY 1 DESC", (t0,)).fetchall(), ["Tanggal", "Login", "User berbeda"])
    print("\n--- Per user ---")
    table(c.execute(
        "SELECT u.username, "
        "(SELECT COUNT(*) FROM events e WHERE e.username=u.username AND e.event='login_success' AND e.epoch>=?1), "
        "(SELECT MAX(ts) FROM events e WHERE e.username=u.username AND e.event='login_success' AND e.epoch>=?1), "
        "(SELECT COUNT(*) FROM submissions s WHERE s.username=u.username AND s.epoch>=?1), "
        "(SELECT COALESCE(SUM(n_unique),0) FROM submissions s WHERE s.username=u.username AND s.epoch>=?1) "
        "FROM (SELECT username FROM events WHERE epoch>=?1 UNION SELECT username FROM submissions WHERE epoch>=?1) u "
        "ORDER BY 2 DESC", (t0,)).fetchall(),
        ["User", "Login OK", "Login terakhir", "Submit", "MSISDN unik"])


def cmd_logins(a):
    c = db()
    q, p = "SELECT ts, username, ip, event, detail FROM events WHERE epoch>=?", [since(a.days)]
    if not a.all:
        q += " AND event='login_success'"
    if a.user:
        q += " AND username=?"; p.append(a.user.lower())
    table(c.execute(q + " ORDER BY id DESC LIMIT ?", p + [a.limit]).fetchall(), ["Waktu", "User", "IP", "Kejadian", "Detail"])


def cmd_submissions(a):
    c = db()
    q, p = "SELECT id, ts, username, ip, source, n_unique, n_found, n_not_found FROM submissions WHERE epoch>=?", [since(a.days)]
    if a.user:
        q += " AND username=?"; p.append(a.user.lower())
    table(c.execute(q + " ORDER BY id DESC LIMIT ?", p + [a.limit]).fetchall(),
          ["ID", "Waktu", "User", "IP", "Sumber", "MSISDN unik", "Ditemukan", "Tidak"])


def cmd_export(a):
    c, t0 = db(), since(a.days)
    with open(a.out, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        if a.what == "submissions":
            q = ("SELECT s.id, s.ts, s.username, s.ip, s.ua, s.source, sm.msisdn, CASE sm.found WHEN 1 THEN 'FOUND' ELSE 'NOT FOUND' END "
                 "FROM submissions s JOIN submission_msisdn sm ON sm.submission_id=s.id WHERE s.epoch>=?")
            p = [t0]
            if a.user:
                q += " AND s.username=?"; p.append(a.user.lower())
            w.writerow(["submission_id", "waktu", "user", "ip", "perangkat", "sumber", "msisdn", "status"])
        else:
            q, p = "SELECT id, ts, username, ip, ua, event, detail FROM events WHERE epoch>=?", [t0]
            if a.user:
                q += " AND username=?"; p.append(a.user.lower())
            w.writerow(["id", "waktu", "user", "ip", "perangkat", "kejadian", "detail"])
        n = 0
        for row in c.execute(q + " ORDER BY 1", p):
            w.writerow(row); n += 1
    print(f"{n:,} baris ditulis ke {a.out}")


def cmd_find(a):
    num = norm_msisdn(a.msisdn)
    if not num:
        sys.exit("Nomor tidak valid.")
    table(db().execute(
        "SELECT s.ts, s.username, s.ip, s.source, CASE sm.found WHEN 1 THEN 'FOUND' ELSE 'NOT FOUND' END "
        "FROM submission_msisdn sm JOIN submissions s ON s.id=sm.submission_id WHERE sm.msisdn=? ORDER BY s.id DESC", (num,)).fetchall(),
        ["Waktu", "User", "IP", "Sumber", "Status"])


def cmd_purge(a):
    if a.days < 1:
        sys.exit("--days minimal 1.")
    c = db()
    cut = since(a.days)
    ids = [r[0] for r in c.execute("SELECT id FROM submissions WHERE epoch<?", (cut,))]
    c.executemany("DELETE FROM submission_msisdn WHERE submission_id=?", ((i,) for i in ids))
    n_sub = c.execute("DELETE FROM submissions WHERE epoch<?", (cut,)).rowcount
    n_ev = c.execute("DELETE FROM events WHERE epoch<?", (cut,)).rowcount
    c.commit()
    c.execute("VACUUM")
    print(f"Dihapus: {n_sub:,} pengecekan (beserta daftar MSISDN) dan {n_ev:,} kejadian yang lebih lama dari {a.days} hari.")


def main():
    ap = argparse.ArgumentParser(description="Laporan aktivitas MSISDN Checker")
    sp = ap.add_subparsers(dest="cmd", required=True)
    s = sp.add_parser("summary"); s.add_argument("--days", type=int, default=30); s.set_defaults(f=cmd_summary)
    s = sp.add_parser("logins"); s.add_argument("--days", type=int, default=7); s.add_argument("--user")
    s.add_argument("--all", action="store_true"); s.add_argument("--limit", type=int, default=100); s.set_defaults(f=cmd_logins)
    s = sp.add_parser("submissions"); s.add_argument("--days", type=int, default=7); s.add_argument("--user")
    s.add_argument("--limit", type=int, default=100); s.set_defaults(f=cmd_submissions)
    s = sp.add_parser("export"); s.add_argument("what", choices=["submissions", "events"]); s.add_argument("out")
    s.add_argument("--days", type=int, default=0, help="0 = semua"); s.add_argument("--user"); s.set_defaults(f=cmd_export)
    s = sp.add_parser("find"); s.add_argument("msisdn"); s.set_defaults(f=cmd_find)
    s = sp.add_parser("purge"); s.add_argument("--days", type=int, required=True); s.set_defaults(f=cmd_purge)
    a = ap.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
