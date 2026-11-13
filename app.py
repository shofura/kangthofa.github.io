"""
Jalankan:
    uvicorn app:app --host 0.0.0.0 --port 8000
Lalu buka http://<IP-server>:8000 dari komputer lain di jaringan lokal.
"""
import csv
import io
import os
import sqlite3
import tempfile
import time
import uuid
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse

import activity
import auth
import captcha
import otp
import wa
from common import OUT_COLS, norm_msisdn, norm_outlet

BASE = Path(__file__).parent
DB_PATH = os.environ.get("MSISDN_DB", str(BASE / "msisdn.db"))
OUTLET_DB = os.environ.get("OUTLET_DB", str(BASE / "outlet_program.db"))
OUT_DIR = Path(tempfile.gettempdir()) / "msisdn_checker"
OUT_DIR.mkdir(exist_ok=True)
CHUNK = 500
PREVIEW = 200
MAX_AGE = 3600  # file hasil dihapus setelah 1 jam

OTP_ENABLED = os.environ.get("OTP_ENABLED", "1") != "0"   # jangan dimatikan untuk akses publik
OTP_MESSAGE = (
    "*{code}* adalah kode OTP MSISDN Checker Anda. Berlaku {menit} menit. "
    "Jangan bagikan kode ini kepada siapa pun."
)

app = FastAPI(title="MSISDN Checker", docs_url=None, redoc_url=None, openapi_url=None)


@app.on_event("startup")
def _startup():
    if not auth.list_users():
        print("\n*** PERINGATAN: belum ada user. Buat dulu: python manage_users.py add <username> <no_wa>\n")
    if OTP_ENABLED and not wa.configured():
        print("\n*** PERINGATAN: OTP aktif tapi WA_PROVIDER belum diatur, login akan gagal kirim OTP. "
              "Lihat petunjuk di wa.py (fonnte / meta / console).\n")
    if os.environ.get("WA_PROVIDER", "").lower() == "console":
        print("\n*** PERINGATAN: WA_PROVIDER=console hanya untuk uji coba, OTP tampil di layar ini.\n")


@app.middleware("http")
async def security_headers(request, call_next):
    resp = await call_next(request)
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    if is_https(request):
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    return resp


_LOCAL = ("127.0.0.1", "::1")


def client_ip(request: Request):
    """IP pengguna. Di belakang Cloudflare Tunnel (cloudflared di komputer yang sama, koneksi dari localhost)
    IP asli dibaca dari header CF-Connecting-IP. Header itu diabaikan jika permintaan datang dari tempat lain,
    supaya tidak bisa dipalsukan oleh orang di jaringan lokal."""
    direct = request.client.host if request.client else "?"
    if direct in _LOCAL:
        real = request.headers.get("cf-connecting-ip", "").strip()
        if real:
            return real
    return direct


def is_https(request: Request):
    """True jika pengguna mengakses lewat HTTPS (diteruskan Cloudflare); hanya dipercaya dari localhost."""
    direct = request.client.host if request.client else "?"
    if direct in _LOCAL:
        return request.headers.get("x-forwarded-proto", "").lower() == "https" or \
               '"scheme":"https"' in request.headers.get("cf-visitor", "").replace(" ", "")
    return False


def _req(request: Request):
    """Dependency kecil agar objek request bisa diterima endpoint yang parameternya sudah berisi nilai bawaan."""
    return request


def ua_of(request: Request):
    return request.headers.get("user-agent", "")


def current_user(request: Request):
    u = auth.get_session(request.cookies.get(auth.COOKIE))
    return u if u and auth.user_exists(u) else None


def require_session(request: Request):
    """Wajib login (boleh walau masih harus ganti password)."""
    u = current_user(request)
    if not u:
        raise HTTPException(401, "Sesi berakhir atau belum login.")
    return u


def require_user(request: Request):
    """Wajib login DAN sudah mengganti password awal."""
    u = require_session(request)
    if auth.must_change(u):
        raise HTTPException(403, "Anda wajib mengganti password terlebih dahulu.")
    return u


def parse_msisdns(text):
    """Ambil kolom pertama tiap baris; header / baris tidak valid dihitung invalid."""
    valid, invalid = [], 0
    for row in csv.reader(io.StringIO(text)):
        if not row or not row[0].strip():
            continue
        m = norm_msisdn(row[0])
        if m:
            valid.append(m)
        else:
            invalid += 1
    # baris pertama biasanya header (mis. "msisdn"), jangan dihitung invalid
    return valid, invalid


def lookup(conn, nums, latest_only):
    found = {}
    for i in range(0, len(nums), CHUNK):
        chunk = nums[i : i + CHUNK]
        ph = ",".join("?" * len(chunk))
        sql = f"SELECT msisdn, {', '.join(OUT_COLS)} FROM raw WHERE msisdn IN ({ph})"
        for r in conn.execute(sql, chunk):
            found.setdefault(r[0], []).append(r[1:])
    if latest_only:
        for k, v in found.items():
            found[k] = [max(v, key=lambda r: r[0] or "")]
    return found


def load_programs(ids):
    """ga_outlet -> Program dari outlet_program.db. Return (dict, db_tersedia)."""
    if not Path(OUTLET_DB).exists():
        return {}, False
    ids = list({i for i in ids if i})
    out = {}
    conn = sqlite3.connect(f"file:{OUTLET_DB}?mode=ro", uri=True)
    try:
        for i in range(0, len(ids), CHUNK):
            chunk = ids[i : i + CHUNK]
            ph = ",".join("?" * len(chunk))
            for oid, prog in conn.execute(
                f"SELECT id_outlet, program FROM outlet_program WHERE id_outlet IN ({ph})", chunk
            ):
                out[oid] = (prog or "").strip() or None
    except sqlite3.Error:
        return {}, False
    finally:
        conn.close()
    return out, True


def cleanup():
    now = time.time()
    for p in OUT_DIR.glob("*.csv"):
        if now - p.stat().st_mtime > MAX_AGE:
            p.unlink(missing_ok=True)


@app.post("/api/check")
async def check(
    files: list[UploadFile] = File(default=[]),
    text: str = Form(""),
    latest: bool = Form(False),
    request: Request = Depends(_req),
    user: str = Depends(require_user),
):
    if not Path(DB_PATH).exists():
        raise HTTPException(500, "Database belum ada. Jalankan import_data.py dulu.")

    chunks = [text] if text.strip() else []
    sources = ["tempel"] if text.strip() else []
    for f in files:
        sources.append(f"file: {f.filename}")
        raw = await f.read()
        chunks.append(raw.decode("utf-8-sig", errors="replace"))
    if not chunks:
        raise HTTPException(400, "Tidak ada data yang dikirim.")

    valid, invalid = [], 0
    for c in chunks:
        v, i = parse_msisdns(c)
        valid += v
        invalid += i
    if not valid:
        raise HTTPException(400, "Tidak ada MSISDN valid pada input.")

    uniq = list(dict.fromkeys(valid))
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    try:
        found = lookup(conn, uniq, latest)
    except sqlite3.Error as e:
        raise HTTPException(
            500,
            f"Error database: {e}. Kemungkinan msisdn.db dibuat dengan versi import_data.py "
            "yang lama atau belum selesai. Hapus msisdn.db lalu jalankan import_data.py lagi.",
        )
    finally:
        conn.close()

    activity.log_submission(
        user, client_ip(request) if request else "?", ua_of(request) if request else "",
        ", ".join(sources), uniq, set(found), len(valid), invalid,
    )

    # isi ga_outlet_program: ga_outlet -> outlet_program.db (ID Outlet -> Program)
    idx_outlet, idx_prog = OUT_COLS.index("ga_outlet"), OUT_COLS.index("ga_outlet_program")
    programs, program_db = load_programs(norm_outlet(r[idx_outlet]) for recs in found.values() for r in recs)
    with_program = 0
    for m, recs in found.items():
        new = []
        for r in recs:
            r = list(r)
            r[idx_prog] = programs.get(norm_outlet(r[idx_outlet]))
            new.append(tuple("" if v is None else v for v in r))
        found[m] = new
        if any(r[idx_prog] for r in new):
            with_program += 1

    cleanup()
    rid = uuid.uuid4().hex
    out_path = OUT_DIR / f"{rid}.csv"
    preview, rows_out = [], 0
    with open(out_path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["msisdn", "status"] + OUT_COLS)
        for m in uniq:
            recs = found.get(m)
            if recs:
                for r in recs:
                    line = [m, "FOUND", *r]
                    w.writerow(line)
                    rows_out += 1
                    if len(preview) < PREVIEW:
                        preview.append(line)
            else:
                line = [m, "NOT FOUND"] + [""] * len(OUT_COLS)
                w.writerow(line)
                rows_out += 1
                if len(preview) < PREVIEW:
                    preview.append(line)

    return {
        "download_id": rid,
        "total_input": len(valid),
        "unique": len(uniq),
        "invalid": invalid,
        "found": len(found),
        "with_program": with_program,
        "program_db": program_db,
        "not_found": len(uniq) - len(found),
        "rows_out": rows_out,
        "columns": ["msisdn", "status"] + OUT_COLS,
        "preview": preview,
    }


@app.get("/api/download/{rid}")
def download(rid: str, request: Request, user: str = Depends(require_user)):
    activity.log_event(user, client_ip(request), ua_of(request), "download", rid)
    if not rid.isalnum():
        raise HTTPException(400)
    p = OUT_DIR / f"{rid}.csv"
    if not p.exists():
        raise HTTPException(404, "File sudah kedaluwarsa, silakan cek ulang.")
    return FileResponse(p, media_type="text/csv", filename="hasil_cek_msisdn.csv")


def _page(name):
    page = BASE / "static" / name
    if not page.exists():
        raise HTTPException(500, f"File tampilan tidak ditemukan: {page}. Pastikan folder 'static' ada di samping app.py.")
    return FileResponse(page)


@app.get("/")
def index(request: Request):
    u = current_user(request)
    if not u:
        return RedirectResponse("/login", status_code=303)
    if auth.must_change(u):
        return RedirectResponse("/change-password", status_code=303)
    return _page("index.html")


@app.get("/change-password")
def change_password_page(request: Request):
    if not current_user(request):
        return RedirectResponse("/login", status_code=303)
    return _page("change_password.html")


@app.get("/login")
def login_page(request: Request):
    if current_user(request):
        return RedirectResponse("/", status_code=303)
    return _page("login.html")


@app.get("/api/captcha")
def new_captcha():
    cid, img = captcha.generate()
    return {"id": cid, "image": img}


@app.post("/api/login")
def login(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    captcha_id: str = Form(""),
    captcha_answer: str = Form(""),
):
    ip = client_ip(request)
    k_user, k_ip = f"u|{ip}|{username.strip().lower()}", f"i|{ip}"
    wait = auth.locked_for((k_user, auth.LIMIT_USER), (k_ip, auth.LIMIT_IP))
    if wait:
        activity.log_event(username, ip, ua_of(request), "locked", "ditolak: terlalu banyak percobaan gagal")
        return JSONResponse(
            {"detail": f"Terlalu banyak percobaan gagal. Coba lagi dalam {wait // 60 + 1} menit."}, status_code=429
        )
    if not captcha.check(captcha_id, captcha_answer):  # dicek sebelum password; sekali pakai
        activity.log_event(username, ip, ua_of(request), "captcha_fail")
        return JSONResponse({"detail": "Kode captcha salah atau kedaluwarsa."}, status_code=400)
    if not auth.verify(username, password):
        activity.log_event(username, ip, ua_of(request), "password_fail")
        auth.register_fail(k_user, k_ip)
        return JSONResponse({"detail": "Username atau password salah."}, status_code=401)
    auth.clear_fails(k_user)
    # login memakai password awal (default) -> wajib ganti password
    if auth.has_default() and not auth.must_change(username) and auth.is_default_password(password):
        auth.set_must_change(username, True)

    if not OTP_ENABLED:
        return _finish_login(username, request)

    # Langkah 2: password benar -> kirim OTP ke WhatsApp
    phone = auth.get_phone(username)
    if not phone:
        return JSONResponse(
            {"detail": "Nomor WhatsApp akun ini belum didaftarkan. Hubungi admin untuk mendaftarkannya."},
            status_code=403,
        )
    try:
        pid, code = otp.start(auth._norm(username), ip)
    except otp.RateLimited as e:
        return JSONResponse(
            {"detail": f"Permintaan OTP terlalu sering. Coba lagi dalam {e.wait // 60 + 1} menit."}, status_code=429
        )
    try:
        wa.send_otp(phone, code, OTP_MESSAGE.format(code=code, menit=otp.TTL // 60))
    except wa.WAError as e:
        otp.cancel(pid)
        print(f"[OTP] gagal kirim WhatsApp untuk '{username}': {e}")  # kode OTP tidak ikut dicatat
        return JSONResponse({"detail": "Gagal mengirim OTP ke WhatsApp. Coba lagi atau hubungi admin."}, status_code=502)
    return {
        "otp_required": True,
        "pending_id": pid,
        "phone": auth.mask_phone(phone),
        "ttl": otp.TTL,
        "resend_in": otp.RESEND_COOLDOWN,
    }


def _finish_login(username, request: Request, method="password"):
    activity.log_event(auth._norm(username), client_ip(request), ua_of(request), "login_success", method)
    resp = JSONResponse({"ok": True})
    resp.set_cookie(
        auth.COOKIE, auth.create_session(username), httponly=True, samesite="strict", path="/",
        secure=is_https(request),  # lewat HTTPS: cookie hanya dikirim lewat HTTPS
    )  # cookie sesi: hilang saat browser ditutup
    return resp


@app.post("/api/login/otp")
def login_otp(request: Request, pending_id: str = Form(""), code: str = Form("")):
    ip = client_ip(request)
    wait = auth.locked_for((f"i|{ip}", auth.LIMIT_IP))
    if wait:
        return JSONResponse({"detail": f"Terlalu banyak percobaan gagal. Coba lagi dalam {wait // 60 + 1} menit."}, status_code=429)
    status, val = otp.verify(pending_id, code, ip)
    if status == "ok":
        return _finish_login(val, request, "password+otp")
    if status == "wrong":
        activity.log_event(otp.user_of(pending_id), ip, ua_of(request), "otp_fail", f"sisa percobaan {val}")
        return JSONResponse({"detail": f"Kode OTP salah. Sisa percobaan: {val}."}, status_code=401)
    activity.log_event(None, ip, ua_of(request), "otp_locked", status)
    auth.register_fail(f"i|{ip}")
    msg = "Terlalu banyak salah memasukkan OTP. Silakan login ulang." if status == "locked" else "OTP kedaluwarsa. Silakan login ulang."
    return JSONResponse({"detail": msg, "restart": True}, status_code=400)


@app.post("/api/login/resend")
def login_resend(request: Request, pending_id: str = Form("")):
    ip = client_ip(request)
    status, val = otp.resend(pending_id, ip)
    if status == "expired":
        return JSONResponse({"detail": "Sesi login berakhir. Silakan login ulang.", "restart": True}, status_code=400)
    if status == "limit":
        return JSONResponse({"detail": "Batas kirim ulang OTP tercapai. Silakan login ulang.", "restart": True}, status_code=429)
    if status == "cooldown":
        return JSONResponse({"detail": f"Tunggu {val} detik sebelum kirim ulang.", "resend_in": val}, status_code=429)
    if status == "hourly":
        return JSONResponse({"detail": f"Permintaan OTP terlalu sering. Coba lagi dalam {val // 60 + 1} menit."}, status_code=429)
    pend_user = otp.user_of(pending_id)
    phone = auth.get_phone(pend_user) if pend_user else None
    try:
        wa.send_otp(phone, val, OTP_MESSAGE.format(code=val, menit=otp.TTL // 60))
    except wa.WAError as e:
        print(f"[OTP] gagal kirim ulang untuk '{pend_user}': {e}")
        return JSONResponse({"detail": "Gagal mengirim OTP ke WhatsApp. Coba lagi."}, status_code=502)
    return {"ok": True, "ttl": otp.TTL, "resend_in": otp.RESEND_COOLDOWN}


@app.post("/api/logout")
def logout(request: Request):
    who = current_user(request)
    if who:
        activity.log_event(who, client_ip(request), ua_of(request), "logout")
    auth.drop_session(request.cookies.get(auth.COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(auth.COOKIE, path="/")
    return resp


@app.get("/api/session")
def session(user: str = Depends(require_session)):
    """Dipanggil berkala oleh browser saat ada aktivitas, untuk memperpanjang sesi."""
    return {"user": user, "idle_seconds": auth.IDLE_SECONDS, "must_change": auth.must_change(user)}


@app.post("/api/change-password")
def change_password(
    request: Request,
    current_password: str = Form(""),
    new_password: str = Form(""),
    confirm_password: str = Form(""),
    user: str = Depends(require_session),
):
    key = f"c|{user}"
    wait = auth.locked_for((key, auth.LIMIT_USER))
    if wait:
        return JSONResponse({"detail": f"Terlalu banyak percobaan gagal. Coba lagi dalam {wait // 60 + 1} menit."}, status_code=429)
    if not auth.verify(user, current_password):
        auth.register_fail(key)
        return JSONResponse({"detail": "Password saat ini salah."}, status_code=400)
    if new_password != confirm_password:
        return JSONResponse({"detail": "Konfirmasi password tidak sama."}, status_code=400)
    problem = auth.check_policy(new_password, username=user, current=current_password)
    if problem:
        return JSONResponse({"detail": problem}, status_code=400)
    auth.clear_fails(key)
    auth.set_user(user, new_password, must_change=False)
    activity.log_event(user, client_ip(request), ua_of(request), "password_changed")
    auth.drop_user_sessions(user, keep_token=request.cookies.get(auth.COOKIE))  # sesi di perangkat lain keluar
    return {"ok": True}
