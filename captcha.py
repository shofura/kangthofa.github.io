"""Captcha gambar buatan sendiri (tanpa layanan eksternal, jadi tetap jalan di jaringan lokal)."""
import base64
import io
import random
import secrets
import threading
import time

try:
    from PIL import Image, ImageDraw, ImageFilter, ImageFont
except ImportError:
    raise RuntimeError("Pillow belum terpasang. Jalankan: py -m pip install pillow")

ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # tanpa 0/O, 1/I/L agar tidak membingungkan
LENGTH = 5
TTL = 180          # captcha kedaluwarsa setelah 3 menit
MAX_STORE = 2000
W, H = 170, 60

_rnd = random.SystemRandom()
_store = {}
_lock = threading.Lock()
_FONTS = ["DejaVuSans-Bold.ttf", "arialbd.ttf", "arial.ttf", "Verdana.ttf",
          "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"]


def _font(size):
    for name in _FONTS:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    try:
        return ImageFont.load_default(size)
    except TypeError:
        return ImageFont.load_default()


def _render(text):
    bg = (_rnd.randint(235, 250), _rnd.randint(235, 250), _rnd.randint(235, 250))
    img = Image.new("RGB", (W, H), bg)
    d = ImageDraw.Draw(img)
    for _ in range(6):  # garis gangguan di belakang huruf
        d.line([(_rnd.randint(0, W), _rnd.randint(0, H)), (_rnd.randint(0, W), _rnd.randint(0, H))],
               fill=(_rnd.randint(120, 200),) * 3, width=_rnd.randint(1, 2))
    step = (W - 20) / len(text)
    for i, ch in enumerate(text):
        size = _rnd.randint(30, 38)
        layer = Image.new("L", (size + 20, size + 20), 0)
        ImageDraw.Draw(layer).text((8, 4), ch, font=_font(size), fill=255)
        layer = layer.rotate(_rnd.randint(-28, 28), resample=Image.BICUBIC, expand=True)
        color = (_rnd.randint(0, 90), _rnd.randint(0, 90), _rnd.randint(40, 140))
        x = int(10 + i * step + _rnd.randint(-3, 3))
        y = _rnd.randint(0, max(1, H - layer.size[1]))
        img.paste(Image.new("RGB", layer.size, color), (x, y), layer)
    for _ in range(4):  # garis gangguan di depan huruf
        d.line([(0, _rnd.randint(8, H - 8)), (W, _rnd.randint(8, H - 8))],
               fill=(_rnd.randint(60, 140),) * 3, width=1)
    for _ in range(180):
        d.point((_rnd.randint(0, W - 1), _rnd.randint(0, H - 1)), fill=(_rnd.randint(80, 200),) * 3)
    img = img.filter(ImageFilter.SMOOTH)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def generate():
    """Return (captcha_id, data_uri_png)."""
    text = "".join(secrets.choice(ALPHABET) for _ in range(LENGTH))
    cid = secrets.token_urlsafe(16)
    now = time.time()
    with _lock:
        for k in [k for k, v in _store.items() if v[1] < now]:
            del _store[k]
        while len(_store) >= MAX_STORE:
            _store.pop(next(iter(_store)))
        _store[cid] = (text, now + TTL)
    return cid, _render(text)


def check(cid, answer):
    """Sekali pakai: captcha dihapus meski jawabannya salah."""
    with _lock:
        rec = _store.pop(cid or "", None)
    if not rec or rec[1] < time.time():
        return False
    return secrets.compare_digest(rec[0], (answer or "").strip().upper())
