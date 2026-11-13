"""
Pengirim pesan WhatsApp untuk OTP. Pilih penyedia lewat environment variable:

  WA_PROVIDER=fonnte    WA_TOKEN=<token device Fonnte>
  WA_PROVIDER=meta      WA_TOKEN=<access token>  WA_META_PHONE_ID=<phone number id>
                        WA_META_TEMPLATE=<nama template kategori Authentication>  [WA_META_LANG=id]
  WA_PROVIDER=console   (HANYA UJI COBA: OTP dicetak di jendela server, jangan dipakai sungguhan)

Hanya memakai library bawaan Python (urllib), tanpa paket tambahan.
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 15


class WAError(Exception):
    pass


def _post(url, data=None, json_body=None, headers=None):
    headers = dict(headers or {})
    if json_body is not None:
        body = json.dumps(json_body).encode()
        headers["Content-Type"] = "application/json"
    else:
        body = urllib.parse.urlencode(data or {}).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # jaringan putus, DNS, timeout, dll
        raise WAError(f"tidak bisa menghubungi penyedia WhatsApp: {e.__class__.__name__}")


def _fonnte(phone, message, code):
    token = os.environ.get("WA_TOKEN", "")
    if not token:
        raise WAError("WA_TOKEN belum diisi")
    url = os.environ.get("WA_API_URL", "https://api.fonnte.com/send")
    status, text = _post(url, data={"target": phone, "message": message}, headers={"Authorization": token})
    try:
        ok = bool(json.loads(text).get("status"))
    except ValueError:
        ok = False
    if status != 200 or not ok:
        raise WAError(f"Fonnte menolak pesan (HTTP {status}): {text[:200]}")


def _meta(phone, message, code):
    token, pid, tpl = (os.environ.get(k, "") for k in ("WA_TOKEN", "WA_META_PHONE_ID", "WA_META_TEMPLATE"))
    if not (token and pid and tpl):
        raise WAError("WA_TOKEN, WA_META_PHONE_ID, dan WA_META_TEMPLATE harus diisi")
    ver = os.environ.get("WA_META_VERSION", "v20.0")
    url = os.environ.get("WA_API_URL", f"https://graph.facebook.com/{ver}/{pid}/messages")
    body = {
        "messaging_product": "whatsapp",
        "to": phone,
        "type": "template",
        "template": {
            "name": tpl,
            "language": {"code": os.environ.get("WA_META_LANG", "id")},
            "components": [  # format template kategori Authentication (kode di isi pesan + tombol salin)
                {"type": "body", "parameters": [{"type": "text", "text": code}]},
                {"type": "button", "sub_type": "url", "index": "0", "parameters": [{"type": "text", "text": code}]},
            ],
        },
    }
    status, text = _post(url, json_body=body, headers={"Authorization": f"Bearer {token}"})
    if status not in (200, 201):
        raise WAError(f"WhatsApp Cloud API menolak pesan (HTTP {status}): {text[:200]}")


def _console(phone, message, code):
    print(f"\n[WA-CONSOLE / HANYA UJI COBA] ke {phone}: {message}\n")


PROVIDERS = {"fonnte": _fonnte, "meta": _meta, "console": _console}


def configured():
    return os.environ.get("WA_PROVIDER", "").strip().lower() in PROVIDERS


def send_otp(phone, code, message):
    name = os.environ.get("WA_PROVIDER", "").strip().lower()
    if name not in PROVIDERS:
        raise WAError("WA_PROVIDER belum diatur (fonnte / meta / console)")
    PROVIDERS[name](phone, message, code)
