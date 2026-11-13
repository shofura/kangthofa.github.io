"""
Kelola akun login aplikasi.

Langkah awal (sekali saja): tentukan password awal / default
    python manage_users.py setdefault

Kelola user:
    python manage_users.py add budi 0812xxxxxxx   # user baru, password = password awal, WAJIB ganti saat login
    python manage_users.py reset budi             # kembalikan ke password awal, WAJIB ganti saat login
    python manage_users.py passwd budi            # set password tertentu (default: wajib ganti saat login)
    python manage_users.py passwd budi --no-force # set password tertentu tanpa wajib ganti
    python manage_users.py phone budi 0813xxxxxxx # ganti nomor WhatsApp
    python manage_users.py force budi             # wajibkan ganti password pada login berikutnya
    python manage_users.py force --all            # untuk semua user
    python manage_users.py delete budi
    python manage_users.py list
"""
import getpass
import sys

import auth
from common import norm_msisdn


def ask_password(label="Password"):
    p1 = getpass.getpass(f"{label}: ")
    if len(p1) < 8:
        sys.exit("Password minimal 8 karakter.")
    if p1 != getpass.getpass("Ulangi password: "):
        sys.exit("Password tidak sama.")
    return p1


def get_phone(arg):
    raw = arg if arg else input("Nomor WhatsApp (contoh 0812xxxxxxx): ")
    phone = norm_msisdn(raw)
    if not phone:
        sys.exit("Nomor WhatsApp tidak valid.")
    return phone


def need_default():
    if not auth.has_default():
        sys.exit("Password awal belum diatur. Jalankan dulu: python manage_users.py setdefault")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    cmds = ("setdefault", "add", "reset", "passwd", "phone", "force", "delete", "list")
    if not args or args[0] not in cmds:
        sys.exit(__doc__)
    cmd = args[0]

    if cmd == "setdefault":
        pw = ask_password("Password awal (default) untuk semua user baru / reset")
        problem = auth.check_policy(pw)
        if problem and "awal" not in problem:
            sys.exit(problem)
        auth.set_default(pw)
        print("Password awal disimpan (sebagai hash). User yang login memakainya wajib menggantinya.")
        return

    if cmd == "list":
        rows = auth.list_users_detail()
        if not rows:
            print("(belum ada user)")
        for u, ph in rows:
            tags = []
            tags.append("WA: " + (auth.mask_phone(ph) if ph else "(BELUM ADA - tidak bisa login)"))
            if auth.must_change(u):
                tags.append("WAJIB GANTI PASSWORD")
            print(f"{u:20} " + " | ".join(tags))
        print("\nPassword awal:", "sudah diatur" if auth.has_default() else "BELUM diatur (jalankan setdefault)")
        return

    if cmd == "force" and "--all" in flags:
        print(f"{auth.set_must_change(None, True)} user wajib ganti password pada login berikutnya.")
        return

    if len(args) < 2:
        sys.exit("Sebutkan username. Contoh: python manage_users.py add budi 0812xxxxxxx")
    u = args[1].strip().lower()
    extra = args[2] if len(args) > 2 else None

    if cmd == "add":
        if auth.user_exists(u):
            sys.exit(f"User '{u}' sudah ada. Pakai 'reset' atau 'passwd' untuk mengubah passwordnya.")
        need_default()
        phone = get_phone(extra)
        auth.apply_default(u)
        auth.set_phone(u, phone)
        print(f"User '{u}' dibuat dengan password awal. Wajib ganti password saat login pertama. "
              f"OTP dikirim ke WhatsApp {auth.mask_phone(phone)}.")
    elif cmd == "reset":
        if not auth.user_exists(u):
            sys.exit(f"User '{u}' tidak ditemukan.")
        need_default()
        auth.apply_default(u)
        print(f"Password '{u}' dikembalikan ke password awal. Wajib ganti password saat login berikutnya.")
        print("Catatan: jika user sedang login, ia akan diminta ganti password pada akses berikutnya.")
    elif cmd == "passwd":
        if not auth.user_exists(u):
            sys.exit(f"User '{u}' tidak ditemukan.")
        pw = ask_password()
        problem = auth.check_policy(pw, username=u)
        if problem:
            sys.exit(problem)
        force = "--no-force" not in flags
        auth.set_user(u, pw, must_change=force)
        print(f"Password '{u}' diganti." + (" Wajib ganti lagi saat login berikutnya." if force else ""))
    elif cmd == "phone":
        if not auth.user_exists(u):
            sys.exit(f"User '{u}' tidak ditemukan.")
        phone = get_phone(extra)
        auth.set_phone(u, phone)
        print(f"Nomor WhatsApp '{u}' diganti ke {auth.mask_phone(phone)}.")
    elif cmd == "force":
        if not auth.set_must_change(u, True):
            sys.exit(f"User '{u}' tidak ditemukan.")
        print(f"'{u}' wajib ganti password pada login berikutnya.")
    elif cmd == "delete":
        print("Dihapus." if auth.delete_user(u) else "User tidak ditemukan.")


if __name__ == "__main__":
    main()
