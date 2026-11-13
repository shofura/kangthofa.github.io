"""
Impor raw data CSV (besar) ke SQLite ber-index.

Contoh:
    python import_data.py D:\\raw_folder                 # semua *.csv di folder itu
    python import_data.py D:\\raw_folder --recursive     # termasuk subfolder
    python import_data.py rguga_details.csv              # satu file
    python import_data.py a.csv b.csv D:\\folder2        # campuran file dan folder

Data selalu digabung ke database (tidak menghapus yang lama):
  - MSISDN baru        -> ditambahkan
  - MSISDN sudah ada   -> kolomnya diperbarui jika ga_date file >= ga_date di database
Tambahkan --reset untuk mengosongkan database dulu sebelum impor.

Pemetaan kolom (kolom di aplikasi <- kolom di raw data) ada di COLUMN_MAP.
Kolom pertama yang ditemukan di header akan dipakai.
"""
import argparse
import csv
import re
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path

from common import OUT_COLS, norm_msisdn

class FileProblem(Exception):
    """File tidak bisa diimpor (kolom tidak cocok, format MSISDN rusak, dll)."""


csv.field_size_limit(10_000_000)
BATCH = 50_000

# kolom aplikasi -> daftar kandidat nama kolom di file (huruf besar/kecil bebas).
# Kandidat pertama yang ada di header file dipakai, jadi beberapa format file bisa diimpor ke database yang sama.
#   format A (rguga_details): ga_dt, ga_pairing_id, ga_site_id, ga_site_branch, first_tag_id, latest_tag_id
#   format B (contoh.csv)   : ga_dt, outlet_id,     ga_site,    ga_branch,    tag_outlet,   last30d_tag_outlet
COLUMN_MAP = {
    "msisdn":            ["msisdn"],
    "ga_date":           ["ga_dt", "ga_date"],
    "ga_outlet":         ["ga_pairing_id", "outlet_id"],
    "ga_outlet_program": None,            # sementara selalu NULL (diisi dari outlet_program.db saat pengecekan)
    "ga_site_id":        ["ga_site_id", "ga_site"],
    "ga_site_branch":    ["ga_site_branch", "ga_branch"],
    "first_tag_id":      ["first_tag_id", "tag_outlet"],
    "latest_tag_id":     ["latest_tag_id", "last30d_tag_outlet"],
}
REQUIRED = ("msisdn", "ga_date")
MIN_OPTIONAL = 2   # minimal 2 kolom data lain harus ada, agar file dengan format asing tidak masuk diam-diam


def build_upsert(cols):
    """UPSERT hanya untuk kolom yang ADA di file. Kolom yang tidak ada di file tidak disentuh,
    sehingga mis. first_tag_id/latest_tag_id yang sudah tersimpan tidak terhapus oleh file format lain."""
    names = ["msisdn"] + cols
    return (
        f"INSERT INTO raw ({', '.join(names)}) VALUES ({','.join('?' * len(names))}) "
        "ON CONFLICT(msisdn) DO UPDATE SET "
        + ", ".join(f"{c}=excluded.{c}" for c in cols)
        + " WHERE COALESCE(excluded.ga_date,'') >= COALESCE(raw.ga_date,'')"
    )


SCI = re.compile(r"^\d(\.\d+)?e\+?\d+$", re.I)


def detect_delimiter(path, enc):
    with open(path, "r", encoding=enc, newline="") as f:
        head = f.readline()
    return max([",", ";", "|", "\t"], key=head.count)


def iso_date(v):
    """9/29/2026 -> 2026-09-29 (supaya bisa diurutkan). Format lain dibiarkan."""
    v = v.strip()
    for fmt in ("%m/%d/%Y", "%d/%m/%Y", "%Y-%m-%d", "%m/%d/%Y %H:%M"):
        try:
            return datetime.strptime(v, fmt).strftime("%Y-%m-%d")
        except ValueError:
            pass
    return v


def import_file(conn, path, delimiter=None):
    enc = "utf-8-sig"
    delim = delimiter or detect_delimiter(path, enc)
    total = skipped = 0
    t0 = time.time()
    with open(path, "r", encoding=enc, newline="", errors="replace") as f:
        reader = csv.reader(f, delimiter=delim)
        try:
            header = [h.strip().lower() for h in next(reader)]
        except StopIteration:
            raise FileProblem("file kosong")
        idx, missing = {}, []
        for target, cands in COLUMN_MAP.items():
            if cands is None:
                continue
            hit = next((c for c in cands if c in header), None)
            if hit is None:
                if target in REQUIRED:
                    raise FileProblem(f"kolom '{target}' tidak ketemu (dicari: {', '.join(cands)})")
                missing.append(target)
            else:
                idx[target] = header.index(hit)
                print(f"  {target:16} <- {hit}")
        if len([t for t in idx if t not in REQUIRED]) < MIN_OPTIONAL:
            raise FileProblem("format file tidak dikenali (kolom data yang cocok terlalu sedikit)")
        if missing:
            print(f"  (tidak ada di file ini, nilai yang sudah tersimpan dipertahankan: {', '.join(missing)})")
        cols = [c for c in OUT_COLS if c in idx]
        upsert = build_upsert(cols)
        batch, checked = [], 0
        for row in reader:
            try:
                raw_ms = row[idx["msisdn"]].strip()
                vals = {k: row[idx[k]].strip() for k in idx}
            except IndexError:
                skipped += 1
                continue
            if checked < 50 and SCI.match(raw_ms):
                raise FileProblem(
                    f"MSISDN berformat notasi ilmiah ('{raw_ms}'), digitnya sudah terpotong "
                    "(biasanya akibat file dibuka/disimpan di Excel). Export ulang dengan kolom "
                    "msisdn berformat Text."
                )
            checked += 1
            m = norm_msisdn(raw_ms)
            if not m:
                skipped += 1
                continue
            vals["ga_date"] = iso_date(vals["ga_date"])
            batch.append((m, *[(vals[c] or None) for c in cols]))
            if len(batch) >= BATCH:
                conn.executemany(upsert, batch)
                total += len(batch)
                batch.clear()
                print(f"  {total:,} baris...", end="\r")
        if batch:
            conn.executemany(upsert, batch)
            total += len(batch)
    conn.commit()
    print(f"  dibaca {total:,} baris, tidak valid {skipped:,} ({time.time()-t0:.1f}s)")
    return total, skipped


def collect_files(paths, recursive, skip):
    """Ubah daftar file/folder/pola (*.csv) menjadi daftar file CSV unik, urut nama."""
    found, seen = [], set()
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            it = p.rglob("*") if recursive else p.glob("*")
            cands = [f for f in it if f.is_file() and f.suffix.lower() == ".csv"]
            if not cands:
                print(f"Peringatan: tidak ada file .csv di folder {p}")
        elif p.is_file():
            cands = [p]
        else:
            cands = [f for f in Path(".").glob(raw) if f.is_file()] if any(c in raw for c in "*?[") else []
            if not cands:
                print(f"Peringatan: '{raw}' tidak ditemukan, dilewati.")
        for f in sorted(cands, key=lambda x: str(x).lower()):
            key = str(f.resolve()).lower()
            if key not in seen and key not in skip:
                seen.add(key)
                found.append(f)
    return found


def ensure_unique_index(conn):
    """Pastikan msisdn unik. Jika db lama berisi duplikat, rapikan dulu (simpan baris terakhir)."""
    for row in conn.execute("PRAGMA index_list(raw)").fetchall():
        if row[1] == "idx_msisdn" and row[2]:
            return
    conn.execute("DROP INDEX IF EXISTS idx_msisdn")
    dup = conn.execute("SELECT COUNT(*) - COUNT(DISTINCT msisdn) FROM raw").fetchone()[0]
    if dup:
        print(f"Database lama berisi {dup:,} baris duplikat, dirapikan dulu...")
        conn.execute("DELETE FROM raw WHERE rowid NOT IN (SELECT MAX(rowid) FROM raw GROUP BY msisdn)")
    conn.execute("CREATE UNIQUE INDEX idx_msisdn ON raw(msisdn)")
    conn.commit()


def count(conn):
    return conn.execute("SELECT COUNT(*) FROM raw").fetchone()[0]


def main():
    ap = argparse.ArgumentParser(description="Impor raw data CSV (file / folder) ke msisdn.db")
    ap.add_argument("paths", nargs="+", help="file CSV, folder berisi CSV, atau pola seperti raw_*.csv")
    ap.add_argument("--db", default="msisdn.db")
    ap.add_argument("--delimiter", default=None)
    ap.add_argument("--recursive", action="store_true", help="ikut baca subfolder")
    ap.add_argument("--reset", action="store_true", help="kosongkan database dulu")
    ap.add_argument("--append", action="store_true", help="(opsional) perilaku ini sudah default")
    a = ap.parse_args()

    files = collect_files(a.paths, a.recursive, skip={str(Path(a.db).resolve()).lower()})
    if not files:
        sys.exit("Tidak ada file CSV yang bisa diimpor.")
    print(f"Ditemukan {len(files)} file CSV:")
    for f in files:
        print(f"  - {f}")

    conn = sqlite3.connect(a.db)
    conn.execute("PRAGMA journal_mode=OFF")
    conn.execute("PRAGMA synchronous=OFF")
    if a.reset:
        conn.execute("DROP TABLE IF EXISTS raw")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS raw (msisdn TEXT, "
        + ", ".join(f"{c} TEXT" for c in OUT_COLS) + ")"
    )
    have = {r[1] for r in conn.execute("PRAGMA table_info(raw)")}
    for c in OUT_COLS:  # database lama: tambahkan kolom yang belum ada
        if c not in have:
            conn.execute(f"ALTER TABLE raw ADD COLUMN {c} TEXT")
            print(f"Kolom baru ditambahkan ke database: {c}")
    ensure_unique_index(conn)

    results, t0 = [], time.time()
    for n, f in enumerate(files, 1):
        print(f"\n[{n}/{len(files)}] {f}")
        before = count(conn)
        try:
            read, bad = import_file(conn, str(f), a.delimiter)
        except FileProblem as e:
            conn.rollback()
            print(f"  DILEWATI: {e}")
            results.append((f.name, "dilewati", 0, 0, 0, str(e)))
            continue
        added = count(conn) - before
        print(f"  -> MSISDN baru: {added:,} | sudah ada (diperbarui bila ga_date lebih baru/sama): {read - added:,}")
        results.append((f.name, "ok", read, added, bad, ""))

    ok = [r for r in results if r[1] == "ok"]
    fail = [r for r in results if r[1] != "ok"]
    print("\n" + "=" * 60)
    print(f"RINGKASAN  ({time.time()-t0:.1f} detik)")
    print(f"  File berhasil : {len(ok)} dari {len(files)}")
    print(f"  Baris dibaca  : {sum(r[2] for r in ok):,}")
    print(f"  MSISDN baru   : {sum(r[3] for r in ok):,}")
    print(f"  Baris invalid : {sum(r[4] for r in ok):,}")
    print(f"  Total MSISDN unik di database: {count(conn):,}")
    if fail:
        print(f"\n  {len(fail)} file DILEWATI:")
        for name, _, _, _, _, why in fail:
            print(f"    - {name}: {why}")
    conn.close()
    if fail:
        sys.exit(1)


if __name__ == "__main__":
    main()
