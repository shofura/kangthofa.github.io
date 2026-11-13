"""
Impor data program outlet ke outlet_program.db (dipakai untuk mengisi ga_outlet_program).

Alur lookup di aplikasi:  ga_outlet (ga_pairing_id)  ->  kolom 'ID Outlet'  ->  hasil kolom 'Program'

Contoh:
    python import_outlet_program.py outlet_program.csv
    python import_outlet_program.py outlet_program.csv --replace    # kosongkan dulu data lama

Default-nya data digabung: ID Outlet yang sudah ada akan diperbarui, yang baru ditambahkan.
Header CSV: ID Outlet, Outlet Name, Micro Cluste(r), Partner Territory, Branch, Program, Periode
"""
import argparse
import csv
import os
import sqlite3
import sys
from pathlib import Path

from common import norm_outlet

DB_DEFAULT = os.environ.get("OUTLET_DB", str(Path(__file__).parent / "outlet_program.db"))

COLUMN_MAP = {
    "id_outlet":         ["id outlet", "id_outlet", "outlet id"],
    "outlet_name":       ["outlet name", "outlet_name"],
    "micro_cluster":     ["micro cluster", "micro cluste", "micro_cluster"],
    "partner_territory": ["partner territory", "partner_territory"],
    "branch":            ["branch"],
    "program":           ["program"],
    "periode":           ["periode", "period"],
}
REQUIRED = ["id_outlet", "program"]

UPSERT = (
    "INSERT INTO outlet_program (id_outlet, outlet_name, micro_cluster, partner_territory, branch, program, periode) "
    "VALUES (?,?,?,?,?,?,?) "
    "ON CONFLICT(id_outlet) DO UPDATE SET outlet_name=excluded.outlet_name, "
    "micro_cluster=excluded.micro_cluster, partner_territory=excluded.partner_territory, "
    "branch=excluded.branch, program=excluded.program, periode=excluded.periode"
)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--db", default=DB_DEFAULT)
    ap.add_argument("--replace", action="store_true", help="kosongkan data lama sebelum impor")
    a = ap.parse_args()

    conn = sqlite3.connect(a.db)
    if a.replace:
        conn.execute("DROP TABLE IF EXISTS outlet_program")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS outlet_program (id_outlet TEXT PRIMARY KEY, outlet_name TEXT, "
        "micro_cluster TEXT, partner_territory TEXT, branch TEXT, program TEXT, periode TEXT)"
    )
    for path in a.files:
        with open(path, "r", encoding="utf-8-sig", newline="", errors="replace") as f:
            head = f.readline()
            f.seek(0)
            delim = max([",", ";", "|", "\t"], key=head.count)
            reader = csv.reader(f, delimiter=delim)
            header = [h.strip().lower() for h in next(reader)]
            idx = {}
            for target, cands in COLUMN_MAP.items():
                hit = next((c for c in cands if c in header), None)
                if hit:
                    idx[target] = header.index(hit)
                elif target in REQUIRED:
                    sys.exit(f"[{path}] kolom untuk '{target}' tidak ketemu. Dicari: {cands}. Header: {header}")
            rows, skipped = [], 0
            for r in reader:
                try:
                    vals = {k: (r[i].strip() or None) for k, i in idx.items()}
                except IndexError:
                    skipped += 1
                    continue
                oid = norm_outlet(vals.get("id_outlet"))
                if not oid:
                    skipped += 1
                    continue
                rows.append((oid, vals.get("outlet_name"), vals.get("micro_cluster"),
                             vals.get("partner_territory"), vals.get("branch"),
                             vals.get("program"), vals.get("periode")))
        before = conn.execute("SELECT COUNT(*) FROM outlet_program").fetchone()[0]
        conn.executemany(UPSERT, rows)
        conn.commit()
        after = conn.execute("SELECT COUNT(*) FROM outlet_program").fetchone()[0]
        print(f"[{path}] dibaca {len(rows):,} baris, tidak valid {skipped:,} -> outlet baru: {after-before:,}, diperbarui: {len(rows)-(after-before):,}")
    print(f"Selesai. Total outlet di database: {after:,}  ({a.db})")
    conn.close()


if __name__ == "__main__":
    main()
