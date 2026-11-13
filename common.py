import re

OUT_COLS = ["ga_date", "ga_outlet", "ga_outlet_program", "ga_site_id", "ga_site_branch",
            "first_tag_id", "latest_tag_id"]


def norm_msisdn(value):
    """Normalisasi ke format 62xxxxxxxxx. Return None jika tidak valid."""
    if value is None:
        return None
    d = re.sub(r"\D", "", str(value))
    if d.startswith("620"):
        d = "62" + d[3:]
    elif d.startswith("0"):
        d = "62" + d[1:]
    elif d.startswith("8"):
        d = "62" + d
    if not d.startswith("62") or not (10 <= len(d) <= 15):
        return None
    return d


def norm_outlet(value):
    """Samakan format ID outlet: trim spasi, buang akhiran '.0' (hasil Excel). Return None jika kosong."""
    if value is None:
        return None
    v = str(value).strip()
    if v.endswith(".0") and v[:-2].isdigit():
        v = v[:-2]
    return v or None
