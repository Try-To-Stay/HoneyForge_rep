"""Offline GeoIP / ASN enrichment (TЗ §7.3 — IP/гео/ASN источника).

Uses the public-domain iptoasn.com IPv4 dataset (bundled at build) to map a
source IP to its country and ASN without any online lookup — works even on the
internal mgmt network. Loaded lazily on first use; degrades gracefully to
(None, None, None) if the dataset is absent.
"""
from __future__ import annotations

import bisect
import gzip
import ipaddress
import os
import threading

_PATH = os.getenv("GEOIP_PATH", "/geodata/ip2asn-v4.tsv.gz")
_starts: list[int] = []
_rows: list[tuple] = []  # (end_int, asn, country, org)
_loaded = False
_lock = threading.Lock()


def _load() -> None:
    global _loaded
    if _loaded:
        return
    with _lock:
        if _loaded:
            return
        try:
            with gzip.open(_PATH, "rt", encoding="utf-8", errors="replace") as f:
                for line in f:
                    p = line.rstrip("\n").split("\t")
                    if len(p) < 5:
                        continue
                    try:
                        s = int(ipaddress.IPv4Address(p[0]))
                        e = int(ipaddress.IPv4Address(p[1]))
                    except ValueError:
                        continue
                    _starts.append(s)
                    _rows.append((e, p[2], p[3], p[4]))
        except Exception:  # noqa: BLE001 - dataset missing/corrupt -> no enrichment
            pass
        _loaded = True


def lookup(ip: str | None) -> tuple[str | None, str | None, str | None]:
    """Return (asn, country_code, as_org) for an IPv4, or (None, None, None)."""
    if not ip:
        return (None, None, None)
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return (None, None, None)
    if addr.version != 4 or addr.is_private or addr.is_loopback:
        return (None, None, None)
    _load()
    if not _starts:
        return (None, None, None)
    v = int(addr)
    i = bisect.bisect_right(_starts, v) - 1
    if i < 0:
        return (None, None, None)
    end, asn, cc, org = _rows[i]
    if v > end:
        return (None, None, None)
    asn = f"AS{asn}" if asn and asn != "0" else None
    cc = cc if cc and cc != "None" else None
    return (asn, cc, org or None)
