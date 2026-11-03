"""Threat memory: every finished scan is kept in SQLite, so Decoy can say "we have seen this before" and link
different scam links that send stolen data to the same server (a campaign). History survives restarts."""
import json
import sqlite3
import threading
import time
from urllib.parse import urlsplit

from .config import RUNS

_LOCK = threading.Lock()
DB = RUNS / "decoy.db"


def _site(host: str) -> str:
    parts = (host or "").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host or ""


def _conn(path=None):
    p = path or DB
    p.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(p, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("""CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY, at REAL, url TEXT, host TEXT, site TEXT, level TEXT, score INTEGER, summary TEXT,
        exfil TEXT, cloaking INTEGER, decision TEXT, note TEXT, evidence TEXT)""")
    c.execute("CREATE INDEX IF NOT EXISTS scans_site ON scans(site)")
    return c


def save(scan_id: str, url: str, v: dict, path=None):
    host = urlsplit(url).hostname or ""
    exfil = sorted({g["host"] for g in v.get("attacker_got", [])})
    cloaked = int(any(e.get("kind") == "cloaking" for e in v.get("evidence", [])))
    with _LOCK, _conn(path) as c:
        c.execute("INSERT OR REPLACE INTO scans (id, at, url, host, site, level, score, summary, exfil, cloaking, decision, note, evidence) "
                  "VALUES (?,?,?,?,?,?,?,?,?,?,NULL,NULL,?)",
                  (scan_id, time.time(), url[:500], host, _site(host), v["level"], v["score"], v.get("summary", "")[:800],
                   json.dumps(exfil), cloaked, json.dumps([e["text"] for e in v.get("evidence", [])][:12])))


def decide(scan_id: str, decision: str, note: str, path=None):
    with _LOCK, _conn(path) as c:
        c.execute("UPDATE scans SET decision=?, note=? WHERE id=?", (decision, note[:300], scan_id))


def memory(url: str, exfil_hosts: list[str], exclude_id: str = "", path=None) -> dict:
    """What we already know: earlier scans of this site, and other sites that sent data to the same servers."""
    host = urlsplit(url).hostname or ""
    with _LOCK, _conn(path) as c:
        before = [dict(r) for r in c.execute(
            "SELECT id, at, url, level, score, decision FROM scans WHERE site=? AND id!=? ORDER BY at DESC LIMIT 5", (_site(host), exclude_id))]
        campaign = []
        for h in exfil_hosts:
            for r in c.execute("SELECT id, at, url, host, level FROM scans WHERE exfil LIKE ? AND id!=? ORDER BY at DESC LIMIT 8",
                               (f'%"{h}"%', exclude_id)):
                campaign.append({**dict(r), "shared_server": h})
    return {"seen_before": before, "campaign": campaign}


def history(limit: int = 12, path=None) -> list[dict]:
    with _LOCK, _conn(path) as c:
        return [dict(r) for r in c.execute(
            "SELECT id, at, url, host, level, score, decision, exfil, cloaking FROM scans ORDER BY at DESC LIMIT ?", (limit,))]


def get(scan_id: str, path=None) -> dict | None:
    with _LOCK, _conn(path) as c:
        r = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    return dict(r) if r else None
