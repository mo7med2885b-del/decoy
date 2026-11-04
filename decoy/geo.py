"""Where in the world is a host? Passive DNS from the control plane plus a public GeoIP lookup.
We never connect to the host's IP: we only resolve its name and look the address up. Our own fake demo hosts (*.test)
have no real address, so they get a clearly labelled SIMULATED location in a major hosting hub."""
import hashlib
import ipaddress
import re
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

import httpx

from .config import env

SIM = {  # fictional demo hosts -> big hosting hubs (simulated, labelled as such in the UI)
    "n0rthbank-login.test": ("Amsterdam", "NL", 52.37, 4.90), "invoice-portal.test": ("Ashburn", "US", 39.04, -77.49),
    "drop-zone.test": ("Singapore", "SG", 1.35, 103.82), "cloaked-promo.test": ("São Paulo", "BR", -23.55, -46.63),
    "go-short.test": ("Dublin", "IE", 53.35, -6.26), "daily-recipes.test": ("Paris", "FR", 48.85, 2.35),
}
HUBS = [("Tokyo", "JP", 35.68, 139.69), ("Toronto", "CA", 43.65, -79.38), ("Sydney", "AU", -33.87, 151.21), ("Mumbai", "IN", 19.08, 72.88)]
_CACHE: dict[str, dict | None] = {}


def origin() -> dict:
    """Where the visitors (our sandboxes) come from: the Vultr server."""
    city, code, lat, lng = (env("DECOY_ORIGIN", "Frankfurt,DE,50.11,8.68").split(",") + ["", "", "0", "0"])[:4]
    return {"city": city, "code": code, "lat": float(lat), "lng": float(lng), "label": f"Vultr · {city}"}


def _public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast)
    except ValueError:
        return False


def locate(host: str) -> dict | None:
    host = (host or "").lower().strip(".")
    if not host or host in _CACHE:
        return _CACHE.get(host)
    out = None
    if host.endswith(".test"):
        city, code, lat, lng = SIM.get(host) or HUBS[int(hashlib.md5(host.encode()).hexdigest(), 16) % len(HUBS)]
        out = {"host": host, "ip": "simulated", "city": city, "code": code, "country": code, "lat": lat, "lng": lng, "org": "demo site", "simulated": True}
    elif not re.match(r"^[\d.]+$", host) or _public(host):
        try:
            socket.setdefaulttimeout(2.5)
            ip = host if re.match(r"^[\d.]+$", host) else next(a[4][0] for a in socket.getaddrinfo(host, None) if ":" not in a[4][0])
            if _public(ip):
                r = httpx.get(f"https://ipwho.is/{ip}", timeout=4).json()
                if r.get("success") and r.get("latitude") is not None:
                    out = {"host": host, "ip": ip, "city": r.get("city") or "", "code": r.get("country_code") or "", "country": r.get("country") or "",
                           "lat": r["latitude"], "lng": r["longitude"], "org": ((r.get("connection") or {}).get("org") or "")[:40], "simulated": False}
        except Exception:
            out = None
    _CACHE[host] = out
    return out


class Tracker:
    """Locates hosts in the background and emits a `geo` event for each (at most 8 per scan)."""
    def __init__(self, emit):
        self.emit, self.roles, self.lock = emit, {}, threading.Lock()
        self.pool, self.futs, self.locs = ThreadPoolExecutor(max_workers=2), [], {}

    def seen(self, host: str, role: str):
        rank = {"lure": 1, "redirect": 2, "contacted": 3, "exfil": 4}
        with self.lock:
            prev = self.roles.get(host)
            if (prev and rank[role] <= rank[prev]) or (not prev and len(self.roles) >= 8):
                return
            self.roles[host] = role
        self.futs.append(self.pool.submit(self._work, host, role))

    def _work(self, host, role):
        loc = locate(host)
        if loc:
            self.locs[host] = {**loc, "role": role}
            self.emit({"type": "geo", "role": role, **loc})

    def wait(self, timeout=8):
        for f in self.futs:
            try:
                f.result(timeout=timeout)
            except Exception:
                pass
        self.pool.shutdown(wait=False)
