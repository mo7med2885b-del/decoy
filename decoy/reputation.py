"""Reputation signals for a host, computed in plain code: free-hosting subdomains, domain age (RDAP), and what a page's
text says about itself (parked, placeholder, loading screen). None of this needs the page to misbehave: many scam sites
sit empty or parked until they are used, so "nothing bad happened" must never be reported as "trusted"."""
import re
from datetime import datetime, timezone

import httpx

# Services where anyone can publish a page on a subdomain in minutes. Real brands rarely live there; scams often do.
FREE_HOSTS = ("ct.ws", "epizy.com", "infinityfreeapp.com", "rf.gd", "wuaze.com", "great-site.net", "42web.io", "lovestoblog.com", "000webhostapp.com",
              "pages.dev", "workers.dev", "web.app", "firebaseapp.com", "netlify.app", "vercel.app", "glitch.me", "herokuapp.com", "weebly.com",
              "wixsite.com", "blogspot.com", "ngrok-free.app", "ngrok.io", "trycloudflare.com", "duckdns.org", "myshopify.com", "webflow.io",
              "godaddysites.com", "yolasite.com", "jimdosite.com", "site123.me", "carrd.co", "000webhost.com", "byethost7.com", "x10.mx")
PARKED = re.compile(r"(domain (name )?(is )?(for sale|parked|available)|this domain (is|may be) for sale|buy this domain|parked (free|domain)|account (has been )?suspended|"
                    r"website (is )?(coming soon|under construction)|coming soon|default web ?(server )?page|welcome to nginx|apache2? (ubuntu )?default|index of /|it works!)", re.I)
INTERSTITIAL = re.compile(r"^(loading|just a moment|checking (your )?browser|redirecting|please wait|attention required|one moment)", re.I)
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu"}


def free_host(host: str) -> str | None:
    host = (host or "").lower()
    for d in FREE_HOSTS:
        if host == d or host.endswith("." + d):
            return d
    return None


def registrable(host: str) -> str:
    p = (host or "").lower().split(".")
    if len(p) >= 3 and p[-2] in SECOND_LEVEL and len(p[-1]) == 2:
        return ".".join(p[-3:])
    return ".".join(p[-2:]) if len(p) >= 2 else host


def domain_age_days(host: str) -> int | None:
    """Age of the registered domain from public RDAP data. None when unknown (never guessed)."""
    host = (host or "").lower()
    if not host or host.endswith(".test") or re.match(r"^[\d.]+$", host) or free_host(host):
        return None
    try:
        r = httpx.get(f"https://rdap.org/domain/{registrable(host)}", timeout=5, follow_redirects=True)
        if r.status_code != 200:
            return None
        for e in r.json().get("events", []):
            if e.get("eventAction") == "registration":
                d = datetime.fromisoformat(e["eventDate"].replace("Z", "+00:00"))
                return max(0, (datetime.now(timezone.utc) - d).days)
    except Exception:
        return None
    return None


def age_signal(days: int | None, host: str) -> dict | None:
    if days is None:
        return None
    if days < 30:
        return {"kind": "new_domain", "weight": 25, "text": f"The domain {registrable(host)} was registered only {days} day(s) ago. Scam sites are usually brand new."}
    if days < 120:
        return {"kind": "new_domain", "weight": 10, "text": f"The domain {registrable(host)} is only {days} days old."}
    return None
