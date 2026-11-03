"""Checks a submitted link in plain code before any sandbox starts, and scores the domain."""
import ipaddress
import re
from urllib.parse import urlsplit

from .config import DEMO_SUFFIX

# Brands that phishing pages copy most. "northbank" is our fictional demo brand.
BRANDS = {"northbank": "northbank.test", "paypal": "paypal.com", "microsoft": "microsoft.com", "apple": "apple.com",
          "google": "google.com", "amazon": "amazon.com", "netflix": "netflix.com", "facebook": "facebook.com",
          "instagram": "instagram.com", "whatsapp": "whatsapp.com", "dhl": "dhl.com", "fedex": "fedex.com",
          "outlook": "outlook.com", "office365": "office.com", "binance": "binance.com", "coinbase": "coinbase.com"}
LOOKALIKE = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy", "shorturl.at"}


class BadLink(ValueError):
    pass


def normalize(raw: str) -> str:
    url = (raw or "").strip()
    if not url:
        raise BadLink("Paste a link first.")
    if len(url) > 2000:
        raise BadLink("That link is too long.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise BadLink("Only web links (http or https) can be opened.")
    host = (parts.hostname or "").lower()
    if not host or "." not in host and host != "localhost":
        raise BadLink("That does not look like a web address.")
    if host.endswith(DEMO_SUFFIX):
        return url  # our own fake demo sites
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise BadLink("Links to private or internal addresses are not allowed.")
    except ValueError:
        if host == "localhost" or host.endswith((".local", ".internal", ".localhost")):
            raise BadLink("Links to private or internal addresses are not allowed.")
    return url


def domain_signals(url: str) -> list[dict]:
    """Facts about the address itself, before the page is even opened."""
    host = (urlsplit(url).hostname or "").lower()
    out = []
    plain = host.translate(LOOKALIKE)
    for brand, official in BRANDS.items():
        if brand in plain and not (host == official or host.endswith("." + official)):
            swapped = brand not in host
            out.append({"kind": "lookalike_domain", "weight": 30 if swapped else 20,
                        "text": f"The address '{host}' imitates {brand.title()}"
                                + (" by swapping letters for numbers" if swapped else "") + f", but it is not {official}."})
            break
    if urlsplit(url).scheme == "http":
        out.append({"kind": "no_https", "weight": 5, "text": "The link is not encrypted (http, not https)."})
    if host in SHORTENERS:
        out.append({"kind": "shortener", "weight": 5, "text": f"The link uses a shortener ({host}) that hides the real address."})
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        out.append({"kind": "raw_ip", "weight": 10, "text": "The link points to a bare IP address instead of a name."})
    return out
