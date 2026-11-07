"""Address read: a risk score and up to three plain reasons from the link ITSELF, in milliseconds, before any sandbox opens.
It is a transparent, hand-weighted checklist (every clue has a visible weight; nothing is trained, so nothing is hidden or overfitted) and it never touches the network.
It is a hint, not a verdict: the score shown to the person is still decided by what the sealed browser observed."""
import math
import re
from urllib.parse import parse_qs, urlsplit

from . import reputation
from .urlcheck import BRANDS, LOOKALIKE, SHORTENERS, official_brand

RISKY_ENDINGS = {"zip", "mov", "top", "xyz", "click", "loan", "work", "gq", "tk", "ml", "cf", "ga", "cfd", "sbs", "icu", "buzz", "rest", "monster", "country", "kim", "men", "date", "bid"}
WORDS = ("login", "signin", "sign-in", "verify", "verification", "secure", "account", "update", "confirm", "wallet", "payment", "invoice", "password", "billing", "unlock", "suspend", "recover", "support", "claim", "reward", "gift")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    return -sum(c / len(s) * math.log2(c / len(s)) for c in (s.count(ch) for ch in set(s)))


def read(url: str) -> dict:
    """Returns {"score": 0..100, "level": "calm|watch|risky", "reasons": [up to 3 plain sentences], "clues": [(name, weight, text)], "official": bool}."""
    try:
        u = urlsplit(url if "://" in url else "http://" + url)
        host = (u.hostname or "").lower()
    except ValueError:
        return {"score": 0, "level": "calm", "reasons": [], "clues": [], "official": False}
    brand = official_brand(host)
    if brand:
        return {"score": 0, "level": "calm", "reasons": [f"This is the official {brand[0]} address."], "clues": [], "official": True}
    labels = host.split(".")
    reg = ".".join(labels[-2:]) if len(labels) >= 2 else host
    sub = ".".join(labels[:-2])
    path = (u.path or "") + ("?" + u.query if u.query else "")
    clues: list[tuple[str, int, str]] = []

    def add(name, w, text):
        clues.append((name, w, text))

    if u.scheme == "http":
        add("no_https", 8, "The link is not encrypted (http).")
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        add("raw_ip", 25, "It points to a bare IP address instead of a name.")
    if "@" in url.split("?", 1)[0].split("://", 1)[-1].split("/", 1)[0]:
        add("at_sign", 25, "The address contains an @ sign, a trick that hides the real destination.")
    if "xn--" in host:
        add("punycode", 20, "The name uses look-alike international letters (punycode).")
    if host in SHORTENERS:
        add("shortener", 12, f"It is a shortened link ({host}) that hides where it goes.")
    ending = labels[-1] if labels else ""
    if ending in RISKY_ENDINGS:
        add("ending", 14, f"The ending .{ending} is cheap and often used for throwaway sites.")
    fh = reputation.free_host(host)
    if fh:
        add("free_hosting", 16, f"It is a free-hosting address ({fh}): anyone can publish a page there in minutes.")
    plain = host.translate(LOOKALIKE)
    for b, official in BRANDS.items():
        if b in plain and not (host == official or host.endswith("." + official)):
            swapped = b not in host
            add("lookalike", 34 if swapped else 26, f"The name imitates {b.title()}" + (" by swapping letters for numbers" if swapped else " inside a longer address") + f", but it is not {official}.")
            break
    if sub and any(b in sub for b in BRANDS) and not host.endswith(tuple("." + o for o in BRANDS.values())):
        add("brand_in_subdomain", 18, "A well-known name sits in the sub-address, in front of an unrelated domain.")
    if len(labels) >= 5:
        add("deep_subdomain", 10, f"The address has {len(labels)} parts, a common way to bury the real domain.")
    hy = reg.count("-") + sub.count("-")
    if hy >= 3:
        add("hyphens", 10, f"The name has {hy} hyphens, typical of made-up addresses.")
    digits = sum(c.isdigit() for c in reg)
    if len(reg) > 6 and digits / len(reg) > 0.3:
        add("digits", 10, "A large share of the domain is digits.")
    core = reg.split(".")[0]
    if len(core) >= 12 and _entropy(core) > 3.4:
        add("random_name", 12, "The domain name looks randomly generated.")
    if len(url) > 100:
        add("long", 8, f"The link is very long ({len(url)} characters).")
    low = path.lower()
    hits = [w for w in WORDS if w in low or w in sub]
    if hits:
        add("words", 8 + 3 * min(len(hits) - 1, 3), "The address uses pressure or sign-in words (" + ", ".join(hits[:3]) + ") on a site that is not an official one.")
    if re.search(r"\.(exe|apk|msi|scr|bat|zip|iso)(\?|$)", low):
        add("file", 22, "The link goes straight to a downloadable file.")
    q = parse_qs(u.query)
    if any(k.lower() in ("redirect", "url", "next", "goto", "continue", "return") and v and v[0].startswith("http") for k, v in q.items()):
        add("open_redirect", 14, "The link carries another web address inside it, a redirect trick.")
    if "//" in (u.path or "").strip("/"):
        add("double_slash", 6, "The path contains a double slash, sometimes used to confuse filters.")
    if u.port and u.port not in (80, 443):
        add("port", 8, f"It uses an unusual port ({u.port}).")
    if re.search(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])", u.query or ""):
        add("ip_in_query", 15, "The link carries a bare IP address inside it, typical of redirect and tracking kits.")
    if len(re.findall(r"[A-Za-z0-9]{24,}", path)) >= 1:
        add("long_token", 6, "The path holds a long random-looking token.")

    score = min(100, sum(w for _, w, _ in clues))
    top = sorted(clues, key=lambda c: -c[1])[:3]
    return {"score": score, "level": "risky" if score >= 45 else "watch" if score >= 20 else "calm", "reasons": [t for _, _, t in top],
            "clues": clues, "official": False}
