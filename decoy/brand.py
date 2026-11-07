"""Brand-claim check. A model reads the page title, the address and the lure analyst's note and says which well-known brand, app or service (if any) the page
presents itself as (its official site, download, login or support page, in any language), and what that brand's own domains are. CODE then checks the claim:
the model must QUOTE the words of the title or address that make the claim, the quote must really be there, and the address must not belong to the brand's domains.
A model can only propose the claim; code owns the weight."""
import difflib
import json
import re

from . import llm
from .guide import with_guide
from .verdict import site

SYSTEM = ("You check whether a web page pretends to be a well-known company, app or service. You get the page title, the address and a short note from another analyst in <DATA>. "
          'Answer with JSON only: {"claims_brand": true or false, "brand": "<name or empty>", "official_domains": ["<the brand\'s real registered domains, e.g. example.com>"], "quote": "<the exact words of the title or address that make the claim>"}. '
          "claims_brand is true only if the title or address presents the page AS that company, app or service: its official site, official download, payment, refund, login or support page, in any language. "
          "A page that merely mentions a brand, a fan page, a tutorial, a news story or the company's own real site is false. If unsure, answer false.")
DOMAIN = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$")


def claim(budget, url_host: str, title: str, lure_note: str, official: bool, model: str | None = None) -> dict | None:
    """Return a verdict item when the page claims a brand whose domain it does not own, else None."""
    if official or not (title or "").strip() or not llm.available():
        return None
    data = {"title": (title or "")[:140], "address": url_host, "analyst_note": (lure_note or "")[:300]}
    p = {}
    for m in (model, "glm-5.3-flash", "qwen3.8-flash-next"):  # models sometimes answer empty or cut off: ask the next one instead of giving up
        try:
            p = llm.parse_json(llm.chat(budget, with_guide(SYSTEM), "<DATA>\n" + json.dumps(data) + "\n</DATA>", max_tokens=600, model=m)) or {}
        except Exception:
            p = {}
        if "claims_brand" in p:
            break
    if "claims_brand" not in p:
        return None
    brand = re.sub(r"\s+", " ", re.sub(r"\(.*?\)", "", str(p.get("brand") or ""))).strip()[:40]
    doms = [str(d).strip().lower() for d in (p.get("official_domains") or [p.get("official_domain")]) if d][:6]
    doms = [d for d in doms if DOMAIN.match(d)]
    quote = re.sub(r"\s+", " ", str(p.get("quote") or "")).strip().lower()
    if p.get("claims_brand") is not True or len(brand) < 2 or not doms:
        return None
    host = (url_host or "").lower()
    for dom in doms:
        if host == dom or host.endswith("." + dom) or site(host) == site(dom):
            return None  # the page is on one of the brand's own domains
        labels = host.removeprefix("www.").split(".")
        if len(labels) == 2 and len(labels[1]) == 2 and labels[0] == dom.split(".")[0]:
            return None  # the brand's plain country domain (amazon.de, google.fr); look-alikes such as roblox.com.gr are not exempt
    flat = re.sub(r"[^a-z0-9]", "", brand.lower())
    near = any(difflib.SequenceMatcher(None, flat, w).ratio() >= 0.8 for w in re.findall(r"[a-z0-9]+", host) if len(w) >= 4)  # a typo of the brand in the address
    said = (title or "").lower() + " " + host
    if not ((len(quote) >= 3 and quote in said) or brand.lower() in said or flat in re.sub(r"[^a-z0-9]", "", said) or near):
        return None  # nothing in the title or address backs the model's claim: ignore it
    return {"kind": "brand_claim", "weight": 30,
            "text": f"The page presents itself as {brand} but its address is {host}, not {doms[0]}. The real {brand} lives on {doms[0]}."}
