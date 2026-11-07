"""Brand-claim check. A model reads the page title, the address and the lure analyst's note and says which well-known brand (if any) the page claims to be
and what that brand's own domain is. CODE then checks the claim: the brand name must really be in the title or address, and the address must not belong to the
brand's domain. A model can only propose the claim; code owns the weight."""
import json
import re

from . import llm
from .guide import with_guide
from .verdict import site

SYSTEM = ("You check whether a web page pretends to be a well-known company or service. You get the page title, the address and a short note from another analyst in <DATA>. "
          'Answer with JSON only: {"claims_brand": true or false, "brand": "<name or empty>", "official_domain": "<the brand\'s real registered domain, e.g. example.com, or empty>"}. '
          "claims_brand is true only if the title or address presents the page AS that company or service (its payment, refund, login or support page). "
          "A page that merely mentions a brand, a fan page, a tutorial, a news story or the company's own real site is false. If unsure, answer false.")
DOMAIN = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$")


def claim(budget, url_host: str, title: str, lure_note: str, official: bool, model: str | None = None) -> dict | None:
    """Return a verdict item when the page claims a brand whose domain it does not own, else None."""
    if official or not (title or "").strip() or not llm.available():
        return None
    data = {"title": (title or "")[:140], "address": url_host, "analyst_note": (lure_note or "")[:300]}
    try:
        p = llm.parse_json(llm.chat(budget, with_guide(SYSTEM), "<DATA>\n" + json.dumps(data) + "\n</DATA>", max_tokens=250, model=model)) or {}
    except Exception:
        return None
    brand = re.sub(r"\s+", " ", str(p.get("brand") or "")).strip()[:40]
    dom = str(p.get("official_domain") or "").strip().lower()
    if p.get("claims_brand") is not True or len(brand) < 3 or not DOMAIN.match(dom):
        return None
    host = (url_host or "").lower()
    if host == dom or host.endswith("." + dom) or site(host) == site(dom):
        return None  # the page is on the brand's own domain
    if brand.lower() not in (title or "").lower() and brand.lower().replace(" ", "") not in host.replace("-", ""):
        return None  # the model named a brand the title and address never mention: ignore it
    return {"kind": "brand_claim", "weight": 20,
            "text": f"The page presents itself as {brand} but its address is {host}, not {dom}. Real {brand} pages live on {dom}."}
