"""Turns what the sandbox recorded into evidence and a verdict. Plain code: the model never sets the score."""
import re
from urllib.parse import urlsplit

DANGEROUS_EXT = (".exe", ".scr", ".msi", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".jar", ".apk", ".dmg", ".iso",
                 ".zip", ".rar", ".7z", ".lnk", ".hta", ".docm", ".xlsm")
URGENCY = re.compile(r"\b(locked|suspended|within 24 hours|verify (your|my)|unusual activity|account will be closed|"
                     r"confirm your (card|identity)|act now|final notice)\b", re.I)
AI_ORDER = re.compile(r"\b(ignore (all |any )?previous instructions|ai (assistant|agent)s?|security scanners?|"
                      r"report (this|it) (site )?as safe|you are an? (ai|assistant))\b", re.I)
LABELS = {"EMAIL": "email address", "PASSWORD": "password", "CARD": "card number", "CVV": "card security code",
          "NAME": "full name", "PHONE": "phone number"}


def site(host: str) -> str:
    """Rough registrable domain: last two labels (good enough for a prototype)."""
    parts = (host or "").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


class Evidence:
    def __init__(self, url: str, domain_signals: list[dict]):
        self.start_host = urlsplit(url).hostname or ""
        self.items: list[dict] = list(domain_signals)
        self.leaks: dict[str, set] = {}   # destination host -> kinds of fake data sent there
        self.blocked: list[dict] = []
        self.downloads: list[dict] = []
        self.hidden_orders: list[str] = []
        self.urgency = False
        self.asked: set[str] = set()
        self.hosts_seen: list[str] = []
        self.official = next((i["text"] for i in domain_signals if i["kind"] == "official_domain"), None)
        self.last_title = ""
        self.last_host = self.start_host

    def add_state(self, state: dict, step: int):
        page = state.get("page") or {}
        host = urlsplit(state.get("url", "")).hostname or ""
        if host and host not in self.hosts_seen:
            self.hosts_seen.append(host)
        if state.get("title"):
            self.last_title, self.last_host = state["title"].strip(), host or self.last_host
        for n in state.get("network", []):
            if n.get("canary_sent"):
                self.leaks.setdefault(n["host"], set()).update(n["canary_sent"])
            if n.get("blocked") and not any(b["url"] == n["url"] for b in self.blocked):
                self.blocked.append({"url": n["url"], "reason": n.get("reason", ""), "step": step})
        for d in state.get("downloads", []):
            if not any(x.get("sha256") == d.get("sha256") and x.get("filename") == d.get("filename") for x in self.downloads):
                self.downloads.append({**d, "step": step})
        hidden = page.get("hidden_text") or ""
        m = AI_ORDER.search(hidden)
        if m and not self.hidden_orders:
            i = max(0, m.start() - 60)
            self.hidden_orders.append(hidden[i:i + 220].strip())
        if URGENCY.search(page.get("visible_text") or ""):
            self.urgency = True
        for f in page.get("fields", []):
            t = (f.get("type", "") + " " + f.get("autocomplete", "") + " " + f.get("name", "")).lower()
            if "password" in t:
                self.asked.add("PASSWORD")
            if "cc-number" in t or "card" in t:
                self.asked.add("CARD")

    def verdict(self) -> dict:
        items = list(self.items)
        start_site = site(self.start_host)
        for dest, kinds in self.leaks.items():
            what = ", ".join(LABELS.get(k, k.lower()) for k in sorted(kinds))
            if site(dest) != start_site:
                items.append({"kind": "credentials_sent_elsewhere", "weight": 60,
                              "text": f"When we typed a FAKE {what}, the page secretly sent it to another server: {dest}."})
            else:
                items.append({"kind": "credentials_collected", "weight": 15,
                              "text": f"The page collects a {what} on its own server ({dest})."})
        if self.blocked:
            targets = sorted({urlsplit(b["url"]).hostname or b["url"] for b in self.blocked})
            items.append({"kind": "internal_probe", "weight": 25,
                          "text": f"The page tried to reach internal or cloud-secret addresses ({', '.join(targets[:4])}). "
                                  "The sandbox blocked every attempt."})
        for d in self.downloads:
            name = d.get("filename", "")
            low = name.lower()
            danger = low.endswith(DANGEROUS_EXT)
            double = bool(re.search(r"\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.[a-z0-9]{2,4}$", low))
            w = 35 + (15 if danger else 0) + (10 if double else 0)
            text = f"The page pushed a download: '{name}'" + (" (a program disguised as a document)" if double and danger else
                                                              " (a program or archive)" if danger else "") + \
                   ". It stayed inside the sandbox and was destroyed with it."
            items.append({"kind": "download", "weight": w, "text": text, "sha256": d.get("sha256", "")})
        if self.hidden_orders:
            items.append({"kind": "hidden_ai_order", "weight": 20,
                          "text": "The page hides a message telling AI scanners to call it safe. Decoy treats page text "
                                  "as data and ignored it.", "quote": self.hidden_orders[0]})
        if self.urgency:
            items.append({"kind": "pressure", "weight": 10, "text": "The page uses pressure (locked account, deadline) to rush you."})
        if "CARD" in self.asked and any(i["kind"] == "lookalike_domain" for i in items):
            items.append({"kind": "card_on_lookalike", "weight": 15, "text": "A look-alike site asks for your card number."})
        if len({site(h) for h in self.hosts_seen}) > 1:
            items.append({"kind": "redirect", "weight": 5, "text": "The link moved you through: " + " → ".join(self.hosts_seen[:5]) + "."})
        score = min(100, sum(i["weight"] for i in items))
        level = "DANGEROUS" if score >= 60 else "SUSPICIOUS" if score >= 25 else \
            "LOOKS SAFE" if self.official and score < 10 else "NO THREAT FOUND"
        items = sorted((i for i in items if i["weight"] > 0), key=lambda i: -i["weight"])
        got = [{"host": h, "data": sorted(k)} for h, k in self.leaks.items() if site(h) != start_site]
        # What was checked and passed (shown on clean results so the answer is concrete).
        checks = [self.official or "The address does not imitate a well-known brand."] if not any(
            i["kind"] == "lookalike_domain" for i in items) else []
        if not self.leaks:
            checks.append("No data we typed was sent to another site." if self.asked else "It did not ask for a password or card.")
        if not self.downloads:
            checks.append("It did not push any download.")
        if not self.blocked:
            checks.append("It did not try to reach private or cloud-secret addresses.")
        if not self.hidden_orders:
            checks.append("No hidden instructions for AI scanners.")
        return {"level": level, "score": score, "evidence": items, "attacker_got": got, "checks": checks,
                "page_title": self.last_title, "page_host": self.last_host, "official": self.official,
                "blocked": self.blocked, "downloads": self.downloads}


def template_summary(v: dict) -> str:
    page = f"'{v['page_title']}'" if v.get("page_title") else "a normal page"
    if v["level"] == "LOOKS SAFE":
        brand = v["official"].split("official ", 1)[1].split(" address", 1)[0] if v.get("official") else "official"
        return (f"This is a real {brand} link. We opened it in a sealed browser and it is a normal page: {page}. "
                "It did not ask for your password, push a download or send data to other sites. Nothing to worry about.")
    if v["level"] == "NO THREAT FOUND":
        return (f"We opened it in a sealed browser: it is {page} on {v.get('page_host') or 'this site'}. It did not ask for "
                "a password or card, push a download or send data to other sites, so it looks fine. As always, do not type "
                "passwords on a page you reached from a message.")
    lead = "Do not open this link." if v["level"] == "DANGEROUS" else "Be careful with this link."
    return lead + " " + v["evidence"][0]["text"] + " The reasons are listed below."
