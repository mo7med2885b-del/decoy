"""Turns what the sandbox recorded into evidence and a verdict. Plain code: the model never sets the score."""
import re
from urllib.parse import urlsplit

from . import reputation

DANGEROUS_EXT = (".exe", ".scr", ".msi", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".jar", ".apk", ".dmg", ".iso",
                 ".zip", ".rar", ".7z", ".lnk", ".hta", ".docm", ".xlsm")
URGENCY = re.compile(r"\b(locked|suspended|within 24 hours|verify (your|my)|unusual activity|account will be closed|"
                     r"confirm your (card|identity)|act now|final notice)\b", re.I)
AI_ORDER = re.compile(r"\b(ignore (all |any )?previous instructions|ai (assistant|agent)s?|security scanners?|"
                      r"report (this|it) (site )?as safe|you are an? (ai|assistant))\b", re.I)
SHORT_HOSTS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy", "go-short.test"}
TELEMETRY = ("sentry.io", "datadoghq.com", "logrocket.", "fullstory.com", "hotjar.", "segment.", "mixpanel.com", "amplitude.com", "posthog.com", "clarity.ms",
             "google-analytics.com", "googletagmanager.com", "doubleclick.net", "newrelic.com", "nr-data.net", "bugsnag.com", "rollbar.com", "browser-intake", "heap.io", "smartlook.com")
EXFIL_CHANNELS = (("api.telegram.org", "a Telegram bot"), ("discord.com", "a Discord webhook"), ("discordapp.com", "a Discord webhook"), ("hooks.slack.com", "a Slack webhook"),
                  ("script.google.com", "a Google Apps Script endpoint"), ("formspree.io", "a form-mail relay"), ("web3forms.com", "a form-mail relay"), ("api.emailjs.com", "an email relay"))


# shared cloud backends: many unrelated sites (legitimate and not) use the same address, so it says nothing about who is behind a form
SHARED_BACKENDS = (".amazonaws.com", ".cloudfunctions.net", ".azurewebsites.net", ".herokuapp.com",
                   "formspree.io", "hsforms.com", "hsforms.net", "mailchimp.com", "list-manage.com", "typeform.com", "getform.io", "web3forms.com", "google.com", "googleapis.com")
SENSITIVE = {"PASSWORD", "CARD", "CVV"}


def is_shared_backend(host: str) -> bool:
    h = (host or "").lower()
    return any(h.endswith(s) or h == s.lstrip(".") for s in SHARED_BACKENDS)


PROVIDER_WARNING = re.compile(r"suspected phishing|phishing (site|warning|page)|deceptive site|dangerous site ahead|reported as (unsafe|phishing|deceptive)|site ahead contains", re.I)


def is_telemetry(host: str) -> bool:
    h = (host or "").lower()
    return any(h == t or h.endswith("." + t) or (t.endswith(".") and t in h) for t in TELEMETRY)


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
        self.redirects: list[dict] = []
        self.first_sig: tuple | None = None   # what this visitor saw first: (title, asked for a password)
        self.extra: list[dict] = []           # evidence added by the swarm (cloaking)
        self.net_log: list[dict] = []         # every request the page made (host, method, type, blocked)
        self.leak_urls: dict[str, set] = {}   # host -> URLs that received the fake data
        self.scripts: list[str] = []
        self.console: list[dict] = []
        self.gates: set[str] = set()
        self.parked = False
        self.max_text = 0
        self.final_title = ""
        self.interactive = False
        self.cookies: list[dict] = []
        self.endpoints: list[dict] = []   # non-page requests (xhr, fetch, beacons, forms) with status and redacted payload
        self.script_srcs: list[str] = []

    def add_state(self, state: dict, step: int):
        page = state.get("page") or {}
        host = urlsplit(state.get("url", "")).hostname or ""
        if host and host not in self.hosts_seen:
            self.hosts_seen.append(host)
        if state.get("title"):
            self.last_title, self.last_host = state["title"].strip(), host or self.last_host
        if state.get("redirects") and len(state["redirects"]) > len(self.redirects):
            self.redirects = list(state["redirects"])
        if self.first_sig is None and (state.get("title") or page.get("fields") is not None):
            self.first_sig = ((state.get("title") or "").strip().lower(), bool(page.get("has_password")))
        if page.get("gate"):
            self.gates.add(page["gate"])
        vt = (page.get("visible_text") or "").strip()
        self.max_text = max(self.max_text, len(vt))
        self.final_title = (state.get("title") or self.final_title or "").strip()
        if reputation.PARKED.search(vt[:1500]) or reputation.PARKED.search(self.final_title):
            self.parked = True
        if page.get("fields") or page.get("buttons") or len(page.get("links") or []) > 1:
            self.interactive = True
        for c in state.get("console") or []:
            if len(self.console) < 80:
                self.console.append(c)
        if state.get("cookies"):
            self.cookies = state["cookies"][:25]
        for s in page.get("scripts") or []:
            if s not in self.scripts and len(self.scripts) < 8:
                self.scripts.append(s)
        for s in page.get("script_srcs") or []:
            if s not in self.script_srcs:
                self.script_srcs.append(s)
        for n in state.get("network", []):
            if len(self.net_log) < 300:
                self.net_log.append({"host": n.get("host", ""), "method": n.get("method", ""), "type": n.get("type", ""), "blocked": bool(n.get("blocked"))})
            if n.get("type") in ("xhr", "fetch", "ping", "other") or n.get("post") or n.get("method") == "POST":
                ep = {"method": n.get("method", ""), "url": n.get("url", "")[:200], "host": n.get("host", ""), "type": n.get("type", ""), "status": n.get("status"),
                      "post": n.get("post", ""), "blocked": bool(n.get("blocked")), "leak": bool(n.get("canary_sent"))}
                if len(self.endpoints) < 40 and not any(e["url"] == ep["url"] and e["method"] == ep["method"] for e in self.endpoints):
                    self.endpoints.append(ep)
            if n.get("canary_sent"):
                self.leaks.setdefault(n["host"], set()).update(n["canary_sent"])
                self.leak_urls.setdefault(n["host"], set()).add(n.get("url", "")[:200])
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

    def absorb(self, other: "Evidence"):
        """Merge what another visitor of the swarm saw (worst case wins: one visitor being robbed is enough)."""
        for dest, kinds in other.leaks.items():
            self.leaks.setdefault(dest, set()).update(kinds)
        for b in other.blocked:
            if not any(x["url"] == b["url"] for x in self.blocked):
                self.blocked.append(b)
        for d in other.downloads:
            if not any(x.get("sha256") == d.get("sha256") and x.get("filename") == d.get("filename") for x in self.downloads):
                self.downloads.append(d)
        self.hidden_orders += [h for h in other.hidden_orders if h not in self.hidden_orders]
        self.urgency = self.urgency or other.urgency
        self.asked |= other.asked
        for h in other.hosts_seen:
            if h not in self.hosts_seen:
                self.hosts_seen.append(h)
        for h, urls in other.leak_urls.items():
            self.leak_urls.setdefault(h, set()).update(urls)
        self.net_log += [n for n in other.net_log if len(self.net_log) < 300]
        self.scripts += [s for s in other.scripts if s not in self.scripts][:max(0, 8 - len(self.scripts))]
        self.script_srcs += [s for s in other.script_srcs if s not in self.script_srcs]
        self.endpoints += [e for e in other.endpoints if len(self.endpoints) < 40 and not any(x["url"] == e["url"] and x["method"] == e["method"] for x in self.endpoints)]
        self.console += [c for c in other.console if len(self.console) < 80 and c not in self.console]
        self.cookies = self.cookies or other.cookies
        self.gates |= other.gates
        self.parked = self.parked or other.parked
        self.max_text = max(self.max_text, other.max_text)
        self.interactive = self.interactive or other.interactive
        if len(other.redirects) > len(self.redirects):
            self.redirects = other.redirects

    def verdict(self) -> dict:
        items = list(self.items) + list(self.extra)
        start_site = site(self.start_host)
        for dest, kinds in self.leaks.items():
            what = ", ".join(LABELS.get(k, k.lower()) for k in sorted(kinds))
            if is_telemetry(dest):
                items.append({"kind": "telemetry_leak", "weight": 12, "text": f"What was typed also reached an analytics or error-monitoring service ({dest}). That is common and not theft, but it means typed text can be recorded."})
            elif site(dest) != start_site and not (set(kinds) & SENSITIVE) and is_shared_backend(dest):
                # an email, name or phone sent to a shared form backend is what a normal newsletter or contact form does: a note, not theft
                items.append({"kind": "form_third_party", "weight": 8,
                              "text": f"The page's form sent the fake {what} to a shared form service ({dest}). Normal for newsletter and contact forms; no password or card was involved."})
            elif site(dest) != start_site:
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
        chain = []
        for r in self.redirects:
            if urlsplit(r.get("from") or "").hostname == urlsplit(r.get("to") or "").hostname:
                continue  # http to https on the same site is not a hop
            for u in (r.get("from"), r.get("to")):
                h = urlsplit(u or "").hostname
                if h and (not chain or chain[-1] != h):
                    chain.append(h)
        if len({site(h) for h in chain or self.hosts_seen}) > 1:
            hops = chain or self.hosts_seen
            short = any(h in SHORT_HOSTS or len(h) <= 9 for h in hops[:1]) and len(hops) > 1
            items.append({"kind": "redirect", "weight": 15 if short else 8,
                          "text": ("A link that hides its destination: " if short else "The link moved you through other sites: ") + " → ".join(hops[:5]) + "."})
        if PROVIDER_WARNING.search(self.final_title or "") and not self.official:
            items.append({"kind": "provider_warning", "weight": 40,
                          "text": f"The page the visitors reached is a security service's own warning ('{self.final_title[:60]}'): a hosting or browser security provider already treats this site as phishing."})
        limits = []
        if reputation.INTERSTITIAL.search(self.final_title or ""):
            limits.append(f"The page stayed on a loading or bot-check screen ('{self.final_title[:50]}'), so Decoy did not see the real content.")
            items.append({"kind": "interstitial", "weight": 10, "text": "The page only showed a loading or bot-check screen, so what it really is stayed hidden. Real pages usually load for a simple visitor."})
        elif self.official:
            pass  # official sites are recognised by address; a thin page there is not a warning
        elif self.parked:
            items.append({"kind": "parked_page", "weight": 15, "text": "The page looks parked or like an empty placeholder. Scam sites often sit empty until they are used, so it tells us little."})
        elif self.max_text < 60 and not self.interactive and not self.leaks and not self.downloads:
            items.append({"kind": "thin_page", "weight": 10, "text": "The page is almost empty: there is nothing to read or click. A site with no content cannot be judged as trustworthy."})
        if "captcha" in self.gates:
            limits.append("A bot check (CAPTCHA) appeared. Decoy does not solve those, so anything behind it was not seen.")
        if "verification" in self.gates:
            limits.append("The page asked for an email or SMS verification code. Decoy never creates real accounts or reads real inboxes, so it stopped there; what the page does after sign-up was not seen.")
        for e in self.endpoints:
            for dom, label in EXFIL_CHANNELS:
                if (e["host"] == dom or e["host"].endswith("." + dom)) and e.get("method") == "POST" and not any(i["kind"] == "exfil_channel" for i in items):
                    items.append({"kind": "exfil_channel", "weight": 30, "text": f"The page sends data to {label} ({e['host']}). Phishing kits use these to collect what victims type."})
        score = min(100, sum(i["weight"] for i in items))
        level = "DANGEROUS" if score >= 60 else "SUSPICIOUS" if score >= 25 else \
            "LOOKS SAFE" if self.official and score < 10 else "NO THREAT FOUND"
        items = sorted((i for i in items if i["weight"] > 0), key=lambda i: -i["weight"])
        got = [{"host": h, "data": sorted(k)} for h, k in self.leaks.items() if site(h) != start_site and not is_telemetry(h)]
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
        return {"level": level, "score": score, "evidence": items, "attacker_got": got, "checks": checks, "limits": limits,
                "page_title": self.last_title, "page_host": self.last_host, "official": self.official,
                "blocked": self.blocked, "downloads": self.downloads}


def template_summary(v: dict) -> str:
    page = f"'{v['page_title']}'" if v.get("page_title") else "a normal page"
    extra = (" Note: " + " ".join(v.get("limits", []))) if v.get("limits") else ""
    if v["level"] == "LOOKS SAFE":
        brand = v["official"].split("official ", 1)[1].split(" address", 1)[0] if v.get("official") else "official"
        return (f"This is a real {brand} link. We opened it in a sealed browser and it is a normal page: {page}. "
                "It did not ask for your password, push a download or send data to other sites. Nothing to worry about." + extra)
    if v["level"] == "NO THREAT FOUND":
        return (f"Nothing harmful happened during this visit: it is {page} on {v.get('page_host') or 'this site'}. It did not ask for "
                "a password or card, push a download or send data to other sites. That is not a trust rating: Decoy has no history for "
                "this site, so do not treat it as trusted, and never type passwords on a page you reached from a message." + extra)
    lead = "Do not open this link." if v["level"] == "DANGEROUS" else "Be careful with this link."
    return lead + " " + v["evidence"][0]["text"] + " The reasons are listed below."


def cloaking(personas: list[dict]) -> dict | None:
    """Compare what each visitor of the swarm saw first. A page that shows different things to different
    visitors (for example a harmless page to a security bot and a login form to a person) is cloaking.
    personas: [{"name", "sig": (title, asked_password) or None}]"""
    seen = [p for p in personas if p.get("sig") and p["sig"][0] is not None]  # only visitors that really loaded the page
    if len(seen) < 2:
        return None
    pw = {p["name"] for p in seen if p["sig"][1]}
    if pw and len(pw) < len(seen):
        quiet = [p["name"] for p in seen if p["name"] not in pw]
        return {"kind": "cloaking", "weight": 45,
                "text": f"The page showed different things to different visitors: {', '.join(sorted(pw))} saw a login form, "
                        f"but {', '.join(quiet)} saw a harmless page. Scam pages do this to hide from security tools."}
    titles = {p["sig"][0] for p in seen if p["sig"][0]}
    if len(titles) > 1:  # informational only: many real sites send phones elsewhere (mobile sites, language, app links)
        return {"kind": "visitor_difference", "weight": 3,
                "text": "Visitors on different devices were shown different pages (" +
                        "; ".join(f"{p['name']}: '{p['sig'][0][:34]}'" for p in seen) + "). That is common for mobile and regional sites, so it is not treated as a threat by itself."}
    return None
