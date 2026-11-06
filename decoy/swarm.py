"""The agent swarm. Besides the three visitors that open the link in their own sandboxes, nine specialist agents work in
parallel on the same case. Each has one job, reports findings live, and may add weighted evidence (never a verdict:
code scores). Four of them can also ask a small Vultr AI model to help; every agent has a rule-based fallback.

  at the start, in parallel with the visitors:   check (address + domain age) · geo (server location) · tls (certificate)
  after the visitors, in parallel:               script · endpoints · privacy · lure · intel · cloak
"""
import re
import socket
import ssl
import time
from urllib.parse import urlsplit

from . import geo as geo_mod
from . import investigate, reputation, store
from .guard import Budget
from .verdict import cloaking, is_telemetry

AGENTS = {  # id: (name, icon, kind, what it does)
    "check": ("Address and reputation", "⌁", "code", "Checks the address in plain code: look-alike brands, link shorteners, free-hosting subdomains, and the age of the domain (public RDAP data)."),
    "geo": ("Server location", "◎", "code", "Resolves the host and looks up where the server is and who runs it (IP, city, country, hosting company). Never connects to the server's IP."),
    "address": ("Address read", "\u2318", "code", "Scores the link itself with a transparent checklist of about 25 clues (look-alike brand, odd ending, free hosting, hyphens and digits, login words, redirect tricks) and gives up to three plain reasons, before any sandbox opens. A hint, never the verdict."),
    "tls": ("TLS certificate", "🔒", "code", "Reads the site's HTTPS certificate: does it verify, who issued it, how new is it. A fresh or broken certificate is a common scam sign."),
    "script": ("Script reverse engineer", "‹/›", "model", "Reads the page's scripts: what they read, where they send it, redirects, obfuscation. Rule-based static analysis first, a small Vultr AI model adds a reading."),
    "endpoints": ("Endpoint hunter", "⇄", "model", "Lists every background request the page made: which carried the typed fake data, which went to analytics, which to a phishing-kit channel, and in which country they end up."),
    "privacy": ("Cookie and privacy inspector", "◔", "model", "Looks at cookies and console output: what is stored in the browser, what is weakly protected, any tracking."),
    "lure": ("Lure analyst", "◉", "model", "Studies how the page manipulates the visitor: urgency, fear, brand borrowing, what it asks for."),
    "intel": ("Threat intelligence", "◈", "code", "Checks threat memory: earlier scans of this site and campaigns linked through the same data-collection server."),
    "cloak": ("Cloaking detector", "⚖", "code", "Compares what the laptop, the phone and the security bot were each shown. A login form hidden from the bot is cloaking."),
}
GROUP_A = ("check", "geo", "tls", "address")
GROUP_B = ("script", "endpoints", "privacy", "lure", "intel", "cloak")
OBFUSCATION = [r"\batob\(", r"\beval\(", r"fromcharcode", r"\bunescape\(", r"(\\x[0-9a-f]{2}){4,}", r"\bdocument\.write\(\s*unescape"]


def _tls_info(host: str) -> dict | None:
    """Handshake with the site's public address only; None when it cannot be reached."""
    try:
        socket.setdefaulttimeout(4)
        ip = next(a[4][0] for a in socket.getaddrinfo(host, 443) if ":" not in a[4][0])
        if not geo_mod._public(ip):
            return None
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, 443), timeout=4) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                c = ss.getpeercert()
        issuer = dict(x[0] for x in c.get("issuer", ())).get("organizationName", "unknown")
        age = max(0, int((time.time() - ssl.cert_time_to_seconds(c["notBefore"])) / 86400))
        return {"ok": True, "issuer": issuer, "age_days": age}
    except ssl.SSLCertVerificationError as e:
        return {"ok": False, "error": getattr(e, "verify_message", str(e))[:90]}
    except Exception:
        return None


# ---------------------------------------------------------------- group A: start immediately ----
def check_agent(ctx):
    host, findings, items = ctx["host"], [], []
    findings += [s["text"] for s in ctx["signals"] if s["kind"] != "official_domain"][:3]
    age = reputation.domain_age_days(host)
    if age is not None:
        findings.append(f"The domain {reputation.registrable(host)} is {age} day(s) old.")
        sig = reputation.age_signal(age, host)
        if sig:
            items.append(sig)
    return {"findings": findings or ["The address looks ordinary: no look-alike brand, shortener or free-hosting name."], "items": items}


def address_agent(ctx):
    from . import address as addr
    r = addr.read(ctx["url"])
    head = f"Address risk {r['score']}/100 ({r['level']})."
    return {"findings": [head] + r["reasons"][:3], "items": []}


def geo_agent(ctx):
    loc = geo_mod.locate(ctx["host"])
    if not loc:
        return {"findings": ["The address could not be located (it does not resolve to a public server)."], "items": []}
    if loc["simulated"]:
        return {"findings": [f"{ctx['host']} is a fake demo site: its location ({loc['city']}, {loc['code']}) is simulated."], "items": []}
    return {"findings": [f"{ctx['host']} is served from {loc['ip']} in {loc['city']}, {loc['code']}" + (f" by {loc['org']}." if loc.get("org") else ".")], "items": []}


def tls_agent(ctx):
    host = ctx["host"]
    if ctx["official"] or host.endswith(".test") or re.match(r"^[\d.]+$", host) or not ctx["url"].startswith("https"):
        return {"findings": ["No certificate check: the link is not an https address of a public site."], "items": []}
    info = _tls_info(host)
    if info is None:
        return {"findings": ["The certificate could not be read (the server did not answer the check)."], "items": []}
    if not info["ok"]:
        return {"findings": [f"The certificate does not verify: {info['error']}."], "items": [{"kind": "bad_cert", "weight": 20, "text": f"The site's HTTPS certificate does not verify ({info['error']})."}]}
    f = [f"Valid certificate from {info['issuer']}, {info['age_days']} day(s) old."]
    items = [{"kind": "fresh_cert", "weight": 6, "text": f"The site's certificate was issued only {info['age_days']} day(s) ago."}] if info["age_days"] < 10 else []
    return {"findings": f, "items": items}


# ---------------------------------------------------------------- group B: after the visitors ----
def _with_ai(role: str, ctx, fallback_findings: list[str]) -> tuple[list[str], str]:
    """Ask the small Vultr AI model for a reading of the evidence slice; keep rules if it fails or is switched off."""
    if not ctx["use_model"]:
        return fallback_findings, "rules"
    a = next(x for x in investigate.ANALYSTS if x["id"] == role)
    res = investigate.analyst_run(a, ctx["case"], ctx["budget"], True)
    return res["findings"], res["by"]


def script_agent(ctx):
    ev, case = ctx["ev"], ctx["case"]
    items = []
    low = " ".join(ev.scripts).lower()
    hits = sum(1 for p in OBFUSCATION if re.search(p, low))
    if hits >= 2:
        items.append({"kind": "obfuscated_script", "weight": 12, "text": "The page's own script hides what it does (encoded strings and eval). Honest pages rarely need to."})
    base = investigate.rules_findings("script", case)
    if not ev.scripts and not ev.script_srcs:
        return {"findings": ["The page has no scripts to read."], "items": items, "by": "rules"}
    f, by = _with_ai("script", ctx, base)
    return {"findings": f, "items": items, "by": by}


def endpoints_agent(ctx):
    ev, case = ctx["ev"], ctx["case"]
    base = investigate.rules_findings("endpoint", case)
    for e in ev.endpoints:
        if e["host"] and not e["blocked"] and not e["host"].endswith(ctx["host"]):
            loc = geo_mod.locate(e["host"])
            if loc and (e["leak"] or not is_telemetry(e["host"])):
                base.append(f"{e['host']} ends up in {loc['city']}, {loc['code']}" + (" (simulated)" if loc["simulated"] else "") + (" and received the fake data" if e["leak"] else "") + ".")
                break
    f, by = _with_ai("endpoint", ctx, base)
    return {"findings": f, "items": [], "by": by}


def privacy_agent(ctx):
    f, by = _with_ai("cookies", ctx, investigate.rules_findings("cookies", ctx["case"]))
    return {"findings": f, "items": [], "by": by}


def lure_agent(ctx):
    f, by = _with_ai("lure", ctx, investigate.rules_findings("lure", ctx["case"]))
    return {"findings": f, "items": [], "by": by}


def intel_agent(ctx):
    mem = store.memory(ctx["url"], ctx["exfil_hosts"], exclude_id=ctx["scan_id"])
    ctx["out"]["memory"] = mem
    f, items = [], []
    if mem["seen_before"]:
        f.append(f"We have scanned this site {len(mem['seen_before'])} time(s) before; last result: {mem['seen_before'][0]['level']}.")
    if mem["campaign"]:
        hosts = sorted({m["shared_server"] for m in mem["campaign"]})
        f.append(f"{len(mem['campaign'])} earlier scan(s) sent stolen data to the same server ({', '.join(hosts)}).")
        items.append({"kind": "campaign", "weight": 15, "text": f"{len(mem['campaign'])} earlier scan(s) sent stolen data to the same server ({', '.join(hosts)}): this looks like part of one scam campaign."})
    return {"findings": f or ["New to us: no earlier scan of this site or of the servers it talks to."], "items": items}


def cloak_agent(ctx):
    c = cloaking([{"name": x["name"], "sig": x["sig"]} for x in ctx["visitors"]])
    if len(ctx["visitors"]) < 2:
        return {"findings": ["Only one visitor was sent (official site), so there is nothing to compare."], "items": []}
    if not c:
        return {"findings": ["All visitors were shown the same page."], "items": []}
    ctx["out"]["cloak"] = c
    return {"findings": [c["text"]], "items": [c]}


FUNCS = {"check": check_agent, "address": address_agent, "geo": geo_agent, "tls": tls_agent, "script": script_agent, "endpoints": endpoints_agent,
         "privacy": privacy_agent, "lure": lure_agent, "intel": intel_agent, "cloak": cloak_agent}


def run_agent(aid: str, ctx: dict, emit) -> dict:
    name, icon, kind, desc = AGENTS[aid]
    emit({"type": "agent", "id": aid, "name": name, "icon": icon, "kind": kind, "status": "working"})
    t0 = time.time()
    try:
        res = FUNCS[aid](ctx)
    except Exception as e:  # one agent failing never stops the others
        res = {"findings": [f"Could not finish ({type(e).__name__})."], "items": []}
    res.setdefault("by", "rules")
    emit({"type": "agent", "id": aid, "name": name, "icon": icon, "kind": kind, "status": "done", "findings": res["findings"][:4],
          "weight": sum(i["weight"] for i in res["items"]), "by": res["by"], "seconds": round(time.time() - t0, 1)})
    return res
