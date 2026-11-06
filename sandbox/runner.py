"""Decoy sandbox runner. Runs INSIDE the sealed container.

It drives one headless Chromium and talks to the control plane over stdin/stdout,
one JSON object per line. It holds no API keys, no credentials except the fake
"canary" data the control plane hands it, and it blocks every request to private,
loopback or cloud-metadata addresses.

Commands: open, state, fill_and_submit, click, close.
"""
import base64
import re
import hashlib
import ipaddress
import json
import os
import socket
import sys
import time
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

MAX_REQUESTS = 600
VIEW = {"width": 1280, "height": 800}
BLOCKED_NAMES = {"localhost", "metadata.google.internal", "metadata", "host.docker.internal"}

# Marks every interactive element with data-decoy-id and returns what a person would see.
SCAN_JS = r"""
() => {
  const out = {fields: [], buttons: [], links: []};
  let n = 0;
  const visible = el => { const r = el.getBoundingClientRect(); const s = getComputedStyle(el);
    return r.width > 2 && r.height > 2 && s.visibility !== 'hidden' && s.display !== 'none' && parseFloat(s.opacity) > 0.05; };
  const label = el => { if (el.id) { const l = document.querySelector('label[for="' + el.id + '"]'); if (l) return l.innerText.trim(); }
    const p = el.closest('label'); return p ? p.innerText.trim() : ''; };
  document.querySelectorAll('input, textarea, select').forEach(el => {
    if (!visible(el) || ['hidden','submit','button','image','reset'].includes(el.type)) return;
    el.setAttribute('data-decoy-id', ++n);
    out.fields.push({id: n, type: el.type || el.tagName.toLowerCase(), name: el.name || '', placeholder: el.placeholder || '',
                     label: label(el).slice(0, 80), autocomplete: el.autocomplete || ''});
  });
  document.querySelectorAll('button, input[type=submit], input[type=button], [role=button]').forEach(el => {
    if (!visible(el)) return;
    el.setAttribute('data-decoy-id', ++n);
    out.buttons.push({id: n, text: (el.innerText || el.value || '').trim().slice(0, 60)});
  });
  document.querySelectorAll('a[href]').forEach(el => {
    if (!visible(el) || out.links.length >= 25) return;
    el.setAttribute('data-decoy-id', ++n);
    out.links.push({id: n, text: el.innerText.trim().slice(0, 60), href: el.href.slice(0, 200)});
  });
  // Text a person cannot see (hidden, transparent or tiny) is where pages hide orders for AI agents.
  const hidden = [];
  const walk = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT);
  while (walk.nextNode()) {
    const t = walk.currentNode.textContent.trim(); const el = walk.currentNode.parentElement;
    if (!t || !el || ['SCRIPT','STYLE','NOSCRIPT'].includes(el.tagName)) continue;
    const s = getComputedStyle(el);
    if (s.display === 'none' || s.visibility === 'hidden' || parseFloat(s.opacity) < 0.05 || parseFloat(s.fontSize) < 3 || el.offsetParent === null && s.position !== 'fixed')
      hidden.push(t);
  }
  out.hidden_text = hidden.join(' ').slice(0, 1500);
  out.visible_text = ((document.body && document.body.innerText) || '').slice(0, 2500);
  out.has_password = !!document.querySelector('input[type=password]');
  const frames = [...document.querySelectorAll('iframe')].map(f => f.src || '').join(' ');
  const txt = ((document.body && document.body.innerText) || '').slice(0, 4000);
  out.gate = /recaptcha|hcaptcha|turnstile|challenges\.cloudflare|captcha/i.test(frames + ' ' + document.documentElement.innerHTML.slice(0, 60000)) || /i'?m not a robot|verify (that )?you('| a)re (a )?human|are you a robot/i.test(txt) ? 'captcha'
    : /(verification|security|confirmation) code|we('| ha)ve sent (you )?(an? )?(email|code|text)|check your (email|inbox)|enter the (6|4|5)[- ]digit/i.test(txt) ? 'verification' : '';
  out.scripts = [...document.scripts].filter(s => !s.src && s.textContent.trim()).slice(0, 6).map(s => s.textContent.trim().slice(0, 2500));
  out.script_srcs = [...document.scripts].filter(s => s.src).slice(0, 10).map(s => s.src.slice(0, 200));
  return out;
}
"""


# A drawn cursor (headless browsers have none) so the live view shows where the agent points and clicks.
CURSOR_JS = r"""
(() => {
  const mk = () => {
    if (document.getElementById('__decoy_cursor') || !document.body) return;
    const c = document.createElement('div');
    c.id = '__decoy_cursor';
    c.innerHTML = '<svg width="26" height="26" viewBox="0 0 24 24"><path d="M4 2l15 10.5-6.6 1.3 3.9 7.4-3 1.5-3.8-7.5L4 20z" fill="#111" stroke="#fff" stroke-width="1.6" stroke-linejoin="round"/></svg>';
    c.style.cssText = 'position:fixed;left:640px;top:400px;z-index:2147483647;pointer-events:none;transition:none;filter:drop-shadow(0 2px 3px rgba(0,0,0,.35))';
    document.body.appendChild(c);
    const ring = document.createElement('div');
    ring.style.cssText = 'position:fixed;width:34px;height:34px;margin:-17px 0 0 -17px;border-radius:50%;border:3px solid #ff6b5e;z-index:2147483646;pointer-events:none;opacity:0;transition:opacity .25s,transform .25s;transform:scale(.4)';
    document.body.appendChild(ring);
    addEventListener('mousemove', e => { c.style.left = e.clientX + 'px'; c.style.top = e.clientY + 'px'; }, true);
    addEventListener('mousedown', e => { ring.style.left = e.clientX + 'px'; ring.style.top = e.clientY + 'px';
      ring.style.opacity = 1; ring.style.transform = 'scale(1)'; setTimeout(() => { ring.style.opacity = 0; ring.style.transform = 'scale(.4)'; }, 350); }, true);
  };
  document.readyState === 'loading' ? addEventListener('DOMContentLoaded', mk) : mk();
})();
"""


def emit(obj):
    # Written in 16 KB pieces: under gVisor one big write to the pipe is cut at 64 KB and a large page never arrives.
    s = json.dumps(obj) + "\n"
    for i in range(0, len(s), 16384):
        sys.stdout.write(s[i:i + 16384])
        sys.stdout.flush()


def is_private_host(host: str) -> bool:
    """True for loopback, private, link-local (cloud metadata) and reserved addresses."""
    host = (host or "").strip("[]").lower()
    if not host or host in BLOCKED_NAMES:
        return True
    try:
        ips = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            ips = [ipaddress.ip_address(a[4][0]) for a in socket.getaddrinfo(host, None)]
        except OSError:
            return False  # unresolvable: Chromium will fail the request anyway
    return any(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast for ip in ips)


class Runner:
    def __init__(self):
        self.pw = sync_playwright().start()
        self.browser = None
        self.page = None
        self.network = []      # every request the page made, with verdict flags
        self.downloads = []
        self.dialogs = []
        self.canary = {}
        self.demo_suffix = None
        self.requests_seen = 0
        self.lead = True
        self.redirects = []
        self.console = []
        self.status = {}
        self.ctx = None
        self.mouse = (VIEW["width"] / 2, VIEW["height"] / 2)

    # ---- setup -------------------------------------------------------------
    def launch(self, demo_ip, demo_suffix):
        """Start Chromium (or keep the one a warm-up already started: same settings means it can be reused, a clean browser either way)."""
        key = (demo_ip, demo_suffix)
        if self.browser is not None and getattr(self, "_launch_key", None) == key:
            return
        if self.browser is not None:
            try:
                self.browser.close()
            except Exception:
                pass
        self.demo_suffix = demo_suffix
        args = ["--disable-dev-shm-usage", "--no-first-run", "--disable-extensions", "--disable-quic"]  # QUIC (UDP) stalls page loads inside gVisor
        if demo_ip and demo_suffix:
            if demo_ip == "host-gateway":
                demo_ip = socket.gethostbyname("host.docker.internal")
            args.append(f"--host-resolver-rules=MAP *{demo_suffix} {demo_ip}")
        self.browser = self.pw.chromium.launch(headless=True, args=args)
        self._launch_key = key

    def open(self, msg):
        self.canary = msg.get("canary", {})
        self.lead = bool((msg.get("persona") or {}).get("lead", True))
        demo_ip = msg.get("demo_ip")
        self.demo_suffix = msg.get("demo_suffix")  # e.g. ".test": our own fake sites only
        self.launch(demo_ip, self.demo_suffix)
        # Each visitor persona looks different to the website: device, browser string, language.
        per = msg.get("persona") or {}
        view = per.get("viewport") or VIEW
        self.mouse = (view["width"] / 2, view["height"] / 2)
        ctx = self.browser.new_context(viewport=view, accept_downloads=True, java_script_enabled=True,
                                       user_agent=per.get("ua") or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                                                                   "(KHTML, like Gecko) Chrome/130.0 Safari/537.36",
                                       is_mobile=bool(per.get("mobile")), has_touch=bool(per.get("mobile")),
                                       locale=per.get("locale") or "en-US")
        ctx.route("**/*", self._route)
        ctx.add_init_script(CURSOR_JS)
        self.ctx = ctx
        ctx.on("page", self._watch)
        self.page = ctx.new_page()
        self._watch(self.page)
        try:
            self.page.goto(msg["url"], wait_until="domcontentloaded", timeout=12000)
            self.frame()  # the first picture goes out the moment the page has a skeleton, not after everything loaded
            try:
                self.page.wait_for_load_state("load", timeout=4000)
            except Exception:
                pass
        except Exception as e:  # a dead or slow page is still evidence
            return self.state(note=f"page did not finish loading: {str(e)[:120]}")
        return self.state()

    def _watch(self, page):
        self.page = page  # follow pop-ups and new tabs
        page.on("download", self._download)
        page.on("response", self._response)
        page.on("console", lambda m: len(self.console) < 80 and self.console.append({"type": m.type, "text": m.text[:300]}))
        page.on("pageerror", lambda e: len(self.console) < 80 and self.console.append({"type": "error", "text": str(e)[:300]}))
        page.on("dialog", lambda d: (self.dialogs.append({"type": d.type, "message": d.message[:200]}), d.dismiss()))

    def _response(self, resp):
        """Record every redirect of a page navigation (a short link hiding the real destination, a hop through another site)."""
        self.status[resp.url[:300]] = resp.status
        try:
            if 300 <= resp.status < 400 and resp.request.is_navigation_request():
                self.redirects.append({"from": resp.url[:200], "to": (resp.headers.get("location") or "")[:200], "status": resp.status})
        except Exception:
            pass

    def _download(self, dl):
        path = f"/tmp/dl-{len(self.downloads)}" if os.name != "nt" else os.path.join(os.environ.get("TEMP", "."), f"decoy-dl-{len(self.downloads)}")
        try:
            dl.save_as(path)
            data = open(path, "rb").read()
            os.remove(path)
            self.downloads.append({"filename": dl.suggested_filename[:120], "size": len(data),
                                   "sha256": hashlib.sha256(data).hexdigest()})
        except Exception as e:
            self.downloads.append({"filename": dl.suggested_filename[:120], "error": str(e)[:120]})

    def _route(self, route):
        try:
            return self._route_inner(route)
        except Exception:  # the page navigated or closed while we decided: the request is gone, nothing to do
            return None

    def _route_inner(self, route):
        req = route.request
        if req.resource_type not in ("image", "font", "stylesheet", "media"):
            self.requests_seen += 1
        host = urlsplit(req.url).hostname or ""
        demo = bool(self.demo_suffix and host.endswith(self.demo_suffix))
        entry = {"url": req.url[:300], "method": req.method, "host": host, "type": req.resource_type}
        body = req.post_data or ""
        if body:  # payload preview with our fake values replaced by their names (never keep what was typed)
            prev = body[:240]
            for k, v in self.canary.items():
                if v:
                    prev = prev.replace(v, f"<{k}>").replace(v.replace("@", "%40"), f"<{k}>")
            entry["post"] = prev
        hay = (req.url + " " + body).lower()
        sent = [k for k, v in self.canary.items() if v and len(v) >= 8 and (v.lower() in hay or v.lower().replace("@", "%40") in hay)]
        if "CARD" in sent and self.canary.get("CVV") and self.canary["CVV"] in hay:
            sent.append("CVV")  # the short code only counts together with the card number
        if sent:
            entry["canary_sent"] = sent
        if req.resource_type in ("image", "font", "stylesheet", "media") and self.requests_seen > MAX_REQUESTS:
            return route.abort()  # pictures, fonts and styles are not evidence: past the cap they are dropped silently (never reported as a block)
        if self.requests_seen > MAX_REQUESTS * 3:
            entry.update(limited=True, reason="request limit reached")  # a safety cap against endless pages: a note, not an attack, so not "blocked"
            self.network.append(entry)
            return route.abort()
        if not req.url.startswith(("http://", "https://", "data:", "blob:")):
            entry.update(blocked=True, reason="non-web scheme")
            self.network.append(entry)
            return route.abort()
        if not demo and req.url.startswith("http") and is_private_host(host):
            entry.update(blocked=True, reason="private, loopback or cloud-metadata address")
            self.network.append(entry)
            return route.abort()
        self.network.append(entry)
        return route.continue_()

    # ---- observation -------------------------------------------------------
    def state(self, note=None):
        self.page.wait_for_timeout(400)  # lets the browser deliver events (time.sleep would not)
        for _ in range(3):  # bot-check and loading screens often finish by themselves: give the real page a few seconds
            try:
                title = self.page.title() or ""
                n = self.page.evaluate("((document.body && document.body.innerText) || '').length")
                if n >= 40 and not re.match(r"(?i)^(loading|just a moment|checking|redirecting|please wait|one moment)", title):
                    break
            except Exception:
                pass
            self.page.wait_for_timeout(1000)
        info = {}
        for _ in range(2):  # the page may still be navigating (scripts redirect after a submit)
            try:
                self.page.wait_for_load_state("load", timeout=3000)
            except Exception:
                pass
            try:
                info = self.page.evaluate(SCAN_JS)
                break
            except Exception as e:
                info = {"error": str(e)[:120]}
                self.page.wait_for_timeout(800)
        try:
            self.page.mouse.move(*self.mouse)  # a new page draws a new cursor: put it where the mouse is
        except Exception:
            pass
        try:
            shot = base64.b64encode(self.page.screenshot(type="jpeg", quality=62)).decode()
        except Exception:
            shot = None
        full = None  # the whole page, only for the laptop visitor (the extra screenshots are the slowest step under gVisor)
        try:
            if not self.lead:
                raise RuntimeError('skip')
            vp = self.page.viewport_size or VIEW
            height = int(self.page.evaluate("Math.min(document.documentElement.scrollHeight, 6000)"))
            if height > vp["height"] + 40:
                full = base64.b64encode(self.page.screenshot(type="jpeg", quality=50, full_page=True,
                                                             clip={"x": 0, "y": 0, "width": vp["width"], "height": height})).decode()
        except Exception:
            full = None
        net, self.network = self.network, []
        for n in net:
            n["status"] = self.status.get(n["url"])
        con, self.console = self.console, []
        cookies = []
        try:
            for c in (self.ctx.cookies() if self.ctx else [])[:25]:
                cookies.append({"name": c["name"][:60], "domain": c["domain"], "secure": c["secure"], "httpOnly": c["httpOnly"], "sameSite": c.get("sameSite", "")})
        except Exception:
            pass
        dls, self.downloads = self.downloads, []
        dlg, self.dialogs = self.dialogs, []
        try:
            ttl = (self.page.title() or "")[:150]
        except Exception:  # the page was navigating or closed under us: a title is not worth failing the step
            ttl = ""
        return {"ok": True, "url": self.page.url[:500], "title": ttl, "screenshot": shot, "full": full or shot,
                "page": info, "network": net, "downloads": dls, "dialogs": dlg, "note": note, "redirects": self.redirects[:12], "console": con, "cookies": cookies}

    # ---- live frames + a visible cursor, so a person can watch the agent work ----
    def frame(self):
        """Send one small live screenshot before the command's final answer (control plane streams it)."""
        try:
            emit({"frame": base64.b64encode(self.page.screenshot(type="jpeg", quality=45)).decode()})
        except Exception:
            pass

    def move_to(self, selector):
        loc = self.page.locator(selector).first
        loc.scroll_into_view_if_needed(timeout=3000)
        box = loc.bounding_box(timeout=3000)
        if not box:
            raise RuntimeError("element has no position")
        tx, ty = box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
        sx, sy = self.mouse
        steps = 9
        for i in range(1, steps + 1):
            t = i / steps
            t = t * t * (3 - 2 * t)  # ease in and out
            self.page.mouse.move(sx + (tx - sx) * t, sy + (ty - sy) * t)
            if i % 3 == 0:
                self.frame()
        self.mouse = (tx, ty)
        return loc

    def press(self, selector):
        loc = self.move_to(selector)
        self.page.mouse.down()
        self.frame()
        self.page.mouse.up()
        return loc

    # ---- actions (only fake canary values can be typed) ---------------------
    def fill_and_submit(self, msg):
        for f in msg.get("fields", []):
            value = self.canary.get(f.get("value"), "")
            if not value:
                continue
            try:
                loc = self.press(f'[data-decoy-id="{int(f["id"])}"]')
                loc.fill("", timeout=2000)
                for i in range(0, len(value), 3):  # type like a person, a few letters per live frame
                    loc.press_sequentially(value[i:i + 3], delay=45)
                    self.frame()
            except Exception:
                pass
        sub = msg.get("submit_id")
        try:
            if sub:
                self.press(f'[data-decoy-id="{int(sub)}"]')
            else:
                self.page.keyboard.press("Enter")
        except Exception as e:
            return self.state(note=f"submit failed: {str(e)[:100]}")
        self.page.wait_for_timeout(700)
        self.frame()
        self.page.wait_for_timeout(800)
        return self.state()

    def click(self, msg):
        try:
            self.press(f'[data-decoy-id="{int(msg["id"])}"]')
        except Exception as e:
            return self.state(note=f"click failed: {str(e)[:100]}")
        self.page.wait_for_timeout(700)
        self.frame()
        self.page.wait_for_timeout(800)
        return self.state()

    def close(self):
        try:
            self.browser and self.browser.close()
            self.pw.stop()
        except Exception:
            pass


def main():
    r = Runner()
    emit({"ok": True, "ready": True, "pid": os.getpid(), "user": os.environ.get("USER") or os.environ.get("USERNAME", "")})
    for line in sys.stdin:
        try:
            msg = json.loads(line)
            cmd = msg.get("cmd")
            if cmd == "prewarm":
                r.launch(msg.get("demo_ip"), msg.get("demo_suffix"))
                emit({"ok": True, "warm": True})
            elif cmd == "open":
                emit(r.open(msg))
            elif cmd == "state":
                emit(r.state())
            elif cmd == "fill_and_submit":
                emit(r.fill_and_submit(msg))
            elif cmd == "click":
                emit(r.click(msg))
            elif cmd == "close":
                r.close()
                emit({"ok": True, "closed": True})
                return
            else:
                emit({"ok": False, "error": f"unknown command {cmd!r}"})
        except Exception as e:
            emit({"ok": False, "error": str(e)[:200]})
    r.close()


if __name__ == "__main__":
    main()
