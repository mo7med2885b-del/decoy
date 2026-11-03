"""Decoy sandbox runner. Runs INSIDE the sealed container.

It drives one headless Chromium and talks to the control plane over stdin/stdout,
one JSON object per line. It holds no API keys, no credentials except the fake
"canary" data the control plane hands it, and it blocks every request to private,
loopback or cloud-metadata addresses.

Commands: open, state, fill_and_submit, click, close.
"""
import base64
import hashlib
import ipaddress
import json
import os
import socket
import sys
import time
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

MAX_REQUESTS = 400
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
  return out;
}
"""


def emit(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
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

    # ---- setup -------------------------------------------------------------
    def open(self, msg):
        self.canary = msg.get("canary", {})
        demo_ip = msg.get("demo_ip")
        self.demo_suffix = msg.get("demo_suffix")  # e.g. ".test": our own fake sites only
        args = ["--disable-dev-shm-usage", "--no-first-run", "--disable-extensions"]
        if demo_ip and self.demo_suffix:
            if demo_ip == "host-gateway":
                demo_ip = socket.gethostbyname("host.docker.internal")
            args.append(f"--host-resolver-rules=MAP *{self.demo_suffix} {demo_ip}")
        self.browser = self.pw.chromium.launch(headless=True, args=args)
        ctx = self.browser.new_context(viewport=VIEW, accept_downloads=True, java_script_enabled=True,
                                       user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                                                  "(KHTML, like Gecko) Chrome/130.0 Safari/537.36")
        ctx.route("**/*", self._route)
        ctx.on("page", self._watch)
        self.page = ctx.new_page()
        self._watch(self.page)
        try:
            self.page.goto(msg["url"], wait_until="load", timeout=15000)
        except Exception as e:  # a dead or slow page is still evidence
            return self.state(note=f"page did not finish loading: {str(e)[:120]}")
        return self.state()

    def _watch(self, page):
        self.page = page  # follow pop-ups and new tabs
        page.on("download", self._download)
        page.on("dialog", lambda d: (self.dialogs.append({"type": d.type, "message": d.message[:200]}), d.dismiss()))

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
        req = route.request
        self.requests_seen += 1
        host = urlsplit(req.url).hostname or ""
        demo = bool(self.demo_suffix and host.endswith(self.demo_suffix))
        entry = {"url": req.url[:300], "method": req.method, "host": host, "type": req.resource_type}
        body = req.post_data or ""
        hay = (req.url + " " + body).lower()
        sent = [k for k, v in self.canary.items() if v and (v.lower() in hay or v.lower().replace("@", "%40") in hay)]
        if sent:
            entry["canary_sent"] = sent
        if self.requests_seen > MAX_REQUESTS:
            entry.update(blocked=True, reason="request limit reached")
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
        time.sleep(0.4)
        info = {}
        for _ in range(4):  # the page may still be navigating (scripts redirect after a submit)
            try:
                self.page.wait_for_load_state("load", timeout=5000)
            except Exception:
                pass
            try:
                info = self.page.evaluate(SCAN_JS)
                break
            except Exception as e:
                info = {"error": str(e)[:120]}
                time.sleep(0.8)
        try:
            shot = base64.b64encode(self.page.screenshot(type="jpeg", quality=62)).decode()
        except Exception:
            shot = None
        net, self.network = self.network, []
        dls, self.downloads = self.downloads, []
        dlg, self.dialogs = self.dialogs, []
        return {"ok": True, "url": self.page.url[:500], "title": (self.page.title() or "")[:150], "screenshot": shot,
                "page": info, "network": net, "downloads": dls, "dialogs": dlg, "note": note}

    # ---- actions (only fake canary values can be typed) ---------------------
    def fill_and_submit(self, msg):
        for f in msg.get("fields", []):
            value = self.canary.get(f.get("value"), "")
            if not value:
                continue
            try:
                self.page.fill(f'[data-decoy-id="{int(f["id"])}"]', value, timeout=3000)
            except Exception:
                pass
        sub = msg.get("submit_id")
        try:
            if sub:
                self.page.click(f'[data-decoy-id="{int(sub)}"]', timeout=3000)
            else:
                self.page.keyboard.press("Enter")
        except Exception as e:
            return self.state(note=f"submit failed: {str(e)[:100]}")
        time.sleep(1.2)
        return self.state()

    def click(self, msg):
        try:
            self.page.click(f'[data-decoy-id="{int(msg["id"])}"]', timeout=3000)
        except Exception as e:
            return self.state(note=f"click failed: {str(e)[:100]}")
        time.sleep(1.2)
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
            if cmd == "open":
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
