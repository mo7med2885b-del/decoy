"""Decoy web app: the control plane. Run: python -m uvicorn server:app --port 8020

Scans go through a bounded queue with worker threads (a swarm uses several sandboxes, so only a few run at once),
a watchdog removes the containers of a scan that overruns, and every visitor is rate limited."""
import asyncio
import collections
import json
import queue
import re
import threading
import time
import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from decoy import ask as ask_mod
from decoy import guard, investigate, llm, qr, store
from decoy import agent
from decoy.agent import run_scan
from decoy.config import DEMO_PORT, ROOT, RUNS, env, env_float, env_int
from decoy.sandbox import docker_ready, kill_scan
from decoy.urlcheck import BadLink, normalize

app = FastAPI(title="Decoy")
SCANS: dict[str, dict] = {}
LOCK = threading.Lock()
JOBS: "queue.Queue[tuple]" = queue.Queue(maxsize=env_int("MAX_QUEUE", 8))
WORKERS = env_int("SCAN_WORKERS", 1)
HARD_SECONDS = env_int("MAX_SECONDS_PER_SCAN", 120) * 2 + 30   # watchdog: the whole swarm must be gone by then
HITS: dict[str, collections.deque] = collections.defaultdict(collections.deque)
ACTIVE = [0]   # scans running right now


class NoStore(StaticFiles):
    async def get_response(self, path, scope):
        r = await super().get_response(path, scope)
        r.headers["Cache-Control"] = "no-store"
        return r


app.mount("/static", NoStore(directory=ROOT / "static"), name="static")


def client_ip(request: Request) -> str:
    """The visitor's address. X-Forwarded-For is trusted only when the request comes from our own reverse proxy."""
    peer = request.client.host if request.client else "?"
    if peer in ("127.0.0.1", "::1"):
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return peer


def rate_limit(request: Request, kind: str, per_hour: int):
    key, now = f"{kind}:{client_ip(request)}", time.time()
    q = HITS[key]
    while q and now - q[0] > 3600:
        q.popleft()
    if len(q) >= per_hour:
        raise HTTPException(429, f"Too many requests from your address. Try again in {int((3600 - (now - q[0])) / 60) + 1} minutes.")
    q.append(now)


@app.get("/")
def index():
    return FileResponse(ROOT / "static" / "index.html", headers={"Cache-Control": "no-store"})


@app.post("/api/inspect-ai")
async def inspect_ai(request: Request):
    """Plain-words AI summary of the 'Behind the page' data. One small-model call; the facts are counted by code."""
    from decoy import inspect_ai
    rate_limit(request, "inspect_ai", env_int("INSPECT_AI_PER_HOUR", 20))
    raw = await request.body()
    if len(raw) > 200_000:
        raise HTTPException(413, "Too much data.")
    try:
        data = json.loads(raw)
    except ValueError:
        raise HTTPException(400, "Not valid JSON.")
    if not isinstance(data, dict):
        raise HTTPException(400, "Expected an object.")
    if guard.today()["usd"] >= env_float("MAX_USD_PER_DAY", 5.0) or env("KILL_SWITCH") == "1":
        return inspect_ai.rules_only(data)  # the daily cap is reached: rules still answer, no model call
    return await asyncio.to_thread(inspect_ai.analyze, data, guard.Budget())


@app.on_event("startup")
def warm_up():
    try:
        agent.WARM.kick()
    except Exception:
        pass


@app.get("/api/address")
def address_read(url: str, request: Request):
    """The link's own risk read (about 25 clues, no network): answered at once, before any sandbox opens."""
    from decoy import address as addr
    rate_limit(request, "address", 240)
    r = addr.read(url)
    return {"score": r["score"], "level": r["level"], "reasons": r["reasons"], "official": r["official"]}


@app.get("/api/geo")
def early_geo(url: str, request: Request):
    """Where the link's server is, answered at once (before the scan leaves the queue) so the globe can lead. Public addresses only."""
    from urllib.parse import urlsplit
    from decoy import geo as geo_mod
    rate_limit(request, "geo", 120)
    u = urlsplit(url if "://" in url else "http://" + url)
    if u.scheme not in ("http", "https") or not u.hostname:
        return {"origin": geo_mod.origin(), "loc": None}
    return {"origin": geo_mod.origin(), "loc": geo_mod.locate(u.hostname)}


@app.get("/api/agents")
def agent_cards():
    from decoy import cards
    return cards.cards()


@app.get("/api/health")
def health():
    mode = env("DECOY_SANDBOX", "docker")
    return {"sandbox": mode, "sandbox_ready": docker_ready() if mode == "docker" else True,
            "runtime": env("DECOY_SANDBOX_RUNTIME") or "runc", "planner": llm.model_name(),
            "model_key": llm.available(), "today": guard.today(), "queue": JOBS.qsize(), "workers": WORKERS,
            "caps": {"calls_per_scan": env("MAX_CALLS_PER_SCAN", "12"), "seconds_per_scan": env("MAX_SECONDS_PER_SCAN", "120"),
                     "usd_per_day": env("MAX_USD_PER_DAY", "5.00"), "scans_per_hour_per_visitor": env("SCANS_PER_HOUR", "15")}}


@app.get("/api/examples")
def examples():
    p = DEMO_PORT
    return [{"label": "Fake bank login", "url": f"http://n0rthbank-login.test:{p}/"},
            {"label": "Fake invoice", "url": f"http://invoice-portal.test:{p}/"},
            {"label": "Cloaked scam", "url": f"http://cloaked-promo.test:{p}/"},
            {"label": "Short link", "url": f"http://go-short.test:{p}/x"},
            {"label": "Harmless recipe", "url": f"http://daily-recipes.test:{p}/"}]


def _run(scan_id: str, url: str, budget: guard.Budget, mode: str = "simple"):
    def emit(ev):
        ev["t"] = round(time.time() - SCANS[scan_id]["started"], 2)
        if ev.get("type") == "verdict":
            SCANS[scan_id]["verdict"] = ev
        elif ev.get("type") == "consensus_final" and SCANS[scan_id].get("verdict"):
            SCANS[scan_id]["verdict"]["consensus"] = {k: x for k, x in ev.items() if k != "type"}  # the debate ended after the verdict went out
        with LOCK:
            SCANS[scan_id]["events"].append(ev)
    watchdog = threading.Timer(HARD_SECONDS, lambda: (budget.cancelled.set(), kill_scan(scan_id)))
    watchdog.daemon = True
    watchdog.start()
    try:
        emit({"type": "running"})
        run_scan(scan_id, url, emit, budget, sink=SCANS[scan_id])
        if mode == "investigate" and SCANS[scan_id].get("case"):
            SCANS[scan_id]["report"] = investigate.run_investigation(SCANS[scan_id]["case"], emit, llm.available(), SCANS[scan_id].get("agents"))
    except Exception as e:
        emit({"type": "note", "text": f"Scan failed: {e}"})
    finally:
        watchdog.cancel()
        kill_scan(scan_id)  # belt and braces: nothing of this scan may outlive it
        with LOCK:
            SCANS[scan_id]["done"] = True


def _worker():
    while True:
        scan_id, url, budget, mode = JOBS.get()
        try:
            if budget.cancelled.is_set():  # cancelled while waiting in the queue
                with LOCK:
                    SCANS[scan_id]["events"].append({"type": "note", "text": "Cancelled before it started.", "t": 0})
                    SCANS[scan_id]["done"] = True
            else:
                ACTIVE[0] += 1
                try:
                    _run(scan_id, url, budget, mode)
                finally:
                    ACTIVE[0] -= 1
        finally:
            JOBS.task_done()


for _ in range(WORKERS):
    threading.Thread(target=_worker, daemon=True).start()


@app.post("/api/scan")
async def start_scan(request: Request):
    body = await request.json()
    try:
        url = normalize(str(body.get("url", "")))
    except BadLink as e:
        raise HTTPException(400, str(e))
    if env("KILL_SWITCH") == "1":
        raise HTTPException(503, "Decoy is paused by the operator.")
    rate_limit(request, "scan", env_int("SCANS_PER_HOUR", 15))
    scan_id = uuid.uuid4().hex[:12]
    budget = guard.Budget()
    SCANS[scan_id] = {"url": url, "events": [], "done": False, "started": time.time(), "budget": budget, "verdict": None}
    try:
        JOBS.put_nowait((scan_id, url, budget, "investigate" if body.get("mode") == "investigate" else "simple"))
    except queue.Full:
        del SCANS[scan_id]
        raise HTTPException(429, "Decoy is busy. Try again in a minute.")
    pos = max(0, JOBS.qsize() + ACTIVE[0] - WORKERS)  # how many scans are ahead of this one
    SCANS[scan_id]["events"].append({"type": "queued", "position": pos, "t": 0})
    return {"id": scan_id, "url": url, "queued": pos}


@app.post("/api/scan/{scan_id}/cancel")
def cancel(scan_id: str):
    s = SCANS.get(scan_id)
    if not s:
        raise HTTPException(404, "unknown scan")
    s["budget"].cancelled.set()
    return {"ok": True}


@app.get("/api/scan/{scan_id}/events")
async def events(scan_id: str, since: int = 0):
    if scan_id not in SCANS:
        raise HTTPException(404, "unknown scan")

    async def stream():
        sent = max(0, since)
        while True:
            s = SCANS[scan_id]
            with LOCK:
                new, done = s["events"][sent:], s["done"]
            for ev in new:
                yield f"data: {json.dumps(ev)}\n\n"
            sent += len(new)
            if done and sent >= len(s["events"]):
                yield "data: {\"type\": \"end\"}\n\n"
                return
            await asyncio.sleep(0.25)

    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-store"})


@app.post("/api/scan/{scan_id}/decision")
async def decision(scan_id: str, request: Request):
    """The human decides. Decoy never blocks or reports anything on its own."""
    s = SCANS.get(scan_id)
    if not s or not s["done"]:
        raise HTTPException(400, "The scan is not finished yet.")
    body = await request.json()
    choice = body.get("decision")
    if choice not in ("block", "allow", "dismiss"):
        raise HTTPException(400, "Choose block, allow or dismiss.")
    note = str(body.get("note", ""))[:500]
    rec = {"scan": scan_id, "url": s["url"], "decision": choice, "note": note, "at": time.strftime("%Y-%m-%d %H:%M:%S")}
    try:
        store.decide(scan_id, choice, note)
    except Exception:
        pass
    return rec


@app.post("/api/scan/{scan_id}/ask")
async def ask(scan_id: str, request: Request):
    """Ask Decoy a question about a finished scan; answers come only from that scan's evidence."""
    rate_limit(request, "ask", env_int("ASKS_PER_HOUR", 40))
    body = await request.json()
    s = SCANS.get(scan_id)
    v = s and s.get("verdict")
    if not v:
        row = store.get(scan_id)
        if not row:
            raise HTTPException(404, "That scan is not finished or unknown.")
        v = {"level": row["level"], "score": row["score"], "summary": row["summary"], "evidence": json.loads(row["evidence"] or "[]"),
             "attacker_got": [{"host": h, "data": []} for h in json.loads(row["exfil"] or "[]")], "swarm": [], "memory": {}}
    return ask_mod.answer(str(body.get("question", "")), v, guard.Budget())


@app.post("/api/scan/{scan_id}/investigate")
async def investigate_scan(scan_id: str, request: Request):
    """Run the analyst team on a finished scan (Investigate mode after the fact). Events are appended to the scan's stream."""
    rate_limit(request, "investigate", env_int("INVESTIGATIONS_PER_HOUR", 10))
    s = SCANS.get(scan_id)
    if not s or not s["done"] or not s.get("case"):
        raise HTTPException(400, "The scan must be finished (and still in memory) to investigate it.")
    if s.get("investigating"):
        raise HTTPException(409, "The analysts are already working on it.")
    start = len(s["events"])
    s["investigating"], s["done"] = True, False

    def work():
        def emit(ev):
            with LOCK:
                s["events"].append(ev)
        try:
            s["report"] = investigate.run_investigation(s["case"], emit, llm.available(), s.get("agents"))
        except Exception as e:
            emit({"type": "note", "text": f"Investigation failed: {e}"})
        finally:
            with LOCK:
                s["done"], s["investigating"] = True, False

    threading.Thread(target=work, daemon=True).start()
    return {"since": start}


@app.get("/api/scan/{scan_id}/report.json")
def report_json(scan_id: str):
    r = (SCANS.get(scan_id) or {}).get("report")
    if not r:
        raise HTTPException(404, "No report yet. Run the investigation first.")
    return JSONResponse(r, headers={"Content-Disposition": f'attachment; filename="decoy-report-{r["id"]}.json"'})


@app.get("/api/scan/{scan_id}/report.md")
def report_md(scan_id: str):
    r = (SCANS.get(scan_id) or {}).get("report")
    if not r:
        raise HTTPException(404, "No report yet. Run the investigation first.")
    return PlainTextResponse(investigate.to_markdown(r), headers={"Content-Disposition": f'attachment; filename="decoy-report-{r["id"]}.md"'})


@app.get("/api/scan/{scan_id}/report.pdf")
def report_pdf(scan_id: str):
    """A PDF of the scan: verdict, reasons, screenshots, visitors, and the incident report when the analysts ran."""
    from decoy import pdfreport
    s = SCANS.get(scan_id) or {}
    v = s.get("verdict")
    if not v:
        raise HTTPException(404, "No finished scan to put in a PDF yet.")
    data = pdfreport.build(scan_id, s.get("url", ""), v, s.get("report"), RUNS / scan_id, ROOT / "assets" / "logo.png")
    return Response(data, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="decoy-report-{scan_id}.pdf"'})


@app.post("/api/qr")
async def read_qr(request: Request):
    """Decode a QR code from an uploaded picture and return the link inside it (the caller then scans that link)."""
    rate_limit(request, "qr", env_int("QR_PER_HOUR", 30))
    data = await request.body()
    try:
        text = qr.decode(data)
        return {"url": normalize(text)}
    except qr.BadImage as e:
        raise HTTPException(422, str(e))
    except BadLink:
        raise HTTPException(422, "The QR code does not contain a web link Decoy can open.")


@app.get("/api/threats")
def threat_feed(demo: int = 0):
    """Flagged sites and where their data goes: share it with your team and your customers."""
    return store.threats(30, bool(demo))


@app.get("/api/blocklist.txt")
def blocklist_txt(demo: int = 0):
    return PlainTextResponse("\n".join(store.blocklist(bool(demo))) + "\n")


@app.get("/api/blocklist.hosts")
def blocklist_hosts(demo: int = 0):
    head = "# Decoy block-list (hosts file format). Review before use.\n"
    return PlainTextResponse(head + "".join(f"0.0.0.0 {d}\n" for d in store.blocklist(bool(demo))))


@app.get("/api/scan/{scan_id}/abuse.txt")
def abuse_txt(scan_id: str):
    s = SCANS.get(scan_id) or {}
    if not s.get("case"):
        raise HTTPException(404, "No case file in memory for that scan.")
    return PlainTextResponse(investigate.abuse_draft(s["case"], scan_id), headers={"Content-Disposition": f'attachment; filename="abuse-report-{scan_id}.txt"'})


@app.get("/api/history")
def history():
    return store.history(12)


@app.get("/runs/{scan_id}/{name}")
def run_file(scan_id: str, name: str):
    if not re.fullmatch(r"[0-9a-z]{12}", scan_id) or not re.fullmatch(r"(step-\d{1,2}|frame-\d{1,4}|p-[a-z]+-\d{1,2})(-full)?\.jpg", name):
        raise HTTPException(404)
    f = RUNS / scan_id / name
    if not f.exists():
        raise HTTPException(404)
    return FileResponse(f, headers={"Cache-Control": "no-store"})
