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
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from decoy import ask as ask_mod
from decoy import guard, llm, qr, store
from decoy.agent import run_scan
from decoy.config import DEMO_PORT, ROOT, RUNS, env, env_int
from decoy.sandbox import docker_ready, kill_scan
from decoy.urlcheck import BadLink, normalize

app = FastAPI(title="Decoy")
SCANS: dict[str, dict] = {}
LOCK = threading.Lock()
JOBS: "queue.Queue[tuple]" = queue.Queue(maxsize=env_int("MAX_QUEUE", 8))
WORKERS = env_int("SCAN_WORKERS", 1)
HARD_SECONDS = env_int("MAX_SECONDS_PER_SCAN", 120) * 2 + 30   # watchdog: the whole swarm must be gone by then
HITS: dict[str, collections.deque] = collections.defaultdict(collections.deque)


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


def _run(scan_id: str, url: str, budget: guard.Budget):
    def emit(ev):
        ev["t"] = round(time.time() - SCANS[scan_id]["started"], 2)
        if ev.get("type") == "verdict":
            SCANS[scan_id]["verdict"] = ev
        with LOCK:
            SCANS[scan_id]["events"].append(ev)
    watchdog = threading.Timer(HARD_SECONDS, lambda: (budget.cancelled.set(), kill_scan(scan_id)))
    watchdog.daemon = True
    watchdog.start()
    try:
        emit({"type": "running"})
        run_scan(scan_id, url, emit, budget)
    except Exception as e:
        emit({"type": "note", "text": f"Scan failed: {e}"})
    finally:
        watchdog.cancel()
        kill_scan(scan_id)  # belt and braces: nothing of this scan may outlive it
        with LOCK:
            SCANS[scan_id]["done"] = True


def _worker():
    while True:
        scan_id, url, budget = JOBS.get()
        try:
            if budget.cancelled.is_set():  # cancelled while waiting in the queue
                with LOCK:
                    SCANS[scan_id]["events"].append({"type": "note", "text": "Cancelled before it started.", "t": 0})
                    SCANS[scan_id]["done"] = True
            else:
                _run(scan_id, url, budget)
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
        JOBS.put_nowait((scan_id, url, budget))
    except queue.Full:
        del SCANS[scan_id]
        raise HTTPException(429, "Decoy is busy. Try again in a minute.")
    pos = JOBS.qsize()
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
async def events(scan_id: str):
    if scan_id not in SCANS:
        raise HTTPException(404, "unknown scan")

    async def stream():
        sent = 0
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


@app.get("/api/history")
def history():
    return store.history(12)


@app.get("/runs/{scan_id}/{name}")
def run_file(scan_id: str, name: str):
    if not re.fullmatch(r"[0-9a-z]{12}", scan_id) or not re.fullmatch(r"(step-\d{1,2}|frame-\d{1,4}|p-[a-z]+-\d{1,2})\.jpg", name):
        raise HTTPException(404)
    f = RUNS / scan_id / name
    if not f.exists():
        raise HTTPException(404)
    return FileResponse(f, headers={"Cache-Control": "no-store"})
