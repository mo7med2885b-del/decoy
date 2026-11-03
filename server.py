"""Decoy web app: the control plane. Run: python -m uvicorn server:app --port 8020"""
import asyncio
import json
import re
import threading
import time
import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from decoy import guard, llm
from decoy.agent import run_scan
from decoy.config import DEMO_PORT, ROOT, RUNS, env
from decoy.sandbox import docker_ready
from decoy.urlcheck import BadLink, normalize

app = FastAPI(title="Decoy")
SCANS: dict[str, dict] = {}
LOCK = threading.Lock()
DECISIONS = RUNS / "decisions.json"


class NoStore(StaticFiles):
    async def get_response(self, path, scope):
        r = await super().get_response(path, scope)
        r.headers["Cache-Control"] = "no-store"
        return r


app.mount("/static", NoStore(directory=ROOT / "static"), name="static")


@app.get("/")
def index():
    return FileResponse(ROOT / "static" / "index.html", headers={"Cache-Control": "no-store"})


@app.get("/api/health")
def health():
    mode = env("DECOY_SANDBOX", "docker")
    return {"sandbox": mode, "sandbox_ready": docker_ready() if mode == "docker" else True,
            "runtime": env("DECOY_SANDBOX_RUNTIME") or "runc", "planner": llm.model_name(),
            "model_key": llm.available(), "today": guard.today(),
            "caps": {"calls_per_scan": env("MAX_CALLS_PER_SCAN", "12"), "seconds_per_scan": env("MAX_SECONDS_PER_SCAN", "120"),
                     "usd_per_day": env("MAX_USD_PER_DAY", "2.00")}}


@app.get("/api/examples")
def examples():
    p = DEMO_PORT
    return [{"label": "Fake bank login", "url": f"http://n0rthbank-login.test:{p}/"},
            {"label": "Fake invoice", "url": f"http://invoice-portal.test:{p}/"},
            {"label": "Harmless recipe", "url": f"http://daily-recipes.test:{p}/"},
            {"label": "Short link", "url": f"http://go-short.test:{p}/x"},
            {"label": "Cloaked scam", "url": f"http://cloaked-promo.test:{p}/"}]


def _worker(scan_id: str, url: str, budget: guard.Budget):
    def emit(ev):
        ev["t"] = round(time.time() - SCANS[scan_id]["started"], 2)
        with LOCK:
            SCANS[scan_id]["events"].append(ev)
    try:
        run_scan(scan_id, url, emit, budget)
    except Exception as e:
        emit({"type": "note", "text": f"Scan failed: {e}"})
    finally:
        with LOCK:
            SCANS[scan_id]["done"] = True
        guard.SCAN_SLOTS.release()


@app.post("/api/scan")
async def start_scan(request: Request):
    body = await request.json()
    try:
        url = normalize(str(body.get("url", "")))
    except BadLink as e:
        raise HTTPException(400, str(e))
    if env("KILL_SWITCH") == "1":
        raise HTTPException(503, "Decoy is paused by the operator.")
    if not guard.SCAN_SLOTS.acquire(blocking=False):
        raise HTTPException(429, "Decoy is busy with other scans. Try again in a minute.")
    scan_id = uuid.uuid4().hex[:12]
    budget = guard.Budget()
    SCANS[scan_id] = {"url": url, "events": [], "done": False, "started": time.time(), "budget": budget}
    threading.Thread(target=_worker, args=(scan_id, url, budget), daemon=True).start()
    return {"id": scan_id, "url": url}


@app.post("/api/scan/{scan_id}/cancel")
def cancel(scan_id: str):
    s = SCANS.get(scan_id) or {}
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
    data = json.loads(DECISIONS.read_text()) if DECISIONS.exists() else []
    data.append(rec)
    DECISIONS.parent.mkdir(parents=True, exist_ok=True)
    DECISIONS.write_text(json.dumps(data, indent=1))
    return rec


@app.get("/api/decisions")
def decisions():
    return json.loads(DECISIONS.read_text())[-50:] if DECISIONS.exists() else []


@app.get("/runs/{scan_id}/{name}")
def run_file(scan_id: str, name: str):
    if not re.fullmatch(r"[0-9a-f]{12}", scan_id) or not re.fullmatch(r"(step-\d{1,2}|frame-\d{1,4})\.jpg", name):
        raise HTTPException(404)
    f = RUNS / scan_id / name
    if not f.exists():
        raise HTTPException(404)
    return FileResponse(f, headers={"Cache-Control": "no-store"})
