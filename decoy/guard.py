"""Budget guard for model calls. Never weaken it.

Per scan: max calls and a wall-clock deadline. Per day: max calls and max dollars (ledger on disk).
Global: a kill switch and a limit on parallel scans.
"""
import json
import threading
import time
from datetime import date

from .config import ROOT, env, env_float, env_int

_LOCK = threading.Lock()
LEDGER = ROOT / "runs" / "ledger.json"
SCAN_SLOTS = threading.BoundedSemaphore(env_int("MAX_PARALLEL_SCANS", 2))


class BudgetExceeded(RuntimeError):
    pass


def _read_day(path=None) -> dict:
    path = path or LEDGER
    today = date.today().isoformat()
    try:
        d = json.loads(path.read_text())
        if d.get("date") == today:
            return d
    except Exception:
        pass
    return {"date": today, "calls": 0, "usd": 0.0}


class Budget:
    def __init__(self, ledger=None):
        self.ledger = ledger or LEDGER
        self.calls = 0
        self.max_calls = env_int("MAX_CALLS_PER_SCAN", 12)
        self.deadline = time.time() + env_int("MAX_SECONDS_PER_SCAN", 120)
        self.cancelled = threading.Event()

    def time_left(self) -> float:
        return self.deadline - time.time()

    def check(self):
        """Raise before a model call (or a sandbox step) that would break a cap."""
        if env("KILL_SWITCH") == "1":
            raise BudgetExceeded("kill switch is on")
        if self.cancelled.is_set():
            raise BudgetExceeded("scan cancelled")
        if self.time_left() <= 0:
            raise BudgetExceeded("scan time limit reached")
        if self.calls >= self.max_calls:
            raise BudgetExceeded(f"scan call cap ({self.max_calls}) reached")
        with _LOCK:
            day = _read_day(self.ledger)
        if day["calls"] >= env_int("MAX_CALLS_PER_DAY", 300):
            raise BudgetExceeded("daily call cap reached")
        if day["usd"] >= env_float("MAX_USD_PER_DAY", 2.0):
            raise BudgetExceeded("daily spend cap reached")

    def record(self, tokens_in: int, tokens_out: int) -> float:
        usd = tokens_in / 1e6 * env_float("PRICE_IN_PER_M", 0.55) + tokens_out / 1e6 * env_float("PRICE_OUT_PER_M", 2.75)
        self.calls += 1
        with _LOCK:
            day = _read_day(self.ledger)
            day["calls"] += 1
            day["usd"] = round(day["usd"] + usd, 6)
            self.ledger.parent.mkdir(parents=True, exist_ok=True)
            self.ledger.write_text(json.dumps(day))
        return usd


def today() -> dict:
    with _LOCK:
        return _read_day()
