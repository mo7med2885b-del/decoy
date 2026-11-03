"""Settings from the environment (and an optional .env file next to server.py)."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / "runs"


def _load_dotenv():
    f = ROOT / ".env"
    if not f.exists():
        return
    for line in f.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())


_load_dotenv()


def env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def env_int(key: str, default: int) -> int:
    try:
        return int(env(key, str(default)))
    except ValueError:
        return default


def env_float(key: str, default: float) -> float:
    try:
        return float(env(key, str(default)))
    except ValueError:
        return default


# Our own fake demo sites live under this suffix (never real sites).
DEMO_SUFFIX = ".test"
DEMO_PORT = env_int("DECOY_DEMO_PORT", 8601)
