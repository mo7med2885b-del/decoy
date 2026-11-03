"""Create (once) a Vultr Serverless Inference subscription and store its key in .env. Never prints keys.
Usage: python tools/vultr_inference.py"""
import re
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from decoy.config import env  # noqa: E402

API = "https://api.vultr.com/v2"
H = {"Authorization": "Bearer " + env("VULTR_API_KEY")}


def save_key(key: str):
    f = ROOT / ".env"
    text = f.read_text(encoding="utf-8")
    text = re.sub(r"(?m)^VULTR_INFERENCE_KEY=.*$", "VULTR_INFERENCE_KEY=" + key, text)
    f.write_text(text, encoding="utf-8")


def main():
    subs = httpx.get(API + "/inference", headers=H, timeout=20).json().get("subscriptions", [])
    sub = next((s for s in subs if s.get("label") == "decoy"), None)
    if sub is None:
        r = httpx.post(API + "/inference", headers=H, json={"label": "decoy"}, timeout=30)
        if r.status_code not in (200, 201, 202):
            sys.exit(f"create failed: HTTP {r.status_code} {r.text[:300]}")
        sub = r.json().get("subscription", r.json())
        print("created subscription", sub.get("id"))
    else:
        print("subscription exists", sub.get("id"))
    key = sub.get("api_key")
    if not key:
        sub = httpx.get(API + f"/inference/{sub['id']}", headers=H, timeout=20).json().get("subscription", {})
        key = sub.get("api_key")
    if not key:
        sys.exit("no api_key returned")
    save_key(key)
    print("inference key saved to .env (not shown)")


if __name__ == "__main__":
    main()
