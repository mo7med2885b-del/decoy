"""Read-only look at the Vultr account: balance, charges, inference subscriptions and their usage.
Never prints keys. Usage: python tools/vultr_account.py"""
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from decoy.config import env  # noqa: E402  (loads .env)

API = "https://api.vultr.com/v2"


def get(path):
    r = httpx.get(API + path, headers={"Authorization": "Bearer " + env("VULTR_API_KEY")}, timeout=20)
    return r.status_code, (r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text[:200])


def main():
    if not env("VULTR_API_KEY"):
        sys.exit("VULTR_API_KEY is not set in .env")
    code, acc = get("/account")
    if code != 200:
        sys.exit(f"account: HTTP {code} {acc}")
    a = acc.get("account", {})
    print(f"balance {a.get('balance')}  pending charges {a.get('pending_charges')}  last payment {a.get('last_payment_date')}")
    code, inf = get("/inference")
    if code != 200:
        print(f"inference list: HTTP {code} {inf}")
        return
    subs = inf.get("subscriptions", [])
    print(f"inference subscriptions: {len(subs)}")
    for s in subs:
        print(f"  {s.get('id')}  label={s.get('label')}  created={s.get('date_created')}  key={'yes' if s.get('api_key') else 'no'}")
        code, use = get(f"/inference/{s['id']}/usage")
        print(f"  usage: {use if code == 200 else f'HTTP {code}'}")


if __name__ == "__main__":
    main()
