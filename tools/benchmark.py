"""Measure Decoy on labelled URLs. Reproducible: python tools/benchmark.py run bench/urls.csv bench/results.jsonl
then python tools/benchmark.py report bench/results.jsonl

Labels: "phish" (verified phishing from a public feed) or "benign" (well-known legitimate sites). A scan counts as a DETECTION when the
verdict is SUSPICIOUS or DANGEROUS. Scans where the page could not be reached or only a loading or bot-check screen was seen are reported
separately ("not assessable"), never counted as a detection or a miss. Rates come with 95% Wilson intervals. Small samples: read the intervals."""
import json
import math
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def run(urls_csv: str, out: str, limit: int = 0):
    from decoy import agent
    from decoy.guard import Budget
    rows = [l.strip().split(",", 2) for l in Path(urls_csv).read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]
    done = {json.loads(l)["url"] for l in Path(out).read_text(encoding="utf-8").splitlines()} if Path(out).exists() else set()
    for url, label, source in rows[: limit or None]:
        if url in done:
            continue
        t0, ev = time.time(), []
        try:
            v = agent.run_scan(uuid.uuid4().hex[:12], url, ev.append, Budget())
            rec = {"url": url, "label": label, "source": source, "level": v["level"], "score": v["score"], "kinds": [e["kind"] for e in v["evidence"]],
                   "limits": v.get("limits", []), "title": v.get("page_title", ""), "error": v.get("error"), "seconds": round(time.time() - t0, 1),
                   "static_only": all(e["kind"] in {"free_hosting", "new_domain", "lookalike_domain", "no_https", "shortener", "raw_ip", "bad_cert", "fresh_cert"} for e in v["evidence"]) if v["evidence"] else None}
        except Exception as e:  # a crash is a result too
            rec = {"url": url, "label": label, "source": source, "level": "ERROR", "score": 0, "kinds": [], "limits": [], "error": str(e)[:120], "seconds": round(time.time() - t0, 1)}
        with open(out, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
        print(rec["label"], rec["level"], rec["score"], url[:70], flush=True)


def assessable(r: dict) -> bool:
    if r["level"] == "ERROR" or r.get("error"):
        return False
    return not any("loading or bot-check" in x for x in r.get("limits", [])) and bool(r.get("title") or r["kinds"])


def report(path: str):
    rs = [json.loads(l) for l in Path(path).read_text(encoding="utf-8").splitlines() if l.strip()]
    print(f"{len(rs)} scans")
    flagged = lambda r: r["level"] in ("SUSPICIOUS", "DANGEROUS")
    for label, want in (("phish", True), ("benign", False)):
        s = [r for r in rs if r["label"] == label]
        ok = [r for r in s if assessable(r)]
        k = sum(1 for r in ok if flagged(r))
        lo, hi = wilson(k, len(ok))
        name = "detection rate (recall)" if want else "false-positive rate"
        print(f"\n{label}: {len(s)} scanned, {len(s) - len(ok)} not assessable (unreachable, error or bot-check), {len(ok)} assessed")
        print(f"  flagged {k}/{len(ok)} -> {name} {k / len(ok):.0%} (95% CI {lo:.0%}-{hi:.0%})" if ok else "  nothing assessable")
        if label == "phish" and ok:
            pw = sum(1 for r in ok if flagged(r) and "provider_warning" in r["kinds"])
            print(f"  {pw} of the detections came from a security provider's own warning page (for example Cloudflare 'Suspected Phishing'), not from Decoy's own sandbox behaviour")
            dyn = sum(1 for r in ok if flagged(r) and r.get("static_only") is False and "provider_warning" not in r["kinds"])
            print(f"  of the detections, {dyn} needed behaviour seen in the sandbox (data leaks, exfiltration channel, cloaking, scripts...), {k - dyn} came from address/reputation signals alone")
        if label == "benign":
            for r in ok:
                if flagged(r):
                    print("  FALSE POSITIVE:", r["url"], r["level"], r["score"], r["kinds"])
    ph = [r for r in rs if r["label"] == "phish" and assessable(r)]
    be = [r for r in rs if r["label"] == "benign" and assessable(r)]
    tp = sum(1 for r in ph if flagged(r)); fp = sum(1 for r in be if flagged(r))
    if tp + fp:
        pr = tp / (tp + fp); rc = tp / len(ph) if ph else 0
        print(f"\nprecision {pr:.0%}, recall {rc:.0%}, F1 {2 * pr * rc / (pr + rc):.2f}" if pr + rc else "")
    secs = sorted(r["seconds"] for r in rs if r["seconds"])
    if secs:
        print(f"scan time: median {secs[len(secs) // 2]}s, max {secs[-1]}s")
    import statistics as st
    for label in ("phish", "benign"):
        g = [r for r in rs if r["label"] == label and assessable(r)]
        if g:
            print(f"{label}: median score {st.median(r['score'] for r in g):g}, median scan time {st.median(r['seconds'] for r in g):g}s, "
                  f"median score of flagged {st.median([r['score'] for r in g if flagged(r)] or [0]):g}")
    print("not assessable counts:", {l: sum(1 for r in rs if r["label"] == l and not assessable(r)) for l in ("phish", "benign")})


if __name__ == "__main__":
    {"run": lambda: run(sys.argv[2], sys.argv[3], int(sys.argv[4]) if len(sys.argv) > 4 else 0), "report": lambda: report(sys.argv[2])}[sys.argv[1]]()
