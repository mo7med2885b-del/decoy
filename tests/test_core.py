import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from decoy import guard  # noqa: E402
from decoy.agent import rules_plan, valid_action  # noqa: E402
from decoy.urlcheck import BadLink, domain_signals, normalize  # noqa: E402
from decoy.verdict import Evidence  # noqa: E402


@pytest.mark.parametrize("bad", ["", "javascript:alert(1)", "file:///etc/passwd", "http://127.0.0.1/", "http://10.0.0.5/x",
                                 "http://169.254.169.254/latest/meta-data/", "http://localhost:8020/", "http://printer.local/"])
def test_bad_links_are_refused(bad):
    with pytest.raises(BadLink):
        normalize(bad)


def test_links_are_normalized():
    assert normalize("example.com/a") == "http://example.com/a"
    assert normalize("http://n0rthbank-login.test:8601/").startswith("http://n0rthbank")


def test_lookalike_domain_is_flagged():
    kinds = [s["kind"] for s in domain_signals("https://paypa1-secure-login.com/")]
    assert "lookalike_domain" in kinds
    assert not [s for s in domain_signals("https://www.paypal.com/") if s["kind"] == "lookalike_domain"]


def test_credentials_sent_elsewhere_is_dangerous():
    ev = Evidence("http://n0rthbank-login.test:8601/", [])
    ev.add_state({"url": "http://n0rthbank-login.test:8601/signin", "page": {},
                  "network": [{"url": "http://drop-zone.test:8601/collect", "host": "drop-zone.test", "canary_sent": ["PASSWORD"]}]}, 1)
    v = ev.verdict()
    assert v["level"] == "DANGEROUS"
    assert v["attacker_got"] == [{"host": "drop-zone.test", "data": ["PASSWORD"]}]


def test_quiet_page_has_no_threat():
    ev = Evidence("https://daily-recipes.example/", [])
    ev.add_state({"url": "https://daily-recipes.example/", "page": {"visible_text": "Lentil soup"}, "network": []}, 0)
    assert ev.verdict()["level"] == "NO THREAT FOUND"


def test_official_youtube_link_looks_safe():
    url = "https://www.youtube.com/watch?v=abc"
    ev = Evidence(url, domain_signals(url))
    ev.add_state({"url": url, "title": "Lentil soup - YouTube", "page": {"visible_text": "video"}, "network": []}, 0)
    v = ev.verdict()
    assert v["level"] == "LOOKS SAFE" and v["evidence"] == []
    assert "YouTube" in v["checks"][0]
    from decoy.verdict import template_summary
    assert "real YouTube link" in template_summary(v) and "Lentil soup - YouTube" in template_summary(v)
    assert not [s for s in domain_signals("https://y0utube-login.com/") if s["kind"] == "official_domain"]


def test_disguised_download_is_dangerous():
    ev = Evidence("http://invoice-portal.test:8601/", [])
    ev.add_state({"url": "x", "page": {}, "network": [], "downloads": [{"filename": "Invoice.pdf.exe", "sha256": "a"}]}, 1)
    ev.add_state({"url": "x", "page": {}, "network": [], "downloads": [{"filename": "Invoice.pdf.exe", "sha256": "a"}]}, 2)
    v = ev.verdict()
    assert v["level"] == "DANGEROUS" and len(v["downloads"]) == 1


PAGE = {"fields": [{"id": 1, "type": "email"}, {"id": 2, "type": "password"}], "buttons": [{"id": 3, "text": "Sign in"}], "links": []}


def test_model_cannot_type_real_values_or_click_unknown_ids():
    assert valid_action({"action": "fill_and_submit", "fields": [{"id": 2, "value": "hunter2"}], "submit_id": 3}, PAGE) is None
    assert valid_action({"action": "click", "id": 99}, PAGE) is None
    ok = valid_action({"action": "fill_and_submit", "fields": [{"id": 2, "value": "PASSWORD"}], "submit_id": 3}, PAGE)
    assert ok and ok["fields"] == [{"id": 2, "value": "PASSWORD"}]


def test_rules_fill_a_login_form_once():
    tried = set()
    first = rules_plan(PAGE, tried)
    assert first["action"] == "fill_and_submit" and {f["value"] for f in first["fields"]} == {"EMAIL", "PASSWORD"}
    assert rules_plan(PAGE, tried)["action"] != "fill_and_submit"


def test_guard_caps(tmp_path, monkeypatch):
    b = guard.Budget(ledger=tmp_path / "ledger.json")
    b.max_calls = 1
    b.check()
    b.record(1000, 100)
    with pytest.raises(guard.BudgetExceeded):
        b.check()
    monkeypatch.setenv("KILL_SWITCH", "1")
    with pytest.raises(guard.BudgetExceeded):
        guard.Budget(ledger=tmp_path / "other.json").check()


def test_daily_dollar_cap(tmp_path, monkeypatch):
    monkeypatch.setenv("MAX_USD_PER_DAY", "0.0001")
    b = guard.Budget(ledger=tmp_path / "ledger.json")
    b.record(1_000_000, 0)
    with pytest.raises(guard.BudgetExceeded):
        guard.Budget(ledger=tmp_path / "ledger.json").check()


def test_cloaking_login_form_hidden_from_a_bot():
    from decoy.verdict import cloaking
    c = cloaking([{"name": "Careless employee", "sig": ("northbank - sign in", True)}, {"name": "Security bot", "sig": ("daily recipes", False)}])
    assert c and c["weight"] >= 40 and "Security bot" in c["text"]
    assert cloaking([{"name": "A", "sig": ("recipes", False)}, {"name": "B", "sig": ("recipes", False)}]) is None
    assert cloaking([{"name": "A", "sig": ("recipes", False)}]) is None


def test_swarm_merge_and_redirect_chain():
    lead = Evidence("http://go-short.test/x", [])
    scout = Evidence("http://go-short.test/x", [])
    scout.add_state({"url": "http://n0rthbank-login.test/", "title": "t", "page": {}, "network": [
        {"url": "http://drop-zone.test/c", "host": "drop-zone.test", "canary_sent": ["PASSWORD"]}],
        "redirects": [{"from": "http://go-short.test/x", "to": "http://n0rthbank-login.test/", "status": 302}]}, 0)
    lead.absorb(scout)
    v = lead.verdict()
    assert v["attacker_got"] and any(i["kind"] == "redirect" for i in v["evidence"])


def test_threat_memory_links_scams_that_share_a_drop_server(tmp_path):
    from decoy import store
    db = tmp_path / "t.db"
    v = {"level": "DANGEROUS", "score": 100, "summary": "s", "evidence": [{"text": "x", "kind": "k"}], "attacker_got": [{"host": "drop-zone.test", "data": ["PASSWORD"]}]}
    store.save("aaa", "http://n0rthbank-login.test/", v, db)
    store.save("bbb", "http://paypa1-help.test/", v, db)
    m = store.memory("http://paypa1-help.test/", ["drop-zone.test"], exclude_id="bbb", path=db)
    assert m["campaign"] and m["campaign"][0]["shared_server"] == "drop-zone.test"
    assert store.memory("http://n0rthbank-login.test/", [], exclude_id="aaa", path=db)["seen_before"] == []
    store.decide("aaa", "block", "n", db)
    assert store.get("aaa", db)["decision"] == "block" and len(store.history(5, db)) == 2
