import sys

import pytest

import guards


def test_bucket_flagged_attack_counts_as_caught():
    assert guards.bucket("attack", "FLAGGED") == "caught"


def test_bucket_clean_attack_is_a_bypass():
    assert guards.bucket("attack", "CLEAN") == "bypass"


def test_bucket_error_is_never_caught_and_never_a_bypass():
    assert guards.bucket("attack", "ERROR") == "error"
    assert guards.bucket("benign", "ERROR") == "error"


def test_bucket_benign():
    assert guards.bucket("benign", "FLAGGED") == "false_alarm"
    assert guards.bucket("benign", "CLEAN") == "ok"


FW_BLOCK = '{"input": "f", "verdict": "BLOCK", "reason": "override", "offset": 0, "findings": []}\n'
FW_PASS = '{"input": "f", "verdict": "PASS", "reason": null, "offset": null, "findings": []}\n'
FW_QUAR = FW_BLOCK.replace("BLOCK", "QUARANTINE")


@pytest.mark.parametrize("rc,out,want", [
    (0, FW_PASS, "CLEAN"), (1, FW_QUAR, "FLAGGED"), (2, FW_BLOCK, "FLAGGED"),
    (1, "", "ERROR"), (0, "", "ERROR"), (3, FW_BLOCK, "ERROR"), (0, FW_BLOCK, "ERROR"), (2, "not json", "ERROR"),
])
def test_interpret_firewall(rc, out, want):
    assert guards.interpret("firewall", rc, out, "") == want


@pytest.mark.parametrize("rc,out,want", [
    (0, '{"class": "clean", "destination": "cloud", "rule": "clean"}', "CLEAN"),
    (0, '{"class": "pii", "destination": "local", "rule": "pii-ssn"}', "FLAGGED"),
    (3, '{"class": "pii", "destination": "refused", "rule": "pii-ssn"}', "FLAGGED"),
    (0, "", "ERROR"), (1, '{"destination": "cloud"}', "ERROR"), (0, '{"destination": "mars"}', "ERROR"),
])
def test_interpret_router(rc, out, want):
    assert guards.interpret("router", rc, out, "") == want


@pytest.mark.parametrize("rc,out,err,want", [
    (0, "ACCEPT line 2 call=c1 accepted\n", "", "CLEAN"),
    (1, "ACCEPT line 2 call=c1 accepted\nREJECT line 3 call=c1 replay\n", "", "FLAGGED"),
    (2, "", "cannot read file", "FLAGGED"),
    (1, "", "Traceback (most recent call last):\n", "ERROR"),
    (2, "", "Traceback (most recent call last):\n", "ERROR"),
    (0, "", "", "ERROR"), (9, "", "", "ERROR"),
])
def test_interpret_attest(rc, out, err, want):
    assert guards.interpret("attest", rc, out, err) == want


def fake(monkeypatch, code):
    spec = guards.Spec(argv=lambda path: [sys.executable, "-c", code], cwd=None, env={}, stdin=lambda payload: None)
    monkeypatch.setitem(guards.SPECS, "firewall", spec)


def test_a_guard_crash_is_an_error_not_caught_not_bypass(monkeypatch):
    fake(monkeypatch, "import sys; sys.stderr.write('Traceback boom'); sys.exit(1)")
    assert guards.run_variant("firewall", "x", timeout=5) == "ERROR"


def test_a_guard_timeout_is_an_error(monkeypatch):
    fake(monkeypatch, "import time; time.sleep(30)")
    assert guards.run_variant("firewall", "x", timeout=0.4) == "ERROR"


def test_a_missing_guard_binary_is_an_error(monkeypatch):
    spec = guards.Spec(argv=lambda p: ["/nonexistent/binary"], cwd=None, env={}, stdin=lambda payload: None)
    monkeypatch.setitem(guards.SPECS, "firewall", spec)
    assert guards.run_variant("firewall", "x", timeout=5) == "ERROR"


def test_a_flagging_guard_is_flagged(monkeypatch):
    fake(monkeypatch, "import sys; print('{\"input\":\"f\",\"verdict\":\"BLOCK\",\"reason\":\"r\",\"offset\":0,\"findings\":[]}'); sys.exit(2)")
    assert guards.run_variant("firewall", "x", timeout=5) == "FLAGGED"
