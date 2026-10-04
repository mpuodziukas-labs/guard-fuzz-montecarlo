import report


def rec(kind, outcome, chain=(), guard="firewall", seed="s", text="t"):
    import guards
    return {"guard": guard, "kind": kind, "outcome": outcome, "bucket": guards_bucket(kind, outcome),
            "chain": chain, "seed_id": seed, "text": text, "id": "x"}


def guards_bucket(kind, outcome):
    import guards
    return guards.bucket(kind, outcome)


def test_tally_counts_errors_separately_and_out_of_the_denominator():
    rs = [rec("attack", "FLAGGED"), rec("attack", "CLEAN"), rec("attack", "ERROR"), rec("attack", "ERROR")]
    t = report.tally(rs, "attack")
    assert (t["caught"], t["bypass"], t["error"], t["scored"]) == (1, 1, 2, 2)


def test_tally_benign():
    rs = [rec("benign", "FLAGGED"), rec("benign", "CLEAN"), rec("benign", "CLEAN"), rec("benign", "ERROR")]
    t = report.tally(rs, "benign")
    assert (t["false_alarm"], t["ok"], t["error"], t["scored"]) == (1, 2, 1, 3)


def test_operator_rates_use_solo_and_any_chain():
    rs = [rec("attack", "CLEAN", ("zero_width",)), rec("attack", "FLAGGED", ("zero_width",)),
          rec("attack", "CLEAN", ("case_change", "zero_width")), rec("attack", "FLAGGED", ("case_change",))]
    rows = {r["op"]: r for r in report.operator_rows("firewall", rs)}
    assert rows["zero_width"]["solo"] == (1, 2) and rows["zero_width"]["any"] == (2, 3)
    assert rows["case_change"]["solo"] == (0, 1)


def test_shortest_bypasses_are_the_shortest_bypasses_only():
    rs = [rec("attack", "CLEAN", text="aaaa"), rec("attack", "CLEAN", text="a"), rec("attack", "FLAGGED", text=""),
          rec("attack", "ERROR", text="z")]
    out = report.shortest_bypasses(rs, 10)
    assert [r["text"] for r in out] == ["a", "aaaa"]


def test_display_masks_long_alphanumeric_runs_and_escapes_invisible():
    s = report.show("ab​" + "A" * 30)
    assert "\\u200b" in s and "A" * 16 not in s
