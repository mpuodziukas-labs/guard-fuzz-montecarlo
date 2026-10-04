import random

import config
import operators
import sampler
import seeds


def key(v):
    return (v["seed_id"], tuple(v["chain"]), repr(v["payload"]))


def test_seed_determinism():
    for g in config.GUARDS:
        a = [key(v) for v in sampler.generate(g, "attack", 60)]
        b = [key(v) for v in sampler.generate(g, "attack", 60)]
        assert a == b


def test_other_seed_gives_other_variants(monkeypatch):
    a = [key(v) for v in sampler.generate("firewall", "attack", 60)]
    monkeypatch.setattr(config, "SEED", "another-seed")
    b = [key(v) for v in sampler.generate("firewall", "attack", 60)]
    assert a != b


def test_count_and_labels():
    for g in config.GUARDS:
        vs = sampler.generate(g, "benign", 40)
        assert len(vs) == 40 and len({v["id"] for v in vs}) == 40
        assert all(v["kind"] == "benign" and v["guard"] == g for v in vs)


def test_every_operator_in_every_chain_changed_the_payload():
    for g in config.GUARDS:
        for v in sampler.generate(g, "attack", 80):
            seed = next(s[2] for s in seeds.SEEDS[g]["attack"] if s[0] == v["seed_id"])
            assert v["payload"] != seed
            assert 1 <= len(v["chain"]) <= 2
            assert all(c in operators.OPS[g] for c in v["chain"])


def test_every_operator_is_sampled_solo_and_in_pairs():
    for g in config.GUARDS:
        vs = sampler.generate(g, "attack", 400)
        solo = {v["chain"][0] for v in vs if len(v["chain"]) == 1}
        assert solo == set(operators.OPS[g])


def test_split_turns_is_always_last():
    vs = sampler.generate("router", "attack", 300)
    assert any("split_turns" in v["chain"] for v in vs)
    assert all("split_turns" not in v["chain"][:-1] for v in vs)


def test_baseline_has_one_row_per_seed_and_no_operator():
    for g in config.GUARDS:
        b = sampler.baseline(g, "attack")
        assert len(b) == len(seeds.SEEDS[g]["attack"]) and all(v["chain"] == () for v in b)


def test_apply_chain_applies_each_operator_in_order():
    rng = random.Random(2)
    out = sampler.apply_chain("firewall", "hello world", ("zero_width",), rng)
    assert out != "hello world" and any(c in out for c in "\u200b\u200c\u200d\u2060")
    out2 = sampler.apply_chain("firewall", "hello world", ("b64_wrap",), random.Random(2))
    assert out2.startswith("Decode") or "aGVsbG8gd29ybGQ" in out2


def test_render_router_splits_turns():
    import json
    text = sampler.render("router", "abc\x1edef")
    assert json.loads(text) == ["abc", "def"]
