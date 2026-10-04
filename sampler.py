"""Variant generation: a seed plus a chain of one or two operators, sampled with a fixed seed."""
import copy
import itertools
import json
import random

import config
import operators
import seeds


def apply_chain(guard, payload, chain, rng):
    for name in chain:
        payload = operators.OPS[guard][name](payload, rng)
    return payload


def _ordered(chain):
    """Text operators first, then encoders, then turn splitting, so no operator sees text it cannot change."""
    return tuple(sorted(chain, key=lambda n: (n in operators.FINAL) * 2 + (n in operators.WRAP)))


def _try(guard, kind, chain, rng):
    """Pick a seed and apply the chain. Every operator must change the payload at its own step."""
    pool = seeds.SEEDS[guard][kind]
    for _ in range(500):
        sid, cls, base = pool[rng.randrange(len(pool))]
        cur = copy.deepcopy(base)
        ok = True
        for name in chain:
            nxt = operators.OPS[guard][name](copy.deepcopy(cur), rng)
            if nxt == cur:
                ok = False
                break
            cur = nxt
        if ok:
            return sid, cls, cur
    raise RuntimeError(f"operator chain {chain} never changed any {guard} {kind} seed")


def generate(guard, kind, n):
    """n variants: half solo operators round robin, half unordered operator pairs round robin."""
    rng = random.Random(f"{config.SEED}:{guard}:{kind}")
    names = list(operators.OPS[guard])
    pairs = list(itertools.combinations(names, 2))
    n_solo = n // 2
    out = []
    for i in range(n):
        if i < n_solo:
            chain = (names[i % len(names)],)
        else:
            a, b = pairs[(i - n_solo) % len(pairs)]
            chain = _ordered((a, b) if rng.random() < 0.5 else (b, a))
        sid, cls, payload = _try(guard, kind, chain, rng)
        out.append({"id": f"{guard}-{kind}-{i:05d}", "guard": guard, "kind": kind, "seed_id": sid,
                    "seed_class": cls, "chain": chain, "payload": payload})
    return out


def baseline(guard, kind):
    return [{"id": f"{guard}-{kind}-base-{sid}", "guard": guard, "kind": kind, "seed_id": sid, "seed_class": cls,
             "chain": (), "payload": copy.deepcopy(p)} for sid, cls, p in seeds.SEEDS[guard][kind]]


def _ordered_keys(obj, order_seed, salt):
    keys = sorted(obj)
    if not order_seed or len(keys) < 2:
        return keys
    r = random.Random(f"{order_seed}:{salt}")
    r.shuffle(keys)
    return keys if keys != sorted(obj) else keys[1:] + keys[:1]


def _dump(obj, style, salt):
    spaced = style["sep"] == "spaced"
    seps = (", ", ": ") if spaced else (",", ":")

    def enc(o, s):
        if isinstance(o, dict):
            body = seps[0].join(json.dumps(k, ensure_ascii=style["ascii"]) + seps[1] + enc(o[k], f"{s}/{k}")
                                for k in _ordered_keys(o, style["order_seed"], s))
            return "{" + body + "}"
        if isinstance(o, list):
            return "[" + seps[0].join(enc(x, s) for x in o) + "]"
        return json.dumps(o, ensure_ascii=style["ascii"])
    return enc(obj, salt)


def render(guard, payload):
    """The exact text given to the guard."""
    if guard == "attest":
        st = payload["style"]
        lines = [_dump(e, st, f"l{i}") for i, e in enumerate(payload["events"])]
        nl = "\r\n" if st["crlf"] else "\n"
        return (nl + nl if st["blank"] else nl).join(lines) + nl
    if guard == "router":
        return json.dumps(payload.split("\x1e"))
    return payload
