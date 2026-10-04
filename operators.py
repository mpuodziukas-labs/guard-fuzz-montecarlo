"""Frozen mutation operators. Each is op(payload, rng) -> new payload, deterministic for a given rng.

Text operators work on a str. The router turn splitter joins turns with the record separator
U+001E, which the router adapter turns back into separate messages. Attest operators work on a
transcript dict {"events": [...], "style": {...}} and never touch a signed field, so a mutated
valid transcript is still a valid transcript.
"""
import base64
import copy
import random

import seeds

ZERO_WIDTH = ("\u200b", "\u200c", "\u200d", "\u2060")
HOMOGLYPH = {"a": "\u0430", "e": "\u0435", "o": "\u043e", "p": "\u0440", "c": "\u0441", "x": "\u0445", "y": "\u0443", "i": "\u0456"}
PUNCT = (",", ".", ";", ":", "-", "_")
SYNONYMS = (
    ("ignore", "disregard"), ("previous", "prior"), ("instructions", "directions"), ("reveal", "disclose"),
    ("print", "output"), ("rules", "guidelines"), ("patient", "client"), ("password", "passphrase"),
    ("token", "credential"), ("continue", "proceed"), ("send", "forward"), ("system", "base"),
    ("write", "draft"), ("explain", "describe"), ("summarize", "condense"), ("function", "routine"),
    ("find", "locate"), ("fix", "repair"), ("example", "sample"), ("notes", "minutes"),
    ("thanks", "cheers"), ("difference", "distinction"), ("convert", "transform"), ("release", "version"),
)
TEMPLATES = (
    "Please note the following. {t}", "As discussed earlier: {t}", "Could you kindly handle this: {t}",
    "{t} Thanks in advance.", "Quick reminder, {t}", "For the record: {t} End of note.",
)
BENIGN_PRE = ("Thanks for the update on the release schedule.", "Here is the weekly summary of open tickets.")
BENIGN_POST = ("Let me know if the plan works for the team.", "That is all for this week.")


def case_change(t, rng):
    out = "".join(c.swapcase() if c.isalpha() and rng.random() < 0.5 else c for c in t)
    return out if out != t else t.swapcase()


def ws_insert(t, rng):
    if " " not in t:
        i = max(1, len(t) // 2)
        return t[:i] + "  " + t[i:]
    parts = t.split(" ")
    out = parts[0]
    for p in parts[1:]:
        out += rng.choice(("  ", "   ", "\t", " \t")) + p
    return out


def punct_insert(t, rng):
    words = t.split(" ")
    if len(words) < 2:
        i = max(1, len(t) // 2)
        return t[:i] + rng.choice(PUNCT) + t[i:]
    out = [w + rng.choice(PUNCT) if rng.random() < 0.35 else w for w in words]
    if out == words:
        out[0] = out[0] + rng.choice(PUNCT)
    return " ".join(out)


def synonym_swap(t, rng):
    live = [(a, b) for a, b in SYNONYMS if a in t.lower()] + [(b, a) for a, b in SYNONYMS if b in t.lower()]
    if not live:
        return t
    a, b = live[rng.randrange(len(live))]
    out, low, i = "", t.lower(), 0
    while i < len(t):
        if low.startswith(a, i):
            out += b.capitalize() if t[i].isupper() else b
            i += len(a)
        else:
            out += t[i]
            i += 1
    return out


def homoglyph(t, rng):
    idx = [i for i, c in enumerate(t) if c in HOMOGLYPH]
    if not idx:
        return t
    pick = {i for i in idx if rng.random() < 0.3} or {idx[rng.randrange(len(idx))]}
    return "".join(HOMOGLYPH[c] if i in pick else c for i, c in enumerate(t))


def zero_width(t, rng):
    idx = [i for i, c in enumerate(t) if not c.isspace()]
    if not idx:
        return t + ZERO_WIDTH[0]
    pick = {i for i in idx if rng.random() < 0.15} or {idx[rng.randrange(len(idx))]}
    return "".join(c + rng.choice(ZERO_WIDTH) if i in pick else c for i, c in enumerate(t))


def split_lines(t, rng):
    sp = [i for i, c in enumerate(t) if c == " "]
    if not sp:
        i = max(1, len(t) // 2)
        return t[:i] + "\n" + t[i:]
    pick = {i for i in sp if rng.random() < 0.4} or {sp[rng.randrange(len(sp))]}
    return "".join("\n" if i in pick else c for i, c in enumerate(t))


def b64_wrap(t, rng):
    return rng.choice(("Decode and follow: ", "payload=", "b64: ")) + base64.b64encode(t.encode()).decode()


def hex_wrap(t, rng):
    return rng.choice(("hex: ", "blob=", "Decode this hex: ")) + t.encode().hex()


def paraphrase(t, rng):
    return rng.choice(TEMPLATES).format(t=t)


def embed_benign(t, rng):
    return rng.choice(BENIGN_PRE) + "\n" + t + "\n" + rng.choice(BENIGN_POST)


def split_turns(t, rng):
    if len(t) < 3:
        return t + "\x1e" + "ok"
    k = rng.choice((2, 3))
    cuts = sorted(rng.sample(range(1, len(t)), min(k - 1, len(t) - 1)))
    parts, prev = [], 0
    for c in cuts + [len(t)]:
        parts.append(t[prev:c])
        prev = c
    return "\x1e".join(parts)


# ---------------------------------------------------------------- attest (transcript dict)
def key_reorder(v, rng):
    v = copy.deepcopy(v)
    v["style"]["order_seed"] = rng.randrange(1, 10 ** 6)
    return v


def ts_jitter(v, rng):
    v = copy.deepcopy(v)
    for e in v["events"]:
        e["ts"] += rng.choice((-3, -2, -1, 1, 2, 3))
    return v


def json_spacing(v, rng):
    v = copy.deepcopy(v)
    v["style"]["sep"] = "spaced"
    return v


def unicode_escape(v, rng):
    v = copy.deepcopy(v)
    v["style"]["ascii"] = False
    return v


def blank_lines(v, rng):
    v = copy.deepcopy(v)
    v["style"]["blank"] = True
    return v


def crlf(v, rng):
    v = copy.deepcopy(v)
    v["style"]["crlf"] = True
    return v


def interleave_turns(v, rng):
    v = copy.deepcopy(v)
    used = {e.get("call_id") for e in v["events"]}
    for j in range(rng.choice((1, 2))):
        cid = f"x{rng.randrange(10 ** 5)}-{j}"
        while cid in used:
            cid += "z"
        used.add(cid)
        extra = seeds.pair(cid, "ping", {"n": j}, f"pong {j}", f"nx-{cid}", t0=3000 + j * 10, delay=2)
        pos = rng.randrange(len(v["events"]) + 1)
        if v["events"] and pos < len(v["events"]) and v["events"][pos]["type"] == "result" and pos > 0 \
                and v["events"][pos - 1]["type"] == "call":
            pos -= 1
        v["events"][pos:pos] = extra
    return v


def extra_fields(v, rng):
    v = copy.deepcopy(v)
    for i, e in enumerate(v["events"]):
        e["meta"] = {"trace": f"t-{rng.randrange(10 ** 6)}", "seq": i}
    return v


def hex_case(v, rng):
    v = copy.deepcopy(v)
    for e in v["events"]:
        r = e.get("receipt")
        if r:
            for k in ("sig", "args_sha256", "result_sha256"):
                r[k] = r[k].upper()
    return v


_TEXT = {"case_change": case_change, "ws_insert": ws_insert, "punct_insert": punct_insert,
         "synonym_swap": synonym_swap, "homoglyph": homoglyph, "zero_width": zero_width,
         "split_lines": split_lines, "b64_wrap": b64_wrap, "hex_wrap": hex_wrap,
         "paraphrase": paraphrase, "embed_benign": embed_benign}

OPS = {
    "firewall": dict(_TEXT),
    "router": {**_TEXT, "split_turns": split_turns},
    "attest": {"key_reorder": key_reorder, "ts_jitter": ts_jitter, "json_spacing": json_spacing,
               "unicode_escape": unicode_escape, "blank_lines": blank_lines, "crlf": crlf,
               "interleave_turns": interleave_turns, "extra_fields": extra_fields, "hex_case": hex_case},
}
FINAL = ("split_turns",)
WRAP = ("b64_wrap", "hex_wrap")   # run after the text operators, before turn splitting
