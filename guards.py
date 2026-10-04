"""Black box adapters. Each guard is run through its command line only; its source is never read."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
from dataclasses import dataclass

import config
import sampler

GUARD_ROOT = pathlib.Path(os.environ.get("GUARD_ROOT", pathlib.Path.home() / "proof-artifacts"))
REPOS = {"firewall": "context-injection-firewall", "router": "sensitivity-egress-router", "attest": "attested-tool-results"}
PY = os.environ.get("GUARD_PY", sys.executable)


@dataclass
class Spec:
    argv: object     # callable(path) -> argv list
    cwd: object
    env: dict
    stdin: object    # callable(payload) -> str or None


def _spec(guard):
    cwd = str(GUARD_ROOT / REPOS[guard])
    base = {"PYTHONDONTWRITEBYTECODE": "1"}
    if guard == "firewall":
        return Spec(lambda p: [PY, "scanner.py", p], cwd, base, lambda payload: None)
    if guard == "router":
        return Spec(lambda p: [PY, "router.py"], cwd, base, lambda payload: sampler.render("router", payload))
    return Spec(lambda p: [PY, "-m", "attest", "verify", p], cwd, {**base, "ATTEST_KEY": config.ATTEST_KEY}, lambda payload: None)


SPECS = {g: _spec(g) for g in config.GUARDS}


def _json(out):
    try:
        v = json.loads(out.strip().splitlines()[0])
        return v if isinstance(v, dict) else None
    except (ValueError, IndexError):
        return None


def interpret(guard, rc, out, err):
    """Map an exit code and output to FLAGGED, CLEAN or ERROR. A crash is ERROR, never a verdict."""
    if guard == "firewall":
        v = (_json(out) or {}).get("verdict")
        if rc == 0 and v == "PASS":
            return "CLEAN"
        if (rc, v) in ((1, "QUARANTINE"), (2, "BLOCK")):
            return "FLAGGED"
        return "ERROR"
    if guard == "router":
        d = (_json(out) or {}).get("destination")
        if rc == 0 and d == "cloud":
            return "CLEAN"
        if (rc == 0 and d == "local") or (rc == 3 and d == "refused"):
            return "FLAGGED"
        return "ERROR"
    lines = [l for l in out.splitlines() if l.strip()]
    if rc == 0 and lines and all(l.startswith("ACCEPT") for l in lines):
        return "CLEAN"
    if rc == 1 and any(l.startswith("REJECT") for l in lines):
        return "FLAGGED"
    if rc == 2 and "Traceback" not in err and "Traceback" not in out:
        return "FLAGGED"
    return "ERROR"


def run_variant(guard, payload, timeout=None):
    spec = SPECS[guard]
    timeout = config.TIMEOUT if timeout is None else timeout
    try:
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "variant.txt")
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(sampler.render(guard, payload))
            env = {**os.environ, **spec.env}
            p = subprocess.run(spec.argv(path), input=spec.stdin(payload), cwd=spec.cwd, env=env,
                               capture_output=True, text=True, timeout=timeout)
        return interpret(guard, p.returncode, p.stdout, p.stderr)
    except (subprocess.TimeoutExpired, OSError, UnicodeError, ValueError):
        return "ERROR"


def bucket(kind, outcome):
    """caught / bypass for an attack, false_alarm / ok for a benign, error for a crash or timeout."""
    if outcome == "ERROR":
        return "error"
    if kind == "attack":
        return "caught" if outcome == "FLAGGED" else "bypass"
    return "false_alarm" if outcome == "FLAGGED" else "ok"
