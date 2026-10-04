"""Mutation check: break the harness on purpose and require the test suite to go RED.

The control (no change) must pass first. Each mutant replaces one exact text in one file of a
scratch copy and the offline test suite must then fail. A mutant whose target text is missing
is an error, never a kill.
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PY = os.environ.get("PY", sys.executable)

MUTANTS = [
    ("wilson: swap lower and upper", "stats.py",
     "return (0.0 if k == 0 else max(0.0, c - h), 1.0 if k == n else min(1.0, c + h))",
     "return (1.0 if k == n else min(1.0, c + h), 0.0 if k == 0 else max(0.0, c - h))"),
    ("wilson: wrong z", "stats.py", "z=1.959964", "z=1.644854"),
    ("operators: application skipped", "sampler.py",
     "payload = operators.OPS[guard][name](payload, rng)", "payload = payload"),
    ("operators: unchanged output accepted", "sampler.py",
     "            if nxt == cur:\n                ok = False\n                break\n", ""),
    ("bucket: ERROR counted as caught", "guards.py",
     '    if outcome == "ERROR":\n        return "error"\n    if kind == "attack":',
     '    if kind == "attack":\n        if outcome == "ERROR":\n            return "caught"'),
    ("bucket: ERROR counted as bypass", "guards.py",
     '    if outcome == "ERROR":\n        return "error"\n    if kind == "attack":',
     '    if kind == "attack":\n        if outcome == "ERROR":\n            return "bypass"'),
    ("run_variant: timeout becomes CLEAN", "guards.py",
     "except (subprocess.TimeoutExpired, OSError, UnicodeError, ValueError):\n        return \"ERROR\"",
     "except (subprocess.TimeoutExpired, OSError, UnicodeError, ValueError):\n        return \"CLEAN\""),
    ("interpret: crash read as FLAGGED", "guards.py",
     '        if (rc, v) in ((1, "QUARANTINE"), (2, "BLOCK")):\n            return "FLAGGED"\n        return "ERROR"',
     '        if rc != 0:\n            return "FLAGGED"\n        return "ERROR"'),
]


def run_tests(root):
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    p = subprocess.run([PY, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "-m", "not live"],
                       cwd=root, env=env, capture_output=True, text=True, timeout=300)
    return p.returncode


def scratch():
    d = tempfile.mkdtemp(prefix="mcfuzz-mut-")
    root = os.path.join(d, "repo")
    shutil.copytree(HERE, root, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
    return d, root


def main():
    d, root = scratch()
    try:
        if run_tests(root) != 0:
            print("control FAILED: the unmodified suite is not green, mutants not run")
            return 1
        print("control green")
    finally:
        shutil.rmtree(d, ignore_errors=True)
    killed = 0
    for name, fname, old, new in MUTANTS:
        d, root = scratch()
        try:
            path = os.path.join(root, fname)
            text = open(path, encoding="utf-8").read()
            if text.count(old) != 1:
                print(f"  ERROR  {name}: target text found {text.count(old)} times")
                return 1
            open(path, "w", encoding="utf-8").write(text.replace(old, new))
            red = run_tests(root) != 0
            print(f"  {'killed  ' if red else 'SURVIVED'} {name}")
            killed += red
        finally:
            shutil.rmtree(d, ignore_errors=True)
    print(f"mutants killed {killed}/{len(MUTANTS)}")
    return 0 if killed == len(MUTANTS) else 1


if __name__ == "__main__":
    sys.exit(main())
