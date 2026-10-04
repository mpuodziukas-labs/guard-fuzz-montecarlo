"""Run the Monte Carlo attack fuzz against three guards and print the bypass table.

    python3 evaluate.py            default run (N_DEFAULT attack variants per guard)
    python3 evaluate.py --full     full run (N_FULL = 2000 per guard)
    python3 evaluate.py --check    default run, exit 1 unless it equals results-default.txt
    python3 evaluate.py --record   write results-default.txt (or results-full.txt with --full)
"""
import hashlib
import pathlib
import sys
from concurrent.futures import ThreadPoolExecutor

import config
import guards
import report
import sampler

ROOT = pathlib.Path(__file__).parent


def run_all(n, workers=6):
    """Score every variant. Records keep every outcome, including errors; nothing is dropped."""
    variants = []
    for g in config.GUARDS:
        variants += sampler.generate(g, "attack", n) + sampler.generate(g, "benign", max(1, n // config.BENIGN_DIVISOR))
        variants += sampler.baseline(g, "attack") + sampler.baseline(g, "benign")
    with ThreadPoolExecutor(max_workers=workers) as ex:
        outcomes = list(ex.map(lambda v: guards.run_variant(v["guard"], v["payload"]), variants))
    return [{"id": v["id"], "guard": v["guard"], "kind": v["kind"], "seed_id": v["seed_id"], "chain": v["chain"],
             "outcome": o, "bucket": guards.bucket(v["kind"], o), "text": sampler.render(v["guard"], v["payload"])}
            for v, o in zip(variants, outcomes)]


def render(n, workers=6):
    man = hashlib.sha256((ROOT / "MANIFEST").read_bytes()).hexdigest()[:12]
    recs = run_all(n, workers)
    out = [f"guard-fuzz-montecarlo seed={config.SEED} attack_n={n} benign_n={n // config.BENIGN_DIVISOR} manifest={man}"]
    for g in config.GUARDS:
        out += [""] + report.guard_report(g, guards.REPOS[g], [r for r in recs if r["guard"] == g])
    scored = sum(1 for r in recs if r["bucket"] != "error")
    return "\n".join(out) + "\n", scored


def render_default():
    return render(config.N_DEFAULT)[0]


def main(argv):
    full = "--full" in argv
    text, scored = render(config.N_FULL if full else config.N_DEFAULT)
    print(text, end="")
    if scored == 0:
        print("RED no variant was scored (are the guard repos under GUARD_ROOT?)", file=sys.stderr)
        return 1
    target = ROOT / ("results-full.txt" if full else "results-default.txt")
    if "--record" in argv:
        target.write_text(text)
    if "--check" in argv and text != target.read_text():
        print("RED output differs from " + target.name, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
