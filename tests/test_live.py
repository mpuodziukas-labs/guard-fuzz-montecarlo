import pathlib

import pytest

import guards
import report

ROOT = pathlib.Path(__file__).parent.parent
have = all((guards.GUARD_ROOT / d).is_dir() for d in guards.REPOS.values())
live = pytest.mark.skipif(not have, reason="guard repos not found under GUARD_ROOT")


def test_readme_contains_the_recorded_default_run_exactly():
    readme = (ROOT / "README.md").read_text()
    recorded = (ROOT / "results-default.txt").read_text().rstrip("\n")
    assert recorded in readme, "README drifted from results-default.txt"


@pytest.mark.live
@live
def test_live_smoke_every_guard_answers_without_error():
    import evaluate
    recs = evaluate.run_all(24, workers=4)
    assert recs and all(r["outcome"] in ("FLAGGED", "CLEAN") for r in recs)


@pytest.mark.live
@live
def test_recorded_default_run_reproduces():
    import evaluate
    out = evaluate.render_default()
    assert out.rstrip("\n") == (ROOT / "results-default.txt").read_text().rstrip("\n")
