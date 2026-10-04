import hashlib
import pathlib

import config

ROOT = pathlib.Path(__file__).parent.parent
FROZEN = ["config.py", "operators.py", "seeds.py"]


def digest(name):
    return hashlib.sha256((ROOT / name).read_bytes()).hexdigest()


def test_manifest_lists_every_frozen_file_with_its_current_hash():
    rows = dict(l.split("  ", 1)[::-1] for l in (ROOT / "MANIFEST").read_text().splitlines() if l.strip())
    assert sorted(rows) == FROZEN
    for name in FROZEN:
        assert rows[name] == digest(name), f"{name} changed after the freeze: update MANIFEST only with a new frozen run"


def test_frozen_sample_sizes():
    assert config.N_FULL == 2000 and config.N_DEFAULT <= 600 and config.BENIGN_DIVISOR == 2
