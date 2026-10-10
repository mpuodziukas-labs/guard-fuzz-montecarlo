#!/bin/bash
# One command: reproduce the recorded default run, run the offline tests, run the mutants.
# The three guard repos must sit under GUARD_ROOT (default: the folder that holds this repo) for the fuzz step.
set -euo pipefail
cd "$(dirname "$0")"
PY="${PY:-python3}"
export PY PYTHONDONTWRITEBYTECODE=1
"$PY" evaluate.py --check
"$PY" -m pytest -q -p no:cacheprovider -m "not live"
"$PY" mutants.py
