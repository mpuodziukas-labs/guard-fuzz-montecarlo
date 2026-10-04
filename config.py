"""Frozen run parameters. Changing any value changes the sha256 in MANIFEST and fails the freeze test."""
SEED = "mcfuzz-v1-20261004"
N_FULL = 2000          # attack variants per guard in the full run
N_DEFAULT = 400        # attack variants per guard in ./run.sh (the 60 second run)
BENIGN_DIVISOR = 2     # benign variants per guard = attack variants // 2
TIMEOUT = 20           # seconds per guard call, a timeout is an ERROR
GUARDS = ("firewall", "router", "attest")
ATTEST_KEY = "synthetic-demo-key-not-a-secret"
