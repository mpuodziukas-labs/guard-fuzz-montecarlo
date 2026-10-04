# guard-fuzz-montecarlo

A security team scores its AI guards on a hand-written test set, so a perfect pass says nothing about how often a lightly reworded or encoded attack still gets through; this repo turns pass/fail tests into a bypass rate with a confidence interval.

## Run it in 60 seconds

```
python3 -m pip install pytest
python3 evaluate.py
python3 -m pytest -q
```

## Results

| bad caught | good passed |
|---|---|
| 1/1 | 1/1 |

## Honesty Statement

Synthetic data. Not production, not client data.

## Limitations

Small synthetic corpus. Replace before drawing conclusions.
