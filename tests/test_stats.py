from stats import wilson


def close(a, b, tol=5e-4):
    return abs(a - b) <= tol


def test_wilson_half():
    lo, hi = wilson(5, 10)
    assert close(lo, 0.2366) and close(hi, 0.7634)


def test_wilson_zero_successes():
    lo, hi = wilson(0, 10)
    assert lo == 0.0 and close(hi, 0.2775)


def test_wilson_all_successes():
    lo, hi = wilson(10, 10)
    assert close(lo, 0.7225) and hi == 1.0


def test_wilson_order_and_bounds():
    for n in (1, 7, 50, 400):
        for k in range(0, n + 1, max(1, n // 5)):
            lo, hi = wilson(k, n)
            assert 0.0 <= lo <= k / n <= hi <= 1.0


def test_wilson_narrows_with_n():
    a = wilson(50, 100)
    b = wilson(500, 1000)
    assert (b[1] - b[0]) < (a[1] - a[0])


def test_wilson_empty_is_full_interval():
    assert wilson(0, 0) == (0.0, 1.0)
