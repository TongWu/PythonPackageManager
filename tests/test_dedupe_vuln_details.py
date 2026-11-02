"""Self-check for dedupe_vuln_details. Run from repo root: PYTHONPATH=. python3 tests/test_dedupe_vuln_details.py"""
from utils.InstructionFormatter import dedupe_vuln_details

A = "CVE-1, CVSS_V3, A: bad thing, CVSS:3.1/AV:N, affects: >=0,<2"
B = "CVE-2, CVSS_V4, B, CVSS:4.0/AV:L, affects: >=0,<2; >=3,<4"  # two ranges joined by "; "
CURRENT = f"{A}\n{B}"
# Same layout GenerateReport builds: "ver: <lines>; ver: <lines>"
UPGRADE = f"2.0: {CURRENT}; 1.9: {CURRENT}; 1.8: {A}"


def test_collapses_per_version_repeats():
    assert dedupe_vuln_details(UPGRADE) == f"{A}\n{B}"


def test_keeps_multi_range_affects_intact():
    assert "affects: >=0,<2; >=3,<4" in dedupe_vuln_details(UPGRADE)


def test_current_details_unchanged():
    assert dedupe_vuln_details(CURRENT) == CURRENT


def test_empty_and_placeholder():
    assert dedupe_vuln_details(None) == ""
    assert dedupe_vuln_details("") == ""
    assert dedupe_vuln_details("None") == ""


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
