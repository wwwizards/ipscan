# Testing & Validation

`ipscan.py` ships with a stdlib-only regression suite (`test_ipscan.py`, 15 tests, ~110ms) covering every known historical breakage class. No `pytest`, `tox`, or other test deps required — just the standard library `unittest`.

## Run it

```bash
python -m unittest test_ipscan -v
```

## Coverage matrix

| Bug class | Test(s) | Why it matters |
|---|---|---|
| **Py3.14 `socket.timeout` removal** | `test_timeout_error_treated_as_closed_port` | `socket.timeout` was deprecated in 3.12, removed in 3.14. The original `except (socket.timeout, ...)` clause raised `NameError` on 3.14, killing every port probe. Fix uses canonical `TimeoutError`. |
| **Windows ping flags wrong** | `test_windows_ping_uses_n_and_w_ms` | Linux `-c 1 -W 1` was passed unchanged to Windows `ping.exe`, which silently fell back to default behavior (4 packets, ~4× slowdown). Fix branches on `platform.system()`. |
| **macOS ping flag semantics** | `test_macos_ping_uses_W_milliseconds` | BSD `ping -W` is **milliseconds**, not seconds. Original code passed `1` → 1 ms timeout → most hosts reported as dead. Fix multiplies by 1000 on Darwin. |
| **Linux ping flags preserved** | `test_linux_ping_uses_c_and_W_seconds` | Regression guard — make sure the platform branching didn't break the historically-working path. |
| **Missing `ping` binary** | `test_missing_ping_binary_returns_false` | Minimal Py3.12+ container/runtime images sometimes lack `ping` in PATH. Original raised uncaught `FileNotFoundError`, killing the whole scan. Fix catches `OSError` and treats host as unreachable. |
| **Ping timeout** | `test_ping_timeout_returns_false` | `subprocess.TimeoutExpired` from a `timeout=` kwarg is now caught explicitly. |
| **`ConnectionRefusedError`** | `test_connection_refused_treated_as_closed_port` | Closed ports must report `False`, not crash. |
| **OS inference fingerprint** | `test_windows_signature`, `test_linux_signature`, `test_hybrid_signature`, `test_unknown_signature` | Behavioral lock-in for the port-pattern → OS-family heuristic. |
| **Reverse DNS resilience** | `test_reverse_dns_returns_none_on_failure`, `test_reverse_dns_returns_none_on_gaierror` | DNS failures must not abort the scan. |
| **Module import safety** | `test_imports_cleanly_on_current_python` | Catches future stdlib breakage early — if Python removes another symbol we use, this test goes red on import. |
| **Python version floor** | `test_runs_on_python_3_9_or_newer` | Documented support floor; failing here means the runtime is older than supported. |

## Latest run (Python 3.14.5, Windows 11)

```
==============================================================================
 ipscan TEST RUN
 Repo: https://github.com/wwwizards/ipscan
 Bugs: https://github.com/wwwizards/ipscan/issues
==============================================================================
 Timestamp (UTC)   : 2026-06-03T19:10:18+00:00
 Timestamp (local) : 2026-06-03T15:10:18-04:00
 SUT               : ipscan.py @ 0.9.1
 Python            : 3.14.5 (CPython)
 Python exe        : C:\Python314\python.exe
 Platform          : Windows 11 (AMD64)
 Platform detail   : Windows-11-10.0.26200-SP0
 Elevated/Admin    : no
 NOTE: not running elevated — on some Linux distros raw ICMP
       sockets require root/CAP_NET_RAW; ping may silently fall
       back to a setuid helper or fail. If real-network scans
       behave oddly, retry with sudo / Run-as-Administrator.
==============================================================================

test_imports_cleanly_on_current_python ... ok
test_runs_on_python_3_9_or_newer ... ok
test_hybrid_signature ... ok
test_linux_signature ... ok
test_unknown_signature ... ok
test_windows_signature ... ok
test_linux_ping_uses_c_and_W_seconds ... ok
test_macos_ping_uses_W_milliseconds ... ok
psst ... ok
test_missing_ping_binary_returns_false ... ok
test_ping_timeout_returns_false ... ok
test_connection_refused_treated_as_closed_port ... ok
test_reverse_dns_returns_none_on_failure ... ok
test_reverse_dns_returns_none_on_gaierror ... ok
test_timeout_error_treated_as_closed_port ... ok

------------------------------------------------------------------------------
 For a friendlier cross-runner test harness, 
    - try https://github.com/wwwizards/pyst
 (coming soon — it is pytest's companion to PowerShell's `psst`).
------------------------------------------------------------------------------

----------------------------------------------------------------------
Ran 15 tests in 0.149s

OK
```

> The header is **PII-safe** by design — no hostname, no username, no working directory paths. Just timestamps, Python build, OS, SUT version, and elevation status. Safe to paste into public GitHub issues.

## Sharing test results (for cross-platform validation)

When reporting a pass/fail back to the maintainer, paste the **entire output** including the header block. The header alone answers the standard triage questions ("which Python? which OS? when?") without a back-and-forth thread.

Capture to file:

```bash
# Linux / macOS
python -m unittest test_ipscan -v 2>&1 | tee testrun-$(uname -s)-$(python --version | awk '{print $2}').log

# Windows (PowerShell)
python -m unittest test_ipscan -v *>&1 | Tee-Object "testrun-Windows-$(python --version).log"
```

## Validated platforms × Python versions

| Platform | Python | Status | Notes |
|---|---|---|---|
| Windows 11 | 3.14.5 | ✅ 15/15 | v0.9.1 baseline; also passes elevated; perf slower than 3.12 |
| Windows 11 | 3.12.0 | ✅ 15/15 | non-elevated + elevated, 2026-06-03 |
| Windows Server 2022 | 3.14.5 | ✅ 15/15 | 2026-06-03; pyst -a all green |
| Windows Server 2022 | multi (`pyst -a`) | ✅ | every Python on box, 2026-06-03 |
| macOS | 3.12.12 | ✅ 15/15 | non-elevated, 2026-06-03 |
| macOS | multi (`pyst -a`) | ✅ | every Python on box, 2026-06-03 |
| Windows 10 | 3.12.x | 🟡 pending | |
| Linux | 3.10+ | 🟡 pending | original complainer to validate |

Legend: ✅ verified · 🟡 expected based on logic + mocked tests · ❌ known broken

## What the tests deliberately do **not** cover

- **Live network behavior** — no real ICMP/TCP traffic in the unit suite. Run a real subnet smoke test (`python ipscan.py 192.168.1.0/24`) for end-to-end validation.
- **Concurrency races** — `ThreadPoolExecutor` correctness is treated as stdlib-trusted; we don't test the lock dance.
- **Terminal rendering** — ANSI escape sequences and the spinner are not asserted on; visual regressions need a human eye.

These are intentional scope cuts: the unit suite catches the historical bug *classes*, not every possible failure mode. Real-world smoke complements it.

## Adding a new regression test

Each historical bug becomes a permanent test. The pattern:

1. Reproduce the bug in a unit test (it should fail on the unfixed code).
2. Apply the fix to `ipscan.py`.
3. Test goes green; commit both together.
4. Add a row to the **Coverage matrix** above with a short "why it matters" note.

This keeps `TESTING.md` synchronized with the suite and gives reviewers (and future-you) a one-page audit trail of what's been actively defended against.
