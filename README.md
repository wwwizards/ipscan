# ipscan

ABSTRACT: an extremely lightweight os-agnostic cross-platform parallel IP/port scanner. which requires `stdlib` only. It is a single file. You can clone the whole repo and try some of our other FREE tools, and/or just copy & paste the contents of [ipscan.py](ipscan.py) to your machine & run it with: 
```
python ipscan.py -h

S /Users/jnegron9/DATA/miners/ipscan> python ./ipscan.py -h
usage: ipscan.py [-h] [-q] [-t THREADS] ip_range [ip_range ...]

Parallel IP Scanner

positional arguments:
  ip_range              Space-separated list of subnet/CIDR addresses (e.g., '192.168.0.0/24 10.0.0.0/16')

options:
  -h, --help            show this help message and exit
  -q, --quiet           Suppress progress indicators & emit JSON only
  -t THREADS, --threads THREADS
                        Number of threads for parallel scanning
``` 

## What's new in v0.9.1

Users reported `ipscan.py` failing on Python 3.12 / 3.14 (post-CVE patches) and never working right on Win32 based systems. Audit found three real bugs:

1. **`socket.timeout` removed in Py3.14** — `is_port_active()` caught it by name; throws `NameError` on 3.14. Fixed: use canonical `TimeoutError`.
2. **Linux-only ping flags** — `-c` / `-W (sec)` hardcoded. Windows needs `-n` / `-w (ms)`; macOS BSD ping `-W` is **ms not sec**, so the overlap "worked" on Mac but with a 1000× wrong timeout. Fixed: per-platform flag builder.
3. **Missing `ping` binary crashed the scan** — minimal Py3.12+ container/runtime images sometimes lack `ping` in PATH; `is_pingable()` now catches `FileNotFoundError` / `OSError` and returns `False`.

Plus minor cleanup: duplicate `FG_RED`, duplicate port `5896` in `windows_tcp`, unused `re` import, ASCII spinner fallback for legacy Windows codepages, ctypes ANSI mode enable.

## Zero pip dependencies

Stdlib only: `argparse`, `ipaddress`, `itertools`, `json`, `platform`, `socket`, `subprocess`, `sys`, `time`, `threading`, `concurrent.futures`. No `requirements.txt`, no `pip install`, no CVE-from-deps surface.

## Usage

```bash
python ipscan.py "192.168.0.0/24 10.0.0.0/16"
python ipscan.py 10.0.0.0/24 -t 128 -q > scan.json
```

## Test

```bash
python -m unittest test_ipscan -v
```

15 regression tests, stdlib only. Covers all three bug classes (Py3.14 `socket.timeout`, cross-platform ping flags, missing ping binary) plus OS-fingerprint heuristics and DNS resilience.

See [`TESTING.md`](TESTING.md) for the full coverage matrix, latest run output, and platform × Python version validation status.

---
## (PRE-RELEASE PREVIEW BONUS)
---
### pyst — the smart test runner 

`pyst.py` ships alongside `ipscan.py` as a **pre-release bonus** while it
matures. Think of it as Python's answer to PowerShell's `psst`: fuzzy
pattern matching, tier-based test discovery, and an animated spinner —
all stdlib, no pip install required.

```bash
python pyst.py                  # run all tests
python pyst.py smoke            # tier match: test_*_smoke.py
python pyst.py unit ipscan      # AND-match: test_ipscan_unit.py
python pyst.py --tree           # show discovered tests grouped by tier
python pyst.py -a smoke         # fan-out across every Python on PATH
PYST_MODE=OFF python pyst.py    # raw passthrough — no pyst logic
```

**Tiers** (matched by test filename suffix):

| Suffix | Intent |
|---|---|
| `_smoke` | Fast pre-commit gate, no network |
| `_unit` | Isolated logic, mocks where needed |
| `_integration` | Live network / external deps |
| `_sanity` | Post-deploy sanity checks |

> **Pre-release caveat:** `pyst` is in active development (v0.1.4). The
> API and tier conventions may shift before v1.0. It will likely graduate
> into its own module once [pickaxe](https://github.com/wwwizards/pickaxe)
> handles the heavy lifting for discovery and dependency wiring.

## Roadmap

- **v0.9.1** (this) — Py3.14 + cross-platform fixes, regression suite.
- **v0.9.2+** — IPv6 support, configurable port lists, JSONL streaming.
- **pyst v1.0** — graduates to standalone module; pickaxe-powered discovery.

## License

MIT. See [`LICENSE`](LICENSE).
