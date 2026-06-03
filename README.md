# ipscan

Cross-platform parallel IP/port scanner. Stdlib only. Single file.

## What's new in v0.9.1

Users reported `ipscan.py` failing on Python 3.12 / 3.14 (post-CVE patches) and never working right on macOS. Audit found three real bugs:

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

## Roadmap

- **v0.9.1** (this) — Py3.14 + cross-platform fixes, regression suite.
- **v0.9.2+** — IPv6 support, configurable port lists, JSONL streaming.

## License

MIT. See [`LICENSE`](LICENSE).
