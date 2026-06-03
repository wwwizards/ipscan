#!/usr/bin/env python3
"""pyst — Python's smart test runner. Companion to PowerShell's psst.

:SCRIPT:   pyst.py
:PURPOSE:  Smart Python test runner with fuzzy pattern matching + tiering.
:ABSTRACT: Python's companion to PowerShell's ``psst``. Discovers
           ``test_*.py`` files in a directory tree, classifies them by tier
           suffix (smoke / sanity / unit / integration), and runs subsets
           matched by fuzzy patterns or tier names. Auto-prefers pytest if
           installed, falls back to stdlib unittest. Multi-Python fan-out
           via ``py -0p``.
:REQUIRES: Python 3.9+. stdlib only (pytest optional).
:CREATED:  2026-06-03 BY Joe Negron <Joe@LogicWizards.NYC>
:COMPANY:  LogicWizards.NYC <LogicWizards.NYC>
:VERSION:  0.1.3
:LICENSE:  MIT

Usage::

    pyst                       # all tests
    pyst smoke                 # tier match: test_*_smoke.py
    pyst unit ipscan           # AND-match: test_ipscan_unit.py
    pyst --tree                # show discovered tests, grouped by tier
    pyst -a smoke              # --all-pythons: fan-out across every Python
    PYST_MODE=OFF pyst smoke   # passthrough — raw runner, no pyst logic
"""
from __future__ import annotations

import argparse
import importlib
import io
import itertools
import os
import pathlib
import re
import shutil
import subprocess
import sys
import threading
import time
import unittest
from typing import Iterable

__version__ = "0.1.3"

# Reconfigure stdout/stderr to UTF-8 so emoji + box-drawing don't crash on
# Windows cp1252 consoles (default for cmd.exe / pwsh on en-US Windows).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass

TIERS = ("smoke", "sanity", "unit", "integration")
TIER_SUFFIX_RE = re.compile(
    r"_(?P<tier>" + "|".join(TIERS) + r")\.py$",
    re.IGNORECASE,
)
TEST_GLOB = "test_*.py"

# ANSI — degrades gracefully if the host shell ignores them.
C_RESET = "\033[0m"
C_DIM = "\033[2m"
C_BOLD = "\033[1m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_RED = "\033[31m"
C_CYAN = "\033[36m"


# ---------- discovery -------------------------------------------------------

def discover(root: pathlib.Path, exclude: Iterable[str] = ()) -> list[pathlib.Path]:
    """Find all test_*.py files under root, skipping excluded paths."""
    excl = tuple(e.lower() for e in exclude)
    out = []
    for p in root.rglob(TEST_GLOB):
        if not p.is_file():
            continue
        s = str(p).lower()
        if any(e in s for e in excl):
            continue
        out.append(p)
    return sorted(out)


def classify(path: pathlib.Path) -> str:
    """Return tier name (smoke/sanity/unit/integration) or 'untiered'."""
    m = TIER_SUFFIX_RE.search(path.name)
    return m.group("tier").lower() if m else "untiered"


def fuzzy_match(path: pathlib.Path, patterns: list[str]) -> bool:
    """All patterns must appear (substring, case-insensitive) in the path."""
    if not patterns:
        return True
    s = str(path).lower()
    name = path.stem.lower()
    for raw in patterns:
        p = raw.lower()
        # tier name → match suffix-tier-classification
        if p in TIERS:
            if classify(path) != p:
                return False
            continue
        # otherwise plain substring against full path or stem
        if p not in s and p not in name:
            return False
    return True


# ---------- runner backends -------------------------------------------------

def _have_pytest() -> bool:
    try:
        import pytest  # noqa: F401
        return True
    except ImportError:
        return False


def run_with_pytest(files: list[pathlib.Path], extra_args: list[str],
                    spinner: bool = True) -> int:
    cmd = [sys.executable, "-m", "pytest", *extra_args, *map(str, files)]
    print(f"{C_DIM}$ {' '.join(cmd)}{C_RESET}", flush=True)
    use_spinner = spinner and sys.stderr.isatty() and "-v" not in extra_args
    if not use_spinner:
        return subprocess.call(cmd)

    use_unicode = (sys.stdout.encoding or "").lower().startswith("utf")
    spin = _BackgroundSpinner(label="running pytest…",
                              stream=sys.stderr,
                              use_unicode=use_unicode)
    spin.start()
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True,
                              encoding="utf-8", errors="replace")
    finally:
        spin.stop()
    sys.stdout.write(proc.stdout)
    sys.stdout.flush()
    return proc.returncode


def _path_to_module(p: pathlib.Path) -> str:
    cwd = pathlib.Path.cwd().resolve()
    try:
        rel = p.resolve().relative_to(cwd)
    except ValueError:
        rel = p
    return ".".join(rel.with_suffix("").parts)


# ASCII fallback used on cp1252 / dumb consoles. Modern Win Terminal +
# pwsh handle the Unicode set fine after our utf-8 reconfigure above.
_SPINNER_GLYPHS_UNI = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
_SPINNER_GLYPHS_ASCII = ("|", "/", "-", "\\")
_CLOBBER = "\r" + " " * 100 + "\r"


class _BackgroundSpinner:
    """Thread-driven progress spinner.

    Runs a glyph animation on ``stream`` every ~120ms while the caller
    does other work. Output is buffered by the caller; the spinner only
    owns the live single line. ``update(label)`` swaps the trailing text
    safely. ``stop()`` clears the line.
    """

    _TICK_SECONDS = 0.12

    def __init__(self, label: str, stream, use_unicode: bool = True):
        self._label = label
        self._stream = stream
        glyphs = _SPINNER_GLYPHS_UNI if use_unicode else _SPINNER_GLYPHS_ASCII
        self._glyphs = itertools.cycle(glyphs)
        self._lock = threading.Lock()
        self._stop_evt = threading.Event()
        self._started = time.perf_counter()
        self._thread: threading.Thread | None = None

    def update(self, label: str) -> None:
        with self._lock:
            self._label = label

    def _render(self) -> None:
        glyph = next(self._glyphs)
        elapsed = time.perf_counter() - self._started
        label = self._label
        if len(label) > 60:
            label = label[:59] + "…"
        line = (f"{_CLOBBER}{C_CYAN}{glyph}{C_RESET} {label} "
                f"{C_DIM}({elapsed:0.1f}s){C_RESET}")
        try:
            self._stream.write(line)
            self._stream.flush()
        except UnicodeEncodeError:
            self._stream.write(line.encode("ascii", "replace").decode("ascii"))
            self._stream.flush()
        except Exception:
            pass

    def _animate(self) -> None:
        while not self._stop_evt.is_set():
            with self._lock:
                self._render()
            self._stop_evt.wait(self._TICK_SECONDS)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_evt.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        try:
            self._stream.write(_CLOBBER)
            self._stream.flush()
        except Exception:
            pass


def run_with_unittest(files: list[pathlib.Path], verbose: bool,
                      spinner: bool = True) -> int:
    """In-process unittest run — captures counts for the psst-style summary."""
    cwd = str(pathlib.Path.cwd().resolve())
    if cwd not in sys.path:
        sys.path.insert(0, cwd)

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for f in files:
        mod_name = _path_to_module(f)
        try:
            mod = importlib.import_module(mod_name)
            suite.addTests(loader.loadTestsFromModule(mod))
        except Exception as e:
            print(f"{C_RED}pyst: failed to load {mod_name}: {e}{C_RESET}")
            return 2

    total = suite.countTestCases()

    # Spinner only when output is interactive and we're not in -v (which the
    # user probably ran specifically to see per-test names live).
    use_spinner = spinner and not verbose and sys.stderr.isatty()
    started = time.perf_counter()
    if use_spinner:
        use_unicode = (sys.stdout.encoding or "").lower().startswith("utf")
        buf = io.StringIO()
        runner = unittest.TextTestRunner(verbosity=1, stream=buf)
        spin = _BackgroundSpinner(
            label=f"running {total} unittest case{'s' if total != 1 else ''}…",
            stream=sys.stderr,
            use_unicode=use_unicode,
        )
        spin.start()
        try:
            result = runner.run(suite)
        finally:
            spin.stop()
        # Replay buffered runner output (the dots + tracebacks) so users
        # still see the standard unittest report between spinner and summary.
        sys.stderr.write(buf.getvalue())
        sys.stderr.flush()
    else:
        runner = unittest.TextTestRunner(verbosity=(2 if verbose else 1),
                                         stream=sys.stderr)
        result = runner.run(suite)
    duration = time.perf_counter() - started

    total = result.testsRun
    failed = len(result.failures) + len(result.errors)
    skipped = len(result.skipped)
    passed = total - failed - skipped
    rate = round((passed / total) * 100, 1) if total else 0.0
    rate_color = (C_GREEN if rate >= 100 else C_YELLOW if rate >= 80
                  else C_RED)

    bar = "=" * 80
    print()
    print(f"{C_CYAN}{bar}{C_RESET}")
    print(f"{rate_color}{C_BOLD}TEST SUMMARY: {rate}%{C_RESET}")
    print(f"{C_CYAN}{bar}{C_RESET}")
    print(f"{C_DIM}Total Tests:{C_RESET}   {total}")
    print(f"{C_GREEN}Passed:{C_RESET}        {passed}")
    print(f"{C_RED if failed else C_DIM}Failed:{C_RESET}        {failed}")
    print(f"{C_YELLOW}Skipped:{C_RESET}       {skipped}")
    print(f"{C_DIM}Duration:{C_RESET}      {duration:.2f}s")
    if failed:
        print()
        print(f"{C_RED}Failed tests:{C_RESET}")
        for tc, _ in result.failures[:15]:
            print(f"  {C_RED}- FAIL  {tc}{C_RESET}")
        for tc, _ in result.errors[:15]:
            print(f"  {C_RED}- ERROR {tc}{C_RESET}")
    print(f"{C_CYAN}{bar}{C_RESET}")
    return 0 if failed == 0 else 1


# ---------- multi-python fan-out --------------------------------------------

def list_pythons_windows() -> list[str]:
    """Parse `py -0p` output. Returns list of interpreter paths."""
    py = shutil.which("py")
    if not py:
        return []
    try:
        out = subprocess.check_output([py, "-0p"], text=True, stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, OSError):
        return []
    paths = []
    for line in out.splitlines():
        # format: "-V:3.12 *        C:\path\to\python.exe"
        m = re.search(r"([A-Za-z]:\\[^\s].*?python(?:w)?\.exe)", line)
        if m:
            paths.append(m.group(1))
    return paths


def list_pythons_posix() -> list[str]:
    """Probe common locations + pyenv for POSIX interpreters."""
    found: set[str] = set()
    for pat in ("/usr/bin/python3*", "/usr/local/bin/python3*",
                "/opt/homebrew/bin/python3*"):
        for hit in pathlib.Path("/").glob(pat.lstrip("/")):
            if hit.is_file() and os.access(hit, os.X_OK):
                found.add(str(hit))
    pyenv_root = pathlib.Path.home() / ".pyenv" / "versions"
    if pyenv_root.is_dir():
        for v in pyenv_root.iterdir():
            exe = v / "bin" / "python"
            if exe.is_file():
                found.add(str(exe))
    # de-dupe by version+arch
    return sorted(found)


def list_pythons() -> list[str]:
    return list_pythons_windows() if os.name == "nt" else list_pythons_posix()


# ---------- tree view -------------------------------------------------------

def print_tree(files: list[pathlib.Path]) -> None:
    by_tier: dict[str, list[pathlib.Path]] = {}
    for f in files:
        by_tier.setdefault(classify(f), []).append(f)
    print(f"{C_BOLD}pyst v{__version__} — discovered tests{C_RESET}")
    for tier in (*TIERS, "untiered"):
        items = by_tier.get(tier, [])
        if not items:
            continue
        color = C_GREEN if tier == "smoke" else C_CYAN if tier == "unit" \
            else C_YELLOW if tier == "integration" else C_DIM
        print(f"  {color}[{tier}]{C_RESET} ({len(items)})")
        for f in items:
            print(f"    {f}")
    print(f"{C_DIM}total: {len(files)} file(s){C_RESET}")


# ---------- entrypoint ------------------------------------------------------

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pyst",
        description="Python smart test runner — companion to PowerShell's psst.",
    )
    p.add_argument("patterns", nargs="*",
                   help="Fuzzy patterns and/or tier names (smoke/sanity/unit/integration).")
    p.add_argument("--root", default=".", help="Root dir to scan (default: cwd).")
    p.add_argument("--exclude", action="append", default=[],
                   help="Substring to exclude from paths (repeatable).")
    p.add_argument("--tree", action="store_true",
                   help="Print discovered tests grouped by tier; don't run.")
    p.add_argument("--all-pythons", "-a", action="store_true",
                   help="Run the matched suite across every Python on the box.")
    p.add_argument("--runner", choices=("auto", "pytest", "unittest"),
                   default="auto", help="Test runner backend (default: auto).")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Verbose unittest output (-v). Disables spinner.")
    p.add_argument("--no-spinner", action="store_true",
                   help="Disable the per-test progress spinner.")
    p.add_argument("--version", action="version", version=f"pyst {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args, extra = build_argparser().parse_known_args(argv)

    # PYST_MODE=OFF → raw passthrough, no discovery, no fuzzy matching
    if os.environ.get("PYST_MODE", "").upper() == "OFF":
        runner = "pytest" if _have_pytest() else "unittest"
        print(f"{C_YELLOW}PYST_MODE=OFF → passthrough to {runner}{C_RESET}")
        cmd = [sys.executable, "-m", runner, *args.patterns, *extra]
        return subprocess.call(cmd)

    root = pathlib.Path(args.root).resolve()
    files = discover(root, exclude=args.exclude)
    matched = [f for f in files if fuzzy_match(f, args.patterns)]

    if args.tree:
        print_tree(matched if args.patterns else files)
        return 0

    if not matched:
        print(f"{C_RED}pyst: no tests matched patterns: {args.patterns}{C_RESET}")
        print(f"{C_DIM}  scanned {len(files)} file(s) under {root}{C_RESET}")
        return 2

    # psst-style banner
    print(f"{C_CYAN}⚙️  TESTER = pyst:{C_RESET} {C_GREEN}ON{C_RESET}")
    print(f"{C_DIM}Invoking Extended Test Intelligence...{C_RESET}\n")
    print(f"{C_CYAN}🧪 pyst v{__version__} — {len(matched)} file(s) matched{C_RESET}")
    if args.patterns:
        print(f"{C_DIM}  patterns: {' '.join(args.patterns)}{C_RESET}")
    print(f"\n{C_GREEN}Selected tests:{C_RESET}")
    for f in matched:
        tier = classify(f)
        col = (C_GREEN if tier == "smoke" else C_CYAN if tier == "unit"
               else C_YELLOW if tier == "integration" else C_DIM)
        print(f"  {col}✓ [{tier:<11}]{C_RESET} {C_DIM}{f.name}{C_RESET}")
    print()

    # Multi-Python fan-out
    if args.all_pythons:
        pys = list_pythons()
        if not pys:
            print(f"{C_YELLOW}pyst: no other Python interpreters discovered.{C_RESET}")
            pys = [sys.executable]
        results: list[tuple[str, int]] = []
        for py in pys:
            print(f"\n{C_BOLD}━━ {py}{C_RESET}")
            cmd = [py, str(pathlib.Path(__file__).resolve()),
                   *args.patterns, *(["-v"] if args.verbose else [])]
            rc = subprocess.call(cmd, env={**os.environ, "PYST_MODE": "OFF_RECURSE"})
            results.append((py, rc))
        print(f"\n{C_BOLD}━━ multi-python summary{C_RESET}")
        for py, rc in results:
            tag = f"{C_GREEN}PASS{C_RESET}" if rc == 0 else f"{C_RED}FAIL ({rc}){C_RESET}"
            print(f"  {tag}  {py}")
        return 0 if all(rc == 0 for _, rc in results) else 1

    # Mark the env so suite footers can detect they're already inside pyst
    # and suppress the "try the pyst beta" nag.
    os.environ["PYST_RUNNING"] = "1"

    # Single-Python run
    use_pytest = (args.runner == "pytest") or (args.runner == "auto" and _have_pytest())
    if use_pytest:
        return run_with_pytest(matched, extra, spinner=not args.no_spinner)
    return run_with_unittest(matched, verbose=args.verbose,
                             spinner=not args.no_spinner)


if __name__ == "__main__":
    sys.exit(main())
