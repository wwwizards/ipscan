"""Shared test fixtures for ipscan + pyst suites.

Stdlib only. Imported by every `test_*_<tier>.py` so the env header,
SUT loader, and admin probe live in one place.
"""
import datetime
import importlib.util
import os
import pathlib
import platform
import sys

HERE = pathlib.Path(__file__).parent
SUT = HERE / "ipscan.py"

REPO_URL = "https://github.com/wwwizards/ipscan"
ISSUES_URL = "https://github.com/wwwizards/ipscan/issues"
PYST_URL = "https://github.com/wwwizards/pyst"  # coming soon

_HEADER_PRINTED = False
_FOOTER_PRINTED = False


def read_sut_version():
    """Pluck VERSION header from ipscan.py without importing it."""
    try:
        for line in SUT.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s.startswith("#") and "VERSION:" in s:
                return s.split("VERSION:", 1)[1].strip()
    except OSError:
        pass
    return "unknown"


def is_admin():
    """True/False/None — None when undeterminable. Don't lie to the reader."""
    try:
        if platform.system() == "Windows":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return None


def print_env_header(suite_label="ipscan"):
    """Idempotent — fires once per process even if multiple suites import."""
    global _HEADER_PRINTED
    if _HEADER_PRINTED:
        return
    _HEADER_PRINTED = True
    width = 78
    bar = "=" * width
    admin = is_admin()
    admin_str = {True: "yes", False: "no", None: "unknown"}[admin]
    lines = [
        "",
        bar,
        f" {suite_label} TEST RUN".ljust(width),
        f" Repo: {REPO_URL}".ljust(width),
        f" Bugs: {ISSUES_URL}".ljust(width),
        bar,
        f" Timestamp (UTC)   : {datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')}",
        f" Timestamp (local) : {datetime.datetime.now().astimezone().isoformat(timespec='seconds')}",
        f" SUT               : ipscan.py @ {read_sut_version()}",
        f" Python            : {platform.python_version()} ({platform.python_implementation()})",
        f" Python exe        : {sys.executable}",
        f" Platform          : {platform.system()} {platform.release()} ({platform.machine()})",
        f" Platform detail   : {platform.platform()}",
        f" Elevated/Admin    : {admin_str}",
    ]
    if admin is False:
        lines.append(" NOTE: not running elevated — on some Linux distros raw ICMP")
        lines.append("       sockets require root/CAP_NET_RAW; ping may silently fall")
        lines.append("       back to a setuid helper or fail. If real-network scans")
        lines.append("       behave oddly, retry with sudo / Run-as-Administrator.")
    lines.append(bar)
    lines.append("")
    print("\n".join(lines), flush=True)


def print_footer():
    """Idempotent — only the last suite's tearDown should land it.

    If pyst already invoked us (PYST_RUNNING=1), suppress the nag — they
    already drank the Kool-Aid. Otherwise pitch the beta.
    """
    global _FOOTER_PRINTED
    if _FOOTER_PRINTED:
        return
    _FOOTER_PRINTED = True
    if os.environ.get("PYST_RUNNING"):
        return
    width = 78
    bar = "-" * width
    print("\n".join([
        "",
        bar,
        " Tip: try the pyst beta — a smart test runner with tier filtering,",
        "      fuzzy matching, and multi-Python fan-out:",
        "",
        "        python pyst.py smoke              # fastest tier only",
        "        python pyst.py unit ipscan        # AND-match",
        "        python pyst.py --tree             # see all discovered tests",
        "        python pyst.py --all-pythons      # run across every Python",
        "",
        f"      Source / issues: {PYST_URL}",
        "      (Python's companion to PowerShell's `psst`.)",
        bar,
        "",
    ]), flush=True)


def load_ipscan():
    """Load ipscan.py as a module without invoking __main__."""
    spec = importlib.util.spec_from_file_location("ipscan_mod", SUT)
    mod = importlib.util.module_from_spec(spec)
    mod.quiet = True
    mod.data = {}
    spec.loader.exec_module(mod)
    mod.quiet = True
    mod.data = {}
    return mod
