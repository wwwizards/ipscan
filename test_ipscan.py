#!/usr/bin/env python3
"""Smoke tests for ipscan.py — stdlib unittest, no pytest required.

Run:
    python -m unittest test_ipscan -v
"""
import datetime
import importlib.util
import os
import pathlib
import platform
import socket
import sys
import unittest
from unittest.mock import patch, MagicMock

HERE = pathlib.Path(__file__).parent
SUT = HERE / "ipscan.py"

REPO_URL = "https://github.com/wwwizards/ipscan"
ISSUES_URL = "https://github.com/wwwizards/ipscan/issues"
PYST_URL = "https://github.com/wwwizards/pyst"  # coming soon — it's pytest's companion to psst


def _read_sut_version():
    """Pluck the VERSION header from ipscan.py without importing it."""
    try:
        for line in SUT.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s.startswith("#") and "VERSION:" in s:
                return s.split("VERSION:", 1)[1].strip()
    except OSError:
        pass
    return "unknown"


def _is_admin():
    """Return True/False/None for elevated-process detection.

    None = couldn't determine (don't lie to the reader).
    """
    try:
        if platform.system() == "Windows":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        # POSIX: euid 0 = root
        return os.geteuid() == 0
    except Exception:
        return None


def setUpModule():
    """Print an environment header before any test runs.

    Captured in test logs / CI artifacts / bug reports so cross-platform
    failures can be triaged without back-and-forth ('which Python?',
    'which OS?', 'when?'). Deliberately omits username/hostname to avoid
    leaking PII in publicly-shared output — ports/admin-status/Python build
    are what matters for triage.
    """
    width = 78
    bar = "=" * width
    admin = _is_admin()
    admin_str = {True: "yes", False: "no", None: "unknown"}[admin]
    lines = [
        "",
        bar,
        " ipscan TEST RUN".ljust(width),
        f" Repo: {REPO_URL}".ljust(width),
        f" Bugs: {ISSUES_URL}".ljust(width),
        bar,
        f" Timestamp (UTC)   : {datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')}",
        f" Timestamp (local) : {datetime.datetime.now().astimezone().isoformat(timespec='seconds')}",
        f" SUT               : ipscan.py @ {_read_sut_version()}",
        f" Python            : {platform.python_version()} ({platform.python_implementation()})",
        f" Python exe        : {sys.executable}",
        f" Platform          : {platform.system()} {platform.release()} ({platform.machine()})",
        f" Platform detail   : {platform.platform()}",
        f" Elevated/Admin    : {admin_str}",
    ]
    if admin is False:
        lines.append(
            " NOTE: not running elevated — on some Linux distros raw ICMP"
        )
        lines.append(
            "       sockets require root/CAP_NET_RAW; ping may silently fall"
        )
        lines.append(
            "       back to a setuid helper or fail. If real-network scans"
        )
        lines.append(
            "       behave oddly, retry with sudo / Run-as-Administrator."
        )
    lines.append(bar)
    lines.append("")
    print("\n".join(lines), flush=True)


def tearDownModule():
    """Footer with a forward-link to the upcoming `pyst` test harness."""
    width = 78
    bar = "-" * width
    print("\n".join([
        "",
        bar,
        f" For a friendlier cross-runner test harness, \n   - try {PYST_URL}",
        " (coming soon — pytest's companion to PowerShell's `psst`).",
        bar,
        "",
    ]), flush=True)


def load_ipscan():
    """Load ipscan.py as a module without invoking __main__."""
    spec = importlib.util.spec_from_file_location("ipscan_mod", SUT)
    mod = importlib.util.module_from_spec(spec)
    # Inject the implicit globals the script expects when functions are
    # called outside of __main__ (quiet flag, data dict).
    mod.quiet = True
    mod.data = {}
    spec.loader.exec_module(mod)
    mod.quiet = True
    mod.data = {}
    return mod


class TestImportSafety(unittest.TestCase):
    def test_imports_cleanly_on_current_python(self):
        """Module loads without throwing on the active interpreter."""
        mod = load_ipscan()
        self.assertTrue(hasattr(mod, "is_pingable"))
        self.assertTrue(hasattr(mod, "is_port_active"))

    def test_runs_on_python_3_9_or_newer(self):
        self.assertGreaterEqual(sys.version_info[:2], (3, 9))


class TestPingCommandBuilding(unittest.TestCase):
    """Regression test for the cross-platform ping flag bug."""

    def setUp(self):
        self.mod = load_ipscan()

    def test_windows_ping_uses_n_and_w_ms(self):
        with patch.object(self.mod, "IS_WINDOWS", True), \
             patch.object(self.mod, "IS_DARWIN", False):
            cmd = self.mod._ping_cmd("10.0.0.1", timeout=1)
            self.assertIn("-n", cmd)
            self.assertIn("-w", cmd)
            # -w on Windows = milliseconds; 1s -> 1000
            self.assertIn("1000", cmd)

    def test_linux_ping_uses_c_and_W_seconds(self):
        with patch.object(self.mod, "IS_WINDOWS", False), \
             patch.object(self.mod, "IS_DARWIN", False):
            cmd = self.mod._ping_cmd("10.0.0.1", timeout=1)
            self.assertIn("-c", cmd)
            self.assertIn("-W", cmd)
            self.assertIn("1", cmd)
            self.assertNotIn("1000", cmd)

    def test_macos_ping_uses_W_milliseconds(self):
        """macOS ping -W is ms (BSD), not sec. This is the Mac-broken bug."""
        with patch.object(self.mod, "IS_WINDOWS", False), \
             patch.object(self.mod, "IS_DARWIN", True):
            cmd = self.mod._ping_cmd("10.0.0.1", timeout=1)
            self.assertIn("-c", cmd)
            self.assertIn("-W", cmd)
            self.assertIn("1000", cmd)


class TestPingErrorHandling(unittest.TestCase):
    def setUp(self):
        self.mod = load_ipscan()

    def test_missing_ping_binary_returns_false(self):
        with patch.object(self.mod.subprocess, "check_output",
                          side_effect=FileNotFoundError):
            self.assertFalse(self.mod.is_pingable("10.0.0.1"))

    def test_ping_timeout_returns_false(self):
        with patch.object(self.mod.subprocess, "check_output",
                          side_effect=self.mod.subprocess.TimeoutExpired(
                              cmd="ping", timeout=1)):
            self.assertFalse(self.mod.is_pingable("10.0.0.1"))


class TestPortScanErrorHandling(unittest.TestCase):
    """Regression test for socket.timeout removal in Py3.14."""

    def setUp(self):
        self.mod = load_ipscan()

    def test_timeout_error_treated_as_closed_port(self):
        # TimeoutError is the 3.14-correct exception (socket.timeout alias)
        fake_sock = MagicMock()
        fake_sock.__enter__ = MagicMock(return_value=fake_sock)
        fake_sock.__exit__ = MagicMock(return_value=False)
        fake_sock.connect.side_effect = TimeoutError
        with patch.object(self.mod.socket, "socket", return_value=fake_sock):
            self.assertFalse(self.mod.is_port_active("10.0.0.1", 22))

    def test_connection_refused_treated_as_closed_port(self):
        fake_sock = MagicMock()
        fake_sock.__enter__ = MagicMock(return_value=fake_sock)
        fake_sock.__exit__ = MagicMock(return_value=False)
        fake_sock.connect.side_effect = ConnectionRefusedError
        with patch.object(self.mod.socket, "socket", return_value=fake_sock):
            self.assertFalse(self.mod.is_port_active("10.0.0.1", 22))


class TestOSInference(unittest.TestCase):
    def setUp(self):
        self.mod = load_ipscan()

    def test_windows_signature(self):
        self.assertEqual(self.mod.infer_os([3389, 445]), "Windows")

    def test_linux_signature(self):
        self.assertEqual(self.mod.infer_os([22, 80]), "Linux")

    def test_hybrid_signature(self):
        self.assertEqual(self.mod.infer_os([22, 3389]), "Hybrid")

    def test_unknown_signature(self):
        self.assertEqual(self.mod.infer_os([80, 443]), "Unknown")
        self.assertEqual(self.mod.infer_os([]), "Unknown")


class TestReverseDNS(unittest.TestCase):
    def setUp(self):
        self.mod = load_ipscan()

    def test_reverse_dns_returns_none_on_failure(self):
        with patch.object(self.mod.socket, "gethostbyaddr",
                          side_effect=socket.herror):
            self.assertIsNone(self.mod.get_reverse_dns("203.0.113.1"))

    def test_reverse_dns_returns_none_on_gaierror(self):
        with patch.object(self.mod.socket, "gethostbyaddr",
                          side_effect=socket.gaierror):
            self.assertIsNone(self.mod.get_reverse_dns("203.0.113.1"))


if __name__ == "__main__":
    unittest.main()
