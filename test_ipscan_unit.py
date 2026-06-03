#!/usr/bin/env python3
"""ipscan UNIT tests — mocked, deterministic, no real I/O.

Covers the v0.9.1 regression bugs:

- cross-platform ping flag building (Windows -w ms vs BSD -W ms vs Linux -W sec)
- Py3.14 socket.timeout removal (TimeoutError aliasing)
- missing ping binary handling
- OS inference + reverse DNS error paths

:SCRIPT:   test_ipscan_unit.py
:PURPOSE:  Mocked unit coverage for ipscan internals.
:REQUIRES: Python 3.9+. stdlib only.
:COMPANY:  LogicWizards.NYC <LogicWizards.NYC>
:LICENSE:  MIT

Run::

    python -m unittest test_ipscan_unit -v
    pyst unit
"""
import socket
import unittest
from unittest.mock import MagicMock, patch

from _test_common import load_ipscan, print_env_header, print_footer


def setUpModule():
    print_env_header("ipscan [unit]")


def tearDownModule():
    print_footer()


class TestPingCommandBuilding(unittest.TestCase):
    """Regression: cross-platform ping flag bug."""

    def setUp(self):
        self.mod = load_ipscan()

    def test_windows_ping_uses_n_and_w_ms(self):
        with patch.object(self.mod, "IS_WINDOWS", True), \
             patch.object(self.mod, "IS_DARWIN", False):
            cmd = self.mod._ping_cmd("10.0.0.1", timeout=1)
            self.assertIn("-n", cmd)
            self.assertIn("-w", cmd)
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
        """macOS ping -W is ms (BSD), not sec — the Mac-broken bug."""
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
    """Regression: socket.timeout removal in Py3.14."""

    def setUp(self):
        self.mod = load_ipscan()

    def test_timeout_error_treated_as_closed_port(self):
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
