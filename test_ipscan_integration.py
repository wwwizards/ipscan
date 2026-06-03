#!/usr/bin/env python3
"""ipscan INTEGRATION tests — real network, opt-in.

Gated by env var so CI / casual `pyst` runs don't hit the network or
prompt for elevation. Set RUN_INTEGRATION_TESTS=1 to enable.

Run: $env:RUN_INTEGRATION_TESTS=1; python -m unittest test_ipscan_integration -v
     pyst integration
"""
import os
import unittest

from _test_common import load_ipscan, print_env_header, print_footer

INTEGRATION = bool(os.environ.get("RUN_INTEGRATION_TESTS"))


def setUpModule():
    print_env_header("ipscan [integration]")


def tearDownModule():
    print_footer()


@unittest.skipUnless(INTEGRATION, "set RUN_INTEGRATION_TESTS=1 to enable")
class TestRealLoopback(unittest.TestCase):
    """Smoke-checks against 127.0.0.1 — no external network required."""

    def setUp(self):
        self.mod = load_ipscan()

    def test_loopback_is_pingable(self):
        # Loopback should always answer ICMP (or the OS is broken).
        self.assertTrue(self.mod.is_pingable("127.0.0.1"))

    def test_closed_high_port_returns_false(self):
        # Port 1 on loopback is essentially never open.
        self.assertFalse(self.mod.is_port_active("127.0.0.1", 1))


if __name__ == "__main__":
    unittest.main()
