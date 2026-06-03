#!/usr/bin/env python3
"""ipscan SMOKE tests — fastest tier. Import + python-version sanity.

Tier policy: no mocks, no network, no subprocess. <100ms total.
Run: python -m unittest test_ipscan_smoke -v
     pyst smoke
"""
import sys
import unittest

from _test_common import load_ipscan, print_env_header, print_footer


def setUpModule():
    print_env_header("ipscan [smoke]")


def tearDownModule():
    print_footer()


class TestImportSafety(unittest.TestCase):
    def test_imports_cleanly_on_current_python(self):
        mod = load_ipscan()
        self.assertTrue(hasattr(mod, "is_pingable"))
        self.assertTrue(hasattr(mod, "is_port_active"))

    def test_runs_on_python_3_9_or_newer(self):
        self.assertGreaterEqual(sys.version_info[:2], (3, 9))


if __name__ == "__main__":
    unittest.main()
