#!/usr/bin/env python3
"""pyst SMOKE tests — import + version + arg-parser sanity.

Run: python -m unittest test_pyst_smoke -v
     pyst smoke pyst
"""
import unittest

from _test_common import print_env_header, print_footer


def setUpModule():
    print_env_header("pyst [smoke]")


def tearDownModule():
    print_footer()


class TestPystImport(unittest.TestCase):
    def test_module_imports(self):
        import pyst
        self.assertTrue(hasattr(pyst, "main"))
        self.assertTrue(hasattr(pyst, "discover"))
        self.assertTrue(hasattr(pyst, "classify"))

    def test_version_is_semver_ish(self):
        import pyst
        parts = pyst.__version__.split(".")
        self.assertGreaterEqual(len(parts), 2)
        self.assertTrue(all(p.isdigit() for p in parts))

    def test_argparser_builds(self):
        import pyst
        p = pyst.build_argparser()
        ns = p.parse_args(["smoke"])
        self.assertEqual(ns.patterns, ["smoke"])
        self.assertFalse(ns.tree)
        self.assertFalse(ns.all_pythons)


if __name__ == "__main__":
    unittest.main()
