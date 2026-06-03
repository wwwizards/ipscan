#!/usr/bin/env python3
"""pyst UNIT tests — discovery, classification, fuzzy matching, py-list parsing.

Run: python -m unittest test_pyst_unit -v
     pyst unit pyst
"""
import pathlib
import tempfile
import unittest
from unittest.mock import patch

import pyst
from _test_common import print_env_header, print_footer


def setUpModule():
    print_env_header("pyst [unit]")


def tearDownModule():
    print_footer()


class TestClassify(unittest.TestCase):
    def test_smoke_suffix(self):
        self.assertEqual(pyst.classify(pathlib.Path("test_foo_smoke.py")), "smoke")

    def test_unit_suffix(self):
        self.assertEqual(pyst.classify(pathlib.Path("test_foo_unit.py")), "unit")

    def test_integration_suffix(self):
        self.assertEqual(pyst.classify(pathlib.Path("test_x_integration.py")), "integration")

    def test_sanity_suffix(self):
        self.assertEqual(pyst.classify(pathlib.Path("test_x_sanity.py")), "sanity")

    def test_untiered_falls_through(self):
        self.assertEqual(pyst.classify(pathlib.Path("test_legacy.py")), "untiered")


class TestFuzzyMatch(unittest.TestCase):
    def test_empty_patterns_matches_everything(self):
        self.assertTrue(pyst.fuzzy_match(pathlib.Path("test_anything.py"), []))

    def test_tier_pattern_filters_by_classification(self):
        self.assertTrue(pyst.fuzzy_match(pathlib.Path("test_foo_smoke.py"), ["smoke"]))
        self.assertFalse(pyst.fuzzy_match(pathlib.Path("test_foo_unit.py"), ["smoke"]))

    def test_substring_pattern(self):
        self.assertTrue(pyst.fuzzy_match(pathlib.Path("test_ipscan_unit.py"), ["ipscan"]))
        self.assertFalse(pyst.fuzzy_match(pathlib.Path("test_pyst_unit.py"), ["ipscan"]))

    def test_and_semantics_across_patterns(self):
        # Both 'ipscan' AND 'unit' must match
        self.assertTrue(pyst.fuzzy_match(pathlib.Path("test_ipscan_unit.py"),
                                         ["ipscan", "unit"]))
        self.assertFalse(pyst.fuzzy_match(pathlib.Path("test_ipscan_smoke.py"),
                                          ["ipscan", "unit"]))

    def test_case_insensitive(self):
        self.assertTrue(pyst.fuzzy_match(pathlib.Path("test_FOO_smoke.py"), ["foo"]))
        self.assertTrue(pyst.fuzzy_match(pathlib.Path("test_foo_smoke.py"), ["SMOKE"]))


class TestDiscover(unittest.TestCase):
    def test_discover_finds_test_files_only(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            (root / "test_a.py").write_text("")
            (root / "test_b_smoke.py").write_text("")
            (root / "not_a_test.py").write_text("")
            (root / "sub").mkdir()
            (root / "sub" / "test_c_unit.py").write_text("")
            files = pyst.discover(root)
            names = sorted(f.name for f in files)
            self.assertEqual(names, ["test_a.py", "test_b_smoke.py", "test_c_unit.py"])

    def test_discover_respects_exclude(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            (root / "test_keep.py").write_text("")
            (root / "legacy").mkdir()
            (root / "legacy" / "test_old.py").write_text("")
            files = pyst.discover(root, exclude=["legacy"])
            names = [f.name for f in files]
            self.assertEqual(names, ["test_keep.py"])


class TestPyListParser(unittest.TestCase):
    """Parser for `py -0p` output — Windows interpreter discovery."""

    def test_parses_typical_py_dash_zero_p_output(self):
        fake = (
            " -V:3.14 *         C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python314\\python.exe\n"
            " -V:3.12           C:\\Python312\\python.exe\n"
            " -V:3.11           C:\\Python311\\python.exe\n"
        )
        with patch.object(pyst.shutil, "which", return_value="C:\\Windows\\py.exe"), \
             patch.object(pyst.subprocess, "check_output", return_value=fake):
            paths = pyst.list_pythons_windows()
        self.assertEqual(len(paths), 3)
        self.assertTrue(all(p.lower().endswith("python.exe") for p in paths))

    def test_returns_empty_when_py_launcher_missing(self):
        with patch.object(pyst.shutil, "which", return_value=None):
            self.assertEqual(pyst.list_pythons_windows(), [])


if __name__ == "__main__":
    unittest.main()
