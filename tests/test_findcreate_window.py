"""Regression tests for bounded KeyValues leaf candidate selection."""
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "rp", Path(__file__).parent / ".." / "tools" / "resolve_patterns.py")
rp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rp)


class FakeCtx:
    def __init__(self, entries):
        self.entries = entries

    def refs_by_func(self):
        return {}

    def callees(self, _):
        return {}


class TestFindCreateWindow(unittest.TestCase):
    def test_prior_window_fallback(self):
        ctx = FakeCtx([0x1F000, 0x1F100, 0x20010])
        result, err = rp.p2_findcreate(
            ctx, 0x21000, {0x1F000: set(range(170)),
                           0x1F100: set(range(112)),
                           0x20010: set(range(20))})
        self.assertEqual((result, err), (0x1F000, None))

    def test_original_window_still_wins(self):
        ctx = FakeCtx([0x1F000, 0x20010])
        result, err = rp.p2_findcreate(
            ctx, 0x21000, {0x1F000: set(range(170)),
                           0x20010: set(range(110))})
        self.assertEqual((result, err), (0x20010, None))

    def test_tied_fallback_refused(self):
        ctx = FakeCtx([0x1F000, 0x1F100])
        result, err = rp.p2_findcreate(
            ctx, 0x21000, {0x1F000: set(range(120)),
                           0x1F100: set(range(120))})
        self.assertIsNone(result)
        self.assertIn("tie", err)


if __name__ == "__main__":
    unittest.main()
