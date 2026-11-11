"""Regression checks for Steam buildworker hotfix source-root normalization."""
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "rp", Path(__file__).parent / ".." / "tools" / "resolve_patterns.py")
rp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rp)


class TestSourcePaths(unittest.TestCase):
    def test_hotfix_buildworker_path(self):
        hotfix = rp.CS.replace("steam_rel_client_win64", "steam_rel_client_hotfix_win64")
        self.assertEqual(
            rp.canonical_source_path(hotfix + "public\\tier1\\utlmemory.h"),
            rp.CS + "public\\tier1\\utlmemory.h")

    def test_standard_root_unchanged(self):
        self.assertEqual(rp.canonical_source_path(rp.CS + "clientdll\\controller.cpp"),
                         rp.CS + "clientdll\\controller.cpp")

    def test_unrelated_text_unchanged(self):
        text = "prefix steam_rel_client_hotfix_win64 suffix"
        self.assertEqual(rp.canonical_source_path(text), text)


if __name__ == "__main__":
    unittest.main()
