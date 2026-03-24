import unittest
from pathlib import Path


ADVARCHIVER_ROOT = Path(__file__).resolve().parents[1]
DEPRECATED_ROOT = ADVARCHIVER_ROOT / "deprecated"
LEGACY_ENTRYPOINTS = {
    "adv7z.py": "7z",
    "advRar.py": "rar",
    "advZip.py": "zip",
}


class TestDeprecatedScriptLayout(unittest.TestCase):
    def test_deprecated_scripts_exist_under_deprecated_directory(self):
        for script_name, backend in LEGACY_ENTRYPOINTS.items():
            del backend
            with self.subTest(script_name=script_name):
                self.assertTrue((DEPRECATED_ROOT / script_name).exists())

    def test_top_level_legacy_entrypoints_are_removed(self):
        for script_name, backend in LEGACY_ENTRYPOINTS.items():
            del backend
            with self.subTest(script_name=script_name):
                self.assertFalse((ADVARCHIVER_ROOT / script_name).exists())

    def test_deprecated_scripts_include_migration_guidance(self):
        for script_name, backend in LEGACY_ENTRYPOINTS.items():
            with self.subTest(script_name=script_name):
                content = (DEPRECATED_ROOT / script_name).read_text(encoding="utf-8")

                self.assertIn("DEPRECATED:", content)
                self.assertIn("not maintained", content)
                self.assertIn(f"advArchiver/advArchiver.py {backend}", content)
