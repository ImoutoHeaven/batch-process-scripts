import unittest
from pathlib import Path


README_PATH = Path(__file__).resolve().parents[1] / "README.md"


class TestCompatibilityInventory(unittest.TestCase):
    def test_readme_exists_for_backend_compatibility_inventory(self):
        self.assertTrue(README_PATH.exists())

    def test_readme_covers_delete_inside_native_command_baseline(self):
        self.assertTrue(README_PATH.exists())
        content = README_PATH.read_text(encoding="utf-8")

        self.assertIn("Compatibility Inventory", content)
        self.assertIn("7z", content)
        self.assertIn("zip", content)
        self.assertIn("rar", content)
        self.assertIn("delete-inside-native-command", content)
        self.assertIn(
            "advArchiver/tests/test_7z_backend.py::TestSevenZipBackend.test_dry_run_skips_7z_subprocess_execution",
            content,
        )
        self.assertIn(
            "advArchiver/tests/test_zip_backend.py::TestZipBackend.test_zip_delete_stays_in_native_archive_command_during_dry_run",
            content,
        )
        self.assertIn(
            "advArchiver/tests/test_rar_backend.py::TestRarBackend.test_rar_delete_stays_in_native_archive_command_during_dry_run",
            content,
        )

    def test_readme_tracks_current_rar_warning_coverage_case(self):
        self.assertTrue(README_PATH.exists())
        content = README_PATH.read_text(encoding="utf-8")

        self.assertIn(
            "advArchiver/tests/test_rar_backend.py::TestRarBackend.test_execute_job_surfaces_recovery_record_warning_as_warning_data",
            content,
        )
        self.assertNotIn(
            "advArchiver/tests/test_rar_backend.py::TestRarBackend.test_execute_job_surfaces_native_recovery_failure_as_warning_data",
            content,
        )

    def test_readme_documents_supported_entrypoint_and_deprecated_layout(self):
        self.assertTrue(README_PATH.exists())
        content = README_PATH.read_text(encoding="utf-8")

        self.assertIn("advArchiver/advArchiver.py", content)
        self.assertIn("advArchiver/deprecated/adv7z.py", content)
        self.assertIn("advArchiver/deprecated/advRar.py", content)
        self.assertIn("advArchiver/deprecated/advZip.py", content)
        self.assertIn("old top-level paths have been removed", content)
        self.assertIn(
            "advArchiver/tests/test_deprecated_entrypoints.py::TestDeprecatedScriptLayout.test_top_level_legacy_entrypoints_are_removed",
            content,
        )
        self.assertNotIn("deprecated compatibility entrypoints", content)
        self.assertNotIn("TestDeprecatedEntrypoints", content)
