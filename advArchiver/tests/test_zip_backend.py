import argparse
import importlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from advArchiver.advArchiver import models


def args_for(**overrides):
    defaults = {
        "code_page": "mcu",
        "debug": False,
        "delete": False,
        "dry_run": False,
        "no_rec": False,
        "out": None,
        "password": None,
        "profile": "best",
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def backend_module():
    try:
        return importlib.import_module("advArchiver.advArchiver.backends.zip_backend")
    except ModuleNotFoundError:
        return None


def execution_result_for(*archive_files):
    return models.BackendExecutionResult(
        archive_result=models.ArchiveExecutionResult(
            archive_files=list(archive_files),
            command="7z a -tzip",
        )
    )


class TestZipBackend(unittest.TestCase):
    def test_zip_preserves_numeric_code_page_switch(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None

        switches = module.build_zip_switches(
            "best",
            password=None,
            code_page="65001",
        )

        self.assertIn("-mcp=65001", switches)

    def test_zip_preserves_legacy_mcu_default(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None

        switches = module.build_zip_switches(
            "best",
            password=None,
            code_page="mcu",
        )

        self.assertIn("-mcu=on", switches)

    def test_zip_delete_preserves_legacy_sdel_behavior(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None

        switches = module.build_zip_switches(
            "best",
            password=None,
            code_page="mcu",
            delete_files=True,
        )

        self.assertIn("-sdel", switches)

    def test_zip_defaults_to_external_parpar_recovery(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.ZipBackend()

        provider = backend.select_recovery_provider(
            args_for(),
            execution_result_for("sample.zip"),
        )

        self.assertTrue(provider.uses_recovery_executor)
        self.assertEqual(provider.mode, "external")

    def test_zip_no_rec_disables_external_recovery(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.ZipBackend()

        provider = backend.select_recovery_provider(
            args_for(no_rec=True),
            execution_result_for("sample.zip"),
        )

        self.assertIsNone(provider)

    def test_zip_delete_stays_in_native_archive_command_during_dry_run(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.ZipBackend()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            source_file = source_root / "movie.mkv"
            source_file.write_text("payload", encoding="utf-8")

            job = backend.build_job(
                str(source_file),
                args_for(dry_run=True, delete=True),
                str(source_root),
            )
            job.tmp_dir = str(root / "tmp")

            with mock.patch(
                "advArchiver.advArchiver.backends.zip_backend.process.run_command",
                return_value=mock.Mock(returncode=0, stdout="", stderr=""),
            ) as run_command:
                result = backend.execute_job(job, args_for(dry_run=True, delete=True))

            run_command.assert_not_called()
            self.assertIn("-sdel", result.archive_result.command)
            self.assertEqual(result.archive_result.archive_files, [])
