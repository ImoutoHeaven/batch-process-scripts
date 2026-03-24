import argparse
import importlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from advArchiver.advArchiver import models


def args_for(**overrides):
    defaults = {
        "debug": False,
        "delete": False,
        "dry_run": False,
        "no_emb": False,
        "no_rec": False,
        "out": None,
        "password": None,
        "profile": "best",
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def backend_module():
    try:
        return importlib.import_module("advArchiver.advArchiver.backends.sevenzip")
    except ModuleNotFoundError:
        return None


def parpar_module():
    try:
        return importlib.import_module("advArchiver.advArchiver.recovery.parpar")
    except ModuleNotFoundError:
        return None


def execution_result_for(*archive_files):
    return models.BackendExecutionResult(
        archive_result=models.ArchiveExecutionResult(
            archive_files=list(archive_files),
            command="7z a",
        )
    )


class TestSevenZipBackend(unittest.TestCase):
    def test_build_job_preserves_legacy_out_root_for_nested_items(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.SevenZipBackend()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            nested = source_root / "nested"
            nested.mkdir(parents=True)
            source_file = nested / "movie.mkv"
            source_file.write_text("payload", encoding="utf-8")
            out_dir = root / "out"

            job = backend.build_job(
                str(source_file),
                args_for(out=str(out_dir)),
                str(source_root),
            )

            self.assertEqual(job.rel_path, "nested/movie.mkv")
            self.assertEqual(job.final_output_dir, str(out_dir.resolve()))

    def test_parted_profile_forces_external_recovery(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.SevenZipBackend()

        provider = backend.select_recovery_provider(
            args_for(profile="parted-10g"),
            execution_result_for("a.7z.001"),
        )

        self.assertTrue(provider.uses_recovery_executor)
        self.assertEqual(provider.mode, "external")

    def test_single_archive_defaults_to_append_embed(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.SevenZipBackend()

        provider = backend.select_recovery_provider(
            args_for(profile="best"),
            execution_result_for("a.7z"),
        )

        self.assertEqual(provider.mode, "append-embed")

    def test_delete_preserves_legacy_sdel_behavior(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None

        switches = module.build_7z_switches(
            "best",
            password=None,
            delete_files=True,
        )

        self.assertIn("-sdel", switches)

    def test_find_and_rename_split_archives_preserves_volume_suffixes(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None

        with tempfile.TemporaryDirectory() as temp_dir:
            workdir = Path(temp_dir)
            for suffix in ("001", "002"):
                (workdir / f"temp_archive.7z.{suffix}").write_text(
                    suffix,
                    encoding="utf-8",
                )

            success, renamed_files = module.find_and_rename_7z_files(
                "temp_archive",
                "movie",
                str(workdir),
            )

            self.assertTrue(success)
            self.assertEqual(
                renamed_files,
                [
                    str((workdir / "movie.7z.001").resolve()),
                    str((workdir / "movie.7z.002").resolve()),
                ],
            )

    def test_dry_run_skips_7z_subprocess_execution(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.SevenZipBackend()

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
                "advArchiver.advArchiver.backends.sevenzip.process.run_command",
                return_value=mock.Mock(returncode=0, stdout="", stderr=""),
            ) as run_command:
                result = backend.execute_job(job, args_for(dry_run=True, delete=True))

            run_command.assert_not_called()
            self.assertIn("-sdel", result.archive_result.command)
            self.assertEqual(result.archive_result.archive_files, [])


class TestParparProvider(unittest.TestCase):
    def test_append_embed_mode_returns_no_external_files(self):
        module = parpar_module()
        self.assertIsNotNone(module)
        assert module is not None
        provider = module.ParparRecoveryProvider(mode="append-embed")

        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "a.7z"
            archive_path.write_bytes(b"archive")
            job = models.ArchiveJob(
                backend_name="7z",
                item_path=str(archive_path),
                item_type="file",
                rel_path="a.txt",
                final_output_dir=temp_dir,
                tmp_dir=temp_dir,
            )

            def fake_run(command, debug=False):
                del debug
                output_path = Path(command[command.index("-o") + 1])
                output_path.write_bytes(b"par2")
                return mock.Mock(returncode=0, stdout="", stderr="")

            with mock.patch(
                "advArchiver.advArchiver.recovery.parpar.process.run_command",
                side_effect=fake_run,
            ):
                result = provider.apply(
                    job,
                    execution_result_for(str(archive_path)),
                    args_for(),
                )

            self.assertTrue(result.succeeded)
            self.assertTrue(result.embedded)
            self.assertEqual(result.recovery_files, [])
            self.assertEqual(archive_path.read_bytes(), b"archivepar2")
            self.assertFalse(Path(f"{archive_path}.par2").exists())

    def test_external_mode_returns_par2_files(self):
        module = parpar_module()
        self.assertIsNotNone(module)
        assert module is not None
        provider = module.ParparRecoveryProvider(mode="external")

        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "a.7z"
            archive_path.write_bytes(b"archive")
            job = models.ArchiveJob(
                backend_name="7z",
                item_path=str(archive_path),
                item_type="file",
                rel_path="a.txt",
                final_output_dir=temp_dir,
                tmp_dir=temp_dir,
            )

            def fake_run(command, debug=False):
                del debug
                output_path = Path(command[command.index("-o") + 1])
                output_path.write_bytes(b"par2")
                return mock.Mock(returncode=0, stdout="", stderr="")

            with mock.patch(
                "advArchiver.advArchiver.recovery.parpar.process.run_command",
                side_effect=fake_run,
            ):
                result = provider.apply(
                    job,
                    execution_result_for(str(archive_path)),
                    args_for(no_emb=True),
                )

            self.assertTrue(result.succeeded)
            self.assertFalse(result.embedded)
            self.assertEqual(result.recovery_files, [str(Path(f"{archive_path}.par2"))])
            self.assertTrue(Path(f"{archive_path}.par2").exists())

    def test_dry_run_skips_parpar_subprocess_execution(self):
        module = parpar_module()
        self.assertIsNotNone(module)
        assert module is not None
        provider = module.ParparRecoveryProvider(mode="append-embed")

        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "a.7z"
            archive_path.write_bytes(b"archive")
            job = models.ArchiveJob(
                backend_name="7z",
                item_path=str(archive_path),
                item_type="file",
                rel_path="a.txt",
                final_output_dir=temp_dir,
                tmp_dir=temp_dir,
            )

            with mock.patch(
                "advArchiver.advArchiver.recovery.parpar.process.run_command",
                return_value=mock.Mock(returncode=0, stdout="", stderr=""),
            ) as run_command:
                result = provider.apply(
                    job,
                    execution_result_for(str(archive_path)),
                    args_for(dry_run=True),
                )

            run_command.assert_not_called()
            self.assertTrue(result.embedded)
            self.assertEqual(result.recovery_files, [])
            self.assertIn("parpar", result.command)
            self.assertEqual(archive_path.read_bytes(), b"archive")
            self.assertFalse(Path(f"{archive_path}.par2").exists())
