import argparse
import importlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock


def args_for(**overrides):
    defaults = {
        "debug": False,
        "delete": False,
        "dry_run": False,
        "format": "tar",
        "no_rec": False,
        "out": None,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def backend_module():
    try:
        return importlib.import_module("advArchiver.advArchiver.backends.tar")
    except ModuleNotFoundError:
        return None


class TestTarBackend(unittest.TestCase):
    def test_tgz_output_keeps_tgz_suffix(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None

        self.assertEqual(module.output_name("sample", "tgz"), "sample.tgz")

    def test_tar_folder_mode_keeps_top_level_folder(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.TarBackend()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            folder = source_root / "foo"
            nested = folder / "nested"
            nested.mkdir(parents=True)
            (nested / "file.txt").write_text("payload", encoding="utf-8")

            job = backend.build_job(
                str(folder),
                args_for(format="tar.gz"),
                str(source_root),
            )
            job.tmp_dir = str(root / "tmp")

            command = module.build_command(job, args_for(format="tar.gz"))

        self.assertEqual(command[0], "tar")
        self.assertEqual(command[-1], "foo")
        self.assertEqual(command[-4], "-C")
        self.assertEqual(command[-3], str(source_root.resolve()))
        self.assertEqual(command[-2], "--")

    def test_tar_inserts_option_terminator_before_dashed_basename(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.TarBackend()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            source_file = source_root / "-danger.txt"
            source_file.write_text("payload", encoding="utf-8")

            job = backend.build_job(
                str(source_file),
                args_for(format="tar"),
                str(source_root),
            )
            job.tmp_dir = str(root / "tmp")

            command = module.build_command(job, args_for(format="tar"))

        self.assertEqual(command[-2], "--")
        self.assertEqual(command[-1], "-danger.txt")

    def test_tar_rejects_unsupported_zstd_aliases(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None

        with self.assertRaises(ValueError):
            module.validate_format("tar.zst")

        with self.assertRaises(ValueError):
            module.validate_format("tzst")

    def test_tar_format_specific_tool_check_fails_early(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.TarBackend()

        with mock.patch.object(backend, "has_tooling_for_format", return_value=False):
            with self.assertRaises(module.process.MissingToolError):
                backend.check_required_tools(args_for(format="tar.xz"))

    def test_tar_uses_system_tar_binary(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.TarBackend()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            source_file = source_root / "sample.txt"
            source_file.write_text("payload", encoding="utf-8")

            job = backend.build_job(
                str(source_file),
                args_for(format="tar"),
                str(source_root),
            )
            job.tmp_dir = str(root / "tmp")

            command = module.build_command(job, args_for(format="tar"))

        self.assertEqual(command[0], "tar")

    def test_tar_defaults_to_external_parpar_recovery(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.TarBackend()

        provider = backend.select_recovery_provider(args_for(), None)

        self.assertTrue(provider.uses_recovery_executor)
        self.assertEqual(provider.mode, "external")

    def test_tar_no_rec_disables_external_recovery(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.TarBackend()

        provider = backend.select_recovery_provider(args_for(no_rec=True), None)

        self.assertIsNone(provider)

    def test_execute_job_renames_output_with_requested_alias_suffix(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.TarBackend()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            source_file = source_root / "sample.txt"
            source_file.write_text("payload", encoding="utf-8")

            job = backend.build_job(
                str(source_file),
                args_for(format="tgz"),
                str(source_root),
            )
            job.tmp_dir = str(root / "tmp")
            Path(job.tmp_dir).mkdir()

            def fake_run(command, debug=False):
                del debug
                Path(command[2]).write_text("archive", encoding="utf-8")
                return mock.Mock(returncode=0, stdout="", stderr="")

            with mock.patch(
                "advArchiver.advArchiver.backends.tar.process.run_command",
                side_effect=fake_run,
            ):
                result = backend.execute_job(job, args_for(format="tgz"))

            self.assertEqual(
                result.archive_result.archive_files,
                [str((Path(job.tmp_dir) / "sample.tgz").resolve())],
            )

    def test_find_and_rename_tar_file_allows_identical_source_and_target(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None

        with tempfile.TemporaryDirectory() as temp_dir:
            workdir = Path(temp_dir)
            archive_path = workdir / "temp_archive.tar"
            archive_path.write_text("archive", encoding="utf-8")

            success, renamed_files = module.find_and_rename_tar_file(
                "temp_archive",
                "temp_archive",
                str(workdir),
                "tar",
            )

            self.assertTrue(success)
            self.assertEqual(renamed_files, [str(archive_path.resolve())])
            self.assertTrue(archive_path.exists())
