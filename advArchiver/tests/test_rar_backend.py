import argparse
import importlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from advArchiver.advArchiver import models


def args_for(**overrides):
    defaults = {
        "comments": None,
        "comments_path": None,
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
        return importlib.import_module("advArchiver.advArchiver.backends.rar")
    except ModuleNotFoundError:
        return None


def recovery_module():
    try:
        return importlib.import_module("advArchiver.advArchiver.recovery.rar_native")
    except ModuleNotFoundError:
        return None


def execution_result_for(*archive_files, recovery_error_msg=""):
    recovery_result = None
    if archive_files:
        recovery_result = models.RecoveryExecutionResult(
            error_msg=recovery_error_msg,
            command="rar a sample.rar",
            embedded=True,
        )
    return models.BackendExecutionResult(
        archive_result=models.ArchiveExecutionResult(
            archive_files=list(archive_files),
            command="rar a sample.rar",
        ),
        recovery_result=recovery_result,
    )


class TestRarBackend(unittest.TestCase):
    @staticmethod
    def _archive_stdout():
        return (
            "Creating archive /tmp/sample.rar\n"
            "Adding /tmp/movie.mkv OK\n"
            "Adding data recovery record 100%\n"
            "Done\n"
        )

    def test_rar_default_switches_include_native_rr(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None

        switches = module.build_switches(args_for())

        self.assertIn("-rr5p", switches)

    def test_rar_no_rec_disables_native_rr(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None

        switches = module.build_switches(args_for(no_rec=True))

        self.assertNotIn("-rr5p", switches)

    def test_rar_delete_preserves_legacy_df_behavior(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None

        switches = module.build_switches(args_for(delete=True))

        self.assertIn("-df", switches)

    def test_validate_args_rejects_conflicting_comment_sources(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.RarBackend()

        with self.assertRaises(ValueError):
            backend.validate_args(args_for(comments="note", comments_path="note.txt"))

    def test_validate_args_rejects_missing_comments_path(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.RarBackend()

        with tempfile.TemporaryDirectory() as temp_dir:
            missing_path = Path(temp_dir) / "missing-note.txt"

            with self.assertRaises(ValueError):
                backend.validate_args(args_for(comments_path=str(missing_path)))

    def test_rar_default_recovery_provider_is_native_inline(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.RarBackend()

        provider = backend.select_recovery_provider(
            args_for(),
            execution_result_for("sample.rar"),
        )

        self.assertFalse(provider.uses_recovery_executor)
        self.assertEqual(provider.__class__.__name__, "RarNativeRecoveryProvider")

    def test_rar_no_rec_disables_native_provider(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.RarBackend()

        provider = backend.select_recovery_provider(
            args_for(no_rec=True),
            execution_result_for("sample.rar"),
        )

        self.assertIsNone(provider)

    def test_execute_job_treats_missing_input_exit_with_artifact_as_hard_failure(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.RarBackend()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            source_file = source_root / "movie.mkv"
            source_file.write_text("payload", encoding="utf-8")

            job = backend.build_job(str(source_file), args_for(), str(source_root))
            job.tmp_dir = str(root / "tmp")
            Path(job.tmp_dir).mkdir()

            def fake_run(command, debug=False):
                del debug
                archive_path = Path(command[-2])
                archive_path.write_text("archive", encoding="utf-8")
                return mock.Mock(
                    returncode=10,
                    stdout=self._archive_stdout(),
                    stderr="Cannot open /tmp/missing.bin",
                )

            with mock.patch(
                "advArchiver.advArchiver.backends.rar.process.run_command",
                side_effect=fake_run,
            ):
                result = backend.execute_job(job, args_for())

            self.assertEqual(result.archive_result.error_code, 10)
            self.assertEqual(result.archive_result.archive_files, [])
            self.assertEqual(
                result.archive_result.error_msg, "Cannot open /tmp/missing.bin"
            )
            self.assertIsNone(result.recovery_result)

    def test_execute_job_treats_non_recovery_warning_exit_code_one_as_hard_failure(
        self,
    ):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.RarBackend()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            source_file = source_root / "movie.mkv"
            source_file.write_text("payload", encoding="utf-8")

            job = backend.build_job(str(source_file), args_for(), str(source_root))
            job.tmp_dir = str(root / "tmp")
            Path(job.tmp_dir).mkdir()

            def fake_run(command, debug=False):
                del debug
                archive_path = Path(command[-2])
                archive_path.write_text("archive", encoding="utf-8")
                return mock.Mock(
                    returncode=1,
                    stdout=self._archive_stdout(),
                    stderr="Password warning: value truncated",
                )

            with mock.patch(
                "advArchiver.advArchiver.backends.rar.process.run_command",
                side_effect=fake_run,
            ):
                result = backend.execute_job(job, args_for())

            self.assertEqual(result.archive_result.error_code, 1)
            self.assertEqual(result.archive_result.archive_files, [])
            self.assertEqual(
                result.archive_result.error_msg,
                "Password warning: value truncated",
            )
            self.assertIsNone(result.recovery_result)

    def test_execute_job_surfaces_recovery_record_warning_as_warning_data(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.RarBackend()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            source_file = source_root / "movie.mkv"
            source_file.write_text("payload", encoding="utf-8")

            job = backend.build_job(str(source_file), args_for(), str(source_root))
            job.tmp_dir = str(root / "tmp")
            Path(job.tmp_dir).mkdir()

            def fake_run(command, debug=False):
                del debug
                archive_path = Path(command[-2])
                archive_path.write_text("archive", encoding="utf-8")
                return mock.Mock(
                    returncode=1,
                    stdout=self._archive_stdout(),
                    stderr="Recovery record warning: native recovery failed",
                )

            with mock.patch(
                "advArchiver.advArchiver.backends.rar.process.run_command",
                side_effect=fake_run,
            ):
                result = backend.execute_job(job, args_for())

            self.assertEqual(
                result.archive_result.archive_files,
                [str((Path(job.tmp_dir) / "movie.rar").resolve())],
            )
            self.assertEqual(
                result.recovery_result.error_msg,
                "Recovery record warning: native recovery failed",
            )
            self.assertTrue(result.recovery_result.embedded)

    def test_rar_delete_stays_in_native_archive_command_during_dry_run(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.RarBackend()

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
                "advArchiver.advArchiver.backends.rar.process.run_command",
                return_value=mock.Mock(returncode=0, stdout="", stderr=""),
            ) as run_command:
                result = backend.execute_job(job, args_for(dry_run=True, delete=True))

            run_command.assert_not_called()
            self.assertIn("-df", result.archive_result.command)
            self.assertEqual(result.archive_result.archive_files, [])
            self.assertIsNotNone(result.recovery_result)
            self.assertEqual(
                result.recovery_result.command, result.archive_result.command
            )
            self.assertTrue(result.recovery_result.embedded)

    def test_rar_parted_profile_preserves_volume_switch(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None

        switches = module.build_switches(args_for(profile="parted-10g"))

        self.assertIn("-v10g", switches)

    def test_rar_comments_path_preserves_comment_file_switch(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.RarBackend()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            source_file = source_root / "movie.mkv"
            source_file.write_text("payload", encoding="utf-8")
            comments_path = root / "note.txt"
            comments_path.write_text("note", encoding="utf-8")

            job = backend.build_job(
                str(source_file),
                args_for(dry_run=True, comments_path=str(comments_path)),
                str(source_root),
            )
            job.tmp_dir = str(root / "tmp")

            result = backend.execute_job(
                job,
                args_for(dry_run=True, comments_path=str(comments_path)),
            )

            self.assertIn(
                f"-z{str(comments_path.resolve())}",
                result.archive_result.command,
            )


class TestRarNativeRecoveryProvider(unittest.TestCase):
    def test_provider_passthrough_keeps_inline_recovery_distinct(self):
        module = recovery_module()
        self.assertIsNotNone(module)
        assert module is not None
        provider = module.RarNativeRecoveryProvider()

        job = models.ArchiveJob(
            backend_name="rar",
            item_path="/tmp/sample.bin",
            item_type="file",
            rel_path="sample.bin",
            final_output_dir="/tmp",
        )
        execution_result = execution_result_for(
            "/tmp/sample.rar",
            recovery_error_msg="native recovery failed",
        )

        result = provider.apply(job, execution_result, args_for())

        self.assertFalse(provider.uses_recovery_executor)
        self.assertEqual(result.error_msg, "native recovery failed")
        self.assertTrue(result.embedded)
