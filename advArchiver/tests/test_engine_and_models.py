import argparse
import importlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from advArchiver.advArchiver import engine, models
from advArchiver.advArchiver.backends.base import BackendBase
from advArchiver.advArchiver.common import stats
from advArchiver.advArchiver.recovery.base import RecoveryProviderBase


def make_args(**overrides):
    defaults = {
        "debug": False,
        "delete": False,
        "dry_run": False,
        "lock_timeout": 1,
        "no_lock": True,
        "no_rec": False,
        "out": None,
        "rec_threads": 1,
        "threads": 1,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class FakeRecoveryProvider(RecoveryProviderBase):
    def __init__(self, should_fail=False):
        self.should_fail = should_fail

    def check_required_tools(self, args):
        del args

    def apply(self, job, execution_result, args):
        del args
        if self.should_fail:
            return models.RecoveryExecutionResult(
                error_msg=f"recovery failed for {job.item_path}"
            )

        recovery_file = Path(job.tmp_dir) / (
            Path(execution_result.archive_result.archive_files[0]).name + ".par2"
        )
        recovery_file.write_text("recovery", encoding="utf-8")
        return models.RecoveryExecutionResult(recovery_files=[str(recovery_file)])


class PartialFailureRecoveryProvider(RecoveryProviderBase):
    def check_required_tools(self, args):
        del args

    def apply(self, job, execution_result, args):
        del args, execution_result
        recovery_file = Path(job.tmp_dir) / (Path(job.item_path).name + ".par2")
        recovery_file.write_text("partial recovery", encoding="utf-8")
        return models.RecoveryExecutionResult(
            recovery_files=[str(recovery_file)],
            error_msg=f"recovery failed for {job.item_path}",
            command="fake recovery",
        )


class MultiRecoveryProvider(RecoveryProviderBase):
    def check_required_tools(self, args):
        del args

    def apply(self, job, execution_result, args):
        del args, execution_result
        recovery_files = []
        item_name = Path(job.item_path).name
        for index in range(1, 3):
            recovery_file = Path(job.tmp_dir) / f"{item_name}.{index}.par2"
            recovery_file.write_text(f"recovery-{index}", encoding="utf-8")
            recovery_files.append(str(recovery_file))
        return models.RecoveryExecutionResult(
            recovery_files=recovery_files,
            command="fake multi recovery",
        )


class FakeBackend(BackendBase):
    name = "fake"

    def __init__(self, provider=None, fail_archive=False):
        self.provider = provider
        self.fail_archive = fail_archive

    def register_arguments(self, subparser):
        return subparser

    def capabilities(self):
        return models.BackendCapabilities(
            supports_password=False,
            supports_split_volumes=False,
            supports_native_recovery=False,
            supports_external_recovery=True,
            supports_embedded_recovery=False,
            supports_comments=False,
            supports_explicit_format=False,
        )

    def validate_args(self, args):
        del args

    def check_required_tools(self, args):
        del args

    def build_job(self, item_path, args, base_path):
        del args, base_path
        path = Path(item_path)
        item_type = "file" if path.is_file() else "folder"
        return models.ArchiveJob(
            backend_name=self.name,
            item_path=str(path),
            item_type=item_type,
            rel_path="",
            final_output_dir="",
        )

    def execute_job(self, job, args):
        del args
        if self.fail_archive:
            return models.BackendExecutionResult(
                archive_result=models.ArchiveExecutionResult(
                    error_code=17,
                    error_msg=f"archive failed for {job.item_path}",
                    command="fake archive",
                )
            )

        archive_file = Path(job.tmp_dir) / (Path(job.item_path).name + ".arc")
        archive_file.write_text("archive", encoding="utf-8")
        return models.BackendExecutionResult(
            archive_result=models.ArchiveExecutionResult(
                archive_files=[str(archive_file)],
                command="fake archive",
            )
        )

    def select_recovery_provider(self, args, execution_result):
        del args, execution_result
        return self.provider


class InlineRecoveryPassthroughProvider(RecoveryProviderBase):
    uses_recovery_executor = False

    def check_required_tools(self, args):
        del args

    def apply(self, job, execution_result, args):
        del job, args
        return execution_result.recovery_result


class InlineRecoveryBackend(FakeBackend):
    def __init__(self, recovery_error_msg):
        super().__init__(provider=InlineRecoveryPassthroughProvider())
        self.recovery_error_msg = recovery_error_msg

    def execute_job(self, job, args):
        del args
        archive_file = Path(job.tmp_dir) / (Path(job.item_path).name + ".arc")
        archive_file.write_text("archive", encoding="utf-8")
        return models.BackendExecutionResult(
            archive_result=models.ArchiveExecutionResult(
                archive_files=[str(archive_file)],
                command="fake archive",
            ),
            recovery_result=models.RecoveryExecutionResult(
                error_msg=self.recovery_error_msg,
                command="fake inline recovery",
                embedded=True,
            ),
        )

    def select_recovery_provider(self, args, execution_result):
        del args, execution_result
        return self.provider


class RaisingValidateBackend(FakeBackend):
    def validate_args(self, args):
        del args
        raise ValueError("invalid backend args")


class RaisingExecuteBackend(FakeBackend):
    def execute_job(self, job, args):
        del job, args
        raise RuntimeError("archive command crashed")


class EmptyArchiveSuccessBackend(FakeBackend):
    def execute_job(self, job, args):
        del job, args
        return models.BackendExecutionResult(
            archive_result=models.ArchiveExecutionResult(command="fake archive")
        )


class TestCompressionStats(unittest.TestCase):
    def test_recovery_warning_is_tracked_separately_from_failures(self):
        summary = stats.CompressionStats()

        summary.add_success("file", "/tmp/ok.txt")
        summary.add_recovery_warning("file", "/tmp/warn.txt", ["warn.7z"])

        self.assertEqual(summary.success_files, 1)
        self.assertEqual(summary.failed_files, 0)
        self.assertEqual(summary.hard_failure_count, 0)
        self.assertEqual(summary.recovery_warning_count, 1)
        self.assertEqual(len(summary.recovery_warning_items), 1)
        self.assertEqual(summary.recovery_warning_items[0].archive_files, ["warn.7z"])

    def test_failure_counts_remain_distinct_from_recovery_warnings(self):
        summary = stats.CompressionStats()

        summary.add_failure("folder", "/tmp/bad", 1, "boom", "rar a bad.rar")
        summary.add_recovery_warning("folder", "/tmp/warn", ["warn.rar"])

        self.assertEqual(summary.failed_folders, 1)
        self.assertEqual(summary.recovery_warning_count, 1)
        self.assertEqual(summary.hard_failure_count, 1)
        self.assertEqual(len(summary.failed_items), 1)
        self.assertEqual(summary.failed_items[0].path, "/tmp/bad")


class TestEngineLifecycle(unittest.TestCase):
    def test_archive_failure_maps_to_exit_code_one(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            source_file = source_root / "broken.txt"
            source_file.write_text("payload", encoding="utf-8")

            summary = engine.run(
                [str(source_file)],
                FakeBackend(fail_archive=True),
                make_args(),
                str(source_root),
                lock_path=str(root / "engine.lock"),
            )

            self.assertEqual(summary.exit_code, 1)
            self.assertEqual(summary.hard_failure_count, 1)
            self.assertEqual(summary.warning_count, 0)
            self.assertTrue(source_file.exists())

    def test_lock_failure_maps_to_exit_code_two(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            lock_path = root / "engine.lock"
            first_lock = engine.acquire_lock(
                lock_path=str(lock_path),
                max_attempts=1,
                sleep_interval=0,
            )
            self.assertTrue(first_lock.acquired)

            try:
                source_root = root / "source"
                source_root.mkdir()
                source_file = source_root / "item.txt"
                source_file.write_text("payload", encoding="utf-8")

                summary = engine.run(
                    [str(source_file)],
                    FakeBackend(),
                    make_args(no_lock=False, lock_timeout=1),
                    str(source_root),
                    lock_path=str(lock_path),
                )
            finally:
                first_lock.release()

            self.assertEqual(summary.exit_code, 2)
            self.assertEqual(summary.hard_failure_count, 0)
            self.assertEqual(summary.warning_count, 0)
            self.assertEqual(summary.job_results, [])

    def test_recovery_warning_maps_to_exit_code_three(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            nested = source_root / "nested"
            nested.mkdir(parents=True)
            source_file = nested / "warn.txt"
            source_file.write_text("payload", encoding="utf-8")
            output_dir = root / "out"

            summary = engine.run(
                [str(source_file)],
                FakeBackend(provider=FakeRecoveryProvider(should_fail=True)),
                make_args(delete=True, out=str(output_dir)),
                str(source_root),
                lock_path=str(root / "engine.lock"),
            )

            self.assertEqual(summary.exit_code, 3)
            self.assertEqual(summary.hard_failure_count, 0)
            self.assertEqual(summary.warning_count, 1)
            self.assertTrue(source_file.exists())
            self.assertEqual(summary.job_results[0].final_artifacts.recovery_files, [])
            self.assertEqual(
                summary.job_results[0].final_artifacts.archive_files,
                [str((output_dir / "nested" / "warn.txt.arc").resolve())],
            )

    def test_recovery_warning_clears_partial_recovery_artifacts_and_blocks_delete(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            source_file = source_root / "warn.txt"
            source_file.write_text("payload", encoding="utf-8")
            output_dir = root / "out"

            summary = engine.run(
                [str(source_file)],
                FakeBackend(provider=PartialFailureRecoveryProvider()),
                make_args(delete=True, out=str(output_dir)),
                str(source_root),
                lock_path=str(root / "engine.lock"),
            )

            self.assertEqual(summary.exit_code, 3)
            self.assertEqual(summary.hard_failure_count, 0)
            self.assertEqual(summary.warning_count, 1)
            self.assertEqual(summary.success_count, 1)
            self.assertTrue(summary.job_results[0].has_recovery_warning)
            self.assertFalse(summary.job_results[0].source_deleted)
            self.assertTrue(source_file.exists())
            self.assertEqual(summary.job_results[0].final_artifacts.recovery_files, [])
            self.assertEqual(summary.job_results[0].recovery_result.recovery_files, [])
            self.assertEqual(
                summary.stats.recovery_warning_items[0].archive_files,
                [str((output_dir / "warn.txt.arc").resolve())],
            )

    def test_recovery_move_failure_rolls_back_partially_moved_recovery_artifacts(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            source_file = source_root / "warn.txt"
            source_file.write_text("payload", encoding="utf-8")
            output_dir = root / "out"
            original_safe_move = engine.fs.safe_move
            recovery_move_count = {"count": 0}

            def flaky_safe_move(src, dst, debug=False):
                if str(src).endswith(".par2"):
                    recovery_move_count["count"] += 1
                    if recovery_move_count["count"] == 2:
                        return False
                return original_safe_move(src, dst, debug=debug)

            with mock.patch(
                "advArchiver.advArchiver.common.fs.safe_move",
                side_effect=flaky_safe_move,
            ):
                summary = engine.run(
                    [str(source_file)],
                    FakeBackend(provider=MultiRecoveryProvider()),
                    make_args(delete=True, out=str(output_dir)),
                    str(source_root),
                    lock_path=str(root / "engine.lock"),
                )

            self.assertEqual(summary.exit_code, 3)
            self.assertEqual(summary.hard_failure_count, 0)
            self.assertEqual(summary.warning_count, 1)
            self.assertTrue((output_dir / "warn.txt.arc").exists())
            self.assertFalse((output_dir / "warn.txt.1.par2").exists())
            self.assertFalse((output_dir / "warn.txt.2.par2").exists())
            self.assertEqual(summary.job_results[0].final_artifacts.recovery_files, [])
            self.assertEqual(summary.job_results[0].recovery_result.recovery_files, [])
            self.assertFalse(summary.job_results[0].source_deleted)
            self.assertTrue(source_file.exists())

    def test_recovery_move_rollback_delete_failure_becomes_hard_failure(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            source_file = source_root / "warn.txt"
            source_file.write_text("payload", encoding="utf-8")
            output_dir = root / "out"
            original_safe_move = engine.fs.safe_move
            original_safe_remove = engine.fs.safe_remove
            recovery_move_count = {"count": 0}

            def flaky_safe_move(src, dst, debug=False):
                if str(src).endswith(".par2"):
                    recovery_move_count["count"] += 1
                    if recovery_move_count["count"] == 2:
                        return False
                return original_safe_move(src, dst, debug=debug)

            def flaky_safe_remove(path, debug=False):
                if str(path).endswith("warn.txt.1.par2"):
                    return False
                return original_safe_remove(path, debug=debug)

            with (
                mock.patch(
                    "advArchiver.advArchiver.common.fs.safe_move",
                    side_effect=flaky_safe_move,
                ),
                mock.patch(
                    "advArchiver.advArchiver.common.fs.safe_remove",
                    side_effect=flaky_safe_remove,
                ),
            ):
                summary = engine.run(
                    [str(source_file)],
                    FakeBackend(provider=MultiRecoveryProvider()),
                    make_args(delete=True, out=str(output_dir)),
                    str(source_root),
                    lock_path=str(root / "engine.lock"),
                )

            self.assertEqual(summary.exit_code, 1)
            self.assertEqual(summary.hard_failure_count, 1)
            self.assertEqual(summary.warning_count, 0)
            self.assertTrue((output_dir / "warn.txt.arc").exists())
            self.assertTrue((output_dir / "warn.txt.1.par2").exists())
            self.assertFalse((output_dir / "warn.txt.2.par2").exists())
            self.assertEqual(
                summary.job_results[0].final_artifacts.archive_files,
                [str((output_dir / "warn.txt.arc").resolve())],
            )
            self.assertEqual(summary.job_results[0].final_artifacts.recovery_files, [])
            self.assertFalse(summary.job_results[0].source_deleted)
            self.assertTrue(source_file.exists())
            self.assertTrue(summary.job_results[0].hard_failure)
            self.assertIn(
                "failed to roll back incomplete recovery artifacts",
                summary.job_results[0].failure_error_msg,
            )

    def test_prepare_job_validates_input_and_hands_off_output_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            nested = source_root / "nested"
            nested.mkdir(parents=True)
            source_file = nested / "item.txt"
            source_file.write_text("payload", encoding="utf-8")

            job = engine.prepare_job(
                FakeBackend(),
                str(source_file),
                make_args(out=str(root / "out")),
                str(source_root),
            )

            self.assertEqual(job.item_path, str(source_file.resolve()))
            self.assertEqual(job.item_type, "file")
            self.assertEqual(job.rel_path, "nested/item.txt")
            self.assertEqual(
                job.final_output_dir, str((root / "out" / "nested").resolve())
            )

    def test_locking_honors_no_lock_and_timeout(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            lock_path = root / "engine.lock"

            self.assertTrue(engine.should_skip_lock(no_lock=True))
            self.assertEqual(engine.lock_attempt_budget(lock_timeout=9), 9)

            first_lock = engine.acquire_lock(
                lock_path=str(lock_path),
                max_attempts=1,
                sleep_interval=0,
            )
            self.assertTrue(first_lock.acquired)

            try:
                second_lock = engine.acquire_lock(
                    lock_path=str(lock_path),
                    max_attempts=1,
                    sleep_interval=0,
                )
                self.assertFalse(second_lock.acquired)
            finally:
                first_lock.release()

            third_lock = engine.acquire_lock(
                lock_path=str(lock_path),
                max_attempts=1,
                sleep_interval=0,
            )
            try:
                self.assertTrue(third_lock.acquired)
            finally:
                third_lock.release()

    def test_recovery_failure_blocks_shared_delete(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            source_file = source_root / "kept.txt"
            source_file.write_text("payload", encoding="utf-8")

            summary = engine.run(
                [str(source_file)],
                FakeBackend(provider=FakeRecoveryProvider(should_fail=True)),
                make_args(delete=True),
                str(source_root),
                lock_path=str(root / "engine.lock"),
            )

            self.assertEqual(summary.exit_code, 3)
            self.assertTrue(source_file.exists())
            self.assertFalse(summary.job_results[0].source_deleted)

    def test_inline_native_recovery_warning_maps_to_exit_code_three_and_blocks_delete(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            source_file = source_root / "native.txt"
            source_file.write_text("payload", encoding="utf-8")

            summary = engine.run(
                [str(source_file)],
                InlineRecoveryBackend("native recovery failed"),
                make_args(delete=True),
                str(source_root),
                lock_path=str(root / "engine.lock"),
            )

            self.assertEqual(summary.exit_code, 3)
            self.assertEqual(summary.hard_failure_count, 0)
            self.assertEqual(summary.warning_count, 1)
            self.assertEqual(
                summary.job_results[0].recovery_result.error_msg,
                "native recovery failed",
            )
            self.assertFalse(summary.job_results[0].source_deleted)
            self.assertTrue(source_file.exists())

    def test_run_normalizes_validation_failure_to_exit_code_one(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            source_file = source_root / "item.txt"
            source_file.write_text("payload", encoding="utf-8")

            summary = engine.run(
                [str(source_file)],
                RaisingValidateBackend(),
                make_args(),
                str(source_root),
                lock_path=str(root / "engine.lock"),
            )

            self.assertEqual(summary.exit_code, 1)
            self.assertEqual(summary.hard_failure_count, 1)
            self.assertEqual(summary.job_results, [])

    def test_run_normalizes_input_validation_failure_to_exit_code_one(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            missing_file = source_root / "missing.txt"

            summary = engine.run(
                [str(missing_file)],
                FakeBackend(),
                make_args(),
                str(source_root),
                lock_path=str(root / "engine.lock"),
            )

            self.assertEqual(summary.exit_code, 1)
            self.assertEqual(summary.hard_failure_count, 1)
            self.assertEqual(len(summary.job_results), 1)

    def test_run_normalizes_execute_failure_to_exit_code_one(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            source_file = source_root / "item.txt"
            source_file.write_text("payload", encoding="utf-8")

            summary = engine.run(
                [str(source_file)],
                RaisingExecuteBackend(),
                make_args(),
                str(source_root),
                lock_path=str(root / "engine.lock"),
            )

            self.assertEqual(summary.exit_code, 1)
            self.assertEqual(summary.hard_failure_count, 1)
            self.assertEqual(len(summary.job_results), 1)

    def test_run_treats_empty_archive_artifacts_as_hard_failure(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            source_file = source_root / "empty.txt"
            source_file.write_text("payload", encoding="utf-8")

            summary = engine.run(
                [str(source_file)],
                EmptyArchiveSuccessBackend(),
                make_args(delete=True),
                str(source_root),
                lock_path=str(root / "engine.lock"),
            )

            self.assertEqual(summary.exit_code, 1)
            self.assertEqual(summary.hard_failure_count, 1)
            self.assertEqual(summary.success_count, 0)
            self.assertFalse(summary.job_results[0].source_deleted)
            self.assertTrue(source_file.exists())

    def test_7z_dry_run_succeeds_without_delete_or_subprocess_execution(self):
        sevenzip = importlib.import_module("advArchiver.advArchiver.backends.sevenzip")
        backend = sevenzip.SevenZipBackend()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            source_file = source_root / "movie.mkv"
            source_file.write_text("payload", encoding="utf-8")

            with (
                mock.patch(
                    "advArchiver.advArchiver.backends.sevenzip.process.require_tool"
                ),
                mock.patch(
                    "advArchiver.advArchiver.backends.sevenzip.process.run_command",
                    return_value=mock.Mock(returncode=0, stdout="", stderr=""),
                ) as run_command,
            ):
                summary = engine.run(
                    [str(source_file)],
                    backend,
                    make_args(dry_run=True, delete=True),
                    str(source_root),
                    lock_path=str(root / "engine.lock"),
                )

            run_command.assert_not_called()
            self.assertEqual(summary.exit_code, 0)
            self.assertEqual(summary.hard_failure_count, 0)
            self.assertEqual(summary.success_count, 1)
            self.assertTrue(source_file.exists())
            self.assertFalse(summary.job_results[0].hard_failure)
            self.assertFalse(summary.job_results[0].source_deleted)
            self.assertEqual(summary.job_results[0].final_artifacts.archive_files, [])
            self.assertIn("-sdel", summary.job_results[0].archive_result.command)
