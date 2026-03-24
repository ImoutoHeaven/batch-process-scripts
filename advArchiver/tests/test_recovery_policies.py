import argparse
import importlib
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from advArchiver.advArchiver import models

engine = importlib.import_module("advArchiver.advArchiver.engine")
backend_base = importlib.import_module("advArchiver.advArchiver.backends.base")
parpar = importlib.import_module("advArchiver.advArchiver.recovery.parpar")
recovery_base = importlib.import_module("advArchiver.advArchiver.recovery.base")


def make_args(**overrides):
    defaults = {
        "debug": False,
        "delete": False,
        "dry_run": False,
        "lock_timeout": 1,
        "no_emb": False,
        "no_lock": True,
        "no_rec": False,
        "out": None,
        "password": None,
        "profile": "best",
        "rec_threads": 1,
        "threads": 1,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def backend_module():
    try:
        return importlib.import_module("advArchiver.advArchiver.backends.sevenzip")
    except ModuleNotFoundError:
        return None


def zip_backend_module():
    try:
        return importlib.import_module("advArchiver.advArchiver.backends.zip_backend")
    except ModuleNotFoundError:
        return None


def rar_backend_module():
    try:
        return importlib.import_module("advArchiver.advArchiver.backends.rar")
    except ModuleNotFoundError:
        return None


def execution_result_for(*archive_files):
    return models.BackendExecutionResult(
        archive_result=models.ArchiveExecutionResult(
            archive_files=list(archive_files),
            command="7z a",
        )
    )


class TestRecoveryProviderBase(unittest.TestCase):
    def test_default_provider_uses_recovery_executor(self):
        self.assertTrue(recovery_base.RecoveryProviderBase.uses_recovery_executor)

    def test_base_contract_raises_until_subclass_implements_it(self):
        provider = recovery_base.RecoveryProviderBase()

        with self.assertRaises(NotImplementedError):
            provider.check_required_tools(make_args())

        with self.assertRaises(NotImplementedError):
            provider.apply(None, [], make_args())


class TestParparProvider(unittest.TestCase):
    def test_external_mode_failure_cleans_up_partial_par2_files(self):
        provider = parpar.ParparRecoveryProvider(mode=parpar.EXTERNAL_MODE)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            first_archive = root / "first.arc"
            second_archive = root / "second.arc"
            first_archive.write_text("archive-one", encoding="utf-8")
            second_archive.write_text("archive-two", encoding="utf-8")

            calls = {"count": 0}

            def fake_run_command(command, debug=False):
                del debug
                calls["count"] += 1
                output_file = Path(command[command.index("-o") + 1])
                output_file.write_text(f"partial-{calls['count']}", encoding="utf-8")
                if calls["count"] == 1:
                    return mock.Mock(returncode=0, stdout="", stderr="")
                return mock.Mock(returncode=1, stdout="partial failure", stderr="")

            with mock.patch(
                "advArchiver.advArchiver.recovery.parpar.process.run_command",
                side_effect=fake_run_command,
            ):
                result = provider.apply(
                    None,
                    execution_result_for(str(first_archive), str(second_archive)),
                    make_args(),
                )

            self.assertFalse(result.succeeded)
            self.assertEqual(result.recovery_files, [])
            self.assertFalse((root / "first.arc.par2").exists())
            self.assertFalse((root / "second.arc.par2").exists())


class TestBackendBase(unittest.TestCase):
    def test_backend_base_methods_raise_until_subclass_implements_it(self):
        backend = backend_base.BackendBase()

        with self.assertRaises(NotImplementedError):
            backend.register_arguments(None)

        with self.assertRaises(NotImplementedError):
            backend.capabilities()

        with self.assertRaises(NotImplementedError):
            backend.validate_args(make_args())

        with self.assertRaises(NotImplementedError):
            backend.check_required_tools(make_args())

        with self.assertRaises(NotImplementedError):
            backend.build_job("item", make_args(), "/tmp")

        with self.assertRaises(NotImplementedError):
            backend.execute_job(None, make_args())

        with self.assertRaises(NotImplementedError):
            backend.select_recovery_provider(make_args(), [])


class TrackingRecoveryProvider(recovery_base.RecoveryProviderBase):
    def __init__(self, event_log, uses_recovery_executor=True, release_event=None):
        self.event_log = event_log
        self.uses_recovery_executor = uses_recovery_executor
        self.release_event = release_event
        self.active = 0
        self.max_active = 0
        self.active_lock = threading.Lock()
        self.barrier = threading.Barrier(2) if not uses_recovery_executor else None

    def check_required_tools(self, args):
        del args

    def apply(self, job, execution_result, args):
        del execution_result, args
        with self.active_lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)

        self.event_log.append(f"recover:start:{Path(job.item_path).name}")

        if self.release_event is not None:
            self.release_event.set()

        if self.barrier is not None:
            try:
                self.barrier.wait(timeout=1)
            except threading.BrokenBarrierError:
                pass
        else:
            time.sleep(0.05)

        recovery_file = Path(job.tmp_dir) / (Path(job.item_path).name + ".par2")
        recovery_file.write_text("recovery", encoding="utf-8")
        self.event_log.append(f"recover:finish:{Path(job.item_path).name}")

        with self.active_lock:
            self.active -= 1

        return models.RecoveryExecutionResult(recovery_files=[str(recovery_file)])


class TrackingBackend(backend_base.BackendBase):
    name = "tracking"

    def __init__(self, provider, event_log, release_event=None):
        self.provider = provider
        self.event_log = event_log
        self.release_event = release_event

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
        return models.ArchiveJob(
            backend_name=self.name,
            item_path=str(path),
            item_type="file",
            rel_path="",
            final_output_dir="",
        )

    def execute_job(self, job, args):
        del args
        name = Path(job.item_path).name
        self.event_log.append(f"archive:start:{name}")
        if self.release_event is not None and name == "b.txt":
            self.release_event.wait(timeout=1)
        archive_file = Path(job.tmp_dir) / (name + ".arc")
        archive_file.write_text("archive", encoding="utf-8")
        self.event_log.append(f"archive:finish:{name}")
        return models.BackendExecutionResult(
            archive_result=models.ArchiveExecutionResult(
                archive_files=[str(archive_file)],
                command="tracking archive",
            )
        )

    def select_recovery_provider(self, args, execution_result):
        del args, execution_result
        return self.provider


class TestRecoveryScheduling(unittest.TestCase):
    def test_external_recovery_honors_rec_threads_budget(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            items = []
            for name in ("a.txt", "b.txt", "c.txt"):
                path = source_root / name
                path.write_text(name, encoding="utf-8")
                items.append(str(path))

            event_log = []
            provider = TrackingRecoveryProvider(event_log, uses_recovery_executor=True)
            backend = TrackingBackend(provider, event_log)

            summary = engine.run(
                items,
                backend,
                make_args(threads=3, rec_threads=1),
                str(source_root),
                lock_path=str(root / "engine.lock"),
            )

            self.assertEqual(summary.exit_code, 0)
            self.assertEqual(summary.success_count, 3)
            self.assertEqual(provider.max_active, 1)

    def test_inline_recovery_does_not_consume_rec_threads(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            items = []
            for name in ("a.txt", "b.txt"):
                path = source_root / name
                path.write_text(name, encoding="utf-8")
                items.append(str(path))

            event_log = []
            provider = TrackingRecoveryProvider(event_log, uses_recovery_executor=False)
            backend = TrackingBackend(provider, event_log)

            summary = engine.run(
                items,
                backend,
                make_args(threads=2, rec_threads=1),
                str(source_root),
                lock_path=str(root / "engine.lock"),
            )

            self.assertEqual(summary.exit_code, 0)
            self.assertEqual(summary.success_count, 2)
            self.assertEqual(provider.max_active, 2)

    def test_job_can_enter_recovery_before_all_archive_jobs_finish(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            items = []
            for name in ("a.txt", "b.txt"):
                path = source_root / name
                path.write_text(name, encoding="utf-8")
                items.append(str(path))

            event_log = []
            recovery_started = threading.Event()
            provider = TrackingRecoveryProvider(
                event_log,
                uses_recovery_executor=True,
                release_event=recovery_started,
            )
            backend = TrackingBackend(
                provider, event_log, release_event=recovery_started
            )

            summary = engine.run(
                items,
                backend,
                make_args(threads=2, rec_threads=1),
                str(source_root),
                lock_path=str(root / "engine.lock"),
            )

            self.assertEqual(summary.exit_code, 0)
            self.assertLess(
                event_log.index("recover:start:a.txt"),
                event_log.index("archive:finish:b.txt"),
            )


class TestSevenZipRecoveryPolicy(unittest.TestCase):
    def test_7z_no_rec_disables_recovery(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.SevenZipBackend()

        provider = backend.select_recovery_provider(
            make_args(no_rec=True),
            execution_result_for("a.7z"),
        )

        self.assertIsNone(provider)

    def test_7z_split_recovery_stays_external(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.SevenZipBackend()

        provider = backend.select_recovery_provider(
            make_args(profile="best"),
            execution_result_for("a.7z.001", "a.7z.002"),
        )

        self.assertEqual(provider.mode, "external")

    def test_7z_no_emb_forces_external_recovery_for_single_archive(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.SevenZipBackend()

        provider = backend.select_recovery_provider(
            make_args(no_emb=True),
            execution_result_for("a.7z"),
        )

        self.assertEqual(provider.mode, "external")


class TestZipRecoveryPolicy(unittest.TestCase):
    def test_zip_default_recovery_is_external_parpar(self):
        module = zip_backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.ZipBackend()

        provider = backend.select_recovery_provider(
            make_args(),
            execution_result_for("a.zip"),
        )

        self.assertTrue(provider.uses_recovery_executor)
        self.assertEqual(provider.mode, "external")

    def test_zip_no_rec_disables_external_recovery(self):
        module = zip_backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.ZipBackend()

        provider = backend.select_recovery_provider(
            make_args(no_rec=True),
            execution_result_for("a.zip"),
        )

        self.assertIsNone(provider)


class TestRarRecoveryPolicy(unittest.TestCase):
    def test_rar_default_recovery_is_inline_native(self):
        module = rar_backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.RarBackend()

        provider = backend.select_recovery_provider(
            make_args(),
            execution_result_for("a.rar"),
        )

        self.assertFalse(provider.uses_recovery_executor)
        self.assertEqual(provider.__class__.__name__, "RarNativeRecoveryProvider")

    def test_rar_no_rec_disables_native_recovery(self):
        module = rar_backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.RarBackend()

        provider = backend.select_recovery_provider(
            make_args(no_rec=True),
            execution_result_for("a.rar"),
        )

        self.assertIsNone(provider)
