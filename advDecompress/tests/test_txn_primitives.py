import contextlib
import inspect
import hashlib
import io
import json
import os
import tempfile
import unittest
import importlib.util
import threading
import types
from concurrent.futures import Future, as_completed as futures_as_completed
from multiprocessing import Process, Pipe
from types import SimpleNamespace
from unittest import mock
import zipfile


def _load_advdecompress_module():
    here = os.path.dirname(__file__)
    script_path = os.path.abspath(os.path.join(here, "..", "advDecompress.py"))
    spec = importlib.util.spec_from_file_location("advDecompress_script", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    module.VERBOSE = False
    return module


class HashedFuture(Future):
    def __init__(self, name, forced_hash):
        super().__init__()
        self.name = name
        self._forced_hash = forced_hash

    def __hash__(self):
        return self._forced_hash


class TestTxnPrimitives(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = _load_advdecompress_module()

    def _make_processor_args(self, **overrides):
        args = {
            "verbose": False,
            "password": None,
            "password_file": None,
            "traditional_zip_policy": "decode-auto",
        }
        args.update(overrides)
        return SimpleNamespace(**args)

    def _make_processing_args(self, root_dir, **overrides):
        if "unsafe_windows_delete" in overrides:
            raise TypeError(
                "removed Windows delete flag overrides are not supported in test helpers"
            )
        args = {
            "verbose": False,
            "password": None,
            "password_file": None,
            "traditional_zip_policy": "decode-auto",
            "traditional_zip_to": None,
            "traditional_zip_decode_confidence": 90,
            "traditional_zip_decode_model": "chardet",
            "dry_run": False,
            "path": root_dir,
            "output": os.path.join(root_dir, "out"),
            "fail_policy": "asis",
            "fail_to": None,
            "success_policy": "asis",
            "success_to": None,
            "zip_decode": None,
            "enable_rar": False,
            "detect_elf_sfx": False,
            "threads": 1,
            "decompress_policy": "direct",
            "degrade_cross_volume": False,
            "conflict_mode": "fail",
            "depth_range": None,
            "skip_7z": False,
            "skip_rar": False,
            "skip_zip": False,
            "skip_exe": False,
            "skip_tar": False,
            "skip_7z_multi": False,
            "skip_rar_multi": False,
            "skip_zip_multi": False,
            "skip_exe_multi": False,
            "fix_ext": False,
            "safe_fix_ext": False,
            "fix_extension_threshold": "10mb",
            "lock_timeout": 30,
            "wal_fsync_every": 1,
            "snapshot_every": 1,
            "fsync_files": "auto",
            "output_lock_timeout_ms": 1000,
            "output_lock_retry_ms": 10,
            "keep_journal_days": 7,
            "success_clean_journal": False,
            "fail_clean_journal": False,
            "legacy": False,
            "no_lock": False,
            "no_durability": False,
        }
        args.update(overrides)
        return SimpleNamespace(**args)

    def _argv_for_main(self, args):
        argv = ["advDecompress.py", args.path, "--no-lock"]

        if args.output:
            argv.extend(["-o", args.output])

        argv.extend(
            [
                "-t",
                str(args.threads),
                "-dp",
                args.decompress_policy,
                "-sp",
                args.success_policy,
                "-fp",
                args.fail_policy,
                "--traditional-zip-policy",
                args.traditional_zip_policy,
                "--traditional-zip-decode-confidence",
                str(args.traditional_zip_decode_confidence),
                "--traditional-zip-decode-model",
                args.traditional_zip_decode_model,
                "--conflict-mode",
                args.conflict_mode,
                "--lock-timeout",
                str(args.lock_timeout),
                "--output-lock-timeout-ms",
                str(args.output_lock_timeout_ms),
                "--output-lock-retry-ms",
                str(args.output_lock_retry_ms),
                "--keep-journal-days",
                str(args.keep_journal_days),
                "--fsync-files",
                args.fsync_files,
                "--fix-extension-threshold",
                str(args.fix_extension_threshold),
            ]
        )

        if args.depth_range:
            argv.extend(["--depth-range", args.depth_range])
        if args.success_to:
            argv.extend(["--success-to", args.success_to])
        if args.fail_to:
            argv.extend(["--fail-to", args.fail_to])
        if args.traditional_zip_to:
            argv.extend(["--traditional-zip-to", args.traditional_zip_to])

        if getattr(args, "success_clean_journal", True) is False:
            argv.extend(["--success-clean-journal", "false"])
        if getattr(args, "fail_clean_journal", True) is False:
            argv.extend(["--fail-clean-journal", "false"])

        bool_flags = [
            ("dry_run", "--dry-run"),
            ("verbose", "-v"),
            ("enable_rar", "--enable-rar"),
            ("detect_elf_sfx", "--detect-elf-sfx"),
            ("degrade_cross_volume", "--degrade-cross-volume"),
            ("no_durability", "--no-durability"),
            ("fix_ext", "--fix-ext"),
            ("safe_fix_ext", "--safe-fix-ext"),
            ("skip_7z", "--skip-7z"),
            ("skip_rar", "--skip-rar"),
            ("skip_zip", "--skip-zip"),
            ("skip_exe", "--skip-exe"),
            ("skip_tar", "--skip-tar"),
            ("skip_7z_multi", "--skip-7z-multi"),
            ("skip_rar_multi", "--skip-rar-multi"),
            ("skip_zip_multi", "--skip-zip-multi"),
            ("skip_exe_multi", "--skip-exe-multi"),
        ]
        for attr, flag in bool_flags:
            if getattr(args, attr, False):
                argv.append(flag)

        if getattr(args, "legacy", False):
            argv.append("--legacy")

        return argv

    def _make_manifest_command_fingerprint(self, input_root, output_root):
        return {
            "version": 1,
            "sha256": "fingerprint-sha256",
            "fields": {
                "path": os.path.abspath(input_root),
                "output": os.path.abspath(output_root),
                "decompress_policy": "direct",
                "success_policy": "asis",
                "fail_policy": "asis",
            },
        }

    def _make_discovered_archives(self, input_root, output_root, rel_paths):
        discovered = []
        for rel_path in rel_paths:
            archive_path = os.path.join(input_root, rel_path)
            os.makedirs(os.path.dirname(archive_path), exist_ok=True)
            with open(archive_path, "wb") as f:
                f.write(rel_path.encode("utf-8"))

            rel_dir = os.path.dirname(rel_path)
            output_dir = os.path.join(output_root, rel_dir) if rel_dir else output_root
            discovered.append(
                {
                    "archive_path": archive_path,
                    "output_dir": output_dir,
                    "volumes": [archive_path],
                    "requested_policy": "direct",
                }
            )
        return discovered

    def _make_txn_result(self, archive_path, *, output_dir, output_base):
        name = os.path.basename(archive_path)
        return {
            "kind": "txn",
            "txn": {
                "archive_path": archive_path,
                "output_dir": output_dir,
                "state": self.m.TXN_STATE_EXTRACTED,
                "txn_id": name.replace(".", "_"),
                "paths": {"work_root": os.path.join(output_base, "work", name)},
            },
        }

    def _make_txn(self, archive_path, *, output_dir, output_base, work_root=None):
        txn = self._make_txn_result(
            archive_path,
            output_dir=output_dir,
            output_base=output_base,
        )["txn"]
        if work_root is not None:
            txn["paths"]["work_root"] = work_root
        return txn

    def _make_single_archive_manifest_fixture(
        self, td, *, rel_path="alpha.zip", manifest_state="pending"
    ):
        input_root = os.path.join(td, "input")
        output_root = os.path.join(td, "output")
        os.makedirs(input_root)
        os.makedirs(output_root)

        discovered = self._make_discovered_archives(
            input_root,
            output_root,
            [rel_path],
        )
        args = self._make_processing_args(
            input_root,
            output=output_root,
            decompress_policy="direct",
            threads=1,
            success_clean_journal=False,
            fail_clean_journal=False,
        )
        manifest = self.m._create_dataset_manifest(
            input_root=input_root,
            output_root=output_root,
            discovered_archives=discovered,
            command_fingerprint=self.m._build_command_fingerprint(args),
        )
        archive = discovered[0]
        archive_id = self.m._dataset_manifest_archive_id(archive["archive_path"])
        manifest["archives"][archive_id]["state"] = manifest_state
        self.m._save_dataset_manifest(manifest)
        return {
            "args": args,
            "input_root": input_root,
            "output_root": output_root,
            "archive": archive,
            "archive_id": archive_id,
        }

    def _make_aborted_manifest_txn_fixture(
        self, td, *, rel_path="alpha.zip", manifest_state="pending"
    ):
        fixture = self._make_single_archive_manifest_fixture(
            td,
            rel_path=rel_path,
            manifest_state=manifest_state,
        )
        archive = fixture["archive"]
        txn = self.m._txn_create(
            archive_path=archive["archive_path"],
            volumes=archive["volumes"],
            output_dir=archive["output_dir"],
            output_base=fixture["output_root"],
            policy="direct",
            wal_fsync_every=1,
            snapshot_every=1,
            durability_enabled=False,
        )
        self.m._txn_abort(txn, "ABORTED", "interrupted")
        self.m._update_dataset_manifest_archive(
            fixture["output_root"],
            archive["archive_path"],
            state=manifest_state,
            last_txn_id=txn["txn_id"],
            error=txn.get("error"),
        )
        fixture["txn"] = txn
        return fixture

    def _make_delete_barrier_txn_fixture(self, td):
        input_root = os.path.join(td, "input")
        output_root = os.path.join(td, "output")
        output_dir = os.path.join(output_root, "placed")
        os.makedirs(input_root)
        os.makedirs(output_root)

        archive_path = os.path.join(input_root, "alpha.zip")
        with open(archive_path, "wb") as f:
            f.write(b"archive")

        args = self._make_processing_args(
            input_root,
            output=output_root,
            decompress_policy="only-file-content-direct",
            success_policy="delete",
            no_durability=False,
            fsync_files="auto",
        )
        self.m._create_dataset_manifest(
            input_root=input_root,
            output_root=output_root,
            discovered_archives=[
                {
                    "archive_path": archive_path,
                    "output_dir": output_dir,
                    "volumes": [archive_path],
                    "requested_policy": args.decompress_policy,
                }
            ],
            command_fingerprint=self.m._build_command_fingerprint(args),
        )
        txn = self.m._txn_create(
            archive_path=archive_path,
            volumes=[archive_path],
            output_dir=output_dir,
            output_base=output_root,
            policy=args.decompress_policy,
            wal_fsync_every=1,
            snapshot_every=1,
            durability_enabled=True,
        )

        file_content_root = os.path.join(txn["paths"]["incoming_dir"], "tree")
        nested_dir = os.path.join(file_content_root, "a", "b")
        os.makedirs(nested_dir, exist_ok=True)
        with open(
            os.path.join(file_content_root, "root.txt"), "w", encoding="utf-8"
        ) as f:
            f.write("root")
        with open(os.path.join(nested_dir, "payload.txt"), "w", encoding="utf-8") as f:
            f.write("payload")

        txn["state"] = self.m.TXN_STATE_INCOMING_COMMITTED
        self.m._txn_snapshot(txn)

        return {
            "args": args,
            "txn": txn,
            "archive_path": archive_path,
            "output_dir": output_dir,
            "output_root": output_root,
            "expected_payload_files": [
                os.path.join(output_dir, "root.txt"),
                os.path.join(output_dir, "a", "b", "payload.txt"),
            ],
            "expected_payload_dirs": [
                os.path.join(output_dir, "a", "b"),
                os.path.join(output_dir, "a"),
                output_dir,
            ],
        }

    def _make_success_finalization_txn_fixture(self, td, *, success_policy="delete"):
        input_root = os.path.join(td, "input")
        output_root = os.path.join(td, "output")
        output_dir = os.path.join(output_root, "placed")
        os.makedirs(input_root)
        os.makedirs(output_root)

        archive_path = os.path.join(input_root, f"alpha-{success_policy}.zip")
        with open(archive_path, "wb") as f:
            f.write(b"archive")

        success_to = None
        if success_policy == "move":
            success_to = os.path.join(td, "success-dest")

        args = self._make_processing_args(
            input_root,
            output=output_root,
            decompress_policy="only-file-content-direct",
            success_policy=success_policy,
            success_to=success_to,
            no_durability=False,
            fsync_files="auto",
            success_clean_journal=False,
            fail_clean_journal=False,
        )
        self.m._create_dataset_manifest(
            input_root=input_root,
            output_root=output_root,
            discovered_archives=[
                {
                    "archive_path": archive_path,
                    "output_dir": output_dir,
                    "volumes": [archive_path],
                    "requested_policy": args.decompress_policy,
                }
            ],
            command_fingerprint=self.m._build_command_fingerprint(args),
        )
        txn = self.m._txn_create(
            archive_path=archive_path,
            volumes=[archive_path],
            output_dir=output_dir,
            output_base=output_root,
            policy=args.decompress_policy,
            wal_fsync_every=1,
            snapshot_every=1,
            durability_enabled=True,
        )

        file_content_root = os.path.join(txn["paths"]["incoming_dir"], "tree")
        nested_dir = os.path.join(file_content_root, "a", "b")
        os.makedirs(nested_dir, exist_ok=True)
        with open(
            os.path.join(file_content_root, "root.txt"), "w", encoding="utf-8"
        ) as f:
            f.write("root")
        with open(os.path.join(nested_dir, "payload.txt"), "w", encoding="utf-8") as f:
            f.write("payload")

        txn["state"] = self.m.TXN_STATE_INCOMING_COMMITTED
        self.m._txn_snapshot(txn)

        return {
            "args": args,
            "txn": txn,
            "archive_path": archive_path,
            "archive_id": self.m._dataset_manifest_archive_id(archive_path),
            "output_dir": output_dir,
            "output_root": output_root,
        }

    def _make_empty_dir_barrier_txn_fixture(self, td):
        input_root = os.path.join(td, "input")
        output_root = os.path.join(td, "output")
        output_dir = os.path.join(output_root, "placed")
        os.makedirs(input_root)
        os.makedirs(output_root)

        archive_path = os.path.join(input_root, "empty.zip")
        with open(archive_path, "wb") as f:
            f.write(b"archive")

        args = self._make_processing_args(
            input_root,
            output=output_root,
            decompress_policy="only-file-content-direct",
            success_policy="delete",
            no_durability=False,
            fsync_files="auto",
        )
        self.m._create_dataset_manifest(
            input_root=input_root,
            output_root=output_root,
            discovered_archives=[
                {
                    "archive_path": archive_path,
                    "output_dir": output_dir,
                    "volumes": [archive_path],
                    "requested_policy": args.decompress_policy,
                }
            ],
            command_fingerprint=self.m._build_command_fingerprint(args),
        )
        txn = self.m._txn_create(
            archive_path=archive_path,
            volumes=[archive_path],
            output_dir=output_dir,
            output_base=output_root,
            policy=args.decompress_policy,
            wal_fsync_every=1,
            snapshot_every=1,
            durability_enabled=True,
        )

        file_content_root = os.path.join(txn["paths"]["incoming_dir"], "tree")
        empty_leaf_dir = os.path.join(file_content_root, "empty-parent", "empty-leaf")
        os.makedirs(empty_leaf_dir, exist_ok=True)
        with open(
            os.path.join(file_content_root, "root.txt"), "w", encoding="utf-8"
        ) as f:
            f.write("root")

        txn["state"] = self.m.TXN_STATE_INCOMING_COMMITTED
        self.m._txn_snapshot(txn)

        return {
            "args": args,
            "txn": txn,
            "archive_path": archive_path,
            "output_dir": output_dir,
            "output_root": output_root,
            "expected_empty_dirs": [
                os.path.join(output_dir, "empty-parent", "empty-leaf"),
                os.path.join(output_dir, "empty-parent"),
                output_dir,
            ],
        }

    def _make_transactional_processor_stub(self):
        return types.SimpleNamespace(
            sfx_detector=None,
            get_all_volumes=lambda path: [os.path.abspath(path)],
            successful_archives=[],
            failed_archives=[],
            skipped_archives=[],
        )

    def _assert_windows_transactional_delete_barrier_failure(
        self,
        fixture,
        *,
        fsync_file_side_effect,
        expected_error_text,
    ):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        archive_path = os.path.abspath(fixture["archive_path"])
        archive_id = self.m._dataset_manifest_archive_id(archive_path)
        with (
            mock.patch.object(self.m.os, "name", "nt"),
            mock.patch.object(self.m, "FileLock", DummyLock),
            mock.patch.object(
                self.m, "_fsync_file", side_effect=fsync_file_side_effect
            ),
            mock.patch.object(self.m, "_fsync_dir", return_value=True),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

        self.assertIn(expected_error_text, str(ctx.exception))
        self.assertTrue(os.path.exists(archive_path))
        with open(fixture["txn"]["paths"]["txn_json"], "r", encoding="utf-8") as f:
            saved_txn = json.load(f)
        manifest = self.m._load_dataset_manifest(fixture["output_root"])
        manifest_entry = manifest["archives"][archive_id]
        self.assertEqual(self.m.TXN_STATE_ABORTED, saved_txn["state"])
        self.assertEqual("DURABILITY_FAILED", saved_txn["error"]["type"])
        self.assertEqual("recoverable", manifest_entry["state"])
        self.assertEqual("unknown", manifest_entry["final_disposition"])
        self.assertIsNone(manifest_entry["finalized_at"])

    def _age_txn_journal(self, txn, *, timestamp=1):
        os.utime(txn["paths"]["journal_dir"], (timestamp, timestamp))
        os.utime(txn["paths"]["txn_json"], (timestamp, timestamp))
        wal_path = txn["paths"].get("wal")
        if wal_path and os.path.exists(wal_path):
            os.utime(wal_path, (timestamp, timestamp))

    def _assert_resume_drift_rejected(self, fixture, *, mutate_archive, expected_text):
        archive_path = os.path.abspath(fixture["archive"]["archive_path"])
        manifest_path = self.m._dataset_manifest_path(fixture["output_root"])
        with open(manifest_path, "rb") as f:
            manifest_before = f.read()

        mutate_archive(archive_path)

        processor = types.SimpleNamespace(
            successful_archives=[],
            failed_archives=[],
            skipped_archives=[],
        )
        stdout = io.StringIO()

        with (
            contextlib.redirect_stdout(stdout),
            mock.patch.object(
                self.m,
                "_recover_all_outputs",
                side_effect=AssertionError(
                    "recovery should not start before strict resume drift validation"
                ),
            ),
            mock.patch.object(
                self.m,
                "_extract_phase",
                side_effect=AssertionError(
                    "extract should not start before strict resume drift validation"
                ),
            ),
        ):
            result = self.m._run_transactional(
                processor,
                [archive_path],
                args=fixture["args"],
            )

        output = stdout.getvalue()
        self.assertFalse(result)
        self.assertIn(archive_path, output)
        self.assertIn(expected_text, output.lower())
        self.assertIn(
            os.path.join(fixture["output_root"], ".advdecompress_work"), output
        )
        self.assertIn("delete", output.lower())
        self.assertEqual([], processor.successful_archives)
        self.assertEqual([], processor.failed_archives)
        self.assertEqual([], processor.skipped_archives)

        with open(manifest_path, "rb") as f:
            self.assertEqual(manifest_before, f.read())

    def _assert_resume_manifest_rejected(
        self, fixture, *, mutate_manifest, expected_text
    ):
        manifest_path = self.m._dataset_manifest_path(fixture["output_root"])
        manifest = self.m._load_dataset_manifest(fixture["output_root"])
        mutate_manifest(manifest["archives"][fixture["archive_id"]])
        self.m._save_dataset_manifest(manifest)

        with open(manifest_path, "rb") as f:
            manifest_before = f.read()

        processor = types.SimpleNamespace(
            successful_archives=[],
            failed_archives=[],
            skipped_archives=[],
        )
        stdout = io.StringIO()

        with (
            contextlib.redirect_stdout(stdout),
            mock.patch.object(
                self.m,
                "_recover_all_outputs",
                side_effect=AssertionError(
                    "recovery should not start before strict resume manifest validation"
                ),
            ),
            mock.patch.object(
                self.m,
                "_extract_phase",
                side_effect=AssertionError(
                    "extract should not start before strict resume manifest validation"
                ),
            ),
        ):
            result = self.m._run_transactional(
                processor,
                [fixture["archive"]["archive_path"]],
                args=fixture["args"],
            )

        output = stdout.getvalue()
        self.assertFalse(result)
        self.assertIn(fixture["archive"]["archive_path"], output)
        self.assertIn(expected_text, output.lower())
        self.assertIn(
            os.path.join(fixture["output_root"], ".advdecompress_work"), output
        )
        self.assertIn("delete", output.lower())
        self.assertEqual([], processor.successful_archives)
        self.assertEqual([], processor.failed_archives)
        self.assertEqual([], processor.skipped_archives)

        with open(manifest_path, "rb") as f:
            self.assertEqual(manifest_before, f.read())

    def _create_startup_rejection_txn(self, fixture):
        txn = self.m._txn_create(
            archive_path=fixture["archive"]["archive_path"],
            volumes=fixture["archive"]["volumes"],
            output_dir=fixture["archive"]["output_dir"],
            output_base=fixture["output_root"],
            policy=fixture["args"].decompress_policy,
            wal_fsync_every=1,
            snapshot_every=1,
            durability_enabled=False,
        )
        txn["state"] = self.m.TXN_STATE_EXTRACTED
        self.m._txn_snapshot(txn)
        return txn

    def _assert_startup_manifest_file_rejected(
        self,
        fixture,
        *,
        manifest_bytes,
        expected_text,
        via_main=False,
        expect_manifest_path_text=False,
    ):
        txn = self._create_startup_rejection_txn(fixture)
        manifest_path = self.m._dataset_manifest_path(fixture["output_root"])
        with open(manifest_path, "wb") as f:
            f.write(manifest_bytes)

        with open(manifest_path, "rb") as f:
            manifest_before = f.read()
        txn_json_path = txn["paths"]["txn_json"]
        with open(txn_json_path, "rb") as f:
            txn_before = f.read()

        stdout = io.StringIO()

        if via_main:
            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(
                    self.m.sys, "argv", self._argv_for_main(fixture["args"])
                ),
                mock.patch.object(
                    self.m,
                    "safe_subprocess_run",
                    return_value=SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
                ),
                mock.patch.object(self.m, "fix_archive_ext") as fix_archive_ext,
                mock.patch.object(
                    self.m,
                    "ArchiveProcessor",
                    side_effect=AssertionError(
                        "ArchiveProcessor should not be constructed for invalid startup manifest"
                    ),
                ),
            ):
                exit_code = self.m.main()

            self.assertEqual(1, exit_code)
            fix_archive_ext.assert_not_called()
        else:
            processor = types.SimpleNamespace(
                successful_archives=[],
                failed_archives=[],
                skipped_archives=[],
            )
            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(
                    self.m,
                    "_recover_all_outputs",
                    side_effect=AssertionError(
                        "recovery should not start before invalid startup manifest rejection"
                    ),
                ),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "extract should not start before invalid startup manifest rejection"
                    ),
                ),
            ):
                result = self.m._run_transactional(
                    processor,
                    [fixture["archive"]["archive_path"]],
                    args=fixture["args"],
                )

            self.assertFalse(result)
            self.assertEqual([], processor.successful_archives)
            self.assertEqual([], processor.failed_archives)
            self.assertEqual([], processor.skipped_archives)

        output = stdout.getvalue()
        if expect_manifest_path_text:
            self.assertIn("dataset_manifest.json", output)
        self.assertIn(expected_text, output.lower())
        self.assertIn(
            os.path.join(fixture["output_root"], ".advdecompress_work"), output
        )
        self.assertIn("delete", output.lower())

        with open(manifest_path, "rb") as f:
            self.assertEqual(manifest_before, f.read())
        with open(txn_json_path, "rb") as f:
            self.assertEqual(txn_before, f.read())

    def _make_async_executor_class(
        self, *, submitted=None, future_hashes=None, event_log=None, tracker=None
    ):
        submitted = submitted if submitted is not None else []
        future_hashes = future_hashes or {}

        class FakeExecutor:
            def __init__(self, max_workers):
                self.max_workers = max_workers
                self._threads = []
                self._slots = threading.Semaphore(max_workers)

            def submit(self, fn, processor, archive_path, *, args, output_base):
                name = os.path.basename(archive_path)
                submitted.append(name)
                if event_log is not None:
                    event_log.append(f"submit:{name}")
                if tracker is not None:
                    tracker["outstanding"] += 1
                    tracker["max_outstanding"] = max(
                        tracker["max_outstanding"], tracker["outstanding"]
                    )
                future = HashedFuture(
                    name, future_hashes.get(name, 1000 + len(submitted))
                )

                def runner():
                    self._slots.acquire()
                    try:
                        result = fn(
                            processor, archive_path, args=args, output_base=output_base
                        )
                    except BaseException as exc:
                        future.set_exception(exc)
                    else:
                        future.set_result(result)
                    finally:
                        if tracker is not None:
                            tracker["outstanding"] -= 1
                        self._slots.release()

                thread = threading.Thread(target=runner, name=f"fake-extract-{name}")
                thread.start()
                self._threads.append(thread)
                return future

            def shutdown(self, wait=True):
                if not wait:
                    return None
                for thread in self._threads:
                    thread.join(timeout=5)
                return None

        return FakeExecutor

    def _pick_done_future_reorder_hashes(self):
        for hash_b in range(32):
            for hash_c in range(32):
                if hash_b == hash_c:
                    continue
                future_b = HashedFuture("b.zip", hash_b)
                future_c = HashedFuture("c.zip", hash_c)
                future_b.set_result("b")
                future_c.set_result("c")
                order = [
                    future.name for future in futures_as_completed([future_b, future_c])
                ]
                if order == ["c.zip", "b.zip"]:
                    return {"b.zip": hash_b, "c.zip": hash_c}
        self.fail("Could not reproduce done-future reordering")

    def _windows_binary_flag(self):
        return getattr(self.m.os, "O_BINARY", 0)

    @contextlib.contextmanager
    def _mock_windows_short_path_destination_bug(self, *, remove_after_existing_hits=1):
        alias_names = {
            "txn.json": "TXN~1.JSO",
            "dataset_manifest.json": "DATASE~1.JSO",
        }
        existing_hits = {}

        def fake_short_path_name(path):
            abs_path = os.path.abspath(os.path.expandvars(path))
            alias_name = alias_names.get(os.path.basename(abs_path).lower())
            if alias_name is None:
                return abs_path
            if not os.path.exists(abs_path):
                return abs_path

            existing_hits[abs_path] = existing_hits.get(abs_path, 0) + 1
            if existing_hits[abs_path] < remove_after_existing_hits:
                return abs_path

            os.remove(abs_path)
            return os.path.join(os.path.dirname(abs_path), alias_name)

        with (
            mock.patch.object(self.m.os, "name", "nt"),
            mock.patch.object(self.m, "is_windows", return_value=True),
            mock.patch.object(
                self.m, "get_short_path_name", side_effect=fake_short_path_name
            ),
        ):
            yield

    def test_atomic_write_json(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "txn.json")
            data = {"a": 1, "b": {"c": "x"}}
            self.m.atomic_write_json(path, data, debug=False)
            with open(path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            self.assertEqual(loaded, data)
            self.assertFalse(os.path.exists(path + ".tmp"))

    def test_atomic_write_json_repeated_writes_preserve_long_filename(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "txn.json")

            with self._mock_windows_short_path_destination_bug(
                remove_after_existing_hits=2
            ):
                self.m.atomic_write_json(path, {"round": 1}, debug=False)
                self.m.atomic_write_json(path, {"round": 2}, debug=False)
                self.m.atomic_write_json(path, {"round": 3}, debug=False)

            self.assertTrue(os.path.exists(path))
            self.assertFalse(os.path.exists(path + ".tmp"))

            entries = sorted(os.listdir(td))
            self.assertEqual(["txn.json"], entries)
            self.assertEqual(
                [],
                [name for name in entries if name.upper().startswith("TXN~")],
            )

            with open(path, "r", encoding="utf-8") as f:
                self.assertEqual({"round": 3}, json.load(f))

    def test_patch_cmd_paths_uses_external_path_normalization_only(self):
        with tempfile.TemporaryDirectory() as td:
            archive_path = os.path.join(td, "archive.zip")
            output_dir = os.path.join(td, "out")
            with open(archive_path, "wb") as f:
                f.write(b"zip")
            os.makedirs(output_dir)

            with (
                mock.patch.object(
                    self.m,
                    "normalize_external_cmd_path",
                    side_effect=lambda path, debug=False: path + ".external",
                    create=True,
                ) as external_norm,
                mock.patch.object(
                    self.m,
                    "normalize_local_fs_path",
                    side_effect=lambda path, debug=False: path + ".local",
                    create=True,
                ) as local_norm,
            ):
                patched = self.m._patch_cmd_paths(
                    ["7z", "x", archive_path, f"-o{output_dir}"]
                )

            self.assertEqual(
                [
                    "7z",
                    "x",
                    archive_path + ".external",
                    f"-o{output_dir}.external",
                ],
                patched,
            )
            self.assertEqual(2, external_norm.call_count)
            self.assertEqual(0, local_norm.call_count)

    def test_local_filesystem_helpers_do_not_use_external_path_normalization(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "txn.json")

            with (
                mock.patch.object(
                    self.m,
                    "normalize_external_cmd_path",
                    side_effect=AssertionError(
                        "local filesystem helpers must not use external path normalization"
                    ),
                    create=True,
                ),
                mock.patch.object(
                    self.m,
                    "normalize_local_fs_path",
                    side_effect=lambda value, debug=False: value,
                    create=True,
                ) as local_norm,
            ):
                self.m.atomic_write_json(path, {"round": 1}, debug=False)
                self.assertTrue(self.m.safe_exists(path, debug=False))

            self.assertGreaterEqual(local_norm.call_count, 2)

    def test_is_password_correct_header_encryption_routes_7z_list_archive_only(self):
        with tempfile.TemporaryDirectory() as td:
            archive_path = os.path.join(td, "archive.zip")
            with open(archive_path, "wb") as f:
                f.write(b"zip")

            captured_cmds = []

            def fake_run(cmd, **kwargs):
                captured_cmds.append(cmd)
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with (
                mock.patch.object(
                    self.m,
                    "normalize_external_cmd_path",
                    side_effect=lambda path, debug=False: path + ".external",
                    create=True,
                ) as external_norm,
                mock.patch.object(
                    self.m,
                    "normalize_local_fs_path",
                    side_effect=AssertionError(
                        "password probe must not use local filesystem normalization"
                    ),
                    create=True,
                ),
                mock.patch.object(self.m, "safe_subprocess_run", side_effect=fake_run),
            ):
                ok = self.m.is_password_correct(
                    archive_path,
                    "secret",
                    encryption_status="encrypted_header",
                )
                patched = self.m._patch_cmd_paths(captured_cmds[0])

            self.assertTrue(ok)
            self.assertEqual(
                [["7z", "l", "-slt", archive_path, "-psecret", "-y"]],
                captured_cmds,
            )
            self.assertEqual(
                ["7z", "l", "-slt", archive_path + ".external", "-psecret", "-y"],
                patched,
            )
            self.assertEqual(1, external_norm.call_count)

    def test_try_extract_builds_raw_commands_before_safe_subprocess_run(self):
        with tempfile.TemporaryDirectory() as td:
            archive_path = os.path.join(td, "archive.zip")
            with open(archive_path, "wb") as f:
                f.write(b"zip")
            tmp_dir = os.path.join(td, "tmp")

            seven_zip_calls = []
            rar_calls = []

            def fake_7z_run(cmd, **kwargs):
                seven_zip_calls.append(cmd)
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            def fake_rar_run(cmd, **kwargs):
                rar_calls.append(cmd)
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            with mock.patch.object(
                self.m, "safe_subprocess_run", side_effect=fake_7z_run
            ):
                ok_7z = self.m.try_extract(archive_path, None, tmp_dir)

            with (
                mock.patch.object(
                    self.m, "should_use_rar_extractor", return_value=True
                ),
                mock.patch.object(
                    self.m, "safe_subprocess_run", side_effect=fake_rar_run
                ),
            ):
                ok_rar = self.m.try_extract(
                    archive_path, None, tmp_dir, enable_rar=True
                )

            self.assertTrue(ok_7z)
            self.assertTrue(ok_rar)
            self.assertEqual(
                [["7z", "x", archive_path, f"-o{tmp_dir}", "-y", "-pDUMMYPASSWORD"]],
                seven_zip_calls,
            )
            self.assertEqual(
                [["rar", "x", archive_path, tmp_dir, "-pDUMMYPASSWORD", "-y"]],
                rar_calls,
            )

    def test_dataset_manifest_archive_entry_uses_safe_path_for_stat(self):
        with tempfile.TemporaryDirectory() as td:
            archive_path = os.path.join(td, "nested", "alpha.zip")
            output_dir = os.path.join(td, "output")
            os.makedirs(os.path.dirname(archive_path), exist_ok=True)
            os.makedirs(output_dir, exist_ok=True)
            with open(archive_path, "wb") as f:
                f.write(b"alpha")

            archive_path_abs = os.path.abspath(archive_path)
            real_stat = os.stat(archive_path_abs)
            safe_archive_path = archive_path_abs + ".safe"
            discovered_archive = {
                "archive_path": archive_path,
                "output_dir": output_dir,
                "volumes": [archive_path],
                "requested_policy": "direct",
            }

            def fake_safe_path(path, debug=False):
                if path == archive_path_abs:
                    return safe_archive_path
                return path

            def fake_stat(path, *args, **kwargs):
                if path == archive_path_abs:
                    raise AssertionError("raw archive path stat should not be used")
                if path == safe_archive_path:
                    return real_stat
                return os.stat(path, *args, **kwargs)

            with (
                mock.patch.object(
                    self.m, "normalize_local_fs_path", side_effect=fake_safe_path
                ),
                mock.patch.object(self.m.os, "stat", side_effect=fake_stat),
            ):
                entry = self.m._build_dataset_manifest_archive_entry(
                    discovered_archive, 1
                )

            self.assertEqual(real_stat.st_size, entry["identity"]["size"])
            self.assertEqual(real_stat.st_mtime_ns, entry["identity"]["mtime_ns"])

    def test_dataset_manifest_create(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                ["alpha.zip", os.path.join("nested", "beta.zip")],
            )
            fingerprint = self._make_manifest_command_fingerprint(
                input_root, output_root
            )

            manifest = self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=discovered,
                command_fingerprint=fingerprint,
            )

            manifest_path = self.m._dataset_manifest_path(output_root)
            self.assertTrue(os.path.exists(manifest_path))
            self.assertFalse(os.path.exists(manifest_path + ".tmp"))

            saved = self.m._load_dataset_manifest(output_root)

            self.assertEqual(saved, manifest)
            self.assertEqual(1, saved["manifest_version"])
            self.assertTrue(saved["run_id"])
            self.assertEqual("active", saved["status"])
            self.assertEqual(os.path.abspath(input_root), saved["input_root"])
            self.assertEqual(os.path.abspath(output_root), saved["output_root"])
            self.assertEqual(fingerprint, saved["command_fingerprint"])
            self.assertEqual(
                {
                    "pending": 2,
                    "extracting": 0,
                    "recoverable": 0,
                    "retryable": 0,
                    "succeeded": 0,
                    "failed": 0,
                },
                saved["progress"]["counts"],
            )

            expected_ids = [
                self.m._dataset_manifest_archive_id(item["archive_path"])
                for item in discovered
            ]
            self.assertCountEqual(expected_ids, saved["archives"].keys())
            self.assertEqual(1, saved["archives"][expected_ids[0]]["discovered_order"])
            self.assertEqual(2, saved["archives"][expected_ids[1]]["discovered_order"])
            self.assertEqual(
                [os.path.abspath(discovered[0]["archive_path"])],
                saved["archives"][expected_ids[0]]["volumes"],
            )
            self.assertEqual(
                os.path.abspath(discovered[1]["output_dir"]),
                saved["archives"][expected_ids[1]]["output_dir"],
            )
            alpha_stat = os.stat(os.path.abspath(discovered[0]["archive_path"]))
            beta_stat = os.stat(os.path.abspath(discovered[1]["archive_path"]))
            self.assertEqual(
                alpha_stat.st_size,
                saved["archives"][expected_ids[0]]["identity"]["size"],
            )
            self.assertEqual(
                alpha_stat.st_mtime_ns,
                saved["archives"][expected_ids[0]]["identity"]["mtime_ns"],
            )
            self.assertEqual(
                beta_stat.st_size,
                saved["archives"][expected_ids[1]]["identity"]["size"],
            )
            self.assertEqual(
                beta_stat.st_mtime_ns,
                saved["archives"][expected_ids[1]]["identity"]["mtime_ns"],
            )

    def test_dataset_manifest_repeated_saves_preserve_long_filename(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                ["alpha.zip"],
            )
            fingerprint = self._make_manifest_command_fingerprint(
                input_root,
                output_root,
            )

            with self._mock_windows_short_path_destination_bug(
                remove_after_existing_hits=2
            ):
                manifest = self.m._create_dataset_manifest(
                    input_root=input_root,
                    output_root=output_root,
                    discovered_archives=discovered,
                    command_fingerprint=fingerprint,
                )
                manifest_path = self.m._dataset_manifest_path(output_root)
                work_dir = os.path.dirname(manifest_path)
                self.m._save_dataset_manifest(manifest)
                self.assertTrue(os.path.exists(manifest_path))
                self.assertFalse(os.path.exists(manifest_path + ".tmp"))
                self.assertEqual(
                    [],
                    [
                        name
                        for name in os.listdir(work_dir)
                        if name.upper().startswith("DATASE~")
                    ],
                )
                self.m._save_dataset_manifest(manifest)

            entries = sorted(os.listdir(work_dir))

            self.assertTrue(os.path.exists(manifest_path))
            self.assertFalse(os.path.exists(manifest_path + ".tmp"))
            self.assertIn("dataset_manifest.json", entries)
            self.assertEqual(
                [],
                [name for name in entries if name.upper().startswith("DATASE~")],
            )

    def test_dataset_manifest_recomputes_progress_counts(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            manifest = self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=self._make_discovered_archives(
                    input_root,
                    output_root,
                    ["alpha.zip", "beta.zip", "gamma.zip", "delta.zip"],
                ),
                command_fingerprint=self._make_manifest_command_fingerprint(
                    input_root, output_root
                ),
            )

            archive_ids = list(manifest["archives"].keys())
            manifest["archives"][archive_ids[0]]["state"] = "recoverable"
            manifest["archives"][archive_ids[1]]["state"] = "succeeded"
            manifest["archives"][archive_ids[2]]["state"] = "failed"
            manifest["archives"][archive_ids[3]]["state"] = "retryable"
            manifest["progress"]["counts"] = {
                "pending": 99,
                "extracting": 99,
                "recoverable": 99,
                "retryable": 99,
                "succeeded": 99,
                "failed": 99,
            }
            manifest["updated_at"] = "2000-01-01T00:00:00+00:00"

            counts = self.m._recompute_dataset_manifest_progress_counts(manifest)

            expected_counts = {
                "pending": 0,
                "extracting": 0,
                "recoverable": 1,
                "retryable": 1,
                "succeeded": 1,
                "failed": 1,
            }
            self.assertEqual(expected_counts, counts)
            self.assertEqual(expected_counts, manifest["progress"]["counts"])
            self.assertNotEqual("2000-01-01T00:00:00+00:00", manifest["updated_at"])

    def test_dataset_manifest_recomputes_status(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            base_manifest = self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=self._make_discovered_archives(
                    input_root,
                    output_root,
                    ["alpha.zip", "beta.zip"],
                ),
                command_fingerprint=self._make_manifest_command_fingerprint(
                    input_root, output_root
                ),
            )

            archive_ids = list(base_manifest["archives"].keys())
            cases = [
                (("pending", "succeeded"), "active"),
                (("succeeded", "succeeded"), "completed"),
                (("failed", "succeeded"), "failed"),
            ]

            for states, expected_status in cases:
                with self.subTest(states=states):
                    manifest = json.loads(json.dumps(base_manifest))
                    manifest["archives"][archive_ids[0]]["state"] = states[0]
                    manifest["archives"][archive_ids[1]]["state"] = states[1]
                    manifest["updated_at"] = "2000-01-01T00:00:00+00:00"

                    status = self.m._recompute_dataset_manifest_status(manifest)

                    self.assertEqual(expected_status, status)
                    self.assertEqual(expected_status, manifest["status"])
                    self.assertNotEqual(
                        "2000-01-01T00:00:00+00:00", manifest["updated_at"]
                    )

    def test_update_dataset_manifest_archive_serializes_concurrent_writes_with_lock(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                ["alpha.zip", "beta.zip"],
            )
            args = self._make_processing_args(
                input_root,
                output=output_root,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=discovered,
                command_fingerprint=self.m._build_command_fingerprint(args),
            )

            tracker = {"active": 0, "max_active": 0}
            tracker_guard = threading.Lock()
            held_lock = threading.Lock()
            acquired_paths = []

            class TrackingLock:
                def __init__(self, path, timeout_ms, retry_ms, debug):
                    self.path = path

                def __enter__(self):
                    acquired_paths.append(self.path)
                    held_lock.acquire()
                    with tracker_guard:
                        tracker["active"] += 1
                        tracker["max_active"] = max(
                            tracker["max_active"], tracker["active"]
                        )
                    return self

                def __exit__(self, exc_type, exc, tb):
                    with tracker_guard:
                        tracker["active"] -= 1
                    held_lock.release()
                    return False

            def update_archive(archive_path, state, txn_id):
                self.m._update_dataset_manifest_archive(
                    output_root,
                    archive_path,
                    state=state,
                    last_txn_id=txn_id,
                )

            expected_lock_path = self.m._dataset_manifest_lock_path(output_root)
            threads = [
                threading.Thread(
                    target=update_archive,
                    args=(discovered[0]["archive_path"], "extracting", "txn-alpha"),
                ),
                threading.Thread(
                    target=update_archive,
                    args=(discovered[1]["archive_path"], "retryable", "txn-beta"),
                ),
            ]

            with mock.patch.object(self.m, "FileLock", TrackingLock):
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=5)

            manifest = self.m._load_dataset_manifest(output_root)
            alpha_id = self.m._dataset_manifest_archive_id(
                discovered[0]["archive_path"]
            )
            beta_id = self.m._dataset_manifest_archive_id(discovered[1]["archive_path"])

            self.assertEqual(1, tracker["max_active"])
            self.assertEqual([expected_lock_path, expected_lock_path], acquired_paths)
            self.assertEqual("extracting", manifest["archives"][alpha_id]["state"])
            self.assertEqual("txn-alpha", manifest["archives"][alpha_id]["last_txn_id"])
            self.assertEqual("retryable", manifest["archives"][beta_id]["state"])
            self.assertEqual("txn-beta", manifest["archives"][beta_id]["last_txn_id"])

    def test_command_fingerprint_includes_semantic_fields(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            direct_args = self._make_processing_args(
                input_root,
                output=output_root,
                decompress_policy="direct",
            )
            collect_args = self._make_processing_args(
                input_root,
                output=output_root,
                decompress_policy="collect",
            )

            direct_fingerprint = self.m._build_command_fingerprint(direct_args)
            collect_fingerprint = self.m._build_command_fingerprint(collect_args)

            self.assertEqual(1, direct_fingerprint["version"])
            self.assertEqual(
                os.path.abspath(input_root), direct_fingerprint["fields"]["path"]
            )
            self.assertEqual(
                os.path.abspath(output_root), direct_fingerprint["fields"]["output"]
            )
            self.assertEqual(
                "direct", direct_fingerprint["fields"]["decompress_policy"]
            )
            self.assertEqual(
                "collect", collect_fingerprint["fields"]["decompress_policy"]
            )
            self.assertNotEqual(
                direct_fingerprint["sha256"], collect_fingerprint["sha256"]
            )

    def test_command_fingerprint_excludes_execution_tuning_fields(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            base_args = self._make_processing_args(
                input_root,
                output=output_root,
                threads=1,
                verbose=False,
                lock_timeout=30,
                output_lock_timeout_ms=1000,
                output_lock_retry_ms=10,
                keep_journal_days=7,
            )
            tuned_args = self._make_processing_args(
                input_root,
                output=output_root,
                threads=8,
                verbose=True,
                lock_timeout=90,
                output_lock_timeout_ms=2500,
                output_lock_retry_ms=250,
                keep_journal_days=30,
            )

            base_fingerprint = self.m._build_command_fingerprint(base_args)
            tuned_fingerprint = self.m._build_command_fingerprint(tuned_args)

            self.assertEqual(base_fingerprint["sha256"], tuned_fingerprint["sha256"])
            for excluded_key in (
                "verbose",
                "threads",
                "lock_timeout",
                "output_lock_timeout_ms",
                "output_lock_retry_ms",
                "keep_journal_days",
            ):
                self.assertNotIn(excluded_key, base_fingerprint["fields"])

    def test_make_processing_args_omits_removed_windows_delete_flag(self):
        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(td)

        self.assertFalse(hasattr(args, "unsafe_windows_delete"))

    def test_argv_for_main_emits_legacy_flag_after_windows_delete_flag_removal(self):
        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                legacy=True,
            )

        argv = self._argv_for_main(args)

        self.assertNotIn("--unsafe-windows-delete", argv)
        self.assertIn("--legacy", argv)

    def test_command_fingerprint_omits_removed_windows_delete_field(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            args = self._make_processing_args(
                input_root,
                output=output_root,
                success_policy="delete",
            )

            with mock.patch.object(self.m.os, "name", "nt"):
                fingerprint = self.m._build_command_fingerprint(args)

        self.assertNotIn("unsafe_windows_delete", fingerprint["fields"])

    def test_resume_rejects_manifest_fingerprint_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                ["alpha.zip"],
            )
            baseline_args = self._make_processing_args(
                input_root,
                output=output_root,
                decompress_policy="direct",
            )
            manifest = self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=discovered,
                command_fingerprint=self.m._build_command_fingerprint(baseline_args),
            )

            txn = self.m._txn_create(
                archive_path=discovered[0]["archive_path"],
                volumes=discovered[0]["volumes"],
                output_dir=discovered[0]["output_dir"],
                output_base=output_root,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_EXTRACTED
            self.m._txn_snapshot(txn)

            manifest_path = self.m._dataset_manifest_path(output_root)
            txn_json_path = txn["paths"]["txn_json"]
            with open(manifest_path, "rb") as f:
                manifest_before = f.read()
            with open(txn_json_path, "rb") as f:
                txn_before = f.read()

            resume_args = self._make_processing_args(
                input_root,
                output=output_root,
                decompress_policy="collect",
            )
            stdout = io.StringIO()

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(self.m.sys, "argv", self._argv_for_main(resume_args)),
                mock.patch.object(
                    self.m,
                    "safe_subprocess_run",
                    return_value=SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
                ),
                mock.patch.object(self.m, "fix_archive_ext") as fix_archive_ext,
                mock.patch.object(
                    self.m,
                    "ArchiveProcessor",
                    side_effect=AssertionError(
                        "ArchiveProcessor should not be constructed on resume mismatch"
                    ),
                ),
            ):
                exit_code = self.m.main()

            self.assertEqual(1, exit_code)
            self.assertIn(manifest["output_root"], stdout.getvalue())
            self.assertIn(".advdecompress_work", stdout.getvalue())
            self.assertIn("delete", stdout.getvalue().lower())
            fix_archive_ext.assert_not_called()

            with open(manifest_path, "rb") as f:
                self.assertEqual(manifest_before, f.read())
            with open(txn_json_path, "rb") as f:
                self.assertEqual(txn_before, f.read())

    def test_run_transactional_rejects_manifest_fingerprint_mismatch_before_recovery(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                ["alpha.zip"],
            )
            baseline_args = self._make_processing_args(
                input_root,
                output=output_root,
                decompress_policy="direct",
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=discovered,
                command_fingerprint=self.m._build_command_fingerprint(baseline_args),
            )

            txn = self.m._txn_create(
                archive_path=discovered[0]["archive_path"],
                volumes=discovered[0]["volumes"],
                output_dir=discovered[0]["output_dir"],
                output_base=output_root,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_EXTRACTED
            self.m._txn_snapshot(txn)

            manifest_path = self.m._dataset_manifest_path(output_root)
            txn_json_path = txn["paths"]["txn_json"]
            with open(manifest_path, "rb") as f:
                manifest_before = f.read()
            with open(txn_json_path, "rb") as f:
                txn_before = f.read()

            resume_args = self._make_processing_args(
                input_root,
                output=output_root,
                decompress_policy="collect",
            )
            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            stdout = io.StringIO()

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(
                    self.m,
                    "_recover_all_outputs",
                    side_effect=AssertionError(
                        "recovery should not start before strict resume validation"
                    ),
                ),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "extract should not start before strict resume validation"
                    ),
                ),
            ):
                result = self.m._run_transactional(
                    processor,
                    [discovered[0]["archive_path"]],
                    args=resume_args,
                )

            self.assertFalse(result)
            self.assertIn(
                os.path.join(output_root, ".advdecompress_work"), stdout.getvalue()
            )
            self.assertIn("delete", stdout.getvalue().lower())
            self.assertEqual([], processor.successful_archives)
            self.assertEqual([], processor.failed_archives)
            self.assertEqual([], processor.skipped_archives)

            with open(manifest_path, "rb") as f:
                self.assertEqual(manifest_before, f.read())
            with open(txn_json_path, "rb") as f:
                self.assertEqual(txn_before, f.read())

    def test_resume_rejects_legacy_workdir_without_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            archive_path = os.path.join(input_root, "legacy.zip")
            with open(archive_path, "wb") as f:
                f.write(b"legacy")

            txn = self.m._txn_create(
                archive_path=archive_path,
                volumes=[archive_path],
                output_dir=output_root,
                output_base=output_root,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_EXTRACTED
            self.m._txn_snapshot(txn)

            txn_json_path = txn["paths"]["txn_json"]
            with open(txn_json_path, "rb") as f:
                txn_before = f.read()
            self.assertFalse(os.path.exists(self.m._dataset_manifest_path(output_root)))

            resume_args = self._make_processing_args(
                input_root,
                output=output_root,
                decompress_policy="direct",
            )
            stdout = io.StringIO()

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(self.m.sys, "argv", self._argv_for_main(resume_args)),
                mock.patch.object(
                    self.m,
                    "safe_subprocess_run",
                    return_value=SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
                ),
                mock.patch.object(self.m, "fix_archive_ext") as fix_archive_ext,
                mock.patch.object(
                    self.m,
                    "ArchiveProcessor",
                    side_effect=AssertionError(
                        "ArchiveProcessor should not be constructed for legacy workdir refusal"
                    ),
                ),
            ):
                exit_code = self.m.main()

            self.assertEqual(1, exit_code)
            self.assertIn(
                os.path.join(output_root, ".advdecompress_work"), stdout.getvalue()
            )
            self.assertIn("dataset_manifest.json", stdout.getvalue())
            self.assertIn("delete", stdout.getvalue().lower())
            fix_archive_ext.assert_not_called()
            self.assertFalse(os.path.exists(self.m._dataset_manifest_path(output_root)))
            with open(txn_json_path, "rb") as f:
                self.assertEqual(txn_before, f.read())

    def test_main_rejects_corrupt_manifest_json(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)

            self._assert_startup_manifest_file_rejected(
                fixture,
                manifest_bytes=b'{"broken":',
                expected_text="malformed",
                via_main=True,
                expect_manifest_path_text=True,
            )

    def test_run_transactional_rejects_manifest_top_level_array(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)

            self._assert_startup_manifest_file_rejected(
                fixture,
                manifest_bytes=b"[]",
                expected_text="top-level",
                expect_manifest_path_text=True,
            )

    def test_run_transactional_rejects_manifest_missing_output_root(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            manifest.pop("output_root", None)

            self._assert_startup_manifest_file_rejected(
                fixture,
                manifest_bytes=json.dumps(manifest).encode("utf-8"),
                expected_text="output_root",
            )

    def test_run_transactional_rejects_manifest_nonstring_output_root(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            manifest["output_root"] = ["bad"]

            self._assert_startup_manifest_file_rejected(
                fixture,
                manifest_bytes=json.dumps(manifest).encode("utf-8"),
                expected_text="output_root",
            )

    def test_run_transactional_rejects_manifest_relative_output_root(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            manifest["output_root"] = "relative-output-root"

            self._assert_startup_manifest_file_rejected(
                fixture,
                manifest_bytes=json.dumps(manifest).encode("utf-8"),
                expected_text="output_root",
            )

    def test_run_transactional_rejects_manifest_mismatched_output_root(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            manifest["output_root"] = os.path.join(td, "different-output-root")

            self._assert_startup_manifest_file_rejected(
                fixture,
                manifest_bytes=json.dumps(manifest).encode("utf-8"),
                expected_text="output_root",
            )

    def test_run_transactional_rejects_manifest_missing_manifest_version(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            manifest.pop("manifest_version", None)

            self._assert_startup_manifest_file_rejected(
                fixture,
                manifest_bytes=json.dumps(manifest).encode("utf-8"),
                expected_text="manifest_version",
            )

    def test_run_transactional_rejects_manifest_unsupported_manifest_version(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            manifest["manifest_version"] = 999

            self._assert_startup_manifest_file_rejected(
                fixture,
                manifest_bytes=json.dumps(manifest).encode("utf-8"),
                expected_text="manifest_version",
            )

    def test_run_transactional_rejects_manifest_bool_manifest_version(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            manifest["manifest_version"] = True

            self._assert_startup_manifest_file_rejected(
                fixture,
                manifest_bytes=json.dumps(manifest).encode("utf-8"),
                expected_text="manifest_version",
            )

    def test_run_transactional_rejects_manifest_missing_run_id(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            manifest.pop("run_id", None)

            self._assert_startup_manifest_file_rejected(
                fixture,
                manifest_bytes=json.dumps(manifest).encode("utf-8"),
                expected_text="run_id",
            )

    def test_run_transactional_rejects_manifest_null_run_id(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            manifest["run_id"] = None

            self._assert_startup_manifest_file_rejected(
                fixture,
                manifest_bytes=json.dumps(manifest).encode("utf-8"),
                expected_text="run_id",
            )

    def test_run_transactional_rejects_manifest_empty_run_id(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            manifest["run_id"] = ""

            self._assert_startup_manifest_file_rejected(
                fixture,
                manifest_bytes=json.dumps(manifest).encode("utf-8"),
                expected_text="run_id",
            )

    def test_run_transactional_rejects_manifest_command_fingerprint_not_dict(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            manifest["command_fingerprint"] = ["bad"]

            self._assert_startup_manifest_file_rejected(
                fixture,
                manifest_bytes=json.dumps(manifest).encode("utf-8"),
                expected_text="command_fingerprint",
            )

    def test_run_transactional_rejects_manifest_missing_archives(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            manifest.pop("archives", None)

            self._assert_startup_manifest_file_rejected(
                fixture,
                manifest_bytes=json.dumps(manifest).encode("utf-8"),
                expected_text="archives",
            )

    def test_run_transactional_rejects_manifest_archives_not_dict(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            manifest["archives"] = []

            self._assert_startup_manifest_file_rejected(
                fixture,
                manifest_bytes=json.dumps(manifest).encode("utf-8"),
                expected_text="archives",
            )

    def test_run_transactional_rejects_manifest_archives_with_nondict_entry(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            manifest["archives"][fixture["archive_id"]] = []

            self._assert_startup_manifest_file_rejected(
                fixture,
                manifest_bytes=json.dumps(manifest).encode("utf-8"),
                expected_text="archive entry",
            )

    def test_run_transactional_rejects_manifest_entry_missing_output_dir(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            manifest["archives"][fixture["archive_id"]].pop("output_dir", None)

            self._assert_startup_manifest_file_rejected(
                fixture,
                manifest_bytes=json.dumps(manifest).encode("utf-8"),
                expected_text="output_dir",
            )

    def test_run_transactional_rejects_manifest_entry_nonstring_last_txn_id(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            manifest["archives"][fixture["archive_id"]]["last_txn_id"] = 123

            self._assert_startup_manifest_file_rejected(
                fixture,
                manifest_bytes=json.dumps(manifest).encode("utf-8"),
                expected_text="last_txn_id",
            )

    def test_run_transactional_rejects_manifest_entry_empty_last_txn_id(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            manifest["archives"][fixture["archive_id"]]["last_txn_id"] = ""

            self._assert_startup_manifest_file_rejected(
                fixture,
                manifest_bytes=json.dumps(manifest).encode("utf-8"),
                expected_text="last_txn_id",
            )

    def test_run_transactional_rejects_manifest_entry_missing_state(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            manifest["archives"][fixture["archive_id"]].pop("state", None)

            self._assert_startup_manifest_file_rejected(
                fixture,
                manifest_bytes=json.dumps(manifest).encode("utf-8"),
                expected_text="state",
            )

    def test_run_transactional_rejects_manifest_entry_nonstring_state(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            manifest["archives"][fixture["archive_id"]]["state"] = 123

            self._assert_startup_manifest_file_rejected(
                fixture,
                manifest_bytes=json.dumps(manifest).encode("utf-8"),
                expected_text="state",
            )

    def test_run_transactional_rejects_manifest_entry_unknown_state(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            manifest["archives"][fixture["archive_id"]]["state"] = "bogus"

            self._assert_startup_manifest_file_rejected(
                fixture,
                manifest_bytes=json.dumps(manifest).encode("utf-8"),
                expected_text="state",
            )

    def test_run_transactional_rejects_manifest_entry_relative_output_dir(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            manifest["archives"][fixture["archive_id"]]["output_dir"] = "relative-out"

            self._assert_startup_manifest_file_rejected(
                fixture,
                manifest_bytes=json.dumps(manifest).encode("utf-8"),
                expected_text="output_dir",
            )

    def test_run_transactional_rejects_manifest_entry_output_dir_outside_output_root(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            outside_output_dir = os.path.join(td, "outside-output")
            manifest["archives"][fixture["archive_id"]]["output_dir"] = (
                outside_output_dir
            )

            self._assert_startup_manifest_file_rejected(
                fixture,
                manifest_bytes=json.dumps(manifest).encode("utf-8"),
                expected_text="output_dir",
            )

    def test_terminal_residue_does_not_block_new_run(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="succeeded"
            )
            archive = fixture["archive"]
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_DONE
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                archive["archive_path"],
                state="recoverable",
                last_txn_id=txn["txn_id"],
                final_disposition="success:asis",
                error=None,
                finalized_at=self.m._now_iso(),
            )

            self.assertTrue(self.m._validate_strict_resume_startup(fixture["args"]))

    def test_parseable_invalid_manifest_fails_startup_validation(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest_path = self.m._dataset_manifest_path(fixture["output_root"])
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump({"manifest_version": 1}, f)

            self.assertFalse(self.m._validate_strict_resume_startup(fixture["args"]))

    def test_invalid_candidate_txn_json_makes_startup_ambiguous(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            with open(txn["paths"]["txn_json"], "w", encoding="utf-8") as f:
                f.write("{broken json")

            self.assertFalse(self.m._validate_strict_resume_startup(fixture["args"]))

    def test_invalid_orphan_txn_json_makes_startup_ambiguous(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="pending"
            )
            orphan_output_dir = os.path.join(fixture["output_root"], "orphan-out")
            orphan_txn = self.m._txn_create(
                archive_path=os.path.join(td, "orphan.zip"),
                volumes=[],
                output_dir=orphan_output_dir,
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            with open(orphan_txn["paths"]["txn_json"], "w", encoding="utf-8") as f:
                json.dump({"txn_id": orphan_txn["txn_id"]}, f)

            self.assertFalse(self.m._validate_strict_resume_startup(fixture["args"]))

    def test_physically_misplaced_candidate_txn_json_makes_startup_ambiguous(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_EXTRACTED
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                archive["archive_path"],
                state="recoverable",
                last_txn_id=txn["txn_id"],
                error=None,
            )

            misplaced_output_dir = os.path.join(fixture["output_root"], "misplaced")
            misplaced_txn_json = os.path.join(
                self.m._work_root(misplaced_output_dir, fixture["output_root"]),
                "journal",
                txn["txn_id"],
                "txn.json",
            )
            os.makedirs(os.path.dirname(misplaced_txn_json), exist_ok=True)
            os.rename(txn["paths"]["txn_json"], misplaced_txn_json)

            with open(misplaced_txn_json, "r", encoding="utf-8") as f:
                saved_txn = json.load(f)

            self.assertEqual(txn["paths"]["txn_json"], saved_txn["paths"]["txn_json"])
            self.assertFalse(os.path.exists(txn["paths"]["txn_json"]))
            self.assertFalse(self.m._validate_strict_resume_startup(fixture["args"]))

    def test_physically_misplaced_orphan_txn_json_makes_startup_ambiguous(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="pending"
            )
            orphan_output_dir = os.path.join(fixture["output_root"], "orphan-out")
            orphan_txn = self.m._txn_create(
                archive_path=os.path.join(td, "orphan.zip"),
                volumes=[],
                output_dir=orphan_output_dir,
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            orphan_txn["state"] = self.m.TXN_STATE_DONE
            self.m._txn_snapshot(orphan_txn)

            misplaced_output_dir = os.path.join(fixture["output_root"], "misplaced")
            misplaced_txn_json = os.path.join(
                self.m._work_root(misplaced_output_dir, fixture["output_root"]),
                "journal",
                orphan_txn["txn_id"],
                "txn.json",
            )
            os.makedirs(os.path.dirname(misplaced_txn_json), exist_ok=True)
            os.rename(orphan_txn["paths"]["txn_json"], misplaced_txn_json)

            with open(misplaced_txn_json, "r", encoding="utf-8") as f:
                saved_txn = json.load(f)

            self.assertEqual(
                orphan_txn["paths"]["txn_json"], saved_txn["paths"]["txn_json"]
            )
            self.assertFalse(os.path.exists(orphan_txn["paths"]["txn_json"]))
            self.assertFalse(self.m._validate_strict_resume_startup(fixture["args"]))

    def test_nonterminal_nonrecoverable_orphan_txn_makes_startup_ambiguous(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="succeeded"
            )
            orphan_output_dir = os.path.join(fixture["output_root"], "orphan-out")
            orphan_txn = self.m._txn_create(
                archive_path=os.path.join(td, "orphan.zip"),
                volumes=[],
                output_dir=orphan_output_dir,
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            orphan_txn["state"] = self.m.TXN_STATE_ABORTED
            orphan_txn["error"] = {
                "type": "RECOVER_FAILED",
                "message": "resume failed and no recoverable continuation remains",
                "at": self.m._now_iso(),
            }
            self.m._txn_snapshot(orphan_txn)

            manifest = self.m._load_dataset_manifest(fixture["output_root"])

            self.assertFalse(self.m._txn_has_recovery_responsibility(orphan_txn))
            self.assertFalse(self.m._txn_is_closed_terminal_outcome(orphan_txn))
            self.assertEqual(
                "ambiguous",
                self.m._classify_existing_work_base(manifest, fixture["output_root"]),
            )
            self.assertFalse(self.m._validate_strict_resume_startup(fixture["args"]))

    def test_selected_txn_prefers_lexicographically_greatest_id_when_mtimes_match(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            txn_a = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn_b = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            for txn in (txn_a, txn_b):
                txn["state"] = self.m.TXN_STATE_DONE
                self.m._txn_snapshot(txn)

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]
            entry["last_txn_id"] = None
            self.m._save_dataset_manifest(manifest)

            shared_mtime = os.path.getmtime(txn_a["paths"]["txn_json"])
            os.utime(txn_a["paths"]["txn_json"], (shared_mtime, shared_mtime))
            os.utime(txn_b["paths"]["txn_json"], (shared_mtime, shared_mtime))

            selected = self.m._selected_txn_for_manifest_archive(entry, fixture["output_root"])

            self.assertEqual(max(txn_a["txn_id"], txn_b["txn_id"]), selected["txn_id"])

    def test_prefixed_non_wal_recoverable_txn_without_snapshots_still_resumes(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_EXTRACTED
            txn.setdefault("placement", {}).pop("move_plan_snapshot", None)
            txn.setdefault("placement", {}).pop("move_done_ids_snapshot", None)
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                archive["archive_path"],
                state="recoverable",
                last_txn_id=txn["txn_id"],
                error=None,
            )

            self.assertTrue(self.m._validate_strict_resume_startup(fixture["args"]))

    def test_same_archive_journal_with_mismatched_output_dir_is_ambiguous(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            wrong_output_dir = os.path.join(fixture["output_root"], "wrong")
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=wrong_output_dir,
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_DONE
            self.m._txn_snapshot(txn)

            self.assertFalse(self.m._validate_strict_resume_startup(fixture["args"]))

    def test_candidate_txn_output_dir_outside_output_base_is_ambiguous(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["output_dir"] = os.path.join(td, "outside-output")
            self.m._txn_snapshot(txn)

            self.assertFalse(self.m._validate_strict_resume_startup(fixture["args"]))

    def test_cleaned_txn_is_treated_as_terminal_historical_compatibility_state(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_CLEANED
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                archive["archive_path"],
                state="recoverable",
                last_txn_id=txn["txn_id"],
                error=None,
            )

            self.assertTrue(self.m._validate_strict_resume_startup(fixture["args"]))

    def test_selected_last_txn_id_controls_startup_plan_and_missing_input(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            output_root = fixture["output_root"]
            args = fixture["args"]

            selected_txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=output_root,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            selected_txn["state"] = self.m.TXN_STATE_EXTRACTED
            self.m._txn_snapshot(selected_txn)

            newer_txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=output_root,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            newer_txn["state"] = self.m.TXN_STATE_DONE
            self.m._txn_snapshot(newer_txn)

            self.m._update_dataset_manifest_archive(
                output_root,
                archive["archive_path"],
                state="recoverable",
                last_txn_id=selected_txn["txn_id"],
                error=None,
            )

            manifest = self.m._load_dataset_manifest(output_root)
            entry = manifest["archives"][fixture["archive_id"]]

            self.assertTrue(self.m._validate_strict_resume_startup(args))
            recoverable_archives, retryable_archives, pending_archives = (
                self.m._build_transactional_archive_plan(
                    manifest,
                    output_root,
                    persist=False,
                )
            )

            self.assertEqual(
                [
                    {
                        "archive_path": os.path.abspath(archive["archive_path"]),
                        "output_dir": os.path.abspath(archive["output_dir"]),
                    }
                ],
                recoverable_archives,
            )
            self.assertEqual([], retryable_archives)
            self.assertEqual([], pending_archives)
            self.assertEqual(selected_txn["txn_id"], entry["last_txn_id"])
            self.assertFalse(
                self.m._manifest_archive_allows_missing_input(
                    manifest,
                    entry,
                    output_root,
                )
            )

    def test_historical_source_finalized_without_plan_is_terminal_for_classification(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_SOURCE_FINALIZED
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                archive["archive_path"],
                state="recoverable",
                last_txn_id=txn["txn_id"],
                error=None,
            )

            self.assertFalse(self.m._txn_has_recovery_responsibility(txn))
            self.assertTrue(self.m._txn_is_closed_terminal_outcome(txn))
            self.assertTrue(self.m._validate_strict_resume_startup(fixture["args"]))

    def test_cleaned_txn_with_incomplete_source_finalization_is_recoverable(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            self.m._set_source_finalization_plan(
                txn,
                manifest_state="succeeded",
                final_disposition="success:move",
                txn_terminal_state=self.m.TXN_STATE_DONE,
            )
            txn["state"] = self.m.TXN_STATE_CLEANED
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                archive["archive_path"],
                state="recoverable",
                last_txn_id=txn["txn_id"],
                error=None,
            )

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]

            self.assertTrue(self.m._txn_has_recovery_responsibility(txn))
            self.assertFalse(self.m._txn_is_closed_terminal_outcome(txn))
            self.assertEqual(
                "recoverable",
                self.m._classify_manifest_archive_state(entry, fixture["output_root"]),
            )
            self.assertTrue(self.m._validate_strict_resume_startup(fixture["args"]))

    def test_cleaned_completed_failure_plan_uses_success_historical_compatibility(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            self.m._set_source_finalization_plan(
                txn,
                manifest_state="failed",
                final_disposition="failure:asis",
                txn_terminal_state=self.m.TXN_STATE_FAILED,
            )
            txn["state"] = self.m.TXN_STATE_CLEANED
            txn["error"] = {
                "type": "PLACE_FAILED",
                "message": "persisted historical failure-looking fields",
                "at": self.m._now_iso(),
            }
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                archive["archive_path"],
                state="recoverable",
                last_txn_id=txn["txn_id"],
                error=None,
            )

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]

            self.assertFalse(self.m._txn_has_incomplete_source_finalization(txn))
            self.assertTrue(self.m._txn_is_closed_terminal_outcome(txn))
            self.assertEqual("succeeded", self.m._txn_terminal_manifest_state(txn))
            self.assertEqual(
                "succeeded",
                self.m._reconciled_archive_classification(entry, txn),
            )

    def test_cleaned_success_compatibility_conflicting_failed_manifest_is_ambiguous(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="failed"
            )
            archive = fixture["archive"]
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            self.m._set_source_finalization_plan(
                txn,
                manifest_state="failed",
                final_disposition="failure:asis",
                txn_terminal_state=self.m.TXN_STATE_FAILED,
            )
            txn["state"] = self.m.TXN_STATE_CLEANED
            txn["error"] = {
                "type": "PLACE_FAILED",
                "message": "persisted historical failure-looking fields",
                "at": self.m._now_iso(),
            }
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                archive["archive_path"],
                state="failed",
                last_txn_id=txn["txn_id"],
                final_disposition="failure:asis",
                error=txn["error"],
                finalized_at=self.m._now_iso(),
            )

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]

            self.assertEqual("succeeded", self.m._txn_terminal_manifest_state(txn))
            with self.assertRaises(ValueError):
                self.m._reconciled_archive_classification(entry, txn)
            self.assertFalse(self.m._validate_strict_resume_startup(fixture["args"]))

    def test_aborted_completed_source_finalization_is_startup_ambiguous(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_success_finalization_txn_fixture(
                td,
                success_policy="move",
            )
            txn = fixture["txn"]
            txn["state"] = self.m.TXN_STATE_PLACED
            self.m._set_source_finalization_plan(
                txn,
                manifest_state="succeeded",
                final_disposition="success:move",
                txn_terminal_state=self.m.TXN_STATE_DONE,
            )
            self.m._txn_snapshot(txn)
            self.m._finalize_sources_success(txn, args=fixture["args"])
            self.m._txn_abort(
                txn,
                "ABORTED",
                "synthetic persisted after source finalization",
            )
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                fixture["archive_path"],
                state="retryable",
                last_txn_id=txn["txn_id"],
                final_disposition="unknown",
                error=txn.get("error"),
                finalized_at=None,
            )

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]

            self.assertTrue(self.m._txn_source_finalization_completed(txn))
            self.assertFalse(self.m._txn_has_recovery_responsibility(txn))
            self.assertFalse(self.m._txn_is_closed_terminal_outcome(txn))
            with self.assertRaises(ValueError):
                self.m._reconciled_archive_classification(entry, txn)
            self.assertFalse(self.m._validate_strict_resume_startup(fixture["args"]))

    def test_interrupt_after_completed_source_finalization_is_startup_ambiguous(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_success_finalization_txn_fixture(
                td,
                success_policy="move",
            )
            real_finalize_success = self.m._finalize_sources_success

            def finalize_then_interrupt(txn, *, args):
                real_finalize_success(txn, args=args)
                raise KeyboardInterrupt("interrupt after source finalization")

            with mock.patch.object(
                self.m,
                "_finalize_sources_success",
                side_effect=finalize_then_interrupt,
            ):
                with self.assertRaises(KeyboardInterrupt):
                    self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]
            saved_txn = self.m._load_latest_txn_for_archive(
                entry,
                fixture["output_root"],
            )

            self.assertFalse(os.path.exists(fixture["archive_path"]))
            self.assertEqual(self.m.TXN_STATE_ABORTED, saved_txn["state"])
            self.assertEqual("ABORTED", saved_txn["error"]["type"])
            self.assertEqual("retryable", entry["state"])
            self.assertTrue(self.m._txn_source_finalization_completed(saved_txn))
            self.assertFalse(self.m._txn_has_recovery_responsibility(saved_txn))
            self.assertFalse(self.m._txn_is_closed_terminal_outcome(saved_txn))
            with self.assertRaises(ValueError):
                self.m._reconciled_archive_classification(entry, saved_txn)
            self.assertFalse(self.m._validate_strict_resume_startup(fixture["args"]))

    def test_incomplete_source_finalization_does_not_allow_missing_input(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="succeeded"
            )
            archive = fixture["archive"]
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            self.m._set_source_finalization_plan(
                txn,
                manifest_state="succeeded",
                final_disposition="success:move",
                txn_terminal_state=self.m.TXN_STATE_DONE,
            )
            txn["state"] = self.m.TXN_STATE_DONE
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                archive["archive_path"],
                state="succeeded",
                last_txn_id=txn["txn_id"],
                final_disposition="success:move",
                error=None,
                finalized_at=self.m._now_iso(),
            )

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]

            self.assertTrue(self.m._txn_has_incomplete_source_finalization(txn))
            self.assertFalse(
                self.m._manifest_archive_allows_missing_input(
                    manifest,
                    entry,
                    fixture["output_root"],
                )
            )

    def test_plan_completed_source_finalized_overrides_stale_non_terminal_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_success_finalization_txn_fixture(td, success_policy="move")
            self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]
            entry["state"] = "recoverable"
            entry["final_disposition"] = "unknown"
            entry["finalized_at"] = None
            self.m._save_dataset_manifest(manifest)

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]
            txn = self.m._load_latest_txn_for_archive(entry, fixture["output_root"])

            self.assertEqual(self.m.TXN_STATE_DONE, txn["state"])
            self.assertTrue(self.m._txn_is_closed_terminal_outcome(txn))
            self.assertEqual(
                "succeeded",
                self.m._reconciled_archive_classification(entry, txn),
            )
            self.assertEqual(
                "succeeded",
                self.m._classify_manifest_archive_state(entry, fixture["output_root"]),
            )

    def test_plan_completed_source_finalized_retires_terminal_residue_on_new_command(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_success_finalization_txn_fixture(td, success_policy="move")
            self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]
            entry["state"] = "recoverable"
            entry["final_disposition"] = "unknown"
            entry["finalized_at"] = None
            manifest["command_fingerprint"] = self.m._build_command_fingerprint(
                self._make_processing_args(
                    os.path.join(td, "other-input"),
                    output=fixture["output_root"],
                    success_policy="move",
                    success_to=fixture["args"].success_to,
                    decompress_policy=fixture["args"].decompress_policy,
                    no_durability=False,
                    fsync_files="auto",
                    success_clean_journal=False,
                    fail_clean_journal=False,
                )
            )
            self.m._save_dataset_manifest(manifest)

            reopen_args = self._make_processing_args(
                os.path.join(td, "other-input"),
                output=fixture["output_root"],
                success_policy="move",
                success_to=fixture["args"].success_to,
                decompress_policy=fixture["args"].decompress_policy,
                no_durability=False,
                fsync_files="auto",
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            os.makedirs(reopen_args.path, exist_ok=True)

            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "_garbage_collect"),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "terminal residue retirement should happen before any re-extract"
                    ),
                ),
            ):
                result = self.m._run_transactional(processor, [], args=reopen_args)

            self.assertIsNone(result)
            self.assertEqual([], processor.successful_archives)
            self.assertEqual([], processor.failed_archives)
            self.assertEqual([], processor.skipped_archives)
            self.assertIsNone(self.m._load_dataset_manifest(fixture["output_root"]))
            self.assertFalse(os.path.exists(self.m._work_base(fixture["output_root"])))

    def test_done_terminal_txn_retires_stale_non_terminal_manifest_before_fingerprint_check(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_DONE
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                archive["archive_path"],
                state="recoverable",
                last_txn_id=txn["txn_id"],
                error=None,
            )

            mismatch_args = self._make_processing_args(
                os.path.join(td, "other-input"),
                output=fixture["output_root"],
            )
            os.makedirs(mismatch_args.path, exist_ok=True)

            self.assertTrue(self.m._validate_strict_resume_startup(mismatch_args))
            self.assertIsNone(self.m._load_dataset_manifest(fixture["output_root"]))

    def _assert_run_transactional_rebuilds_stale_top_level_manifest_cache_metadata(
        self, *, progress_value
    ):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            fixture["args"].success_clean_journal = True
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]
            entry["state"] = "succeeded"
            manifest["status"] = "bogus"
            manifest["progress"] = progress_value
            manifest["updated_at"] = "2000-01-01T00:00:00+00:00"
            self.m._save_dataset_manifest(manifest)

            manifest_path = self.m._dataset_manifest_path(fixture["output_root"])
            txn = self._create_startup_rejection_txn(fixture)
            txn_json_path = txn["paths"]["txn_json"]
            with open(txn_json_path, "rb") as f:
                txn_before = f.read()

            processor = types.SimpleNamespace(
                successful_archives=[],
                failed_archives=[],
                skipped_archives=[],
            )
            cleanup_calls = []
            recover_calls = []
            extract_calls = []
            stdout = io.StringIO()

            def fake_cleanup(output_dir, **kwargs):
                cleanup_calls.append(
                    {
                        "output_dir": output_dir,
                        "should_clean": kwargs["should_clean"],
                        "manifest_terminal": kwargs["manifest_terminal"],
                    }
                )
                return True

            def fake_recover_all_outputs(output_base, **kwargs):
                recover_calls.append(
                    {
                        "output_base": output_base,
                        "recoverable_archives": kwargs["recoverable_archives"],
                    }
                )
                return None

            def fake_run_transactional_extract_phase(
                processor_arg,
                archives_arg,
                *,
                args,
                output_base,
                current_run_touched_output_dirs,
            ):
                extract_calls.append(list(archives_arg))
                return None

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(
                    self.m,
                    "_recover_all_outputs",
                    side_effect=fake_recover_all_outputs,
                ),
                mock.patch.object(
                    self.m,
                    "_run_transactional_extract_phase",
                    side_effect=fake_run_transactional_extract_phase,
                ),
                mock.patch.object(
                    self.m,
                    "_cleanup_one_transactional_output_dir",
                    side_effect=fake_cleanup,
                ),
                mock.patch.object(self.m, "safe_rmtree", return_value=True),
            ):
                result = self.m._run_transactional(processor, [], args=fixture["args"])

            self.assertIsNone(result)
            self.assertEqual([], processor.successful_archives)
            self.assertEqual([], processor.failed_archives)
            self.assertEqual([], processor.skipped_archives)
            self.assertEqual(1, len(recover_calls))
            self.assertEqual(
                [
                    {
                        "archive_path": os.path.abspath(
                            fixture["archive"]["archive_path"]
                        ),
                        "output_dir": os.path.abspath(fixture["archive"]["output_dir"]),
                    }
                ],
                recover_calls[0]["recoverable_archives"],
            )
            self.assertEqual([[], []], extract_calls)
            self.assertEqual([], cleanup_calls)
            self.assertEqual("", stdout.getvalue())

            rebuilt_manifest = self.m._load_dataset_manifest(fixture["output_root"])
            self.assertEqual("active", rebuilt_manifest["status"])
            self.assertEqual(
                {
                    "pending": 0,
                    "extracting": 0,
                    "recoverable": 1,
                    "retryable": 0,
                    "succeeded": 0,
                    "failed": 0,
                },
                rebuilt_manifest["progress"]["counts"],
            )
            self.assertEqual(txn["txn_id"], rebuilt_manifest["archives"][fixture["archive_id"]]["last_txn_id"])
            self.assertNotEqual(
                "2000-01-01T00:00:00+00:00", rebuilt_manifest["updated_at"]
            )
            with open(txn_json_path, "rb") as f:
                self.assertEqual(txn_before, f.read())

    def test_run_transactional_rebuilds_stale_top_level_manifest_cache_metadata(self):
        self._assert_run_transactional_rebuilds_stale_top_level_manifest_cache_metadata(
            progress_value={
                "counts": {
                    "pending": 99,
                    "extracting": 99,
                    "recoverable": 99,
                    "retryable": 99,
                    "succeeded": 99,
                    "failed": 99,
                }
            }
        )

    def test_run_transactional_rebuilds_list_progress_shape(self):
        self._assert_run_transactional_rebuilds_stale_top_level_manifest_cache_metadata(
            progress_value=[]
        )

    def test_run_transactional_rebuilds_string_progress_shape(self):
        self._assert_run_transactional_rebuilds_stale_top_level_manifest_cache_metadata(
            progress_value="oops"
        )

    def test_resume_rejects_missing_manifest_archive(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)

            def remove_archive(archive_path):
                os.remove(archive_path)
                self.assertFalse(os.path.exists(archive_path))

            self._assert_resume_drift_rejected(
                fixture,
                mutate_archive=remove_archive,
                expected_text="missing",
            )

    def test_resume_rejects_manifest_entry_missing_archive_path(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]
            cwd_stat = os.stat(os.path.abspath(""))
            entry["archive_path"] = ""
            entry["identity"] = {
                "size": int(cwd_stat.st_size),
                "mtime_ns": int(cwd_stat.st_mtime_ns),
            }
            self.m._save_dataset_manifest(manifest)

            manifest_path = self.m._dataset_manifest_path(fixture["output_root"])
            with open(manifest_path, "rb") as f:
                manifest_before = f.read()

            processor = types.SimpleNamespace(
                successful_archives=[],
                failed_archives=[],
                skipped_archives=[],
            )
            stdout = io.StringIO()

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(
                    self.m,
                    "_recover_all_outputs",
                    side_effect=AssertionError(
                        "recovery should not start for malformed manifest archive_path"
                    ),
                ),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "extract should not start for malformed manifest archive_path"
                    ),
                ),
            ):
                result = self.m._run_transactional(
                    processor,
                    [fixture["archive"]["archive_path"]],
                    args=fixture["args"],
                )

            output = stdout.getvalue()
            self.assertFalse(result)
            self.assertIn("archive_path", output)
            self.assertIn("delete", output.lower())
            self.assertIn(
                os.path.join(fixture["output_root"], ".advdecompress_work"), output
            )
            self.assertEqual([], processor.successful_archives)
            self.assertEqual([], processor.failed_archives)
            self.assertEqual([], processor.skipped_archives)

            with open(manifest_path, "rb") as f:
                self.assertEqual(manifest_before, f.read())

    def test_resume_rejects_manifest_entry_archive_path_directory(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]
            directory_path = fixture["input_root"]
            directory_stat = os.stat(directory_path)
            entry["archive_path"] = directory_path
            entry["identity"] = {
                "size": int(directory_stat.st_size),
                "mtime_ns": int(directory_stat.st_mtime_ns),
            }
            self.m._save_dataset_manifest(manifest)

            manifest_path = self.m._dataset_manifest_path(fixture["output_root"])
            with open(manifest_path, "rb") as f:
                manifest_before = f.read()

            processor = types.SimpleNamespace(
                successful_archives=[],
                failed_archives=[],
                skipped_archives=[],
            )
            stdout = io.StringIO()

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(
                    self.m,
                    "_recover_all_outputs",
                    side_effect=AssertionError(
                        "recovery should not start for directory archive_path"
                    ),
                ),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "extract should not start for directory archive_path"
                    ),
                ),
            ):
                result = self.m._run_transactional(
                    processor,
                    [fixture["archive"]["archive_path"]],
                    args=fixture["args"],
                )

            output = stdout.getvalue()
            self.assertFalse(result)
            self.assertIn(directory_path, output)
            self.assertIn("not a file", output.lower())
            self.assertIn("delete", output.lower())
            self.assertIn(
                os.path.join(fixture["output_root"], ".advdecompress_work"), output
            )
            self.assertEqual([], processor.successful_archives)
            self.assertEqual([], processor.failed_archives)
            self.assertEqual([], processor.skipped_archives)

            with open(manifest_path, "rb") as f:
                self.assertEqual(manifest_before, f.read())

    def test_resume_rejects_manifest_entry_relative_archive_path(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]
            relative_archive_path = os.path.basename(fixture["archive"]["archive_path"])
            cwd_archive_path = os.path.join(os.getcwd(), relative_archive_path)
            with open(cwd_archive_path, "wb") as f:
                f.write(b"cwd-archive")
            cwd_stat = os.stat(cwd_archive_path)
            entry["archive_path"] = relative_archive_path
            entry["identity"] = {
                "size": int(cwd_stat.st_size),
                "mtime_ns": int(cwd_stat.st_mtime_ns),
            }
            self.m._save_dataset_manifest(manifest)

            manifest_path = self.m._dataset_manifest_path(fixture["output_root"])
            with open(manifest_path, "rb") as f:
                manifest_before = f.read()

            processor = types.SimpleNamespace(
                successful_archives=[],
                failed_archives=[],
                skipped_archives=[],
            )
            stdout = io.StringIO()

            try:
                with (
                    contextlib.redirect_stdout(stdout),
                    mock.patch.object(
                        self.m,
                        "_recover_all_outputs",
                        side_effect=AssertionError(
                            "recovery should not start for relative archive_path"
                        ),
                    ),
                    mock.patch.object(
                        self.m,
                        "_extract_phase",
                        side_effect=AssertionError(
                            "extract should not start for relative archive_path"
                        ),
                    ),
                ):
                    result = self.m._run_transactional(
                        processor,
                        [fixture["archive"]["archive_path"]],
                        args=fixture["args"],
                    )
            finally:
                os.remove(cwd_archive_path)

            output = stdout.getvalue()
            self.assertFalse(result)
            self.assertIn(relative_archive_path, output)
            self.assertIn("relative", output.lower())
            self.assertIn("delete", output.lower())
            self.assertIn(
                os.path.join(fixture["output_root"], ".advdecompress_work"), output
            )
            self.assertEqual([], processor.successful_archives)
            self.assertEqual([], processor.failed_archives)
            self.assertEqual([], processor.skipped_archives)

            with open(manifest_path, "rb") as f:
                self.assertEqual(manifest_before, f.read())

    def test_resume_rejects_manifest_entry_with_nonnumeric_identity(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]
            entry["identity"] = {
                "size": "not-a-number",
                "mtime_ns": "also-not-a-number",
            }
            self.m._save_dataset_manifest(manifest)

            manifest_path = self.m._dataset_manifest_path(fixture["output_root"])
            with open(manifest_path, "rb") as f:
                manifest_before = f.read()

            processor = types.SimpleNamespace(
                successful_archives=[],
                failed_archives=[],
                skipped_archives=[],
            )
            stdout = io.StringIO()

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(
                    self.m,
                    "_recover_all_outputs",
                    side_effect=AssertionError(
                        "recovery should not start for malformed manifest identity"
                    ),
                ),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "extract should not start for malformed manifest identity"
                    ),
                ),
            ):
                result = self.m._run_transactional(
                    processor,
                    [fixture["archive"]["archive_path"]],
                    args=fixture["args"],
                )

            output = stdout.getvalue()
            self.assertFalse(result)
            self.assertIn(fixture["archive"]["archive_path"], output)
            self.assertIn("identity", output.lower())
            self.assertIn("delete", output.lower())
            self.assertIn(
                os.path.join(fixture["output_root"], ".advdecompress_work"), output
            )
            self.assertEqual([], processor.successful_archives)
            self.assertEqual([], processor.failed_archives)
            self.assertEqual([], processor.skipped_archives)

            with open(manifest_path, "rb") as f:
                self.assertEqual(manifest_before, f.read())

    def test_resume_rejects_manifest_entry_missing_identity(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]
            entry.pop("identity", None)
            self.m._save_dataset_manifest(manifest)

            manifest_path = self.m._dataset_manifest_path(fixture["output_root"])
            with open(manifest_path, "rb") as f:
                manifest_before = f.read()

            processor = types.SimpleNamespace(
                successful_archives=[],
                failed_archives=[],
                skipped_archives=[],
            )
            stdout = io.StringIO()

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(
                    self.m,
                    "_recover_all_outputs",
                    side_effect=AssertionError(
                        "recovery should not start for missing manifest identity"
                    ),
                ),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "extract should not start for missing manifest identity"
                    ),
                ),
            ):
                result = self.m._run_transactional(
                    processor,
                    [fixture["archive"]["archive_path"]],
                    args=fixture["args"],
                )

            output = stdout.getvalue()
            self.assertFalse(result)
            self.assertIn(fixture["archive"]["archive_path"], output)
            self.assertIn("identity", output.lower())
            self.assertIn("delete", output.lower())
            self.assertIn(
                os.path.join(fixture["output_root"], ".advdecompress_work"), output
            )
            self.assertEqual([], processor.successful_archives)
            self.assertEqual([], processor.failed_archives)
            self.assertEqual([], processor.skipped_archives)

            with open(manifest_path, "rb") as f:
                self.assertEqual(manifest_before, f.read())

    def test_resume_rejects_manifest_entry_missing_identity_size(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)

            def mutate_manifest(entry):
                entry["identity"].pop("size", None)

            self._assert_resume_manifest_rejected(
                fixture,
                mutate_manifest=mutate_manifest,
                expected_text="identity.size",
            )

    def test_resume_rejects_manifest_entry_null_identity_size(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)

            def mutate_manifest(entry):
                entry["identity"]["size"] = None

            self._assert_resume_manifest_rejected(
                fixture,
                mutate_manifest=mutate_manifest,
                expected_text="identity.size",
            )

    def test_resume_rejects_manifest_entry_bool_identity_size(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)

            def mutate_manifest(entry):
                entry["identity"]["size"] = True

            self._assert_resume_manifest_rejected(
                fixture,
                mutate_manifest=mutate_manifest,
                expected_text="identity.size",
            )

    def test_resume_rejects_manifest_entry_float_identity_size(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)

            def mutate_manifest(entry):
                entry["identity"]["size"] = 1.5

            self._assert_resume_manifest_rejected(
                fixture,
                mutate_manifest=mutate_manifest,
                expected_text="identity.size",
            )

    def test_resume_rejects_manifest_entry_missing_identity_mtime_ns(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)

            def mutate_manifest(entry):
                entry["identity"].pop("mtime_ns", None)

            self._assert_resume_manifest_rejected(
                fixture,
                mutate_manifest=mutate_manifest,
                expected_text="identity.mtime_ns",
            )

    def test_resume_rejects_manifest_entry_null_identity_mtime_ns(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)

            def mutate_manifest(entry):
                entry["identity"]["mtime_ns"] = None

            self._assert_resume_manifest_rejected(
                fixture,
                mutate_manifest=mutate_manifest,
                expected_text="identity.mtime_ns",
            )

    def test_resume_rejects_manifest_entry_bool_identity_mtime_ns(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)

            def mutate_manifest(entry):
                entry["identity"]["mtime_ns"] = False

            self._assert_resume_manifest_rejected(
                fixture,
                mutate_manifest=mutate_manifest,
                expected_text="identity.mtime_ns",
            )

    def test_resume_rejects_manifest_entry_float_identity_mtime_ns(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)

            def mutate_manifest(entry):
                entry["identity"]["mtime_ns"] = 1.5

            self._assert_resume_manifest_rejected(
                fixture,
                mutate_manifest=mutate_manifest,
                expected_text="identity.mtime_ns",
            )

    def test_resume_rejects_manifest_entry_with_nonnumeric_discovered_order(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]
            entry["discovered_order"] = "not-a-number"
            self.m._save_dataset_manifest(manifest)

            manifest_path = self.m._dataset_manifest_path(fixture["output_root"])
            with open(manifest_path, "rb") as f:
                manifest_before = f.read()

            processor = types.SimpleNamespace(
                successful_archives=[],
                failed_archives=[],
                skipped_archives=[],
            )
            stdout = io.StringIO()

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(
                    self.m,
                    "_recover_all_outputs",
                    side_effect=AssertionError(
                        "recovery should not start for malformed discovered_order"
                    ),
                ),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "extract should not start for malformed discovered_order"
                    ),
                ),
            ):
                result = self.m._run_transactional(
                    processor,
                    [fixture["archive"]["archive_path"]],
                    args=fixture["args"],
                )

            output = stdout.getvalue()
            self.assertFalse(result)
            self.assertIn("discovered_order", output)
            self.assertIn("delete", output.lower())
            self.assertIn(
                os.path.join(fixture["output_root"], ".advdecompress_work"), output
            )
            self.assertEqual([], processor.successful_archives)
            self.assertEqual([], processor.failed_archives)
            self.assertEqual([], processor.skipped_archives)

            with open(manifest_path, "rb") as f:
                self.assertEqual(manifest_before, f.read())

    def test_resume_rejects_manifest_entry_bool_discovered_order(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)

            def mutate_manifest(entry):
                entry["discovered_order"] = True

            self._assert_resume_manifest_rejected(
                fixture,
                mutate_manifest=mutate_manifest,
                expected_text="discovered_order",
            )

    def test_resume_rejects_manifest_entry_float_discovered_order(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)

            def mutate_manifest(entry):
                entry["discovered_order"] = 1.5

            self._assert_resume_manifest_rejected(
                fixture,
                mutate_manifest=mutate_manifest,
                expected_text="discovered_order",
            )

    def test_resume_rejects_manifest_entry_missing_discovered_order(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]
            entry.pop("discovered_order", None)
            self.m._save_dataset_manifest(manifest)

            manifest_path = self.m._dataset_manifest_path(fixture["output_root"])
            with open(manifest_path, "rb") as f:
                manifest_before = f.read()

            processor = types.SimpleNamespace(
                successful_archives=[],
                failed_archives=[],
                skipped_archives=[],
            )
            stdout = io.StringIO()

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(
                    self.m,
                    "_recover_all_outputs",
                    side_effect=AssertionError(
                        "recovery should not start for missing discovered_order"
                    ),
                ),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "extract should not start for missing discovered_order"
                    ),
                ),
            ):
                result = self.m._run_transactional(
                    processor,
                    [fixture["archive"]["archive_path"]],
                    args=fixture["args"],
                )

            output = stdout.getvalue()
            self.assertFalse(result)
            self.assertIn("discovered_order", output)
            self.assertIn("delete", output.lower())
            self.assertIn(
                os.path.join(fixture["output_root"], ".advdecompress_work"), output
            )
            self.assertEqual([], processor.successful_archives)
            self.assertEqual([], processor.failed_archives)
            self.assertEqual([], processor.skipped_archives)

            with open(manifest_path, "rb") as f:
                self.assertEqual(manifest_before, f.read())

    def test_resume_rejects_size_drift(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            recorded_size = manifest["archives"][fixture["archive_id"]]["identity"][
                "size"
            ]

            def mutate_size(archive_path):
                with open(archive_path, "ab") as f:
                    f.write(b"-drift")
                self.assertNotEqual(recorded_size, os.stat(archive_path).st_size)

            self._assert_resume_drift_rejected(
                fixture,
                mutate_archive=mutate_size,
                expected_text="size",
            )

    def test_resume_rejects_mtime_drift(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            recorded_mtime_ns = manifest["archives"][fixture["archive_id"]]["identity"][
                "mtime_ns"
            ]

            def mutate_mtime(archive_path):
                drifted_mtime_ns = recorded_mtime_ns + 5_000_000_000
                os.utime(archive_path, ns=(drifted_mtime_ns, drifted_mtime_ns))
                self.assertNotEqual(
                    recorded_mtime_ns, os.stat(archive_path).st_mtime_ns
                )

            self._assert_resume_drift_rejected(
                fixture,
                mutate_archive=mutate_mtime,
                expected_text="mtime",
            )

    def test_resume_rejects_secondary_volume_drift(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            primary = os.path.join(input_root, "bundle.zip")
            secondary = os.path.join(input_root, "bundle.z01")
            with open(primary, "wb") as f:
                f.write(b"primary")
            with open(secondary, "wb") as f:
                f.write(b"secondary")

            args = self._make_processing_args(
                input_root,
                output=output_root,
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=[
                    {
                        "archive_path": primary,
                        "output_dir": output_root,
                        "volumes": [primary, secondary],
                        "requested_policy": args.decompress_policy,
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )

            processor = types.SimpleNamespace(
                successful_archives=[],
                failed_archives=[],
                skipped_archives=[],
            )
            stdout = io.StringIO()
            os.remove(secondary)

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(
                    self.m,
                    "_recover_all_outputs",
                    side_effect=AssertionError(
                        "recovery should not start before secondary volume drift validation"
                    ),
                ),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "extract should not start before secondary volume drift validation"
                    ),
                ),
            ):
                result = self.m._run_transactional(processor, [primary], args=args)

            output = stdout.getvalue()
            self.assertFalse(result)
            self.assertIn(os.path.abspath(primary), output)
            self.assertIn(os.path.abspath(secondary), output)
            self.assertIn("missing", output.lower())

    def test_resume_uses_frozen_manifest_archive_list(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            alpha_archive = os.path.join(input_root, "alpha.zip")
            with open(alpha_archive, "wb") as f:
                f.write(b"alpha")

            resume_args = self._make_processing_args(
                input_root,
                output=output_root,
                decompress_policy="direct",
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=[
                    {
                        "archive_path": alpha_archive,
                        "output_dir": output_root,
                        "volumes": [alpha_archive],
                        "requested_policy": "direct",
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(resume_args),
            )

            beta_archive = os.path.join(input_root, "beta.zip")
            with open(beta_archive, "wb") as f:
                f.write(b"beta")

            processed = []
            processor = types.SimpleNamespace(
                successful_archives=[],
                failed_archives=[],
                skipped_archives=[],
            )
            processor.find_archives = mock.Mock(
                return_value=[
                    os.path.abspath(alpha_archive),
                    os.path.abspath(beta_archive),
                ]
            )
            stdout = io.StringIO()

            def fake_extract(processor, archive_path, *, args, output_base):
                processed.append(os.path.abspath(archive_path))
                return {
                    "kind": "dry_run",
                    "archive_path": os.path.abspath(archive_path),
                }

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(self.m.sys, "argv", self._argv_for_main(resume_args)),
                mock.patch.object(
                    self.m,
                    "safe_subprocess_run",
                    return_value=SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
                ),
                mock.patch.object(self.m, "ArchiveProcessor", return_value=processor),
                mock.patch.object(self.m, "fix_archive_ext") as fix_archive_ext,
                mock.patch.object(self.m, "_extract_phase", side_effect=fake_extract),
                mock.patch.object(self.m, "_recover_all_outputs"),
                mock.patch.object(self.m, "_garbage_collect"),
            ):
                exit_code = self.m.main()

            self.assertEqual(0, exit_code)
            processor.find_archives.assert_not_called()
            fix_archive_ext.assert_not_called()
            self.assertEqual([os.path.abspath(alpha_archive)], processed)
            self.assertEqual(
                [os.path.abspath(alpha_archive)], processor.skipped_archives
            )
            self.assertNotIn(os.path.abspath(beta_archive), processed)

    def test_resume_skips_terminal_manifest_archives(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            rel_paths = [
                "recover-z.zip",
                "done.zip",
                "failed.zip",
                "recover-a.zip",
                "retry.zip",
                "pending.zip",
            ]
            discovered = self._make_discovered_archives(
                input_root, output_root, rel_paths
            )
            args = self._make_processing_args(
                input_root,
                output=output_root,
                decompress_policy="direct",
                threads=1,
                success_clean_journal=False,
                fail_clean_journal=False,
            )

            with mock.patch.object(
                self.m.uuid,
                "uuid4",
                side_effect=[
                    SimpleNamespace(hex="manifestrun"),
                    SimpleNamespace(hex="zeta"),
                    SimpleNamespace(hex="alpha"),
                ],
            ):
                manifest = self.m._create_dataset_manifest(
                    input_root=input_root,
                    output_root=output_root,
                    discovered_archives=discovered,
                    command_fingerprint=self.m._build_command_fingerprint(args),
                )
                recover_z_txn = self.m._txn_create(
                    archive_path=discovered[0]["archive_path"],
                    volumes=discovered[0]["volumes"],
                    output_dir=discovered[0]["output_dir"],
                    output_base=output_root,
                    policy="direct",
                    wal_fsync_every=1,
                    snapshot_every=1,
                    durability_enabled=False,
                )
                recover_a_txn = self.m._txn_create(
                    archive_path=discovered[3]["archive_path"],
                    volumes=discovered[3]["volumes"],
                    output_dir=discovered[3]["output_dir"],
                    output_base=output_root,
                    policy="direct",
                    wal_fsync_every=1,
                    snapshot_every=1,
                    durability_enabled=False,
                )

            recover_z_txn["state"] = self.m.TXN_STATE_EXTRACTED
            recover_a_txn["state"] = self.m.TXN_STATE_EXTRACTED
            self.m._txn_snapshot(recover_z_txn)
            self.m._txn_snapshot(recover_a_txn)

            archive_ids = [
                self.m._dataset_manifest_archive_id(item["archive_path"])
                for item in discovered
            ]
            manifest["archives"][archive_ids[0]]["state"] = "recoverable"
            manifest["archives"][archive_ids[1]]["state"] = "succeeded"
            manifest["archives"][archive_ids[2]]["state"] = "failed"
            manifest["archives"][archive_ids[3]]["state"] = "recoverable"
            manifest["archives"][archive_ids[4]]["state"] = "retryable"
            manifest["archives"][archive_ids[5]]["state"] = "pending"
            self.m._save_dataset_manifest(manifest)

            events = []
            processor = types.SimpleNamespace(
                successful_archives=[],
                failed_archives=[],
                skipped_archives=[],
            )

            def fake_place_and_finalize(txn, *, args, recovery=False):
                self.assertTrue(recovery)
                events.append(f"recover:{os.path.basename(txn['archive_path'])}")

            def fake_extract(processor, archive_path, *, args, output_base):
                archive_path = os.path.abspath(archive_path)
                events.append(f"extract:{os.path.basename(archive_path)}")
                return {"kind": "dry_run", "archive_path": archive_path}

            with (
                mock.patch.object(
                    self.m,
                    "_place_and_finalize_txn",
                    side_effect=fake_place_and_finalize,
                ),
                mock.patch.object(self.m, "_extract_phase", side_effect=fake_extract),
                mock.patch.object(self.m, "_garbage_collect"),
                mock.patch.object(self.m, "FileLock", DummyLock),
            ):
                self.m._run_transactional(
                    processor,
                    [item["archive_path"] for item in discovered],
                    args=args,
                )

            self.assertEqual(
                [
                    "recover:recover-z.zip",
                    "recover:recover-a.zip",
                    "extract:retry.zip",
                    "extract:pending.zip",
                ],
                events,
            )
            self.assertNotIn("extract:done.zip", events)
            self.assertNotIn("extract:failed.zip", events)
            self.assertNotIn("recover:done.zip", events)
            self.assertNotIn("recover:failed.zip", events)
            self.assertEqual(
                [
                    os.path.abspath(discovered[4]["archive_path"]),
                    os.path.abspath(discovered[5]["archive_path"]),
                ],
                processor.skipped_archives,
            )

    def test_resume_recovers_manifest_order_across_output_dirs(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                [
                    os.path.join("z-dir", "first.zip"),
                    os.path.join("a-dir", "second.zip"),
                ],
            )
            args = self._make_processing_args(
                input_root,
                output=output_root,
                decompress_policy="direct",
                threads=1,
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            manifest = self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=discovered,
                command_fingerprint=self.m._build_command_fingerprint(args),
            )

            first_txn = self.m._txn_create(
                archive_path=discovered[0]["archive_path"],
                volumes=discovered[0]["volumes"],
                output_dir=discovered[0]["output_dir"],
                output_base=output_root,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            second_txn = self.m._txn_create(
                archive_path=discovered[1]["archive_path"],
                volumes=discovered[1]["volumes"],
                output_dir=discovered[1]["output_dir"],
                output_base=output_root,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            first_txn["state"] = self.m.TXN_STATE_EXTRACTED
            second_txn["state"] = self.m.TXN_STATE_EXTRACTED
            self.m._txn_snapshot(first_txn)
            self.m._txn_snapshot(second_txn)

            archive_ids = [
                self.m._dataset_manifest_archive_id(item["archive_path"])
                for item in discovered
            ]
            manifest["archives"][archive_ids[0]]["state"] = "recoverable"
            manifest["archives"][archive_ids[1]]["state"] = "recoverable"
            self.m._save_dataset_manifest(manifest)

            events = []
            processor = types.SimpleNamespace(
                successful_archives=[],
                failed_archives=[],
                skipped_archives=[],
            )

            def fake_place_and_finalize(txn, *, args, recovery=False):
                self.assertTrue(recovery)
                events.append(os.path.basename(txn["archive_path"]))

            with (
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "recoverable manifest work should recover before any extraction"
                    ),
                ),
                mock.patch.object(
                    self.m,
                    "_place_and_finalize_txn",
                    side_effect=fake_place_and_finalize,
                ),
                mock.patch.object(self.m, "_garbage_collect"),
                mock.patch.object(self.m, "FileLock", DummyLock),
            ):
                self.m._run_transactional(
                    processor,
                    [item["archive_path"] for item in discovered],
                    args=args,
                )

            self.assertEqual(["first.zip", "second.zip"], events)

    def test_resume_recovers_interleaved_manifest_order_across_output_dirs(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                [
                    os.path.join("x", "first.zip"),
                    os.path.join("y", "second.zip"),
                    os.path.join("x", "third.zip"),
                ],
            )
            args = self._make_processing_args(
                input_root,
                output=output_root,
                decompress_policy="direct",
                threads=1,
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            manifest = self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=discovered,
                command_fingerprint=self.m._build_command_fingerprint(args),
            )

            txns = []
            for item in discovered:
                txn = self.m._txn_create(
                    archive_path=item["archive_path"],
                    volumes=item["volumes"],
                    output_dir=item["output_dir"],
                    output_base=output_root,
                    policy="direct",
                    wal_fsync_every=1,
                    snapshot_every=1,
                    durability_enabled=False,
                )
                txn["state"] = self.m.TXN_STATE_EXTRACTED
                self.m._txn_snapshot(txn)
                txns.append(txn)

            archive_ids = [
                self.m._dataset_manifest_archive_id(item["archive_path"])
                for item in discovered
            ]
            for archive_id in archive_ids:
                manifest["archives"][archive_id]["state"] = "recoverable"
            self.m._save_dataset_manifest(manifest)

            events = []
            processor = types.SimpleNamespace(
                successful_archives=[],
                failed_archives=[],
                skipped_archives=[],
            )

            def fake_place_and_finalize(txn, *, args, recovery=False):
                self.assertTrue(recovery)
                events.append(os.path.basename(txn["archive_path"]))

            with (
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "recoverable manifest work should recover before any extraction"
                    ),
                ),
                mock.patch.object(
                    self.m,
                    "_place_and_finalize_txn",
                    side_effect=fake_place_and_finalize,
                ),
                mock.patch.object(self.m, "_garbage_collect"),
                mock.patch.object(self.m, "FileLock", DummyLock),
            ):
                self.m._run_transactional(
                    processor,
                    [item["archive_path"] for item in discovered],
                    args=args,
                )

            self.assertEqual(["first.zip", "second.zip", "third.zip"], events)

    def test_resume_uses_same_txn_selection_for_planning_and_recovery(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                ["archive.zip"],
            )
            args = self._make_processing_args(
                input_root,
                output=output_root,
                decompress_policy="direct",
                threads=1,
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            archive_info = discovered[0]
            with mock.patch.object(
                self.m.uuid,
                "uuid4",
                side_effect=[
                    SimpleNamespace(hex="manifestrun"),
                    SimpleNamespace(hex="zzz-older"),
                    SimpleNamespace(hex="aaa-newer"),
                ],
            ):
                manifest = self.m._create_dataset_manifest(
                    input_root=input_root,
                    output_root=output_root,
                    discovered_archives=discovered,
                    command_fingerprint=self.m._build_command_fingerprint(args),
                )
                older_txn = self.m._txn_create(
                    archive_path=archive_info["archive_path"],
                    volumes=archive_info["volumes"],
                    output_dir=archive_info["output_dir"],
                    output_base=output_root,
                    policy="direct",
                    wal_fsync_every=1,
                    snapshot_every=1,
                    durability_enabled=False,
                )
                newer_txn = self.m._txn_create(
                    archive_path=archive_info["archive_path"],
                    volumes=archive_info["volumes"],
                    output_dir=archive_info["output_dir"],
                    output_base=output_root,
                    policy="direct",
                    wal_fsync_every=1,
                    snapshot_every=1,
                    durability_enabled=False,
                )

            older_txn["state"] = self.m.TXN_STATE_EXTRACTED
            self.m._txn_snapshot(older_txn)
            newer_txn["state"] = self.m.TXN_STATE_EXTRACTED
            self.m._txn_snapshot(newer_txn)

            older_txn_json = older_txn["paths"]["txn_json"]
            newer_txn_json = newer_txn["paths"]["txn_json"]
            older_dir = older_txn["paths"]["journal_dir"]
            newer_dir = newer_txn["paths"]["journal_dir"]
            os.utime(older_txn_json, (10, 10))
            os.utime(older_dir, (10, 10))
            os.utime(newer_txn_json, (20, 20))
            os.utime(newer_dir, (20, 20))

            archive_id = self.m._dataset_manifest_archive_id(
                archive_info["archive_path"]
            )
            manifest["archives"][archive_id]["state"] = "recoverable"
            self.m._save_dataset_manifest(manifest)

            selected_txn = self.m._load_latest_txn_for_archive(
                manifest["archives"][archive_id], output_root
            )
            self.assertEqual("aaa-newer", selected_txn["txn_id"])

            resumed_txn_ids = []
            processor = types.SimpleNamespace(
                successful_archives=[],
                failed_archives=[],
                skipped_archives=[],
            )

            def fake_place_and_finalize(txn, *, args, recovery=False):
                self.assertTrue(recovery)
                resumed_txn_ids.append(txn["txn_id"])

            with (
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "recoverable manifest work should recover before any extraction"
                    ),
                ),
                mock.patch.object(
                    self.m,
                    "_place_and_finalize_txn",
                    side_effect=fake_place_and_finalize,
                ),
                mock.patch.object(self.m, "_garbage_collect"),
                mock.patch.object(self.m, "FileLock", DummyLock),
            ):
                self.m._run_transactional(
                    processor,
                    [archive_info["archive_path"]],
                    args=args,
                )

            self.assertEqual(["aaa-newer"], resumed_txn_ids)

    def test_run_transactional_threaded_resume_waits_for_retryable_phase_before_pending(
        self,
    ):
        submitted = []
        events = []
        tracker = {"outstanding": 0, "max_outstanding": 0}
        retry_finalized = threading.Event()

        FakeExecutor = self._make_async_executor_class(
            submitted=submitted,
            event_log=events,
            tracker=tracker,
        )

        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                ["retry.zip", "pending.zip"],
            )
            args = self._make_processing_args(
                input_root,
                output=output_root,
                decompress_policy="direct",
                threads=2,
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            manifest = self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=discovered,
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            archive_ids = [
                self.m._dataset_manifest_archive_id(item["archive_path"])
                for item in discovered
            ]
            manifest["archives"][archive_ids[0]]["state"] = "retryable"
            manifest["archives"][archive_ids[1]]["state"] = "pending"
            self.m._save_dataset_manifest(manifest)

            processor = types.SimpleNamespace(
                successful_archives=[],
                failed_archives=[],
                skipped_archives=[],
            )

            def fake_extract(processor, archive_path, *, args, output_base):
                name = os.path.basename(archive_path)
                events.append(f"extract-start:{name}")
                if name == "pending.zip":
                    self.assertTrue(retry_finalized.is_set())
                    self.assertIn("finalize:retry.zip", events)
                events.append(f"extract-end:{name}")
                return self._make_txn_result(
                    archive_path,
                    output_dir=os.path.join(output_base, name.replace(".zip", "")),
                    output_base=output_base,
                )

            def fake_finalize(txn, *, processor, args, output_base):
                name = os.path.basename(txn["archive_path"])
                events.append(f"finalize:{name}")
                processor.successful_archives.append(txn["archive_path"])
                if name == "retry.zip":
                    retry_finalized.set()

            with (
                mock.patch.object(self.m, "ThreadPoolExecutor", FakeExecutor),
                mock.patch.object(self.m, "_extract_phase", side_effect=fake_extract),
                mock.patch.object(
                    self.m, "_finalize_one_txn", side_effect=fake_finalize
                ),
                mock.patch.object(self.m, "_recover_all_outputs"),
                mock.patch.object(self.m, "_garbage_collect"),
                mock.patch.object(self.m, "FileLock", DummyLock),
            ):
                self.m._run_transactional(
                    processor,
                    [item["archive_path"] for item in discovered],
                    args=args,
                )

            self.assertEqual(["retry.zip", "pending.zip"], submitted)
            self.assertLess(
                events.index("finalize:retry.zip"),
                events.index("extract-start:pending.zip"),
            )
            self.assertEqual(
                ["retry.zip", "pending.zip"],
                [os.path.basename(path) for path in processor.successful_archives],
            )

    def test_manifest_marks_archive_extracting_before_extract(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                ["alpha.zip"],
            )
            args = self._make_processing_args(
                input_root,
                output=output_root,
                decompress_policy="direct",
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=discovered,
                command_fingerprint=self.m._build_command_fingerprint(args),
            )

            archive_path = discovered[0]["archive_path"]
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            observed = {}
            processor = types.SimpleNamespace(
                sfx_detector=None,
                get_all_volumes=lambda path: [os.path.abspath(path)],
            )

            def fake_try_extract(
                archive_path,
                password,
                staging_dir,
                zip_decode,
                enable_rar,
                sfx_detector,
                detect_elf_sfx=False,
            ):
                manifest = self.m._load_dataset_manifest(output_root)
                entry = manifest["archives"][archive_id]
                observed.update(
                    {
                        "state": entry["state"],
                        "attempts": entry["attempts"],
                        "last_txn_id": entry["last_txn_id"],
                        "final_disposition": entry["final_disposition"],
                        "error": entry["error"],
                    }
                )
                return True

            with (
                mock.patch.object(self.m, "_validate_environment_for_output_dir"),
                mock.patch.object(self.m, "try_extract", side_effect=fake_try_extract),
                mock.patch.object(
                    self.m, "validate_extracted_tree", return_value=(True, "")
                ),
                mock.patch.object(self.m, "count_items_in_dir", return_value=(1, 0)),
            ):
                result = self.m._extract_phase(
                    processor,
                    archive_path,
                    args=args,
                    output_base=output_root,
                )

            self.assertEqual("txn", result["kind"])
            self.assertEqual("extracting", observed["state"])
            self.assertEqual(1, observed["attempts"])
            self.assertEqual(result["txn"]["txn_id"], observed["last_txn_id"])
            self.assertEqual("unknown", observed["final_disposition"])
            self.assertIsNone(observed["error"])

    def test_manifest_marks_archive_recoverable_from_txn_state(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                ["alpha.zip"],
            )
            args = self._make_processing_args(
                input_root,
                output=output_root,
                decompress_policy="direct",
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=discovered,
                command_fingerprint=self.m._build_command_fingerprint(args),
            )

            archive_path = discovered[0]["archive_path"]
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            processor = types.SimpleNamespace(
                sfx_detector=None,
                get_all_volumes=lambda path: [os.path.abspath(path)],
            )

            with (
                mock.patch.object(self.m, "_validate_environment_for_output_dir"),
                mock.patch.object(self.m, "try_extract", return_value=True),
                mock.patch.object(
                    self.m, "validate_extracted_tree", return_value=(True, "")
                ),
                mock.patch.object(self.m, "count_items_in_dir", return_value=(1, 0)),
            ):
                result = self.m._extract_phase(
                    processor,
                    archive_path,
                    args=args,
                    output_base=output_root,
                )

            manifest = self.m._load_dataset_manifest(output_root)
            entry = manifest["archives"][archive_id]

            self.assertEqual("txn", result["kind"])
            self.assertEqual(self.m.TXN_STATE_EXTRACTED, result["txn"]["state"])
            self.assertEqual("recoverable", entry["state"])
            self.assertEqual(result["txn"]["txn_id"], entry["last_txn_id"])
            self.assertEqual(1, entry["attempts"])
            self.assertEqual("unknown", entry["final_disposition"])
            self.assertIsNone(entry["error"])

    def test_manifest_marks_archive_retryable_after_nonrecoverable_abort(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                ["alpha.zip"],
            )
            args = self._make_processing_args(
                input_root,
                output=output_root,
                decompress_policy="direct",
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=discovered,
                command_fingerprint=self.m._build_command_fingerprint(args),
            )

            archive_path = discovered[0]["archive_path"]
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            processor = types.SimpleNamespace(
                sfx_detector=None,
                get_all_volumes=lambda path: [os.path.abspath(path)],
            )

            with (
                mock.patch.object(self.m, "_validate_environment_for_output_dir"),
                mock.patch.object(
                    self.m,
                    "try_extract",
                    side_effect=KeyboardInterrupt("stop during extract"),
                ),
            ):
                with self.assertRaises(KeyboardInterrupt):
                    self.m._extract_phase(
                        processor,
                        archive_path,
                        args=args,
                        output_base=output_root,
                    )

            manifest = self.m._load_dataset_manifest(output_root)
            recoverable_archives, retryable_archives, pending_archives = (
                self.m._build_transactional_archive_plan(manifest, output_root)
            )
            manifest = self.m._load_dataset_manifest(output_root)
            entry = manifest["archives"][archive_id]

            self.assertEqual([], recoverable_archives)
            self.assertEqual([os.path.abspath(archive_path)], retryable_archives)
            self.assertEqual([], pending_archives)
            self.assertEqual("retryable", entry["state"])
            self.assertEqual(1, entry["attempts"])
            self.assertIsNotNone(entry["last_txn_id"])
            self.assertEqual("unknown", entry["final_disposition"])
            self.assertEqual("ABORTED", entry["error"]["type"])

    def test_aborted_with_staging_is_recoverable(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_aborted_manifest_txn_fixture(
                td,
                manifest_state="pending",
            )
            staging_extracted = fixture["txn"]["paths"]["staging_extracted"]
            os.makedirs(staging_extracted, exist_ok=True)
            with open(
                os.path.join(staging_extracted, "payload.txt"),
                "w",
                encoding="utf-8",
            ) as f:
                f.write("payload")

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]

            self.assertEqual(
                "recoverable",
                self.m._classify_manifest_archive_state(entry, fixture["output_root"]),
            )

    def test_aborted_with_incoming_is_recoverable(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_aborted_manifest_txn_fixture(
                td,
                manifest_state="pending",
            )
            incoming_dir = fixture["txn"]["paths"]["incoming_dir"]
            os.makedirs(incoming_dir, exist_ok=True)
            with open(
                os.path.join(incoming_dir, "payload.txt"),
                "w",
                encoding="utf-8",
            ) as f:
                f.write("payload")

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]

            self.assertEqual(
                "recoverable",
                self.m._classify_manifest_archive_state(entry, fixture["output_root"]),
            )

    def test_aborted_with_conflicting_staging_and_incoming_is_retryable(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_aborted_manifest_txn_fixture(
                td,
                manifest_state="pending",
            )
            staging_extracted = fixture["txn"]["paths"]["staging_extracted"]
            incoming_dir = fixture["txn"]["paths"]["incoming_dir"]
            os.makedirs(staging_extracted, exist_ok=True)
            os.makedirs(incoming_dir, exist_ok=True)
            with open(
                os.path.join(staging_extracted, "staging.txt"),
                "w",
                encoding="utf-8",
            ) as f:
                f.write("staging")
            with open(
                os.path.join(incoming_dir, "incoming.txt"),
                "w",
                encoding="utf-8",
            ) as f:
                f.write("incoming")

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]

            self.assertEqual(
                "retryable",
                self.m._classify_manifest_archive_state(entry, fixture["output_root"]),
            )

    def test_aborted_with_resumable_wal_is_recoverable(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_aborted_manifest_txn_fixture(
                td,
                manifest_state="pending",
            )
            txn = fixture["txn"]
            dst = os.path.join(fixture["archive"]["output_dir"], "payload.txt")
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "w", encoding="utf-8") as f:
                f.write("placed")

            with open(txn["paths"]["wal"], "w", encoding="utf-8") as f:
                f.write(
                    json.dumps(
                        {
                            "t": "MOVE_PLAN",
                            "id": 1,
                            "src": os.path.join(
                                txn["paths"]["incoming_dir"],
                                "payload.txt",
                            ),
                            "dst": dst,
                        }
                    )
                    + "\n"
                )

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]

            self.assertEqual(
                "recoverable",
                self.m._classify_manifest_archive_state(entry, fixture["output_root"]),
            )

    def test_aborted_without_assets_is_retryable(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_aborted_manifest_txn_fixture(
                td,
                manifest_state="pending",
            )
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]

            self.assertEqual(
                "retryable",
                self.m._classify_manifest_archive_state(entry, fixture["output_root"]),
            )

    def test_resume_reclassifies_aborted_instead_of_skipping(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_aborted_manifest_txn_fixture(
                td,
                manifest_state="pending",
            )
            staging_extracted = fixture["txn"]["paths"]["staging_extracted"]
            os.makedirs(staging_extracted, exist_ok=True)
            with open(
                os.path.join(staging_extracted, "payload.txt"),
                "w",
                encoding="utf-8",
            ) as f:
                f.write("payload")

            recovered = []
            processor = types.SimpleNamespace(
                successful_archives=[],
                failed_archives=[],
                skipped_archives=[],
            )

            def fake_place_and_finalize(txn, *, args, recovery=False):
                self.assertTrue(recovery)
                recovered.append(os.path.basename(txn["archive_path"]))

            with (
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "recoverable aborted work should not be re-extracted"
                    ),
                ),
                mock.patch.object(
                    self.m,
                    "_place_and_finalize_txn",
                    side_effect=fake_place_and_finalize,
                ),
                mock.patch.object(self.m, "_garbage_collect"),
                mock.patch.object(self.m, "FileLock", DummyLock),
            ):
                self.m._run_transactional(
                    processor,
                    [fixture["archive"]["archive_path"]],
                    args=fixture["args"],
                )

            self.assertEqual(["alpha.zip"], recovered)

    def test_place_and_finalize_recovers_aborted_with_staging(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_aborted_manifest_txn_fixture(
                td,
                manifest_state="pending",
            )
            txn = fixture["txn"]
            staging_extracted = txn["paths"]["staging_extracted"]
            os.makedirs(staging_extracted, exist_ok=True)
            with open(
                os.path.join(staging_extracted, "payload.txt"),
                "w",
                encoding="utf-8",
            ) as f:
                f.write("payload")

            self.m._place_and_finalize_txn(txn, args=fixture["args"], recovery=True)

            with open(txn["paths"]["txn_json"], "r", encoding="utf-8") as f:
                saved_txn = json.load(f)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]

            self.assertEqual(self.m.TXN_STATE_DONE, saved_txn["state"])
            self.assertTrue(
                os.path.exists(
                    os.path.join(fixture["archive"]["output_dir"], "payload.txt")
                )
            )
            self.assertEqual("succeeded", entry["state"])

    def test_manifest_marks_archive_terminal_after_finalize(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                ["success.zip", "failure.zip"],
            )
            args = self._make_processing_args(
                input_root,
                output=output_root,
                decompress_policy="direct",
                success_policy="asis",
                fail_policy="asis",
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=discovered,
                command_fingerprint=self.m._build_command_fingerprint(args),
            )

            success_archive = discovered[0]
            success_txn = self.m._txn_create(
                archive_path=success_archive["archive_path"],
                volumes=success_archive["volumes"],
                output_dir=success_archive["output_dir"],
                output_base=output_root,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            success_txn["state"] = self.m.TXN_STATE_CLEANED
            self.m._txn_snapshot(success_txn)

            success_processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            with mock.patch.object(self.m, "FileLock", DummyLock):
                ok = self.m._finalize_one_txn(
                    success_txn,
                    processor=success_processor,
                    args=args,
                    output_base=output_root,
                )
            self.assertTrue(ok)

            manifest = self.m._load_dataset_manifest(output_root)
            success_id = self.m._dataset_manifest_archive_id(
                success_archive["archive_path"]
            )
            success_entry = manifest["archives"][success_id]
            self.assertEqual("succeeded", success_entry["state"])
            self.assertEqual("success:asis", success_entry["final_disposition"])
            self.assertEqual(success_txn["txn_id"], success_entry["last_txn_id"])
            self.assertIsNone(success_entry["error"])

            failure_archive = discovered[1]
            failure_txn = self.m._txn_create(
                archive_path=failure_archive["archive_path"],
                volumes=failure_archive["volumes"],
                output_dir=failure_archive["output_dir"],
                output_base=output_root,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            failure_txn["state"] = self.m.TXN_STATE_FAILED
            failure_txn["error"] = {
                "type": "EXTRACT_FAILED",
                "message": "boom",
                "at": self.m._now_iso(),
            }
            self.m._txn_snapshot(failure_txn)

            failure_processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            touched_output_dirs = set()
            self.m._handle_transactional_result(
                {"kind": "txn_failed", "txn": failure_txn},
                processor=failure_processor,
                args=args,
                output_base=output_root,
                touched_output_dirs=touched_output_dirs,
            )

            manifest = self.m._load_dataset_manifest(output_root)
            failure_id = self.m._dataset_manifest_archive_id(
                failure_archive["archive_path"]
            )
            failure_entry = manifest["archives"][failure_id]
            self.assertEqual("failed", failure_entry["state"])
            self.assertEqual("failure:asis", failure_entry["final_disposition"])
            self.assertEqual(failure_txn["txn_id"], failure_entry["last_txn_id"])
            self.assertEqual(failure_txn["error"], failure_entry["error"])

    def test_fsync_file_windows_uses_rdwr_before_wronly(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name

        try:
            with (
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(self.m.os, "open", return_value=99) as open_mock,
                mock.patch.object(self.m.os, "fsync") as fsync_mock,
                mock.patch.object(self.m.os, "close") as close_mock,
            ):
                result = self.m._fsync_file(temp_path)

            self.assertTrue(result)
            open_mock.assert_called_once()
            self.assertEqual(
                self.m.os.O_RDWR | self._windows_binary_flag(),
                open_mock.call_args_list[0].args[1],
            )
            fsync_mock.assert_called_once_with(99)
            close_mock.assert_called_once_with(99)
        finally:
            os.unlink(temp_path)

    def test_fsync_file_windows_falls_back_to_wronly(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name

        try:
            with (
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(
                    self.m.os,
                    "open",
                    side_effect=[OSError("rdwr failed"), 123],
                ) as open_mock,
                mock.patch.object(self.m.os, "fsync") as fsync_mock,
                mock.patch.object(self.m.os, "close") as close_mock,
            ):
                result = self.m._fsync_file(temp_path)

            self.assertTrue(result)
            self.assertEqual(2, open_mock.call_count)
            self.assertEqual(
                self.m.os.O_WRONLY | self._windows_binary_flag(),
                open_mock.call_args_list[1].args[1],
            )
            fsync_mock.assert_called_once_with(123)
            close_mock.assert_called_once_with(123)
        finally:
            os.unlink(temp_path)

    def test_fsync_file_windows_returns_false_when_all_opens_fail(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name

        try:
            with (
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(
                    self.m.os,
                    "open",
                    side_effect=[OSError("rdwr failed"), OSError("wronly failed")],
                ) as open_mock,
                mock.patch.object(self.m.os, "fsync") as fsync_mock,
            ):
                result = self.m._fsync_file(temp_path)

            self.assertFalse(result)
            self.assertEqual(2, open_mock.call_count)
            fsync_mock.assert_not_called()
        finally:
            os.unlink(temp_path)

    def test_fsync_file_windows_returns_false_when_fsync_fails(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name

        try:
            with (
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(self.m.os, "open", return_value=456) as open_mock,
                mock.patch.object(
                    self.m.os,
                    "fsync",
                    side_effect=OSError("fsync failed"),
                ) as fsync_mock,
                mock.patch.object(self.m.os, "close") as close_mock,
            ):
                result = self.m._fsync_file(temp_path)

            self.assertFalse(result)
            open_mock.assert_called_once()
            fsync_mock.assert_called_once_with(456)
            close_mock.assert_called_once_with(456)
        finally:
            os.unlink(temp_path)

    def test_fsync_file_linux_host_succeeds_for_real_file(self):
        with tempfile.TemporaryDirectory() as td:
            temp_path = os.path.join(td, "payload.bin")
            mocked_file = mock.MagicMock()
            mocked_file.__enter__.return_value = mocked_file
            mocked_file.__exit__.return_value = False
            mocked_file.fileno.return_value = 321

            with (
                mock.patch.object(self.m.os, "name", "posix"),
                mock.patch.object(
                    self.m,
                    "open",
                    return_value=mocked_file,
                    create=True,
                ) as open_mock,
                mock.patch.object(self.m.os, "fsync") as fsync_mock,
            ):
                self.assertTrue(self.m._fsync_file(temp_path))

            open_mock.assert_called_once_with(temp_path, "rb")
            mocked_file.fileno.assert_called_once_with()
            fsync_mock.assert_called_once_with(321)

    def test_delete_success_policy_requires_payload_durability_barrier(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_delete_barrier_txn_fixture(td)
            events = []
            real_atomic_rename = self.m._atomic_rename
            archive_path = os.path.abspath(fixture["archive_path"])
            expected_payload_files = [
                os.path.abspath(path) for path in fixture["expected_payload_files"]
            ]
            expected_payload_dirs = [
                os.path.abspath(path) for path in fixture["expected_payload_dirs"]
            ]

            def fake_fsync_file(path, debug=False):
                events.append(("fsync_file", os.path.abspath(path)))
                return True

            def fake_fsync_dir(path, debug=False):
                events.append(("fsync_dir", os.path.abspath(path)))
                return True

            def tracking_atomic_rename(
                src, dst, *, degrade_cross_volume=False, debug=False
            ):
                src_abs = os.path.abspath(src)
                dst_abs = os.path.abspath(dst)
                if src_abs == archive_path:
                    events.append(("delete_source", src_abs, dst_abs))
                return real_atomic_rename(
                    src,
                    dst,
                    degrade_cross_volume=degrade_cross_volume,
                    debug=debug,
                )

            with (
                mock.patch.object(self.m, "_fsync_file", side_effect=fake_fsync_file),
                mock.patch.object(self.m, "_fsync_dir", side_effect=fake_fsync_dir),
                mock.patch.object(
                    self.m, "_atomic_rename", side_effect=tracking_atomic_rename
                ),
            ):
                self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

            payload_file_events = [
                path
                for kind, path, *_rest in events
                if kind == "fsync_file" and path in expected_payload_files
            ]
            payload_dir_events = [
                path
                for kind, path, *_rest in events
                if kind == "fsync_dir" and path in expected_payload_dirs
            ]
            delete_index = next(
                i for i, event in enumerate(events) if event[0] == "delete_source"
            )
            payload_file_indices = [
                i
                for i, event in enumerate(events)
                if event[0] == "fsync_file" and event[1] in expected_payload_files
            ]
            payload_dir_indices = [
                i
                for i, event in enumerate(events)
                if event[0] == "fsync_dir" and event[1] in expected_payload_dirs
            ]

            self.assertCountEqual(expected_payload_files, payload_file_events)
            self.assertEqual(expected_payload_dirs, payload_dir_events)
            self.assertLess(max(payload_file_indices), min(payload_dir_indices))
            self.assertLess(max(payload_dir_indices), delete_index)

    def test_delete_rejects_fsync_files_none(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            args = self._make_processing_args(
                input_root,
                output=output_root,
                success_policy="delete",
                fsync_files="none",
            )
            processor = types.SimpleNamespace(
                find_archives=mock.Mock(return_value=[]),
                successful_archives=[],
                failed_archives=[],
                skipped_archives=[],
            )
            stdout = io.StringIO()

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(self.m.sys, "argv", self._argv_for_main(args)),
                mock.patch.object(
                    self.m,
                    "safe_subprocess_run",
                    return_value=SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
                ),
                mock.patch.object(self.m, "ArchiveProcessor", return_value=processor),
                mock.patch.object(self.m, "fix_archive_ext") as fix_archive_ext,
            ):
                exit_code = self.m.main()

            self.assertEqual(1, exit_code)
            self.assertIn(
                "Transactional source-mutating finalization requires durability",
                stdout.getvalue(),
            )
            self.assertIn("--fsync-files none", stdout.getvalue())
            fix_archive_ext.assert_not_called()
            processor.find_archives.assert_not_called()

    def test_delete_rejects_no_durability(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            args = self._make_processing_args(
                input_root,
                output=output_root,
                success_policy="delete",
                no_durability=True,
            )
            processor = types.SimpleNamespace(
                find_archives=mock.Mock(return_value=[]),
                successful_archives=[],
                failed_archives=[],
                skipped_archives=[],
            )
            stdout = io.StringIO()

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(self.m.sys, "argv", self._argv_for_main(args)),
                mock.patch.object(
                    self.m,
                    "safe_subprocess_run",
                    return_value=SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
                ),
                mock.patch.object(self.m, "ArchiveProcessor", return_value=processor),
                mock.patch.object(self.m, "fix_archive_ext") as fix_archive_ext,
            ):
                exit_code = self.m.main()

            self.assertEqual(1, exit_code)
            self.assertIn(
                "Transactional source-mutating finalization requires durability",
                stdout.getvalue(),
            )
            self.assertIn("--no-durability", stdout.getvalue())
            fix_archive_ext.assert_not_called()
            processor.find_archives.assert_not_called()

    def test_main_help_omits_removed_windows_delete_flag(self):
        stdout = io.StringIO()

        with (
            contextlib.redirect_stdout(stdout),
            mock.patch.object(self.m.sys, "argv", ["advDecompress.py", "--help"]),
            self.assertRaises(SystemExit) as ctx,
        ):
            self.m.main()

        self.assertEqual(0, ctx.exception.code)
        help_text = " ".join(stdout.getvalue().split())
        help_text = help_text.replace(
            "--unsafe- windows-delete", "--unsafe-windows-delete"
        )
        self.assertNotIn("--unsafe-windows-delete", help_text)
        self.assertNotIn("best-effort payload directory durability", help_text)

    def test_main_help_describes_fsync_files_for_transactional_source_mutation(self):
        stdout = io.StringIO()

        with (
            contextlib.redirect_stdout(stdout),
            mock.patch.object(self.m.sys, "argv", ["advDecompress.py", "--help"]),
            self.assertRaises(SystemExit) as ctx,
        ):
            self.m.main()

        self.assertEqual(0, ctx.exception.code)
        help_text = " ".join(stdout.getvalue().split())
        self.assertNotIn("when transactional -sp delete is used", help_text)
        self.assertIn(
            "when transactional source-mutating finalization is used",
            help_text,
        )

    def test_main_rejects_fingerprint_mismatch_after_windows_delete_surface_cleanup(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                ["alpha.zip"],
            )
            safe_args = self._make_processing_args(
                input_root,
                output=output_root,
                success_policy="delete",
            )
            mismatched_args = self._make_processing_args(
                input_root,
                output=output_root,
                success_policy="delete",
                traditional_zip_policy="asis",
            )

            with mock.patch.object(self.m.os, "name", "nt"):
                baseline_fingerprint = self.m._build_command_fingerprint(mismatched_args)

            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=discovered,
                command_fingerprint=baseline_fingerprint,
            )

            txn = self.m._txn_create(
                archive_path=discovered[0]["archive_path"],
                volumes=discovered[0]["volumes"],
                output_dir=discovered[0]["output_dir"],
                output_base=output_root,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_EXTRACTED
            self.m._txn_snapshot(txn)

            manifest_path = self.m._dataset_manifest_path(output_root)
            txn_json_path = txn["paths"]["txn_json"]
            with open(manifest_path, "rb") as f:
                manifest_before = f.read()
            with open(txn_json_path, "rb") as f:
                txn_before = f.read()

            stdout = io.StringIO()

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(self.m.sys, "argv", self._argv_for_main(safe_args)),
                mock.patch.object(
                    self.m,
                    "safe_subprocess_run",
                    return_value=SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
                ),
                mock.patch.object(self.m, "fix_archive_ext") as fix_archive_ext,
                mock.patch.object(
                    self.m,
                    "ArchiveProcessor",
                    side_effect=AssertionError(
                        "ArchiveProcessor should not be constructed before strict resume rejection"
                    ),
                ),
            ):
                exit_code = self.m.main()

            output = stdout.getvalue()
            self.assertEqual(1, exit_code)
            self.assertIn("command fingerprint", output.lower())
            self.assertNotIn("--unsafe-windows-delete", output)
            self.assertIn(
                os.path.join(output_root, ".advdecompress_work"),
                output,
            )
            self.assertIn("delete", output.lower())
            fix_archive_ext.assert_not_called()

            with open(manifest_path, "rb") as f:
                self.assertEqual(manifest_before, f.read())
            with open(txn_json_path, "rb") as f:
                self.assertEqual(txn_before, f.read())

    def test_main_allows_windows_transactional_delete_without_extra_flag(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            args = self._make_processing_args(
                input_root,
                output=output_root,
                success_policy="delete",
            )
            processor = types.SimpleNamespace(
                find_archives=mock.Mock(return_value=[]),
                successful_archives=[],
                failed_archives=[],
                skipped_archives=[],
            )
            stdout = io.StringIO()

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(self.m.sys, "argv", self._argv_for_main(args)),
                mock.patch.object(
                    self.m,
                    "safe_subprocess_run",
                    return_value=SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
                ),
                mock.patch.object(
                    self.m, "ArchiveProcessor", return_value=processor
                ) as archive_processor_ctor,
                mock.patch.object(self.m, "fix_archive_ext") as fix_archive_ext,
            ):
                exit_code = self.m.main()

            self.assertEqual(0, exit_code)
            self.assertNotIn("--unsafe-windows-delete is required", stdout.getvalue())
            archive_processor_ctor.assert_called_once()
            fix_archive_ext.assert_called_once()
            processor.find_archives.assert_called_once_with(os.path.abspath(input_root))

    def test_main_allows_windows_legacy_delete_without_extra_flag(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            args = self._make_processing_args(
                input_root,
                output=output_root,
                success_policy="delete",
                legacy=True,
            )
            processor = types.SimpleNamespace(
                find_archives=mock.Mock(return_value=[]),
                successful_archives=[],
                failed_archives=[],
                skipped_archives=[],
            )
            stdout = io.StringIO()

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(self.m.sys, "argv", self._argv_for_main(args)),
                mock.patch.object(
                    self.m,
                    "safe_subprocess_run",
                    return_value=SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
                ),
                mock.patch.object(
                    self.m, "ArchiveProcessor", return_value=processor
                ) as archive_processor_ctor,
                mock.patch.object(self.m, "fix_archive_ext") as fix_archive_ext,
            ):
                exit_code = self.m.main()

            self.assertEqual(0, exit_code)
            self.assertNotIn("--unsafe-windows-delete is required", stdout.getvalue())
            archive_processor_ctor.assert_called_once()
            fix_archive_ext.assert_called_once()
            processor.find_archives.assert_called_once_with(os.path.abspath(input_root))

    def test_main_fresh_traditional_zip_asis_reaches_extract_phase(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)
            archive_path = os.path.join(input_root, "legacy.zip")
            with open(archive_path, "wb") as f:
                f.write(b"legacy")

            args = self._make_processing_args(
                input_root,
                output=output_root,
                traditional_zip_policy="asis",
            )
            stdout = io.StringIO()

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(self.m.sys, "argv", self._argv_for_main(args)),
                mock.patch.object(
                    self.m,
                    "safe_subprocess_run",
                    return_value=SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
                ),
                mock.patch.object(self.m, "fix_archive_ext") as fix_archive_ext,
                mock.patch.object(self.m, "is_zip_format", return_value=True),
                mock.patch.object(self.m, "is_traditional_zip", return_value=True),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    wraps=self.m._extract_phase,
                ) as extract_phase_mock,
            ):
                exit_code = self.m.main()

            output = stdout.getvalue()
            self.assertEqual(0, exit_code)
            self.assertNotIn("No archives found to process.", output)
            self.assertIn("Found 1 archive(s) to process.", output)
            self.assertIn("Skipped: 1", output)
            extract_phase_mock.assert_called_once()
            fix_archive_ext.assert_called_once()

            manifest = self.m._load_dataset_manifest(output_root)
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            entry = manifest["archives"][archive_id]
            self.assertEqual("succeeded", entry["state"])
            self.assertEqual("skipped:traditional_zip_asis", entry["final_disposition"])
            self.assertIsNone(entry["error"])

    def test_main_fresh_traditional_zip_move_missing_destination_reaches_extract_phase(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)
            archive_path = os.path.join(input_root, "legacy.zip")
            with open(archive_path, "wb") as f:
                f.write(b"legacy")

            args = self._make_processing_args(
                input_root,
                output=output_root,
                traditional_zip_policy="move",
                traditional_zip_to=None,
            )
            stdout = io.StringIO()

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(self.m.sys, "argv", self._argv_for_main(args)),
                mock.patch.object(
                    self.m,
                    "safe_subprocess_run",
                    return_value=SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
                ),
                mock.patch.object(self.m, "fix_archive_ext") as fix_archive_ext,
                mock.patch.object(self.m, "is_zip_format", return_value=True),
                mock.patch.object(self.m, "is_traditional_zip", return_value=True),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    wraps=self.m._extract_phase,
                ) as extract_phase_mock,
            ):
                exit_code = self.m.main()

            output = stdout.getvalue()
            self.assertEqual(1, exit_code)
            self.assertNotIn(
                "Error: --traditional-zip-to is required when using --traditional-zip-policy move",
                output,
            )
            self.assertIn("Found 1 archive(s) to process.", output)
            self.assertIn("Failed to process: 1", output)
            extract_phase_mock.assert_called_once()
            fix_archive_ext.assert_called_once()

            manifest = self.m._load_dataset_manifest(output_root)
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            entry = manifest["archives"][archive_id]
            self.assertEqual("retryable", entry["state"])
            self.assertEqual("unknown", entry["final_disposition"])
            self.assertEqual(
                "TRADITIONAL_ZIP_MOVE_CONFIG_INVALID",
                entry["error"]["type"],
            )

    def test_main_fresh_traditional_zip_decode_invalid_reaches_extract_phase(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)
            archive_path = os.path.join(input_root, "legacy.zip")
            with open(archive_path, "wb") as f:
                f.write(b"legacy")

            args = self._make_processing_args(
                input_root,
                output=output_root,
                traditional_zip_policy="decode-bad",
            )
            stdout = io.StringIO()

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(self.m.sys, "argv", self._argv_for_main(args)),
                mock.patch.object(
                    self.m,
                    "safe_subprocess_run",
                    return_value=SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
                ),
                mock.patch.object(self.m, "fix_archive_ext") as fix_archive_ext,
                mock.patch.object(self.m, "is_zip_format", return_value=True),
                mock.patch.object(self.m, "is_traditional_zip", return_value=True),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    wraps=self.m._extract_phase,
                ) as extract_phase_mock,
            ):
                exit_code = self.m.main()

            output = stdout.getvalue()
            self.assertEqual(0, exit_code)
            self.assertNotIn(
                "Error: Invalid decode format in --traditional-zip-policy",
                output,
            )
            self.assertIn("Found 1 archive(s) to process.", output)
            self.assertIn("Skipped: 1", output)
            extract_phase_mock.assert_called_once()
            fix_archive_ext.assert_called_once()

            manifest = self.m._load_dataset_manifest(output_root)
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            entry = manifest["archives"][archive_id]
            self.assertEqual("succeeded", entry["state"])
            self.assertEqual(
                "skipped:traditional_zip_decode_invalid",
                entry["final_disposition"],
            )
            self.assertIsNone(entry["error"])

    def test_validate_delete_durability_args_rejects_no_durability_for_windows_transactional_delete(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                success_policy="delete",
                no_durability=True,
            )
            stdout = io.StringIO()

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(self.m.os, "name", "nt"),
            ):
                result = self.m._validate_delete_durability_args(args)

            self.assertFalse(result)
            self.assertIn("--no-durability", stdout.getvalue())
            self.assertNotIn("--unsafe-windows-delete", stdout.getvalue())

    def test_validate_delete_durability_args_allows_legacy_delete_with_no_durability_on_windows(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                success_policy="delete",
                legacy=True,
                no_durability=True,
            )
            stdout = io.StringIO()

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(self.m.os, "name", "nt"),
            ):
                result = self.m._validate_delete_durability_args(args)

            self.assertTrue(result)
            self.assertEqual("", stdout.getvalue())

    def test_validate_delete_durability_args_rejects_fsync_files_none_for_windows_transactional_delete(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                success_policy="delete",
                fsync_files="none",
            )
            stdout = io.StringIO()

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(self.m.os, "name", "nt"),
            ):
                result = self.m._validate_delete_durability_args(args)

            self.assertFalse(result)
            self.assertIn("--fsync-files none", stdout.getvalue())
            self.assertNotIn("--unsafe-windows-delete", stdout.getvalue())

    def test_validate_delete_durability_args_allows_legacy_delete_with_fsync_files_none_on_windows(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                success_policy="delete",
                legacy=True,
                fsync_files="none",
            )
            stdout = io.StringIO()

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(self.m.os, "name", "nt"),
            ):
                result = self.m._validate_delete_durability_args(args)

            self.assertTrue(result)
            self.assertEqual("", stdout.getvalue())

    def test_validate_delete_durability_args_allows_windows_transactional_delete_without_extra_flag(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(td, success_policy="delete")

        with mock.patch.object(self.m.os, "name", "nt"):
            self.assertTrue(self.m._validate_delete_durability_args(args))

    def test_main_dry_run_with_fix_ext_does_not_rename_inputs(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            archive_path = os.path.join(input_root, "preview_me")
            with open(archive_path, "wb") as f:
                f.write(b"PK\x03\x04preview")
            renamed_path = archive_path + ".zip"

            args = self._make_processing_args(
                input_root,
                output=output_root,
                dry_run=True,
                fix_ext=True,
                fix_extension_threshold="0",
            )
            processor = types.SimpleNamespace(
                find_archives=mock.Mock(return_value=[]),
                successful_archives=[],
                failed_archives=[],
                skipped_archives=[],
                skipped_rename_archives=[],
                fixed_rename_archives=[],
            )
            stdout = io.StringIO()

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(self.m.sys, "argv", self._argv_for_main(args)),
                mock.patch.object(
                    self.m,
                    "safe_subprocess_run",
                    return_value=SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
                ),
                mock.patch.object(self.m, "ArchiveProcessor", return_value=processor),
                mock.patch.object(self.m, "detect_archive_type", return_value="ZIP"),
                mock.patch("builtins.input", return_value="y") as input_mock,
            ):
                exit_code = self.m.main()

            self.assertEqual(0, exit_code)
            input_mock.assert_not_called()
            self.assertTrue(os.path.exists(archive_path))
            self.assertFalse(os.path.exists(renamed_path))
            self.assertEqual([], processor.fixed_rename_archives)
            processor.find_archives.assert_called_once_with(os.path.abspath(input_root))

    def test_delete_durability_failure_preserves_source_and_recoverable_state(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_delete_barrier_txn_fixture(td)
            archive_path = os.path.abspath(fixture["archive_path"])

            def fail_on_payload_dir(path, debug=False):
                path = os.path.abspath(path)
                if path == os.path.abspath(fixture["output_dir"]):
                    return False
                return True

            with mock.patch.object(
                self.m, "_fsync_dir", side_effect=fail_on_payload_dir
            ):
                with self.assertRaises(RuntimeError) as ctx:
                    self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

            self.assertIn("payload_fsync_failed:dir:", str(ctx.exception))
            self.assertTrue(os.path.exists(archive_path))
            with open(fixture["txn"]["paths"]["txn_json"], "r", encoding="utf-8") as f:
                saved_txn = json.load(f)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            manifest_entry = manifest["archives"][
                self.m._dataset_manifest_archive_id(fixture["archive_path"])
            ]
            self.assertEqual(self.m.TXN_STATE_ABORTED, saved_txn["state"])
            self.assertEqual("DURABILITY_FAILED", saved_txn["error"]["type"])
            self.assertEqual("DURABILITY_FAILED", manifest_entry["error"]["type"])
            self.assertEqual("recoverable", manifest_entry["state"])
            self.assertEqual("unknown", manifest_entry["final_disposition"])
            self.assertIsNone(manifest_entry["finalized_at"])

    def test_delete_durability_failure_on_journal_fsync_preserves_source_and_recoverable_state(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_delete_barrier_txn_fixture(td)
            archive_path = os.path.abspath(fixture["archive_path"])

            def fail_on_wal_fsync(path, debug=False):
                path = os.path.abspath(path)
                if path == os.path.abspath(fixture["txn"]["paths"]["wal"]):
                    return False
                return True

            with mock.patch.object(
                self.m, "_fsync_file", side_effect=fail_on_wal_fsync
            ):
                with self.assertRaises(RuntimeError) as ctx:
                    self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

            self.assertIn("journal_fsync_failed:wal", str(ctx.exception))
            self.assertTrue(os.path.exists(archive_path))
            with open(fixture["txn"]["paths"]["txn_json"], "r", encoding="utf-8") as f:
                saved_txn = json.load(f)
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            manifest_entry = manifest["archives"][
                self.m._dataset_manifest_archive_id(fixture["archive_path"])
            ]
            self.assertEqual(self.m.TXN_STATE_ABORTED, saved_txn["state"])
            self.assertEqual("DURABILITY_FAILED", saved_txn["error"]["type"])
            self.assertEqual("DURABILITY_FAILED", manifest_entry["error"]["type"])
            self.assertEqual("recoverable", manifest_entry["state"])
            self.assertEqual("unknown", manifest_entry["final_disposition"])
            self.assertIsNone(manifest_entry["finalized_at"])

    def test_windows_transactional_delete_payload_dir_fsync_failure_blocks_delete(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_delete_barrier_txn_fixture(td)
            archive_path = os.path.abspath(fixture["archive_path"])
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            expected_payload_dirs = [
                os.path.abspath(path) for path in fixture["expected_payload_dirs"]
            ]
            fsynced_dirs = []

            class DummyLock:
                def __init__(self, path, timeout_ms, retry_ms, debug):
                    self.path = path

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

            def fail_payload_dir_fsync(path, debug=False):
                abs_path = os.path.abspath(path)
                fsynced_dirs.append(abs_path)
                return abs_path not in expected_payload_dirs

            with (
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "same_volume", return_value=True),
                mock.patch.object(self.m, "_fsync_file", return_value=True),
                mock.patch.object(
                    self.m, "_fsync_dir", side_effect=fail_payload_dir_fsync
                ),
                self.assertRaises(RuntimeError),
            ):
                self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][archive_id]

            self.assertIn(expected_payload_dirs[0], fsynced_dirs)
            self.assertTrue(os.path.exists(archive_path))
            self.assertEqual("recoverable", entry["state"])
            self.assertEqual("unknown", entry["final_disposition"])
            self.assertIsNone(entry["finalized_at"])

    def test_windows_transactional_delete_real_fsync_file_path_reaches_success(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_delete_barrier_txn_fixture(td)
            archive_path = os.path.abspath(fixture["archive_path"])
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            expected_open_paths = {
                os.path.abspath(fixture["txn"]["paths"]["wal"]),
                os.path.abspath(fixture["txn"]["paths"]["txn_json"]),
            }
            expected_open_paths.update(
                os.path.abspath(path) for path in fixture["expected_payload_files"]
            )
            open_calls = []
            helper_opened_fds = []
            helper_closed_fds = []
            barrier_called = {"value": False}
            next_fd = {"value": 100}
            original_barrier = self.m._durability_barrier

            class DummyLock:
                def __init__(self, path, timeout_ms, retry_ms, debug):
                    self.path = path

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

            def fake_open(path, flags):
                normalized_path = os.path.abspath(path)
                open_calls.append((normalized_path, flags))
                if normalized_path not in expected_open_paths:
                    raise AssertionError(
                        f"Unexpected helper-path fsync open: {normalized_path}"
                    )
                fd = next_fd["value"]
                next_fd["value"] += 1
                helper_opened_fds.append(fd)
                return fd

            def fake_fsync(fd):
                return None

            def fake_close(fd):
                helper_closed_fds.append(fd)

            def tracking_barrier(*args, **kwargs):
                barrier_called["value"] = True
                with (
                    mock.patch.object(self.m.os, "open", side_effect=fake_open),
                    mock.patch.object(self.m.os, "fsync", side_effect=fake_fsync),
                    mock.patch.object(self.m.os, "close", side_effect=fake_close),
                ):
                    return original_barrier(*args, **kwargs)

            with (
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "same_volume", return_value=True),
                mock.patch.object(self.m, "_fsync_dir", return_value=True),
                mock.patch.object(self.m, "_durability_barrier", new=tracking_barrier),
            ):
                self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            manifest_entry = manifest["archives"][archive_id]
            opened_paths = {path for path, _flags in open_calls}

            self.assertFalse(os.path.exists(archive_path))
            self.assertEqual("succeeded", manifest_entry["state"])
            self.assertEqual(
                "success:delete",
                manifest_entry["final_disposition"],
            )
            self.assertTrue(expected_open_paths.issubset(opened_paths))
            self.assertIs(True, barrier_called["value"])
            self.assertCountEqual(helper_opened_fds, helper_closed_fds)

    def test_windows_transactional_delete_repeated_txn_snapshot_preserves_txn_json_long_path(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            archive_path = os.path.join(input_root, "alpha.zip")
            with open(archive_path, "wb") as f:
                f.write(b"alpha")

            args = self._make_processing_args(
                input_root,
                output=output_root,
                success_policy="delete",
            )

            txn = self.m._txn_create(
                archive_path=archive_path,
                volumes=[archive_path],
                output_dir=os.path.join(output_root, "alpha"),
                output_base=output_root,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=True,
            )
            txn_json_path = txn["paths"]["txn_json"]
            real_fsync_file = self.m._fsync_file

            def assert_long_path_visible(path, debug=False):
                if path == txn_json_path:
                    self.assertTrue(
                        os.path.exists(txn_json_path),
                        "txn.json long path must exist at the fsync point",
                    )
                return real_fsync_file(path, debug=debug)

            with (
                self._mock_windows_short_path_destination_bug(
                    remove_after_existing_hits=2
                ),
                mock.patch.object(self.m, "_fsync_dir", return_value=True),
                mock.patch.object(
                    self.m, "_fsync_file", side_effect=assert_long_path_visible
                ),
            ):
                self.m._txn_snapshot(txn)
                self.m._txn_snapshot(txn)
                self.m._durability_barrier(txn, fsync_files="auto")

            self.assertTrue(os.path.exists(txn_json_path))

    def test_durability_barrier_no_longer_accepts_delete_mode_keyword(self):
        self.assertNotIn(
            "delete_mode",
            inspect.signature(self.m._durability_barrier).parameters,
        )

    def test_windows_transactional_delete_keeps_wal_fsync_failure_blocking(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_delete_barrier_txn_fixture(td)
            wal_path = os.path.abspath(fixture["txn"]["paths"]["wal"])

            def fail_on_wal_fsync(path, debug=False):
                return os.path.abspath(path) != wal_path

            self._assert_windows_transactional_delete_barrier_failure(
                fixture,
                fsync_file_side_effect=fail_on_wal_fsync,
                expected_error_text="journal_fsync_failed:wal",
            )

    def test_windows_transactional_delete_keeps_txn_json_fsync_failure_blocking(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_delete_barrier_txn_fixture(td)
            txn_json_path = os.path.abspath(fixture["txn"]["paths"]["txn_json"])

            def fail_on_txn_json_fsync(path, debug=False):
                return os.path.abspath(path) != txn_json_path

            self._assert_windows_transactional_delete_barrier_failure(
                fixture,
                fsync_file_side_effect=fail_on_txn_json_fsync,
                expected_error_text="journal_fsync_failed:txn_json",
            )

    def test_windows_transactional_delete_keeps_payload_file_fsync_failure_blocking(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_delete_barrier_txn_fixture(td)
            payload_path = os.path.abspath(fixture["expected_payload_files"][0])

            def fail_on_payload_file_fsync(path, debug=False):
                return os.path.abspath(path) != payload_path

            self._assert_windows_transactional_delete_barrier_failure(
                fixture,
                fsync_file_side_effect=fail_on_payload_file_fsync,
                expected_error_text="payload_fsync_failed:file:",
            )

    def test_delete_durability_failure_stays_recoverable_across_resume_plan_rebuild(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_delete_barrier_txn_fixture(td)
            archive_path = os.path.abspath(fixture["archive_path"])
            archive_id = self.m._dataset_manifest_archive_id(archive_path)

            def fail_on_payload_dir(path, debug=False):
                path = os.path.abspath(path)
                if path == os.path.abspath(fixture["output_dir"]):
                    return False
                return True

            with mock.patch.object(
                self.m, "_fsync_dir", side_effect=fail_on_payload_dir
            ):
                with self.assertRaises(RuntimeError):
                    self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            self.assertEqual("recoverable", manifest["archives"][archive_id]["state"])

            recoverable_archives, retryable_archives, pending_archives = (
                self.m._build_transactional_archive_plan(
                    manifest,
                    fixture["output_root"],
                )
            )

            rebuilt_manifest = self.m._load_dataset_manifest(fixture["output_root"])
            rebuilt_entry = rebuilt_manifest["archives"][archive_id]

            self.assertEqual(
                [
                    {
                        "archive_path": archive_path,
                        "output_dir": os.path.abspath(fixture["output_dir"]),
                    }
                ],
                recoverable_archives,
            )
            self.assertEqual([], retryable_archives)
            self.assertEqual([], pending_archives)
            self.assertEqual("recoverable", rebuilt_entry["state"])
            self.assertEqual("DURABILITY_FAILED", rebuilt_entry["error"]["type"])
            self.assertEqual("unknown", rebuilt_entry["final_disposition"])
            self.assertIsNone(rebuilt_entry["finalized_at"])

    def test_delete_durability_failure_resume_uses_recovery_without_reextract(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_delete_barrier_txn_fixture(td)
            archive_path = os.path.abspath(fixture["archive_path"])
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            duplicate_root = os.path.join(fixture["output_dir"], "alpha")

            def fail_on_payload_dir(path, debug=False):
                path = os.path.abspath(path)
                if path == os.path.abspath(fixture["output_dir"]):
                    return False
                return True

            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m.os, "name", "posix"),
                mock.patch.object(self.m, "_fsync_file", return_value=True),
                mock.patch.object(
                    self.m, "_fsync_dir", side_effect=fail_on_payload_dir
                ),
            ):
                with self.assertRaises(RuntimeError):
                    self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

            processor = types.SimpleNamespace(
                successful_archives=[],
                failed_archives=[],
                skipped_archives=[],
            )

            with (
                mock.patch.object(self.m.os, "name", "posix"),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "durability failure resume should continue same txn, not re-extract"
                    ),
                ),
                mock.patch.object(self.m, "_garbage_collect"),
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "_fsync_file", return_value=True),
                mock.patch.object(self.m, "_fsync_dir", return_value=True),
            ):
                self.m._run_transactional(processor, [], args=fixture["args"])

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][archive_id]

            self.assertFalse(os.path.exists(archive_path))
            self.assertTrue(
                os.path.exists(os.path.join(fixture["output_dir"], "root.txt"))
            )
            self.assertTrue(
                os.path.exists(
                    os.path.join(fixture["output_dir"], "a", "b", "payload.txt")
                )
            )
            self.assertFalse(os.path.exists(os.path.join(duplicate_root, "root.txt")))
            self.assertFalse(
                os.path.exists(os.path.join(duplicate_root, "a", "b", "payload.txt"))
            )
            self.assertEqual("succeeded", entry["state"])
            self.assertEqual("success:delete", entry["final_disposition"])
            self.assertIsNone(entry["error"])

    def test_delete_durability_failure_resume_keeps_source_when_expected_payload_missing(
        self,
    ):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_delete_barrier_txn_fixture(td)
            archive_path = os.path.abspath(fixture["archive_path"])
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            missing_payload = os.path.abspath(fixture["expected_payload_files"][1])

            def fail_on_payload_dir(path, debug=False):
                path = os.path.abspath(path)
                if path == os.path.abspath(fixture["output_dir"]):
                    return False
                return True

            with mock.patch.object(
                self.m, "_fsync_dir", side_effect=fail_on_payload_dir
            ):
                with self.assertRaises(RuntimeError):
                    self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

            os.remove(missing_payload)

            processor = types.SimpleNamespace(
                successful_archives=[],
                failed_archives=[],
                skipped_archives=[],
            )

            with (
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "durability failure resume should continue same txn, not re-extract"
                    ),
                ),
                mock.patch.object(self.m, "_garbage_collect"),
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "_fsync_file", return_value=True),
                mock.patch.object(self.m, "_fsync_dir", return_value=True),
            ):
                self.m._run_transactional(processor, [], args=fixture["args"])

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][archive_id]
            with open(fixture["txn"]["paths"]["txn_json"], "r", encoding="utf-8") as f:
                saved_txn = json.load(f)

            self.assertTrue(os.path.exists(archive_path))
            self.assertFalse(os.path.exists(missing_payload))
            self.assertEqual([], processor.successful_archives)
            self.assertEqual("recoverable", entry["state"])
            self.assertEqual("DURABILITY_FAILED", entry["error"]["type"])
            self.assertEqual("unknown", entry["final_disposition"])
            self.assertEqual(self.m.TXN_STATE_ABORTED, saved_txn["state"])
            self.assertEqual("DURABILITY_FAILED", saved_txn["error"]["type"])

    def test_success_delete_source_finalization_resume_recognizes_success(
        self,
    ):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_success_finalization_txn_fixture(
                td,
                success_policy="delete",
            )
            txn = fixture["txn"]
            txn["state"] = self.m.TXN_STATE_PLACED
            self.m._set_source_finalization_plan(
                txn,
                manifest_state="succeeded",
                final_disposition="success:delete",
                txn_terminal_state=self.m.TXN_STATE_DONE,
            )
            self.m._txn_snapshot(txn)

            with (
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "same_volume", return_value=True),
                mock.patch.object(self.m, "_fsync_dir", return_value=True),
            ):
                resumed = self.m._resume_source_finalization_if_needed(
                    txn,
                    args=fixture["args"],
                )

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]

            self.assertTrue(resumed)
            self.assertFalse(os.path.exists(fixture["archive_path"]))
            self.assertEqual(self.m.TXN_STATE_DONE, txn["state"])
            self.assertEqual("succeeded", entry["state"])
            self.assertEqual("success:delete", entry["final_disposition"])

    def test_windows_transactional_delete_success_records_success_delete(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_success_finalization_txn_fixture(
                td,
                success_policy="delete",
            )

            with (
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "same_volume", return_value=True),
                mock.patch.object(self.m, "_fsync_file", return_value=True),
                mock.patch.object(self.m, "_fsync_dir", return_value=True),
            ):
                self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]

            self.assertEqual("succeeded", entry["state"])
            self.assertEqual("success:delete", entry["final_disposition"])
            self.assertFalse(os.path.exists(os.path.abspath(fixture["archive_path"])))

    def test_success_delete_resume_converges_persisted_source_finalization_plan(
        self,
    ):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_success_finalization_txn_fixture(
                td,
                success_policy="delete",
            )
            archive_path = os.path.abspath(fixture["archive_path"])
            archive_id = fixture["archive_id"]
            real_snapshot = self.m._txn_snapshot

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            with mock.patch.object(self.m.os, "name", "nt"):
                manifest["command_fingerprint"] = self.m._build_command_fingerprint(
                    fixture["args"]
                )
            self.m._save_dataset_manifest(manifest)

            def crash_after_plan_persisted(txn):
                real_snapshot(txn)
                plan = self.m._txn_source_finalization_plan(txn)
                if (
                    plan is not None
                    and plan["final_disposition"] == "success:delete"
                    and txn.get("state")
                    in (self.m.TXN_STATE_PLACED, self.m.TXN_STATE_DURABLE)
                ):
                    raise SystemExit("crash-after-delete-source-finalization-plan")

            with (
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "same_volume", return_value=True),
                mock.patch.object(self.m, "_fsync_file", return_value=True),
                mock.patch.object(self.m, "_fsync_dir", return_value=True),
                mock.patch.object(
                    self.m, "_txn_snapshot", side_effect=crash_after_plan_persisted
                ),
                self.assertRaises(SystemExit),
            ):
                self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

            self.assertTrue(os.path.exists(archive_path))

            processor = types.SimpleNamespace(
                successful_archives=[],
                failed_archives=[],
                skipped_archives=[],
            )
            with (
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "same_volume", return_value=True),
                mock.patch.object(self.m, "_fsync_file", return_value=True),
                mock.patch.object(self.m, "_fsync_dir", return_value=True),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "resume should converge persisted transactional delete finalization plan without re-extract"
                    ),
                ),
                mock.patch.object(self.m, "_garbage_collect"),
            ):
                self.m._run_transactional(processor, [], args=fixture["args"])

            resumed_manifest = self.m._load_dataset_manifest(fixture["output_root"])
            resumed_entry = resumed_manifest["archives"][archive_id]
            resumed_txn = self.m._load_latest_txn_for_archive(
                resumed_entry, fixture["output_root"]
            )

            self.assertFalse(os.path.exists(archive_path))
            self.assertEqual([archive_path], processor.successful_archives)
            self.assertEqual([], processor.failed_archives)
            self.assertEqual("succeeded", resumed_entry["state"])
            self.assertEqual("success:delete", resumed_entry["final_disposition"])
            self.assertEqual(self.m.TXN_STATE_DONE, resumed_txn["state"])

    def test_terminal_delete_manifest_reopens_without_missing_source_drift(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_success_finalization_txn_fixture(
                td, success_policy="delete"
            )
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            with mock.patch.object(self.m.os, "name", "nt"):
                manifest["command_fingerprint"] = self.m._build_command_fingerprint(
                    fixture["args"]
                )
            self.m._save_dataset_manifest(manifest)

            with (
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "same_volume", return_value=True),
                mock.patch.object(self.m, "_fsync_file", return_value=True),
                mock.patch.object(self.m, "_fsync_dir", return_value=True),
            ):
                self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

            self.assertFalse(os.path.exists(fixture["archive_path"]))

            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )

            with (
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "same_volume", return_value=True),
                mock.patch.object(self.m, "_fsync_file", return_value=True),
                mock.patch.object(self.m, "_fsync_dir", return_value=True),
                mock.patch.object(self.m, "_garbage_collect"),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "terminal retained manifest should not re-extract on reopen"
                    ),
                ),
            ):
                result = self.m._run_transactional(processor, [], args=fixture["args"])

            manifest = self.m._load_dataset_manifest(fixture["output_root"])

            self.assertIsNone(result)
            self.assertEqual([], processor.successful_archives)
            self.assertEqual([], processor.failed_archives)
            self.assertEqual([], processor.skipped_archives)
            self.assertIsNone(manifest)
            self.assertFalse(
                os.path.exists(self.m._work_base(fixture["output_root"]))
            )

    def test_terminal_move_manifest_reopens_without_missing_source_drift(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_success_finalization_txn_fixture(
                td, success_policy="move"
            )
            self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

            self.assertFalse(os.path.exists(fixture["archive_path"]))

            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )

            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "_garbage_collect"),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "terminal retained move manifest should not re-extract on reopen"
                    ),
                ),
            ):
                result = self.m._run_transactional(processor, [], args=fixture["args"])

            manifest = self.m._load_dataset_manifest(fixture["output_root"])

            self.assertIsNone(result)
            self.assertEqual([], processor.successful_archives)
            self.assertEqual([], processor.failed_archives)
            self.assertEqual([], processor.skipped_archives)
            self.assertIsNone(manifest)
            self.assertFalse(
                os.path.exists(self.m._work_base(fixture["output_root"]))
            )

    def test_terminal_failure_move_manifest_reopens_without_missing_source_drift(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            fail_to = os.path.join(td, "failed")
            os.makedirs(input_root)
            os.makedirs(output_root)

            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                ["alpha.zip"],
            )
            archive_path = os.path.abspath(discovered[0]["archive_path"])
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            args = self._make_processing_args(
                input_root,
                output=output_root,
                fail_policy="move",
                fail_to=fail_to,
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=discovered,
                command_fingerprint=self.m._build_command_fingerprint(args),
            )

            extracting_processor = types.SimpleNamespace(
                sfx_detector=None,
                get_all_volumes=lambda path: [os.path.abspath(path)],
            )
            with (
                mock.patch.object(self.m, "_validate_environment_for_output_dir"),
                mock.patch.object(self.m, "try_extract", return_value=False),
            ):
                result = self.m._extract_phase(
                    extracting_processor,
                    archive_path,
                    args=args,
                    output_base=output_root,
                )

            result_processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            self.m._handle_transactional_result(
                result,
                processor=result_processor,
                args=args,
                output_base=output_root,
                touched_output_dirs=set(),
            )
            self.assertFalse(os.path.exists(archive_path))

            reopen_processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "_garbage_collect"),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "terminal retained failure move manifest should not re-extract"
                    ),
                ),
            ):
                result = self.m._run_transactional(reopen_processor, [], args=args)

            manifest = self.m._load_dataset_manifest(output_root)

            self.assertIsNone(result)
            self.assertEqual([], reopen_processor.successful_archives)
            self.assertEqual([], reopen_processor.failed_archives)
            self.assertEqual([], reopen_processor.skipped_archives)
            self.assertIsNone(manifest)
            self.assertFalse(os.path.exists(self.m._work_base(output_root)))

    def test_success_delete_closed_terminal_crash_retires_residue_on_new_command(
        self,
    ):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_success_finalization_txn_fixture(
                td, success_policy="delete"
            )
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            with mock.patch.object(self.m.os, "name", "nt"):
                manifest["command_fingerprint"] = self.m._build_command_fingerprint(
                    fixture["args"]
                )
            self.m._save_dataset_manifest(manifest)
            archive_path = os.path.abspath(fixture["archive_path"])
            archive_id = fixture["archive_id"]

            real_snapshot = self.m._txn_snapshot

            def crash_after_source_finalized(txn):
                real_snapshot(txn)
                if txn.get("state") == self.m.TXN_STATE_SOURCE_FINALIZED:
                    raise SystemExit("crash-after-source-finalized")

            with (
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(self.m, "same_volume", return_value=True),
                mock.patch.object(self.m, "_fsync_file", return_value=True),
                mock.patch.object(self.m, "_fsync_dir", return_value=True),
                mock.patch.object(
                    self.m, "_txn_snapshot", side_effect=crash_after_source_finalized
                ),
                self.assertRaises(SystemExit),
            ):
                self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

            self.assertFalse(os.path.exists(archive_path))
            crashed_manifest = self.m._load_dataset_manifest(fixture["output_root"])
            crashed_entry = crashed_manifest["archives"][archive_id]
            self.assertNotEqual("succeeded", crashed_entry["state"])

            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            with (
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "same_volume", return_value=True),
                mock.patch.object(self.m, "_fsync_file", return_value=True),
                mock.patch.object(self.m, "_fsync_dir", return_value=True),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "resume should converge existing finalized txn without re-extract"
                    ),
                ),
                mock.patch.object(self.m, "_garbage_collect"),
            ):
                result = self.m._run_transactional(processor, [], args=fixture["args"])

            resumed_manifest = self.m._load_dataset_manifest(fixture["output_root"])

            self.assertIsNone(result)
            self.assertEqual([], processor.successful_archives)
            self.assertEqual([], processor.failed_archives)
            self.assertEqual([], processor.skipped_archives)
            self.assertIsNone(resumed_manifest)
            self.assertFalse(
                os.path.exists(self.m._work_base(fixture["output_root"]))
            )

    def test_success_move_crash_after_rename_before_destination_persistence_resumes(
        self,
    ):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_success_finalization_txn_fixture(
                td, success_policy="move"
            )
            archive_path = os.path.abspath(fixture["archive_path"])
            archive_id = fixture["archive_id"]
            real_atomic_rename = self.m._atomic_rename

            def crash_after_source_move(
                src, dst, *, degrade_cross_volume=False, debug=False
            ):
                result = real_atomic_rename(
                    src,
                    dst,
                    degrade_cross_volume=degrade_cross_volume,
                    debug=debug,
                )
                if os.path.abspath(src) == archive_path:
                    raise SystemExit("crash-after-success-move-rename")
                return result

            with (
                mock.patch.object(
                    self.m, "_atomic_rename", side_effect=crash_after_source_move
                ),
                self.assertRaises(SystemExit),
            ):
                self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

            self.assertFalse(os.path.exists(archive_path))

            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "resume should converge moved source without re-extracting"
                    ),
                ),
                mock.patch.object(self.m, "_garbage_collect"),
            ):
                self.m._run_transactional(processor, [], args=fixture["args"])

            resumed_manifest = self.m._load_dataset_manifest(fixture["output_root"])
            resumed_entry = resumed_manifest["archives"][archive_id]

            self.assertEqual([archive_path], processor.successful_archives)
            self.assertEqual([], processor.failed_archives)
            self.assertEqual("succeeded", resumed_entry["state"])
            self.assertEqual("success:move", resumed_entry["final_disposition"])

    def test_success_move_requires_no_durability_to_be_false(self):
        args = SimpleNamespace(
            success_policy="move",
            fail_policy="asis",
            traditional_zip_policy="decode-auto",
            legacy=False,
            no_durability=True,
            fsync_files="auto",
        )

        self.assertFalse(self.m._validate_delete_durability_args(args))

    def test_success_move_requires_fsync_files_not_none(self):
        args = SimpleNamespace(
            success_policy="move",
            fail_policy="asis",
            traditional_zip_policy="decode-auto",
            legacy=False,
            no_durability=False,
            fsync_files="none",
        )

        self.assertFalse(self.m._validate_delete_durability_args(args))

    def test_fail_move_requires_no_durability_to_be_false(self):
        args = SimpleNamespace(
            success_policy="asis",
            fail_policy="move",
            traditional_zip_policy="decode-auto",
            legacy=False,
            no_durability=True,
            fsync_files="auto",
        )

        self.assertFalse(self.m._validate_delete_durability_args(args))

    def test_fail_move_requires_fsync_files_not_none(self):
        args = SimpleNamespace(
            success_policy="asis",
            fail_policy="move",
            traditional_zip_policy="decode-auto",
            legacy=False,
            no_durability=False,
            fsync_files="none",
        )

        self.assertFalse(self.m._validate_delete_durability_args(args))

    def test_traditional_zip_move_requires_no_durability_to_be_false(self):
        args = SimpleNamespace(
            success_policy="asis",
            fail_policy="asis",
            traditional_zip_policy="move",
            legacy=False,
            no_durability=True,
            fsync_files="auto",
        )

        self.assertFalse(self.m._validate_delete_durability_args(args))

    def test_traditional_zip_move_requires_fsync_files_not_none(self):
        args = SimpleNamespace(
            success_policy="asis",
            fail_policy="asis",
            traditional_zip_policy="move",
            legacy=False,
            no_durability=False,
            fsync_files="none",
        )

        self.assertFalse(self.m._validate_delete_durability_args(args))

    def test_traditional_zip_policy_inspection_returns_fixed_reason_codes(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            trad_to = os.path.join(td, "traditional")
            os.makedirs(input_root)
            archive_path = os.path.join(input_root, "legacy.zip")
            text_path = os.path.join(input_root, "legacy.txt")
            with open(archive_path, "wb") as f:
                f.write(b"legacy")
            with open(text_path, "wb") as f:
                f.write(b"plain")

            move_args = self._make_processing_args(
                input_root,
                traditional_zip_policy="move",
                traditional_zip_to=trad_to,
            )
            move_missing_dest_args = self._make_processing_args(
                input_root,
                traditional_zip_policy="move",
                traditional_zip_to=None,
            )
            asis_args = self._make_processing_args(
                input_root,
                traditional_zip_policy="asis",
            )
            auto_args = self._make_processing_args(
                input_root,
                traditional_zip_policy="decode-auto",
            )
            manual_args = self._make_processing_args(
                input_root,
                traditional_zip_policy="decode-932",
            )
            invalid_args = self._make_processing_args(
                input_root,
                traditional_zip_policy="decode-bad",
            )

            not_zip = self.m._inspect_traditional_zip_policy(move_args, text_path)
            self.assertEqual(
                {
                    "applies",
                    "policy",
                    "zip_decode",
                    "reason",
                    "traditional_zip_to",
                    "error",
                },
                set(not_zip.keys()),
            )
            self.assertFalse(not_zip["applies"])
            self.assertEqual("move", not_zip["policy"])
            self.assertIsNone(not_zip["zip_decode"])
            self.assertEqual("not_zip", not_zip["reason"])
            self.assertIsNone(not_zip["traditional_zip_to"])
            self.assertIsNone(not_zip["error"])

            with (
                mock.patch.object(self.m, "is_zip_format", return_value=True),
                mock.patch.object(self.m, "is_traditional_zip", return_value=False),
            ):
                not_traditional = self.m._inspect_traditional_zip_policy(
                    move_args,
                    archive_path,
                )

            self.assertFalse(not_traditional["applies"])
            self.assertEqual("not_traditional_zip", not_traditional["reason"])

            with (
                mock.patch.object(self.m, "is_zip_format", return_value=True),
                mock.patch.object(self.m, "is_traditional_zip", return_value=True),
            ):
                move_inspected = self.m._inspect_traditional_zip_policy(
                    move_args, archive_path
                )
                missing_dest_inspected = self.m._inspect_traditional_zip_policy(
                    move_missing_dest_args,
                    archive_path,
                )
                asis_inspected = self.m._inspect_traditional_zip_policy(
                    asis_args,
                    archive_path,
                )
                auto_inspected = self.m._inspect_traditional_zip_policy(
                    auto_args,
                    archive_path,
                )
                manual_inspected = self.m._inspect_traditional_zip_policy(
                    manual_args,
                    archive_path,
                )
                invalid_inspected = self.m._inspect_traditional_zip_policy(
                    invalid_args,
                    archive_path,
                )

            self.assertTrue(move_inspected["applies"])
            self.assertEqual("traditional_zip_move", move_inspected["reason"])
            self.assertEqual(os.path.abspath(trad_to), move_inspected["traditional_zip_to"])
            self.assertIsNone(move_inspected["error"])

            self.assertTrue(missing_dest_inspected["applies"])
            self.assertEqual(
                "traditional_zip_move_missing_destination",
                missing_dest_inspected["reason"],
            )
            self.assertEqual(
                {"type", "message", "at"},
                set(missing_dest_inspected["error"].keys()),
            )
            self.assertEqual(
                "TRADITIONAL_ZIP_MOVE_CONFIG_INVALID",
                missing_dest_inspected["error"]["type"],
            )
            self.assertEqual("traditional_zip_asis", asis_inspected["reason"])
            self.assertEqual("traditional_zip_decode_auto", auto_inspected["reason"])
            self.assertEqual("traditional_zip_decode_manual", manual_inspected["reason"])
            self.assertEqual(932, manual_inspected["zip_decode"])
            self.assertEqual("traditional_zip_decode_invalid", invalid_inspected["reason"])
            self.assertEqual(
                {"type", "message", "at"},
                set(invalid_inspected["error"].keys()),
            )
            self.assertEqual(
                "TRADITIONAL_ZIP_DECODE_POLICY_INVALID",
                invalid_inspected["error"]["type"],
            )

    def test_traditional_zip_move_destination_planner_matches_txn_and_non_txn_paths(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            trad_to = os.path.join(td, "traditional")
            os.makedirs(os.path.join(input_root, "nested"), exist_ok=True)
            archive_path = os.path.join(input_root, "nested", "legacy.zip")
            volume_path = os.path.join(input_root, "nested", "legacy.z01")
            with open(archive_path, "wb") as f:
                f.write(b"legacy")
            with open(volume_path, "wb") as f:
                f.write(b"volume")

            existing_target_dir = os.path.join(trad_to, "nested")
            os.makedirs(existing_target_dir, exist_ok=True)
            with open(os.path.join(existing_target_dir, "legacy.zip"), "wb") as f:
                f.write(b"existing")

            args = self._make_processing_args(
                input_root,
                traditional_zip_policy="move",
                traditional_zip_to=trad_to,
            )
            volumes = [archive_path, volume_path]

            non_txn_destinations = self.m._traditional_zip_move_destinations(
                args,
                volumes,
                collision_token="abcd1234",
            )
            txn_destinations = self.m._traditional_zip_move_destinations(
                args,
                volumes,
                collision_token="abcd1234",
            )

            expected = [
                (
                    os.path.abspath(archive_path),
                    os.path.abspath(
                        os.path.join(trad_to, "nested", "legacy_abcd1234_1.zip")
                    ),
                ),
                (
                    os.path.abspath(volume_path),
                    os.path.abspath(os.path.join(trad_to, "nested", "legacy.z01")),
                ),
            ]

            self.assertEqual(expected, non_txn_destinations)
            self.assertEqual(non_txn_destinations, txn_destinations)

    def test_traditional_zip_move_token_is_deterministic_across_entrypoints(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            trad_to = os.path.join(td, "traditional")
            os.makedirs(input_root)
            archive_path = os.path.join(input_root, "legacy.zip")
            volume_path = os.path.join(input_root, "legacy.z01")
            with open(archive_path, "wb") as f:
                f.write(b"legacy")
            with open(volume_path, "wb") as f:
                f.write(b"volume")

            args = self._make_processing_args(
                input_root,
                traditional_zip_policy="move",
                traditional_zip_to=trad_to,
            )

            token_a = self.m._traditional_zip_move_token(args, [archive_path])
            token_b = self.m._traditional_zip_move_token(args, [archive_path])
            token_c = self.m._traditional_zip_move_token(args, [archive_path, volume_path])

            self.assertEqual(token_a, token_b)
            self.assertEqual(8, len(token_a))
            self.assertNotEqual(token_a, token_c)

    def test_process_archive_traditional_zip_move_without_manifest_does_not_create_txn(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            trad_to = os.path.join(td, "traditional")
            os.makedirs(input_root)
            os.makedirs(output_root)
            archive_path = os.path.join(input_root, "legacy.zip")
            with open(archive_path, "wb") as f:
                f.write(b"legacy")

            args = self._make_processing_args(
                input_root,
                output=output_root,
                traditional_zip_policy="move",
                traditional_zip_to=trad_to,
            )
            processor = self.m.ArchiveProcessor(args)

            with (
                mock.patch.object(self.m, "is_zip_format", return_value=True),
                mock.patch.object(self.m, "is_traditional_zip", return_value=True),
                mock.patch.object(self.m, "_txn_create", wraps=self.m._txn_create) as txn_create_mock,
                mock.patch.object(
                    self.m,
                    "_txn_snapshot",
                    wraps=self.m._txn_snapshot,
                ) as txn_snapshot_mock,
                mock.patch.object(
                    self.m,
                    "_set_source_finalization_plan",
                    wraps=self.m._set_source_finalization_plan,
                ) as set_plan_mock,
                mock.patch.object(
                    self.m,
                    "_complete_source_finalization_plan",
                    wraps=self.m._complete_source_finalization_plan,
                ) as complete_plan_mock,
                mock.patch.object(
                    self.m,
                    "_update_dataset_manifest_archive",
                    wraps=self.m._update_dataset_manifest_archive,
                ) as manifest_update_mock,
            ):
                self.assertTrue(processor.process_archive(archive_path))

            txn_create_mock.assert_not_called()
            txn_snapshot_mock.assert_not_called()
            set_plan_mock.assert_not_called()
            complete_plan_mock.assert_not_called()
            manifest_update_mock.assert_not_called()
            self.assertFalse(os.path.exists(self.m._work_base(output_root)))

    def test_process_archive_traditional_zip_move_no_longer_calls_handle_traditional_zip_policy(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            trad_to = os.path.join(td, "traditional")
            os.makedirs(input_root)
            os.makedirs(output_root)
            archive_path = os.path.join(input_root, "legacy.zip")
            with open(archive_path, "wb") as f:
                f.write(b"legacy")

            args = self._make_processing_args(
                input_root,
                output=output_root,
                traditional_zip_policy="move",
                traditional_zip_to=trad_to,
            )
            processor = self.m.ArchiveProcessor(args)

            with (
                mock.patch.object(self.m, "is_zip_format", return_value=True),
                mock.patch.object(self.m, "is_traditional_zip", return_value=True),
                mock.patch.object(
                    self.m.ArchiveProcessor,
                    "handle_traditional_zip_policy",
                    side_effect=AssertionError("legacy helper must not be called"),
                    create=True,
                ),
            ):
                self.assertTrue(processor.process_archive(archive_path))

    def test_process_archive_traditional_zip_move_missing_destination_returns_false_without_txn(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)
            archive_path = os.path.join(input_root, "legacy.zip")
            with open(archive_path, "wb") as f:
                f.write(b"legacy")

            args = self._make_processing_args(
                input_root,
                output=output_root,
                traditional_zip_policy="move",
                traditional_zip_to=None,
            )
            processor = self.m.ArchiveProcessor(args)

            with (
                mock.patch.object(self.m, "is_zip_format", return_value=True),
                mock.patch.object(self.m, "is_traditional_zip", return_value=True),
                mock.patch.object(
                    self.m,
                    "_inspect_traditional_zip_policy",
                    wraps=self.m._inspect_traditional_zip_policy,
                ) as inspect_mock,
                mock.patch.object(self.m, "_txn_create", wraps=self.m._txn_create) as txn_create_mock,
            ):
                self.assertFalse(processor.process_archive(archive_path))

            inspect_mock.assert_called_once_with(args, archive_path)
            txn_create_mock.assert_not_called()
            self.assertTrue(os.path.exists(archive_path))
            self.assertFalse(os.path.exists(self.m._work_base(output_root)))

    def test_process_archive_traditional_zip_move_uses_shared_destination_algorithm(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            trad_to = os.path.join(td, "traditional")
            os.makedirs(os.path.join(input_root, "nested"), exist_ok=True)
            os.makedirs(output_root)
            archive_path = os.path.join(input_root, "nested", "legacy.zip")
            with open(archive_path, "wb") as f:
                f.write(b"legacy")

            os.makedirs(os.path.join(trad_to, "nested"), exist_ok=True)
            with open(os.path.join(trad_to, "nested", "legacy.zip"), "wb") as f:
                f.write(b"existing")

            args = self._make_processing_args(
                input_root,
                output=output_root,
                traditional_zip_policy="move",
                traditional_zip_to=trad_to,
            )
            processor = self.m.ArchiveProcessor(args)
            collision_token = self.m._traditional_zip_move_token(args, [archive_path])
            expected_paths = self.m._traditional_zip_move_destinations(
                args,
                [archive_path],
                collision_token=collision_token,
            )

            with (
                mock.patch.object(self.m, "is_zip_format", return_value=True),
                mock.patch.object(self.m, "is_traditional_zip", return_value=True),
                mock.patch.object(
                    self.m,
                    "_inspect_traditional_zip_policy",
                    wraps=self.m._inspect_traditional_zip_policy,
                ) as inspect_mock,
                mock.patch.object(
                    self.m,
                    "_execute_non_transactional_traditional_zip_move",
                    wraps=self.m._execute_non_transactional_traditional_zip_move,
                ) as move_executor_mock,
                mock.patch.object(
                    self.m,
                    "_txn_create",
                    side_effect=AssertionError("transaction must not be created"),
                ),
            ):
                self.assertTrue(processor.process_archive(archive_path))

            inspect_mock.assert_called_once_with(args, archive_path)
            move_executor_mock.assert_called_once()
            self.assertFalse(os.path.exists(archive_path))
            self.assertTrue(os.path.exists(expected_paths[0][1]))
            self.assertFalse(os.path.exists(self.m._work_base(output_root)))

    def test_process_archive_traditional_zip_move_dry_run_does_not_move_source_or_record_success(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            trad_to = os.path.join(td, "traditional")
            os.makedirs(input_root)
            os.makedirs(output_root)
            archive_path = os.path.join(input_root, "legacy.zip")
            with open(archive_path, "wb") as f:
                f.write(b"legacy")

            args = self._make_processing_args(
                input_root,
                output=output_root,
                traditional_zip_policy="move",
                traditional_zip_to=trad_to,
                dry_run=True,
                legacy=True,
            )
            processor = self.m.ArchiveProcessor(args)
            expected_dst = self.m._traditional_zip_move_destinations(
                args,
                [archive_path],
                collision_token=self.m._traditional_zip_move_token(args, [archive_path]),
            )[0][1]

            with (
                contextlib.redirect_stdout(io.StringIO()),
                mock.patch.object(self.m, "is_zip_format", return_value=True),
                mock.patch.object(self.m, "is_traditional_zip", return_value=True),
            ):
                result = processor.process_archive(archive_path)

            self.assertTrue(result)
            self.assertTrue(os.path.exists(archive_path))
            self.assertFalse(os.path.exists(expected_dst))
            self.assertEqual([], processor.successful_archives)
            self.assertEqual([], processor.failed_archives)
            self.assertEqual([], processor.skipped_archives)

    def test_success_move_fsync_failure_after_rename_keeps_manifest_non_terminal(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            archive_id = self.m._dataset_manifest_archive_id(archive["archive_path"])
            args = fixture["args"]
            args.success_policy = "move"
            args.success_to = os.path.join(td, "success")
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=True,
            )
            txn["state"] = self.m.TXN_STATE_PLACED
            self.m._txn_snapshot(txn)

            with mock.patch.object(
                self.m,
                "_fsync_file",
                side_effect=lambda path, debug=False: not path.endswith(".zip"),
            ):
                with self.assertRaises(RuntimeError):
                    self.m._place_and_finalize_txn(txn, args=args)

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][archive_id]
            self.assertEqual(self.m.TXN_STATE_ABORTED, txn["state"])
            self.assertEqual("DURABILITY_FAILED", txn["error"]["type"])
            self.assertEqual("recoverable", entry["state"])
            self.assertEqual("unknown", entry["final_disposition"])
            self.assertIsNone(entry["finalized_at"])

    def test_success_move_planned_destination_journal_fsync_failure_before_rename_keeps_manifest_recoverable(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_success_finalization_txn_fixture(
                td, success_policy="move"
            )
            archive_path = os.path.abspath(fixture["archive_path"])
            archive_id = fixture["archive_id"]
            planned_dst = os.path.join(
                fixture["args"].success_to,
                fixture["txn"]["txn_id"],
                os.path.basename(archive_path),
            )
            real_fsync_journal_checkpoint = self.m._fsync_journal_checkpoint
            plan_checkpoint_calls = {"count": 0}

            def fail_planned_destination_checkpoint(txn, include_parent=False):
                placement = txn.get("placement") or {}
                finalized_moves = placement.get("finalized_source_moves") or []
                if finalized_moves and not any(
                    record.get("durable") for record in finalized_moves
                ):
                    plan_checkpoint_calls["count"] += 1
                    if plan_checkpoint_calls["count"] == 1:
                        raise RuntimeError(
                            "journal_dir_fsync_failed:dir:planned-destination"
                        )
                return real_fsync_journal_checkpoint(
                    txn, include_parent=include_parent
                )

            with (
                mock.patch.object(self.m, "_fsync_file", return_value=True),
                mock.patch.object(self.m, "_fsync_dir", return_value=True),
                mock.patch.object(
                    self.m,
                    "_fsync_journal_checkpoint",
                    side_effect=fail_planned_destination_checkpoint,
                ),
                self.assertRaises(RuntimeError),
            ):
                self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][archive_id]
            saved_txn = self.m._load_latest_txn_for_archive(
                entry,
                fixture["output_root"],
            )

            self.assertTrue(os.path.exists(archive_path))
            self.assertFalse(os.path.exists(planned_dst))
            self.assertEqual(self.m.TXN_STATE_ABORTED, saved_txn["state"])
            self.assertEqual("DURABILITY_FAILED", saved_txn["error"]["type"])
            self.assertEqual(
                "success:move",
                self.m._txn_source_finalization_plan(saved_txn)["final_disposition"],
            )
            self.assertEqual(
                os.path.abspath(planned_dst),
                self.m._planned_finalized_source_move(saved_txn, archive_path),
            )
            self.assertTrue(self.m._txn_has_incomplete_source_finalization(saved_txn))
            self.assertTrue(self.m._txn_has_recovery_responsibility(saved_txn))
            self.assertEqual("recoverable", entry["state"])
            self.assertEqual("unknown", entry["final_disposition"])
            self.assertIsNone(entry["finalized_at"])
            self.assertEqual("DURABILITY_FAILED", entry["error"]["type"])

    def test_success_move_resume_uses_persisted_destination_without_rerunning_extract(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            args = fixture["args"]
            args.success_policy = "move"
            args.success_to = os.path.join(td, "success")
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=True,
            )
            self.m._set_source_finalization_plan(
                txn,
                manifest_state="succeeded",
                final_disposition="success:move",
                txn_terminal_state=self.m.TXN_STATE_DONE,
            )
            txn["state"] = self.m.TXN_STATE_SOURCE_FINALIZED
            self.m._plan_finalized_source_destination(
                txn,
                archive["archive_path"],
                os.path.join(
                    args.success_to,
                    txn["txn_id"],
                    os.path.basename(archive["archive_path"]),
                ),
            )
            self.m._txn_snapshot(txn)

            with mock.patch.object(
                self.m, "_finalize_sources_success", return_value=None
            ) as finalize_mock:
                self.m._resume_source_finalization_if_needed(txn, args=args)

            self.assertTrue(finalize_mock.called)

    def test_success_move_aborted_after_rename_replays_destination_durability(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_success_finalization_txn_fixture(
                td, success_policy="move"
            )
            txn = fixture["txn"]
            archive_path = os.path.abspath(fixture["archive_path"])
            dst = os.path.join(
                fixture["args"].success_to,
                txn["txn_id"],
                os.path.basename(archive_path),
            )

            self.m._set_source_finalization_plan(
                txn,
                manifest_state="succeeded",
                final_disposition="success:move",
                txn_terminal_state=self.m.TXN_STATE_DONE,
            )
            self.m._plan_finalized_source_destination(txn, archive_path, dst)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            os.replace(archive_path, dst)
            txn["state"] = self.m.TXN_STATE_ABORTED
            txn["error"] = {
                "type": "ABORTED",
                "message": "interrupted after rename before destination fsync",
                "at": self.m._now_iso(),
            }
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                fixture["archive_path"],
                state="retryable",
                last_txn_id=txn["txn_id"],
                final_disposition="unknown",
                error=txn["error"],
                finalized_at=None,
            )

            fsynced_files = []
            fsynced_dirs = []

            def fake_fsync_file(path, debug=False):
                fsynced_files.append(os.path.abspath(path))
                return True

            def fake_fsync_dir(path, debug=False):
                fsynced_dirs.append(os.path.abspath(path))
                return True

            with (
                mock.patch.object(self.m, "_fsync_file", side_effect=fake_fsync_file),
                mock.patch.object(self.m, "_fsync_dir", side_effect=fake_fsync_dir),
            ):
                resumed = self.m._resume_source_finalization_if_needed(
                    txn, args=fixture["args"]
                )

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]

            self.assertTrue(resumed)
            self.assertIn(os.path.abspath(dst), fsynced_files)
            self.assertIn(os.path.abspath(os.path.dirname(dst)), fsynced_dirs)
            self.assertEqual(self.m.TXN_STATE_DONE, txn["state"])
            self.assertEqual("succeeded", entry["state"])
            self.assertEqual("success:move", entry["final_disposition"])

    def test_success_move_durable_marker_journal_fsync_failure_keeps_manifest_recoverable(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_success_finalization_txn_fixture(
                td, success_policy="move"
            )
            archive_path = os.path.abspath(fixture["archive_path"])
            archive_id = fixture["archive_id"]
            real_fsync_journal_checkpoint = self.m._fsync_journal_checkpoint
            marker_failure = RuntimeError("journal_dir_fsync_failed:dir:durable-marker")
            marker_checkpoint_calls = {"count": 0}

            def fail_durable_marker_checkpoint(txn, include_parent=False):
                placement = txn.get("placement") or {}
                finalized_moves = placement.get("finalized_source_moves") or []
                if any(record.get("durable") for record in finalized_moves):
                    marker_checkpoint_calls["count"] += 1
                    if marker_checkpoint_calls["count"] == 1:
                        raise marker_failure
                return real_fsync_journal_checkpoint(txn, include_parent=include_parent)

            with (
                mock.patch.object(self.m, "_fsync_file", return_value=True),
                mock.patch.object(self.m, "_fsync_dir", return_value=True),
                mock.patch.object(
                    self.m,
                    "_fsync_journal_checkpoint",
                    side_effect=fail_durable_marker_checkpoint,
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "journal_dir_fsync_failed:dir:durable-marker",
                ),
            ):
                self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

            moved_dst = os.path.join(
                fixture["args"].success_to,
                fixture["txn"]["txn_id"],
                os.path.basename(archive_path),
            )
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][archive_id]
            saved_txn = self.m._load_latest_txn_for_archive(
                entry,
                fixture["output_root"],
            )

            self.assertFalse(os.path.exists(archive_path))
            self.assertTrue(os.path.exists(moved_dst))
            self.assertEqual(self.m.TXN_STATE_ABORTED, saved_txn["state"])
            self.assertEqual("DURABILITY_FAILED", saved_txn["error"]["type"])
            self.assertEqual(
                "success:move",
                self.m._txn_source_finalization_plan(saved_txn)["final_disposition"],
            )
            self.assertEqual(
                os.path.abspath(moved_dst),
                self.m._planned_finalized_source_move(saved_txn, archive_path),
            )
            self.assertTrue(self.m._txn_has_incomplete_source_finalization(saved_txn))
            self.assertTrue(self.m._txn_has_recovery_responsibility(saved_txn))
            self.assertEqual("recoverable", entry["state"])
            self.assertEqual("unknown", entry["final_disposition"])
            self.assertIsNone(entry["finalized_at"])
            self.assertEqual("DURABILITY_FAILED", entry["error"]["type"])

    def test_success_move_durable_marker_journal_fsync_failure_reopen_resumes_without_rerunning_extract_or_rename(
        self,
    ):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_success_finalization_txn_fixture(
                td, success_policy="move"
            )
            archive_path = os.path.abspath(fixture["archive_path"])
            archive_id = fixture["archive_id"]
            real_fsync_journal_checkpoint = self.m._fsync_journal_checkpoint
            marker_checkpoint_calls = {"count": 0}

            def fail_durable_marker_checkpoint(txn, include_parent=False):
                placement = txn.get("placement") or {}
                finalized_moves = placement.get("finalized_source_moves") or []
                if any(record.get("durable") for record in finalized_moves):
                    marker_checkpoint_calls["count"] += 1
                    if marker_checkpoint_calls["count"] == 1:
                        raise RuntimeError("journal_dir_fsync_failed:dir:durable-marker")
                return real_fsync_journal_checkpoint(txn, include_parent=include_parent)

            with (
                mock.patch.object(self.m, "_fsync_file", return_value=True),
                mock.patch.object(self.m, "_fsync_dir", return_value=True),
                mock.patch.object(
                    self.m,
                    "_fsync_journal_checkpoint",
                    side_effect=fail_durable_marker_checkpoint,
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "journal_dir_fsync_failed:dir:durable-marker",
                ),
            ):
                self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "_fsync_file", return_value=True),
                mock.patch.object(self.m, "_fsync_dir", return_value=True),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "reopen must not re-extract success-move durable-marker journal failure"
                    ),
                ),
                mock.patch.object(
                    self.m,
                    "_atomic_rename",
                    side_effect=AssertionError(
                        "reopen must not rerun success-move source rename after durable-marker journal failure"
                    ),
                ),
                mock.patch.object(self.m, "_garbage_collect"),
            ):
                self.m._run_transactional(processor, [], args=fixture["args"])

            resumed_manifest = self.m._load_dataset_manifest(fixture["output_root"])
            resumed_entry = resumed_manifest["archives"][archive_id]

            self.assertEqual([archive_path], processor.successful_archives)
            self.assertEqual([], processor.failed_archives)
            self.assertEqual("succeeded", resumed_entry["state"])
            self.assertEqual("success:move", resumed_entry["final_disposition"])

    def test_success_delete_resume_cleans_stranded_trash_before_terminalizing(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_success_finalization_txn_fixture(
                td, success_policy="delete"
            )
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            with mock.patch.object(self.m.os, "name", "nt"):
                manifest["command_fingerprint"] = self.m._build_command_fingerprint(
                    fixture["args"]
                )
            self.m._save_dataset_manifest(manifest)
            archive_path = os.path.abspath(fixture["archive_path"])
            archive_id = fixture["archive_id"]
            trash_dir = fixture["txn"]["paths"]["trash_dir"]
            real_safe_rmtree = self.m.safe_rmtree

            def crash_before_trash_cleanup(path, debug=False):
                if os.path.abspath(path) == os.path.abspath(trash_dir):
                    raise SystemExit("crash-before-trash-cleanup")
                return real_safe_rmtree(path, debug)

            with (
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(self.m, "same_volume", return_value=True),
                mock.patch.object(self.m, "_fsync_file", return_value=True),
                mock.patch.object(self.m, "_fsync_dir", return_value=True),
                mock.patch.object(
                    self.m, "safe_rmtree", side_effect=crash_before_trash_cleanup
                ),
                self.assertRaises(SystemExit),
            ):
                self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

            self.assertFalse(os.path.exists(archive_path))
            self.assertTrue(os.path.exists(trash_dir))

            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            with (
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "same_volume", return_value=True),
                mock.patch.object(self.m, "_fsync_file", return_value=True),
                mock.patch.object(self.m, "_fsync_dir", return_value=True),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "resume should clean trash without re-extracting"
                    ),
                ),
                mock.patch.object(self.m, "_garbage_collect"),
            ):
                self.m._run_transactional(processor, [], args=fixture["args"])

            resumed_manifest = self.m._load_dataset_manifest(fixture["output_root"])
            resumed_entry = resumed_manifest["archives"][archive_id]

            self.assertFalse(os.path.exists(trash_dir))
            self.assertEqual([archive_path], processor.successful_archives)
            self.assertEqual([], processor.failed_archives)
            self.assertEqual("succeeded", resumed_entry["state"])
            self.assertEqual("success:delete", resumed_entry["final_disposition"])

    def test_windows_transactional_delete_failure_result_can_still_be_retryable(
        self,
    ):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_success_finalization_txn_fixture(
                td, success_policy="delete"
            )
            archive_path = os.path.abspath(fixture["archive_path"])
            archive_id = fixture["archive_id"]
            planned_dst = os.path.join(
                fixture["txn"]["paths"]["trash_dir"],
                os.path.basename(archive_path),
            )
            real_fsync_journal_checkpoint = self.m._fsync_journal_checkpoint
            plan_checkpoint_calls = {"count": 0}

            def fail_planned_destination_checkpoint(txn, include_parent=False):
                placement = txn.get("placement") or {}
                finalized_moves = placement.get("finalized_source_moves") or []
                if finalized_moves and not any(
                    record.get("durable") for record in finalized_moves
                ):
                    plan_checkpoint_calls["count"] += 1
                    if plan_checkpoint_calls["count"] == 1:
                        raise RuntimeError(
                            "journal_dir_fsync_failed:dir:planned-destination"
                        )
                return real_fsync_journal_checkpoint(
                    txn, include_parent=include_parent
                )

            with (
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "same_volume", return_value=True),
                mock.patch.object(self.m, "_fsync_file", return_value=True),
                mock.patch.object(self.m, "_fsync_dir", return_value=True),
                mock.patch.object(
                    self.m,
                    "_fsync_journal_checkpoint",
                    side_effect=fail_planned_destination_checkpoint,
                ),
                self.assertRaises(RuntimeError),
            ):
                self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][archive_id]
            saved_txn = self.m._load_latest_txn_for_archive(
                entry,
                fixture["output_root"],
            )

            self.assertTrue(os.path.exists(archive_path))
            self.assertFalse(os.path.exists(planned_dst))
            self.assertEqual(self.m.TXN_STATE_ABORTED, saved_txn["state"])
            self.assertEqual("FAIL_FINALIZE_FAILED", saved_txn["error"]["type"])
            self.assertEqual(
                "success:delete",
                self.m._txn_source_finalization_plan(saved_txn)["final_disposition"],
            )
            self.assertEqual(
                os.path.abspath(planned_dst),
                self.m._planned_finalized_source_move(saved_txn, archive_path),
            )
            self.assertTrue(self.m._txn_has_incomplete_source_finalization(saved_txn))
            self.assertTrue(self.m._txn_has_recovery_responsibility(saved_txn))
            self.assertEqual("retryable", entry["state"])
            self.assertEqual("unknown", entry["final_disposition"])
            self.assertIsNone(entry["finalized_at"])
            self.assertEqual("FAIL_FINALIZE_FAILED", entry["error"]["type"])

    def test_manifest_archive_read_side_rejects_removed_legacy_disposition(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td,
                manifest_state="succeeded",
            )
            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]
            entry["state"] = "succeeded"
            entry["final_disposition"] = "success:delete-unsafe-windows"
            entry["finalized_at"] = self.m._now_iso()
            self.m._save_dataset_manifest(manifest)
            os.remove(fixture["archive"]["archive_path"])

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][fixture["archive_id"]]

            self.assertFalse(
                self.m._manifest_archive_allows_missing_input(
                    manifest,
                    entry,
                    fixture["output_root"],
                    missing_path=fixture["archive"]["archive_path"],
                )
            )

    def test_success_delete_trash_cleanup_false_terminalizes_success_with_residue(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_success_finalization_txn_fixture(
                td,
                success_policy="delete",
            )
            archive_path = os.path.abspath(fixture["archive_path"])
            archive_id = fixture["archive_id"]
            trash_dir = fixture["txn"]["paths"]["trash_dir"]
            real_safe_rmtree = self.m.safe_rmtree

            def false_for_trash_dir(path, debug=False):
                if os.path.abspath(path) == os.path.abspath(trash_dir):
                    return False
                return real_safe_rmtree(path, debug)

            with (
                contextlib.redirect_stdout(io.StringIO()),
                mock.patch.object(self.m, "_fsync_file", return_value=True),
                mock.patch.object(self.m, "_fsync_dir", return_value=True),
                mock.patch.object(
                    self.m,
                    "safe_rmtree",
                    side_effect=false_for_trash_dir,
                ),
            ):
                self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][archive_id]
            saved_txn = self.m._load_latest_txn_for_archive(
                entry,
                fixture["output_root"],
            )

            self.assertFalse(os.path.exists(archive_path))
            self.assertTrue(os.path.exists(trash_dir))
            self.assertEqual(self.m.TXN_STATE_DONE, saved_txn["state"])
            self.assertTrue(self.m._txn_source_finalization_completed(saved_txn))
            self.assertFalse(self.m._txn_has_incomplete_source_finalization(saved_txn))
            self.assertFalse(self.m._txn_has_recovery_responsibility(saved_txn))
            self.assertEqual("succeeded", entry["state"])
            self.assertEqual("success:delete", entry["final_disposition"])

    def test_success_delete_trash_cleanup_marker_snapshot_failure_does_not_terminalize_failure(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_success_finalization_txn_fixture(
                td,
                success_policy="delete",
            )
            archive_path = os.path.abspath(fixture["archive_path"])
            archive_id = fixture["archive_id"]
            trash_dir = fixture["txn"]["paths"]["trash_dir"]
            real_safe_rmtree = self.m.safe_rmtree
            real_txn_snapshot = self.m._txn_snapshot
            snapshot_failure = RuntimeError("delete-trash-cleanup-marker-snapshot-failed")
            marker_snapshot_calls = {"count": 0}

            def false_for_trash_dir(path, debug=False):
                if os.path.abspath(path) == os.path.abspath(trash_dir):
                    return False
                return real_safe_rmtree(path, debug)

            def fail_delete_cleanup_marker_snapshot(txn):
                placement = txn.get("placement") or {}
                if placement.get("delete_trash_cleanup_failed"):
                    marker_snapshot_calls["count"] += 1
                    if marker_snapshot_calls["count"] == 1:
                        raise snapshot_failure
                return real_txn_snapshot(txn)

            with (
                contextlib.redirect_stdout(io.StringIO()),
                mock.patch.object(self.m, "_fsync_file", return_value=True),
                mock.patch.object(self.m, "_fsync_dir", return_value=True),
                mock.patch.object(
                    self.m,
                    "safe_rmtree",
                    side_effect=false_for_trash_dir,
                ),
                mock.patch.object(
                    self.m,
                    "_txn_snapshot",
                    side_effect=fail_delete_cleanup_marker_snapshot,
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "delete-trash-cleanup-marker-snapshot-failed",
                ),
            ):
                self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][archive_id]
            saved_txn = self.m._load_latest_txn_for_archive(
                entry,
                fixture["output_root"],
            )

            self.assertFalse(os.path.exists(archive_path))
            self.assertTrue(os.path.exists(trash_dir))
            self.assertEqual(self.m.TXN_STATE_DURABLE, saved_txn["state"])
            self.assertIsNone(saved_txn.get("error"))
            self.assertFalse(
                (saved_txn.get("placement") or {}).get("delete_trash_cleanup_failed")
            )
            self.assertTrue(self.m._txn_has_incomplete_source_finalization(saved_txn))
            self.assertTrue(self.m._txn_has_recovery_responsibility(saved_txn))
            self.assertEqual("pending", entry["state"])
            self.assertEqual("unknown", entry["final_disposition"])
            self.assertIsNone(entry["finalized_at"])
            self.assertIsNone(entry.get("error"))

    def test_extract_failure_move_closed_terminal_crash_retires_residue_on_new_command(
        self,
    ):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            fail_to = os.path.join(td, "failed")
            os.makedirs(input_root)
            os.makedirs(output_root)

            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                ["alpha.zip"],
            )
            archive_path = os.path.abspath(discovered[0]["archive_path"])
            args = self._make_processing_args(
                input_root,
                output=output_root,
                fail_policy="move",
                fail_to=fail_to,
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=discovered,
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            archive_id = self.m._dataset_manifest_archive_id(archive_path)

            processor = types.SimpleNamespace(
                sfx_detector=None,
                get_all_volumes=lambda path: [os.path.abspath(path)],
            )

            real_update_manifest = self.m._update_dataset_manifest_archive

            def crash_before_terminal_manifest(output_base, archive_path_arg, **kwargs):
                if (
                    os.path.abspath(archive_path_arg) == archive_path
                    and kwargs.get("state") == "failed"
                    and kwargs.get("final_disposition") == "failure:move"
                ):
                    raise SystemExit("crash-before-terminal-failure-manifest")
                return real_update_manifest(output_base, archive_path_arg, **kwargs)

            with (
                mock.patch.object(self.m, "_validate_environment_for_output_dir"),
                mock.patch.object(self.m, "try_extract", return_value=False),
                mock.patch.object(
                    self.m,
                    "_update_dataset_manifest_archive",
                    side_effect=crash_before_terminal_manifest,
                ),
                self.assertRaises(SystemExit),
            ):
                self.m._extract_phase(
                    processor,
                    archive_path,
                    args=args,
                    output_base=output_root,
                )

            self.assertFalse(os.path.exists(archive_path))
            crashed_manifest = self.m._load_dataset_manifest(output_root)
            crashed_entry = crashed_manifest["archives"][archive_id]
            self.assertNotEqual("failed", crashed_entry["state"])

            failed_processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "resume should not re-extract after failure source move finalized"
                    ),
                ),
                mock.patch.object(self.m, "_garbage_collect"),
            ):
                result = self.m._run_transactional(failed_processor, [], args=args)

            resumed_manifest = self.m._load_dataset_manifest(output_root)

            self.assertIsNone(result)
            self.assertEqual([], failed_processor.successful_archives)
            self.assertEqual([], failed_processor.failed_archives)
            self.assertEqual([], failed_processor.skipped_archives)
            self.assertIsNone(resumed_manifest)
            self.assertFalse(os.path.exists(self.m._work_base(output_root)))

    def test_extract_failure_move_crash_after_rename_retires_terminal_residue_on_new_command(
        self,
    ):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            fail_to = os.path.join(td, "failed")
            os.makedirs(input_root)
            os.makedirs(output_root)

            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                ["alpha.zip"],
            )
            archive_path = os.path.abspath(discovered[0]["archive_path"])
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            args = self._make_processing_args(
                input_root,
                output=output_root,
                fail_policy="move",
                fail_to=fail_to,
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=discovered,
                command_fingerprint=self.m._build_command_fingerprint(args),
            )

            processor = types.SimpleNamespace(
                sfx_detector=None,
                get_all_volumes=lambda path: [os.path.abspath(path)],
            )
            real_atomic_rename = self.m._atomic_rename

            def crash_after_failure_move(
                src, dst, *, degrade_cross_volume=False, debug=False
            ):
                result = real_atomic_rename(
                    src,
                    dst,
                    degrade_cross_volume=degrade_cross_volume,
                    debug=debug,
                )
                if os.path.abspath(src) == archive_path:
                    raise SystemExit("crash-after-failure-move-rename")
                return result

            with (
                mock.patch.object(self.m, "_validate_environment_for_output_dir"),
                mock.patch.object(self.m, "try_extract", return_value=False),
                mock.patch.object(
                    self.m, "_atomic_rename", side_effect=crash_after_failure_move
                ),
                self.assertRaises(SystemExit),
            ):
                self.m._extract_phase(
                    processor,
                    archive_path,
                    args=args,
                    output_base=output_root,
                )

            self.assertFalse(os.path.exists(archive_path))

            failed_processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "resume should not re-extract after failure move rename"
                    ),
                ),
                mock.patch.object(self.m, "_garbage_collect"),
            ):
                result = self.m._run_transactional(failed_processor, [], args=args)

            resumed_manifest = self.m._load_dataset_manifest(output_root)

            self.assertIsNone(result)
            self.assertEqual([], failed_processor.successful_archives)
            self.assertEqual([], failed_processor.failed_archives)
            self.assertEqual([], failed_processor.skipped_archives)
            self.assertIsNone(resumed_manifest)
            self.assertFalse(os.path.exists(self.m._work_base(output_root)))

    def test_no_password_move_crash_after_source_finalization_resumes_to_terminal_failed(
        self,
    ):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            fail_to = os.path.join(td, "failed")
            os.makedirs(input_root)
            os.makedirs(output_root)

            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                ["secret.zip"],
            )
            archive_path = os.path.abspath(discovered[0]["archive_path"])
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            password_file = os.path.join(td, "passwords.txt")
            with open(password_file, "w", encoding="utf-8") as f:
                f.write("guess\n")

            args = self._make_processing_args(
                input_root,
                output=output_root,
                password_file=password_file,
                fail_policy="move",
                fail_to=fail_to,
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=discovered,
                command_fingerprint=self.m._build_command_fingerprint(args),
            )

            processor = types.SimpleNamespace(
                sfx_detector=None,
                find_correct_password=lambda archive_path, encryption_status=None: None,
                get_all_volumes=lambda path: [os.path.abspath(path)],
            )

            real_finalize_failure = self.m._finalize_sources_failure

            def crash_after_failure_finalize(volumes, *, args, txn=None):
                real_finalize_failure(volumes, args=args, txn=txn)
                raise SystemExit("crash-after-failure-finalize")

            with (
                mock.patch.object(self.m, "_validate_environment_for_output_dir"),
                mock.patch.object(
                    self.m, "check_encryption", return_value="encrypted_header"
                ),
                mock.patch.object(
                    self.m,
                    "_finalize_sources_failure",
                    side_effect=crash_after_failure_finalize,
                ),
                self.assertRaises(SystemExit),
            ):
                self.m._extract_phase(
                    processor,
                    archive_path,
                    args=args,
                    output_base=output_root,
                )

            self.assertFalse(os.path.exists(archive_path))

            failed_processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "resume should not re-enter password probing after fail move finalized"
                    ),
                ),
                mock.patch.object(self.m, "_garbage_collect"),
            ):
                self.m._run_transactional(failed_processor, [], args=args)

            resumed_manifest = self.m._load_dataset_manifest(output_root)
            resumed_entry = resumed_manifest["archives"][archive_id]

            self.assertEqual([], failed_processor.successful_archives)
            self.assertEqual([archive_path], failed_processor.failed_archives)
            self.assertEqual("failed", resumed_entry["state"])
            self.assertEqual("failure:move", resumed_entry["final_disposition"])
            self.assertEqual("NO_PASSWORD", resumed_entry["error"]["type"])

    def test_no_password_move_crash_after_rename_before_destination_persistence_resumes(
        self,
    ):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            fail_to = os.path.join(td, "failed")
            os.makedirs(input_root)
            os.makedirs(output_root)

            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                ["secret.zip"],
            )
            archive_path = os.path.abspath(discovered[0]["archive_path"])
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            password_file = os.path.join(td, "passwords.txt")
            with open(password_file, "w", encoding="utf-8") as f:
                f.write("guess\n")

            args = self._make_processing_args(
                input_root,
                output=output_root,
                password_file=password_file,
                fail_policy="move",
                fail_to=fail_to,
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=discovered,
                command_fingerprint=self.m._build_command_fingerprint(args),
            )

            processor = types.SimpleNamespace(
                sfx_detector=None,
                find_correct_password=lambda archive_path, encryption_status=None: None,
                get_all_volumes=lambda path: [os.path.abspath(path)],
            )
            real_atomic_rename = self.m._atomic_rename

            def crash_after_no_password_move(
                src, dst, *, degrade_cross_volume=False, debug=False
            ):
                result = real_atomic_rename(
                    src,
                    dst,
                    degrade_cross_volume=degrade_cross_volume,
                    debug=debug,
                )
                if os.path.abspath(src) == archive_path:
                    raise SystemExit("crash-after-no-password-move-rename")
                return result

            with (
                mock.patch.object(self.m, "_validate_environment_for_output_dir"),
                mock.patch.object(
                    self.m, "check_encryption", return_value="encrypted_header"
                ),
                mock.patch.object(
                    self.m, "_atomic_rename", side_effect=crash_after_no_password_move
                ),
                self.assertRaises(SystemExit),
            ):
                self.m._extract_phase(
                    processor,
                    archive_path,
                    args=args,
                    output_base=output_root,
                )

            self.assertFalse(os.path.exists(archive_path))

            failed_processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "resume should not rerun password probing after move rename"
                    ),
                ),
                mock.patch.object(self.m, "_garbage_collect"),
            ):
                self.m._run_transactional(failed_processor, [], args=args)

            resumed_manifest = self.m._load_dataset_manifest(output_root)
            resumed_entry = resumed_manifest["archives"][archive_id]

            self.assertEqual([], failed_processor.successful_archives)
            self.assertEqual([archive_path], failed_processor.failed_archives)
            self.assertEqual("failed", resumed_entry["state"])
            self.assertEqual("failure:move", resumed_entry["final_disposition"])
            self.assertEqual("NO_PASSWORD", resumed_entry["error"]["type"])

    def test_traditional_zip_move_closed_terminal_crash_retires_residue_on_new_command(
        self,
    ):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            trad_to = os.path.join(td, "traditional")
            os.makedirs(input_root)
            os.makedirs(output_root)

            archive_path = os.path.join(input_root, "legacy.zip")
            with open(archive_path, "wb") as f:
                f.write(b"legacy")

            args = self._make_processing_args(
                input_root,
                output=output_root,
                traditional_zip_policy="move",
                traditional_zip_to=trad_to,
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=[
                    {
                        "archive_path": archive_path,
                        "output_dir": output_root,
                        "volumes": [archive_path],
                        "requested_policy": args.decompress_policy,
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            archive_id = self.m._dataset_manifest_archive_id(archive_path)

            processor = self.m.ArchiveProcessor(args)

            real_update_manifest = self.m._update_dataset_manifest_archive

            def crash_before_terminal_manifest(
                output_base_arg, archive_path_arg, **kwargs
            ):
                if (
                    os.path.abspath(archive_path_arg) == os.path.abspath(archive_path)
                    and kwargs.get("state") == "succeeded"
                    and kwargs.get("final_disposition")
                    == "skipped:traditional_zip_moved"
                ):
                    raise SystemExit("crash-before-terminal-traditional-manifest")
                return real_update_manifest(output_base_arg, archive_path_arg, **kwargs)

            with (
                mock.patch.object(self.m, "is_zip_format", return_value=True),
                mock.patch.object(self.m, "is_traditional_zip", return_value=True),
                mock.patch.object(
                    self.m,
                    "_update_dataset_manifest_archive",
                    side_effect=crash_before_terminal_manifest,
                ),
                self.assertRaises(SystemExit),
            ):
                result = self.m._extract_phase(
                    processor,
                    archive_path,
                    args=args,
                    output_base=output_root,
                )
                self.m._handle_transactional_result(
                    result,
                    processor=types.SimpleNamespace(
                        successful_archives=[], failed_archives=[], skipped_archives=[]
                    ),
                    args=args,
                    output_base=output_root,
                    touched_output_dirs=set(),
                )

            self.assertFalse(os.path.exists(archive_path))

            resume_processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "resume should not re-run traditional ZIP move after source move finalized"
                    ),
                ),
                mock.patch.object(self.m, "_garbage_collect"),
            ):
                result = self.m._run_transactional(resume_processor, [], args=args)

            resumed_manifest = self.m._load_dataset_manifest(output_root)

            self.assertIsNone(result)
            self.assertEqual([], resume_processor.successful_archives)
            self.assertEqual([], resume_processor.failed_archives)
            self.assertEqual([], resume_processor.skipped_archives)
            self.assertIsNone(resumed_manifest)
            self.assertFalse(os.path.exists(self.m._work_base(output_root)))

    def test_traditional_zip_move_crash_after_rename_before_destination_persistence_resumes(
        self,
    ):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            trad_to = os.path.join(td, "traditional")
            os.makedirs(input_root)
            os.makedirs(output_root)

            archive_path = os.path.join(input_root, "legacy.zip")
            with open(archive_path, "wb") as f:
                f.write(b"legacy")

            args = self._make_processing_args(
                input_root,
                output=output_root,
                traditional_zip_policy="move",
                traditional_zip_to=trad_to,
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=[
                    {
                        "archive_path": archive_path,
                        "output_dir": output_root,
                        "volumes": [archive_path],
                        "requested_policy": args.decompress_policy,
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            processor = self.m.ArchiveProcessor(args)

            real_safe_move = self.m.safe_move
            real_atomic_rename = self.m._atomic_rename

            def crash_after_traditional_move(src, dst, *positional, **kwargs):
                if kwargs:
                    result = real_atomic_rename(src, dst, **kwargs)
                else:
                    result = real_safe_move(src, dst, *positional)
                if os.path.abspath(src) == os.path.abspath(archive_path):
                    raise SystemExit("crash-after-traditional-move-rename")
                return result

            with (
                mock.patch.object(self.m, "is_zip_format", return_value=True),
                mock.patch.object(self.m, "is_traditional_zip", return_value=True),
                mock.patch.object(
                    self.m, "safe_move", side_effect=crash_after_traditional_move
                ),
                mock.patch.object(
                    self.m, "_atomic_rename", side_effect=crash_after_traditional_move
                ),
                self.assertRaises(SystemExit),
            ):
                self.m._extract_phase(
                    processor,
                    archive_path,
                    args=args,
                    output_base=output_root,
                )

            self.assertFalse(os.path.exists(archive_path))

            resume_processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "resume should not rerun traditional ZIP move after rename"
                    ),
                ),
                mock.patch.object(self.m, "_garbage_collect"),
            ):
                self.m._run_transactional(resume_processor, [], args=args)

            resumed_manifest = self.m._load_dataset_manifest(output_root)
            resumed_entry = resumed_manifest["archives"][archive_id]

            self.assertEqual([], resume_processor.failed_archives)
            self.assertEqual(
                [os.path.abspath(archive_path)], resume_processor.successful_archives
            )
            self.assertEqual("succeeded", resumed_entry["state"])
            self.assertEqual(
                "skipped:traditional_zip_moved", resumed_entry["final_disposition"]
            )
            self.assertIsNone(resumed_entry["error"])

    def test_extract_phase_traditional_zip_move_returns_kind_txn_on_success(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            trad_to = os.path.join(td, "traditional")
            os.makedirs(input_root)
            os.makedirs(output_root)
            archive_path = os.path.join(input_root, "legacy.zip")
            with open(archive_path, "wb") as f:
                f.write(b"legacy")

            args = self._make_processing_args(
                input_root,
                output=output_root,
                traditional_zip_policy="move",
                traditional_zip_to=trad_to,
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=[
                    {
                        "archive_path": archive_path,
                        "output_dir": output_root,
                        "volumes": [archive_path],
                        "requested_policy": args.decompress_policy,
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            processor = self.m.ArchiveProcessor(args)
            observed_processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )

            with (
                mock.patch.object(self.m, "is_zip_format", return_value=True),
                mock.patch.object(self.m, "is_traditional_zip", return_value=True),
            ):
                result = self.m._extract_phase(
                    processor,
                    archive_path,
                    args=args,
                    output_base=output_root,
                )

            self.assertEqual("txn", result["kind"])
            self.assertIn("txn", result)

            touched_output_dirs = set()
            self.m._handle_transactional_result(
                result,
                processor=observed_processor,
                args=args,
                output_base=output_root,
                touched_output_dirs=touched_output_dirs,
            )

            manifest = self.m._load_dataset_manifest(output_root)
            entry = manifest["archives"][archive_id]
            txn = self.m._load_latest_txn_for_archive(entry, output_root)
            staging_root = os.path.join(txn["paths"]["work_root"], "staging", txn["txn_id"])
            incoming_root = os.path.join(txn["paths"]["work_root"], "incoming", txn["txn_id"])

            self.assertEqual(
                [os.path.abspath(archive_path)], observed_processor.successful_archives
            )
            self.assertEqual("succeeded", entry["state"])
            self.assertEqual("skipped:traditional_zip_moved", entry["final_disposition"])
            self.assertTrue(self.m._txn_is_closed_terminal_outcome(txn))
            self.assertFalse(os.path.exists(staging_root))
            self.assertFalse(os.path.exists(incoming_root))
            self.assertTrue(os.path.exists(txn["paths"]["journal_dir"]))
            self.assertEqual({output_root}, touched_output_dirs)

    def test_fail_move_fsync_failure_after_rename_keeps_manifest_retryable(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            fail_to = os.path.join(td, "failed")
            os.makedirs(input_root)
            os.makedirs(output_root)
            archive_path = os.path.join(input_root, "alpha.zip")
            with open(archive_path, "wb") as f:
                f.write(b"zip")
            args = self._make_processing_args(
                input_root, output=output_root, fail_policy="move", fail_to=fail_to
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=[
                    {
                        "archive_path": archive_path,
                        "output_dir": output_root,
                        "volumes": [archive_path],
                        "requested_policy": args.decompress_policy,
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            processor = self.m.ArchiveProcessor(args)

            with (
                mock.patch.object(self.m, "try_extract", return_value=False),
                mock.patch.object(
                    self.m,
                    "_fsync_file",
                    side_effect=lambda path, debug=False: not path.endswith(".zip"),
                ),
            ):
                result = self.m._extract_phase(
                    processor, archive_path, args=args, output_base=output_root
                )

            self.assertEqual("txn_failed", result["kind"])
            self.assertEqual(self.m.TXN_STATE_ABORTED, result["txn"]["state"])
            self.assertEqual("FAIL_FINALIZE_FAILED", result["txn"]["error"]["type"])
            manifest = self.m._load_dataset_manifest(output_root)
            entry = manifest["archives"][archive_id]
            self.assertEqual("retryable", entry["state"])
            self.assertEqual("unknown", entry["final_disposition"])
            self.assertIsNone(entry["finalized_at"])

    def test_extract_phase_traditional_zip_move_post_txn_failure_returns_txn_failed(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            trad_to = os.path.join(td, "traditional")
            os.makedirs(input_root)
            os.makedirs(output_root)
            archive_path = os.path.join(input_root, "legacy.zip")
            with open(archive_path, "wb") as f:
                f.write(b"legacy")
            args = self._make_processing_args(
                input_root,
                output=output_root,
                traditional_zip_policy="move",
                traditional_zip_to=trad_to,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=[
                    {
                        "archive_path": archive_path,
                        "output_dir": output_root,
                        "volumes": [archive_path],
                        "requested_policy": args.decompress_policy,
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            processor = self.m.ArchiveProcessor(args)

            with (
                mock.patch.object(self.m, "is_zip_format", return_value=True),
                mock.patch.object(self.m, "is_traditional_zip", return_value=True),
                mock.patch.object(
                    self.m,
                    "_finalize_traditional_zip_move",
                    side_effect=RuntimeError("traditional move finalize boom"),
                ),
            ):
                result = self.m._extract_phase(
                    processor, archive_path, args=args, output_base=output_root
                )

            self.assertEqual("txn_failed", result["kind"])
            self.assertEqual(self.m.TXN_STATE_ABORTED, result["txn"]["state"])
            self.assertEqual("FAIL_FINALIZE_FAILED", result["txn"]["error"]["type"])

            observed_processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            self.m._handle_transactional_result(
                result,
                processor=observed_processor,
                args=args,
                output_base=output_root,
                touched_output_dirs=set(),
            )

            manifest = self.m._load_dataset_manifest(output_root)
            entry = manifest["archives"][archive_id]
            self.assertEqual([os.path.abspath(archive_path)], observed_processor.failed_archives)
            self.assertEqual("retryable", entry["state"])
            self.assertEqual("unknown", entry["final_disposition"])
            self.assertIsNone(entry["finalized_at"])

    def test_traditional_zip_move_source_finalized_snapshot_failure_stays_retryable(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            trad_to = os.path.join(td, "traditional")
            os.makedirs(input_root)
            os.makedirs(output_root)
            archive_path = os.path.join(input_root, "legacy.zip")
            with open(archive_path, "wb") as f:
                f.write(b"legacy")
            args = self._make_processing_args(
                input_root,
                output=output_root,
                traditional_zip_policy="move",
                traditional_zip_to=trad_to,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=[
                    {
                        "archive_path": archive_path,
                        "output_dir": output_root,
                        "volumes": [archive_path],
                        "requested_policy": args.decompress_policy,
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            processor = self.m.ArchiveProcessor(args)
            real_txn_snapshot = self.m._txn_snapshot

            def fail_source_finalized_snapshot(txn):
                if txn.get("state") == self.m.TXN_STATE_SOURCE_FINALIZED:
                    raise RuntimeError("source-finalized-snapshot-failed")
                return real_txn_snapshot(txn)

            with (
                mock.patch.object(self.m, "is_zip_format", return_value=True),
                mock.patch.object(self.m, "is_traditional_zip", return_value=True),
                mock.patch.object(
                    self.m,
                    "_txn_snapshot",
                    side_effect=fail_source_finalized_snapshot,
                ),
            ):
                result = self.m._extract_phase(
                    processor, archive_path, args=args, output_base=output_root
                )
                self.m._handle_transactional_result(
                    result,
                    processor=types.SimpleNamespace(
                        successful_archives=[], failed_archives=[], skipped_archives=[]
                    ),
                    args=args,
                    output_base=output_root,
                    touched_output_dirs=set(),
                )

            manifest = self.m._load_dataset_manifest(output_root)
            entry = manifest["archives"][archive_id]
            saved_txn = self.m._load_latest_txn_for_archive(entry, output_root)

            self.assertEqual("txn_failed", result["kind"])
            self.assertEqual("retryable", entry["state"])
            self.assertEqual("unknown", entry["final_disposition"])
            self.assertIsNone(entry["finalized_at"])
            self.assertEqual(self.m.TXN_STATE_ABORTED, saved_txn["state"])
            self.assertEqual("FAIL_FINALIZE_FAILED", saved_txn["error"]["type"])
            self.assertTrue(saved_txn["placement"]["finalized_source_moves"][0]["durable"])
            self.assertTrue(self.m._txn_has_recovery_responsibility(saved_txn))
            self.assertFalse(self.m._txn_is_closed_terminal_outcome(saved_txn))

    def test_extract_phase_traditional_zip_move_pre_txn_failure_returns_exact_failed_handoff(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            trad_to = os.path.join(td, "traditional")
            os.makedirs(input_root)
            os.makedirs(output_root)
            archive_path = os.path.join(input_root, "legacy.zip")
            with open(archive_path, "wb") as f:
                f.write(b"legacy")
            args = self._make_processing_args(
                input_root,
                output=output_root,
                traditional_zip_policy="move",
                traditional_zip_to=trad_to,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=[
                    {
                        "archive_path": archive_path,
                        "output_dir": output_root,
                        "volumes": [archive_path],
                        "requested_policy": args.decompress_policy,
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            processor = self.m.ArchiveProcessor(args)

            with (
                mock.patch.object(self.m, "is_zip_format", return_value=True),
                mock.patch.object(self.m, "is_traditional_zip", return_value=True),
                mock.patch.object(
                    self.m,
                    "_txn_create",
                    side_effect=RuntimeError("txn create boom"),
                ),
            ):
                result = self.m._extract_phase(
                    processor, archive_path, args=args, output_base=output_root
                )

            self.assertEqual("failed", result["kind"])
            self.assertEqual(os.path.abspath(archive_path), result["archive_path"])
            self.assertEqual("traditional_zip_move_failed", result["reason"])
            self.assertEqual("traditional_zip_move_failed", result["error"])
            self.assertEqual("retryable", result["manifest_state"])
            self.assertEqual("unknown", result["manifest_final_disposition"])
            self.assertEqual("FAIL_FINALIZE_FAILED", result["manifest_error"]["type"])
            self.assertIn("txn create boom", result["manifest_error"]["message"])

    def test_traditional_zip_move_honors_pre_txn_failure_manifest_fields(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)
            archive_path = os.path.join(input_root, "legacy.zip")
            with open(archive_path, "wb") as f:
                f.write(b"legacy")

            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=[
                    {
                        "archive_path": archive_path,
                        "output_dir": output_root,
                        "volumes": [archive_path],
                        "requested_policy": "direct",
                    }
                ],
                command_fingerprint=self._make_manifest_command_fingerprint(
                    input_root, output_root
                ),
            )

            result = {
                "kind": "failed",
                "archive_path": archive_path,
                "reason": "traditional_zip_move_failed",
                "error": "traditional_zip_move_failed",
                "manifest_state": "retryable",
                "manifest_final_disposition": "unknown",
                "manifest_error": {
                    "type": "FAIL_FINALIZE_FAILED",
                    "message": "txn create boom",
                    "at": self.m._now_iso(),
                },
            }
            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )

            self.m._handle_transactional_result(
                result,
                processor=processor,
                args=self._make_processing_args(
                    input_root,
                    output=output_root,
                    traditional_zip_policy="move",
                ),
                output_base=output_root,
                touched_output_dirs=set(),
            )

            manifest = self.m._load_dataset_manifest(output_root)
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            entry = manifest["archives"][archive_id]

            self.assertEqual(
                [os.path.abspath(archive_path)], processor.failed_archives
            )
            self.assertEqual("retryable", entry["state"])
            self.assertEqual("unknown", entry["final_disposition"])
            self.assertIsNone(entry["finalized_at"])
            self.assertEqual("FAIL_FINALIZE_FAILED", entry["error"]["type"])
            self.assertIn("txn create boom", entry["error"]["message"])

    def test_finalize_traditional_zip_move_resume_fallback_does_not_use_txn_id_suffix(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            trad_to = os.path.join(td, "traditional")
            os.makedirs(input_root)
            os.makedirs(output_root)
            os.makedirs(trad_to)
            archive_path = os.path.join(input_root, "legacy.zip")
            with open(archive_path, "wb") as f:
                f.write(b"legacy")
            with open(os.path.join(trad_to, "legacy.zip"), "wb") as f:
                f.write(b"existing")

            args = self._make_processing_args(
                input_root,
                output=output_root,
                traditional_zip_policy="move",
                traditional_zip_to=trad_to,
            )
            txn = self.m._txn_create(
                archive_path=archive_path,
                volumes=[archive_path],
                output_dir=output_root,
                output_base=output_root,
                policy=args.decompress_policy,
                wal_fsync_every=args.wal_fsync_every,
                snapshot_every=args.snapshot_every,
                durability_enabled=True,
            )
            txn["placement"] = {}

            expected_dst = self.m._traditional_zip_move_destinations(
                args,
                [archive_path],
                collision_token=self.m._traditional_zip_move_token(args, [archive_path]),
            )[0][1]
            txn_id_dst = os.path.join(
                trad_to,
                f"legacy_{txn['txn_id'][:8]}_1.zip",
            )

            with (
                mock.patch.object(self.m, "_fsync_file", return_value=True),
                mock.patch.object(self.m, "_fsync_dir", return_value=True),
            ):
                self.m._finalize_traditional_zip_move(txn, args=args)

            self.assertTrue(os.path.exists(expected_dst))
            self.assertFalse(os.path.exists(txn_id_dst))

    def test_fail_move_fsync_failure_reopen_resumes_from_persisted_destination_without_rerunning_move_or_extract(
        self,
    ):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            fail_to = os.path.join(td, "failed")
            os.makedirs(input_root)
            os.makedirs(output_root)
            archive_path = os.path.join(input_root, "alpha.zip")
            with open(archive_path, "wb") as f:
                f.write(b"zip")
            args = self._make_processing_args(
                input_root,
                output=output_root,
                fail_policy="move",
                fail_to=fail_to,
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=[
                    {
                        "archive_path": archive_path,
                        "output_dir": output_root,
                        "volumes": [archive_path],
                        "requested_policy": args.decompress_policy,
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            processor = self.m.ArchiveProcessor(args)

            with (
                mock.patch.object(self.m, "try_extract", return_value=False),
                mock.patch.object(
                    self.m,
                    "_fsync_file",
                    side_effect=lambda path, debug=False: not path.endswith(".zip"),
                ),
            ):
                result = self.m._extract_phase(
                    processor, archive_path, args=args, output_base=output_root
                )

            moved_dst = result["txn"]["placement"]["finalized_source_moves"][0]["dst"]
            self.assertTrue(os.path.exists(moved_dst))
            self.assertFalse(os.path.exists(archive_path))

            plan_manifest = self.m._load_dataset_manifest(output_root)
            recoverable_archives, retryable_archives, pending_archives = (
                self.m._build_transactional_archive_plan(plan_manifest, output_root)
            )
            self.assertEqual(
                [{"archive_path": os.path.abspath(archive_path), "output_dir": output_root}],
                recoverable_archives,
            )
            self.assertEqual([], retryable_archives)
            self.assertEqual([], pending_archives)

            resume_processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "reopen must not re-extract fail-move fsync failure txn"
                    ),
                ),
                mock.patch.object(
                    self.m,
                    "_atomic_rename",
                    side_effect=AssertionError(
                        "reopen must not rerun fail-move source rename"
                    ),
                ),
                mock.patch.object(self.m, "_garbage_collect"),
            ):
                self.m._run_transactional(resume_processor, [], args=args)

            resumed_manifest = self.m._load_dataset_manifest(output_root)
            resumed_entry = resumed_manifest["archives"][archive_id]

            self.assertEqual([], resume_processor.successful_archives)
            self.assertEqual([os.path.abspath(archive_path)], resume_processor.failed_archives)
            self.assertEqual("failed", resumed_entry["state"])
            self.assertEqual("failure:move", resumed_entry["final_disposition"])
            self.assertTrue(os.path.exists(moved_dst))
            self.assertFalse(os.path.exists(archive_path))

    def test_fail_move_aborted_after_rename_replays_destination_durability(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            fail_to = os.path.join(td, "failed")
            os.makedirs(input_root)
            os.makedirs(output_root)
            archive_path = os.path.join(input_root, "alpha.zip")
            with open(archive_path, "wb") as f:
                f.write(b"zip")
            args = self._make_processing_args(
                input_root,
                output=output_root,
                fail_policy="move",
                fail_to=fail_to,
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=[
                    {
                        "archive_path": archive_path,
                        "output_dir": output_root,
                        "volumes": [archive_path],
                        "requested_policy": args.decompress_policy,
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            txn = self.m._txn_create(
                archive_path=archive_path,
                volumes=[archive_path],
                output_dir=output_root,
                output_base=output_root,
                policy=args.decompress_policy,
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            moved_dst = os.path.join(fail_to, txn["txn_id"], os.path.basename(archive_path))

            self.m._set_source_finalization_plan(
                txn,
                manifest_state="failed",
                final_disposition="failure:move",
                txn_terminal_state=self.m.TXN_STATE_FAILED,
            )
            self.m._plan_finalized_source_destination(txn, archive_path, moved_dst)
            os.makedirs(os.path.dirname(moved_dst), exist_ok=True)
            os.replace(archive_path, moved_dst)
            txn["state"] = self.m.TXN_STATE_ABORTED
            txn["error"] = {
                "type": "ABORTED",
                "message": "interrupted after rename before destination fsync",
                "at": self.m._now_iso(),
            }
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                output_root,
                archive_path,
                state="retryable",
                last_txn_id=txn["txn_id"],
                final_disposition="unknown",
                error=txn["error"],
                finalized_at=None,
            )

            fsynced_files = []
            fsynced_dirs = []

            def fake_fsync_file(path, debug=False):
                fsynced_files.append(os.path.abspath(path))
                return True

            def fake_fsync_dir(path, debug=False):
                fsynced_dirs.append(os.path.abspath(path))
                return True

            with (
                mock.patch.object(self.m, "_fsync_file", side_effect=fake_fsync_file),
                mock.patch.object(self.m, "_fsync_dir", side_effect=fake_fsync_dir),
            ):
                resumed = self.m._resume_source_finalization_if_needed(txn, args=args)

            manifest = self.m._load_dataset_manifest(output_root)
            entry = manifest["archives"][archive_id]

            self.assertTrue(resumed)
            self.assertIn(os.path.abspath(moved_dst), fsynced_files)
            self.assertIn(os.path.abspath(os.path.dirname(moved_dst)), fsynced_dirs)
            self.assertEqual(self.m.TXN_STATE_FAILED, txn["state"])
            self.assertEqual("failed", entry["state"])
            self.assertEqual("failure:move", entry["final_disposition"])

    def test_traditional_zip_move_fsync_failure_reopen_resumes_from_persisted_destination_without_rerunning_move(
        self,
    ):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            trad_to = os.path.join(td, "traditional")
            os.makedirs(input_root)
            os.makedirs(output_root)
            archive_path = os.path.join(input_root, "legacy.zip")
            with open(archive_path, "wb") as f:
                f.write(b"legacy")
            args = self._make_processing_args(
                input_root,
                output=output_root,
                traditional_zip_policy="move",
                traditional_zip_to=trad_to,
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=[
                    {
                        "archive_path": archive_path,
                        "output_dir": output_root,
                        "volumes": [archive_path],
                        "requested_policy": args.decompress_policy,
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            processor = self.m.ArchiveProcessor(args)

            with (
                mock.patch.object(self.m, "is_zip_format", return_value=True),
                mock.patch.object(self.m, "is_traditional_zip", return_value=True),
                mock.patch.object(
                    self.m,
                    "_fsync_file",
                    side_effect=lambda path, debug=False: not path.endswith(".zip"),
                ),
            ):
                result = self.m._extract_phase(
                    processor, archive_path, args=args, output_base=output_root
                )
                self.m._handle_transactional_result(
                    result,
                    processor=types.SimpleNamespace(
                        successful_archives=[], failed_archives=[], skipped_archives=[]
                    ),
                    args=args,
                    output_base=output_root,
                    touched_output_dirs=set(),
                )

            moved_dst = result["manifest_error"]
            self.assertIsNotNone(moved_dst)

            latest_manifest = self.m._load_dataset_manifest(output_root)
            latest_txn = self.m._load_latest_txn_for_archive(
                latest_manifest["archives"][archive_id], output_root
            )
            persisted_dst = latest_txn["placement"]["finalized_source_moves"][0]["dst"]
            self.assertTrue(os.path.exists(persisted_dst))
            self.assertFalse(os.path.exists(archive_path))

            plan_manifest = self.m._load_dataset_manifest(output_root)
            recoverable_archives, retryable_archives, pending_archives = (
                self.m._build_transactional_archive_plan(plan_manifest, output_root)
            )
            self.assertEqual(
                [{"archive_path": os.path.abspath(archive_path), "output_dir": output_root}],
                recoverable_archives,
            )
            self.assertEqual([], retryable_archives)
            self.assertEqual([], pending_archives)

            resume_processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "reopen must not re-extract traditional zip move fsync failure"
                    ),
                ),
                mock.patch.object(
                    self.m,
                    "_atomic_rename",
                    side_effect=AssertionError(
                        "reopen must not rerun traditional zip source rename"
                    ),
                ),
                mock.patch.object(self.m, "_garbage_collect"),
            ):
                self.m._run_transactional(resume_processor, [], args=args)

            resumed_manifest = self.m._load_dataset_manifest(output_root)
            resumed_entry = resumed_manifest["archives"][archive_id]

            self.assertEqual([], resume_processor.failed_archives)
            self.assertEqual([os.path.abspath(archive_path)], resume_processor.successful_archives)
            self.assertEqual("succeeded", resumed_entry["state"])
            self.assertEqual("skipped:traditional_zip_moved", resumed_entry["final_disposition"])
            self.assertTrue(os.path.exists(persisted_dst))
            self.assertFalse(os.path.exists(archive_path))

    def test_traditional_zip_move_aborted_after_rename_replays_destination_durability(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            trad_to = os.path.join(td, "traditional")
            os.makedirs(input_root)
            os.makedirs(output_root)
            archive_path = os.path.join(input_root, "legacy.zip")
            with open(archive_path, "wb") as f:
                f.write(b"legacy")
            args = self._make_processing_args(
                input_root,
                output=output_root,
                traditional_zip_policy="move",
                traditional_zip_to=trad_to,
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=[
                    {
                        "archive_path": archive_path,
                        "output_dir": output_root,
                        "volumes": [archive_path],
                        "requested_policy": args.decompress_policy,
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            txn = self.m._txn_create(
                archive_path=archive_path,
                volumes=[archive_path],
                output_dir=output_root,
                output_base=output_root,
                policy=args.decompress_policy,
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            moved_dst = os.path.join(trad_to, os.path.basename(archive_path))

            self.m._set_source_finalization_plan(
                txn,
                manifest_state="succeeded",
                final_disposition="skipped:traditional_zip_moved",
                txn_terminal_state=self.m.TXN_STATE_DONE,
            )
            self.m._plan_finalized_source_destination(txn, archive_path, moved_dst)
            os.makedirs(os.path.dirname(moved_dst), exist_ok=True)
            os.replace(archive_path, moved_dst)
            txn["state"] = self.m.TXN_STATE_ABORTED
            txn["error"] = {
                "type": "ABORTED",
                "message": "interrupted after rename before destination fsync",
                "at": self.m._now_iso(),
            }
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                output_root,
                archive_path,
                state="retryable",
                last_txn_id=txn["txn_id"],
                final_disposition="unknown",
                error=txn["error"],
                finalized_at=None,
            )

            fsynced_files = []
            fsynced_dirs = []

            def fake_fsync_file(path, debug=False):
                fsynced_files.append(os.path.abspath(path))
                return True

            def fake_fsync_dir(path, debug=False):
                fsynced_dirs.append(os.path.abspath(path))
                return True

            with (
                mock.patch.object(self.m, "_fsync_file", side_effect=fake_fsync_file),
                mock.patch.object(self.m, "_fsync_dir", side_effect=fake_fsync_dir),
            ):
                resumed = self.m._resume_source_finalization_if_needed(txn, args=args)

            manifest = self.m._load_dataset_manifest(output_root)
            entry = manifest["archives"][archive_id]

            self.assertTrue(resumed)
            self.assertIn(os.path.abspath(moved_dst), fsynced_files)
            self.assertIn(os.path.abspath(os.path.dirname(moved_dst)), fsynced_dirs)
            self.assertEqual(self.m.TXN_STATE_DONE, txn["state"])
            self.assertEqual("succeeded", entry["state"])
            self.assertEqual("skipped:traditional_zip_moved", entry["final_disposition"])

    def test_traditional_zip_move_recovery_source_finalized_snapshot_failure_stays_recoverable(
        self,
    ):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            trad_to = os.path.join(td, "traditional")
            os.makedirs(input_root)
            os.makedirs(output_root)
            archive_path = os.path.join(input_root, "legacy.zip")
            with open(archive_path, "wb") as f:
                f.write(b"legacy")

            args = self._make_processing_args(
                input_root,
                output=output_root,
                traditional_zip_policy="move",
                traditional_zip_to=trad_to,
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=[
                    {
                        "archive_path": archive_path,
                        "output_dir": output_root,
                        "volumes": [archive_path],
                        "requested_policy": args.decompress_policy,
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            processor = self.m.ArchiveProcessor(args)

            with (
                mock.patch.object(self.m, "is_zip_format", return_value=True),
                mock.patch.object(self.m, "is_traditional_zip", return_value=True),
                mock.patch.object(
                    self.m,
                    "_fsync_file",
                    side_effect=lambda path, debug=False: not path.endswith(".zip"),
                ),
            ):
                result = self.m._extract_phase(
                    processor, archive_path, args=args, output_base=output_root
                )
                self.m._handle_transactional_result(
                    result,
                    processor=types.SimpleNamespace(
                        successful_archives=[], failed_archives=[], skipped_archives=[]
                    ),
                    args=args,
                    output_base=output_root,
                    touched_output_dirs=set(),
                )

            initial_manifest = self.m._load_dataset_manifest(output_root)
            initial_entry = initial_manifest["archives"][archive_id]
            initial_txn = self.m._load_latest_txn_for_archive(initial_entry, output_root)
            self.assertEqual(self.m.TXN_STATE_ABORTED, initial_txn["state"])
            self.assertEqual("FAIL_FINALIZE_FAILED", initial_txn["error"]["type"])

            real_txn_snapshot = self.m._txn_snapshot

            def fail_recovery_source_finalized_snapshot(txn):
                if txn.get("state") == self.m.TXN_STATE_SOURCE_FINALIZED:
                    raise RuntimeError("source-finalized-snapshot-failed-on-recovery")
                return real_txn_snapshot(txn)

            resume_processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "recovery snapshot failure must not rerun extraction"
                    ),
                ),
                mock.patch.object(
                    self.m,
                    "_txn_snapshot",
                    side_effect=fail_recovery_source_finalized_snapshot,
                ),
                mock.patch.object(self.m, "_garbage_collect"),
            ):
                self.m._run_transactional(resume_processor, [], args=args)

            resumed_manifest = self.m._load_dataset_manifest(output_root)
            resumed_entry = resumed_manifest["archives"][archive_id]
            saved_txn = self.m._load_latest_txn_for_archive(resumed_entry, output_root)
            recoverable_archives, retryable_archives, pending_archives = (
                self.m._build_transactional_archive_plan(resumed_manifest, output_root)
            )

            self.assertEqual([], resume_processor.successful_archives)
            self.assertEqual([os.path.abspath(archive_path)], resume_processor.failed_archives)
            self.assertEqual(self.m.TXN_STATE_ABORTED, saved_txn["state"])
            self.assertEqual("FAIL_FINALIZE_FAILED", saved_txn["error"]["type"])
            self.assertTrue(saved_txn["placement"]["finalized_source_moves"][0]["durable"])
            self.assertTrue(self.m._txn_has_recovery_responsibility(saved_txn))
            self.assertFalse(self.m._txn_is_closed_terminal_outcome(saved_txn))
            self.assertEqual("recoverable", resumed_entry["state"])
            self.assertEqual("unknown", resumed_entry["final_disposition"])
            self.assertIsNone(resumed_entry["finalized_at"])
            self.assertEqual(
                "resume_required",
                self.m._reconciled_archive_classification(resumed_entry, saved_txn),
            )
            self.assertEqual(
                [{"archive_path": os.path.abspath(archive_path), "output_dir": output_root}],
                recoverable_archives,
            )
            self.assertEqual([], retryable_archives)
            self.assertEqual([], pending_archives)

    def test_sigint_during_extract_becomes_retryable_or_recoverable(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        self.addCleanup(self.m.reset_interrupt_flag)

        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                ["done.zip", "failed.zip", "interrupt.zip"],
            )
            archive_paths = [
                os.path.abspath(item["archive_path"]) for item in discovered
            ]
            args = self._make_processing_args(
                input_root,
                output=output_root,
                threads=1,
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            archive_ids = {
                os.path.basename(
                    item["archive_path"]
                ): self.m._dataset_manifest_archive_id(item["archive_path"])
                for item in discovered
            }
            first_processor = self._make_transactional_processor_stub()
            first_processor.find_archives = mock.Mock(return_value=archive_paths)

            def first_run_try_extract(
                archive_path,
                password,
                staging_dir,
                zip_decode,
                enable_rar,
                sfx_detector,
                detect_elf_sfx=False,
            ):
                archive_name = os.path.basename(archive_path)
                if archive_name == "failed.zip":
                    return False
                with open(
                    os.path.join(
                        staging_dir,
                        archive_name.replace(".zip", "") + ".txt",
                    ),
                    "w",
                    encoding="utf-8",
                ) as f:
                    f.write(archive_name)
                if archive_name == "interrupt.zip":
                    self.m.set_interrupt_flag()
                return True

            first_stdout = io.StringIO()
            with (
                contextlib.redirect_stdout(first_stdout),
                mock.patch.object(self.m.sys, "argv", self._argv_for_main(args)),
                mock.patch.object(
                    self.m,
                    "safe_subprocess_run",
                    return_value=SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
                ),
                mock.patch.object(
                    self.m, "ArchiveProcessor", return_value=first_processor
                ),
                mock.patch.object(self.m, "fix_archive_ext") as first_fix_archive_ext,
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "_validate_environment_for_output_dir"),
                mock.patch.object(
                    self.m,
                    "try_extract",
                    side_effect=first_run_try_extract,
                ),
                mock.patch.object(self.m, "_garbage_collect"),
            ):
                first_exit_code = self.m.main()

            self.assertEqual(1, first_exit_code)
            first_fix_archive_ext.assert_called_once()
            first_processor.find_archives.assert_called_once_with(
                os.path.abspath(input_root)
            )
            self.m.reset_interrupt_flag()

            manifest = self.m._load_dataset_manifest(output_root)
            done_entry = manifest["archives"][archive_ids["done.zip"]]
            failed_entry = manifest["archives"][archive_ids["failed.zip"]]
            interrupted_entry = manifest["archives"][archive_ids["interrupt.zip"]]

            self.assertEqual("succeeded", done_entry["state"])
            self.assertEqual("failed", failed_entry["state"])
            self.assertIn(interrupted_entry["state"], ("retryable", "recoverable"))
            self.assertEqual(1, interrupted_entry["attempts"])
            self.assertEqual("ABORTED", interrupted_entry["error"]["type"])

            new_archive = os.path.join(input_root, "new.zip")
            with open(new_archive, "wb") as f:
                f.write(b"new")

            resume_processor = self._make_transactional_processor_stub()
            resume_processor.find_archives = mock.Mock(
                side_effect=AssertionError(
                    "same-command strict resume should use the manifest instead of rescanning input"
                )
            )

            resume_stdout = io.StringIO()
            with (
                contextlib.redirect_stdout(resume_stdout),
                mock.patch.object(self.m.sys, "argv", self._argv_for_main(args)),
                mock.patch.object(
                    self.m,
                    "safe_subprocess_run",
                    return_value=SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
                ),
                mock.patch.object(
                    self.m, "ArchiveProcessor", return_value=resume_processor
                ),
                mock.patch.object(self.m, "fix_archive_ext") as resume_fix_archive_ext,
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(
                    self.m,
                    "try_extract",
                    side_effect=AssertionError(
                        "resume should recover the interrupted archive without re-extracting any archive"
                    ),
                ),
                mock.patch.object(self.m, "_garbage_collect"),
            ):
                resume_exit_code = self.m.main()

            resumed_manifest = self.m._load_dataset_manifest(output_root)
            resumed_done_entry = resumed_manifest["archives"][archive_ids["done.zip"]]
            resumed_failed_entry = resumed_manifest["archives"][
                archive_ids["failed.zip"]
            ]
            resumed_interrupted_entry = resumed_manifest["archives"][
                archive_ids["interrupt.zip"]
            ]
            revisited_archives = (
                resume_processor.successful_archives + resume_processor.failed_archives
            )

            resume_processor.find_archives.assert_not_called()
            resume_fix_archive_ext.assert_not_called()
            self.assertNotIn(
                self.m._dataset_manifest_archive_id(new_archive),
                resumed_manifest["archives"],
            )
            self.assertEqual(
                [os.path.abspath(discovered[2]["archive_path"])], revisited_archives
            )
            self.assertNotIn(
                os.path.abspath(discovered[0]["archive_path"]), revisited_archives
            )
            self.assertNotIn(
                os.path.abspath(discovered[1]["archive_path"]), revisited_archives
            )
            self.assertNotIn(os.path.abspath(new_archive), revisited_archives)
            self.assertEqual("succeeded", resumed_done_entry["state"])
            self.assertEqual("failed", resumed_failed_entry["state"])
            self.assertIn(resumed_interrupted_entry["state"], ("succeeded", "failed"))
            self.assertEqual("failed", resumed_manifest["status"])

            if resumed_interrupted_entry["state"] == "succeeded":
                self.assertEqual(0, resume_exit_code)
                self.assertEqual(
                    [os.path.abspath(discovered[2]["archive_path"])],
                    resume_processor.successful_archives,
                )
                self.assertEqual([], resume_processor.failed_archives)
            else:
                self.assertEqual(1, resume_exit_code)
                self.assertEqual([], resume_processor.successful_archives)
                self.assertEqual(
                    [os.path.abspath(discovered[2]["archive_path"])],
                    resume_processor.failed_archives,
                )

    def test_resume_after_partial_placing_uses_recovery_without_reextract(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        self.addCleanup(self.m.reset_interrupt_flag)

        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            archive_path = os.path.join(input_root, "alpha.zip")
            with open(archive_path, "wb") as f:
                f.write(b"alpha")

            args = self._make_processing_args(
                input_root,
                output=output_root,
                threads=1,
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            processor = self._make_transactional_processor_stub()

            def create_two_file_extract(
                archive_path,
                password,
                staging_dir,
                zip_decode,
                enable_rar,
                sfx_detector,
                detect_elf_sfx=False,
            ):
                with open(
                    os.path.join(staging_dir, "a.txt"), "w", encoding="utf-8"
                ) as f:
                    f.write("a")
                with open(
                    os.path.join(staging_dir, "b.txt"), "w", encoding="utf-8"
                ) as f:
                    f.write("b")
                return True

            real_atomic_rename = self.m._atomic_rename
            move_events = []

            def crash_after_second_move(
                src, dst, *, degrade_cross_volume=False, debug=False
            ):
                result = real_atomic_rename(
                    src,
                    dst,
                    degrade_cross_volume=degrade_cross_volume,
                    debug=debug,
                )
                move_events.append((os.path.basename(src), os.path.basename(dst)))
                if os.path.basename(dst) == "b.txt":
                    self.m.set_interrupt_flag()
                    raise KeyboardInterrupt("crash during placing")
                return result

            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "_validate_environment_for_output_dir"),
                mock.patch.object(
                    self.m,
                    "try_extract",
                    side_effect=create_two_file_extract,
                ),
                mock.patch.object(
                    self.m,
                    "_atomic_rename",
                    side_effect=crash_after_second_move,
                ),
                mock.patch.object(self.m, "_garbage_collect"),
            ):
                with self.assertRaises(KeyboardInterrupt):
                    self.m._run_transactional(processor, [archive_path], args=args)

            self.m.reset_interrupt_flag()

            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            crashed_manifest = self.m._load_dataset_manifest(output_root)
            crashed_entry = crashed_manifest["archives"][archive_id]
            crashed_txn_id = crashed_entry["last_txn_id"]

            placement_move_events = [
                event for event in move_events if event[0] in ("a.txt", "b.txt")
            ]

            self.assertEqual(
                [("a.txt", "a.txt"), ("b.txt", "b.txt")], placement_move_events
            )
            self.assertEqual("retryable", crashed_entry["state"])
            self.assertEqual("ABORTED", crashed_entry["error"]["type"])
            self.assertTrue(os.path.exists(os.path.join(output_root, "a.txt")))
            self.assertTrue(os.path.exists(os.path.join(output_root, "b.txt")))

            plan_manifest = self.m._load_dataset_manifest(output_root)
            recoverable_archives, retryable_archives, pending_archives = (
                self.m._build_transactional_archive_plan(plan_manifest, output_root)
            )
            self.assertEqual(
                [
                    {
                        "archive_path": os.path.abspath(archive_path),
                        "output_dir": output_root,
                    }
                ],
                recoverable_archives,
            )
            self.assertEqual([], retryable_archives)
            self.assertEqual([], pending_archives)

            resumed_processor = self._make_transactional_processor_stub()

            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "resume should recover the existing txn without re-extracting"
                    ),
                ),
                mock.patch.object(self.m, "_garbage_collect"),
            ):
                self.m._run_transactional(resumed_processor, [archive_path], args=args)

            resumed_manifest = self.m._load_dataset_manifest(output_root)
            resumed_entry = resumed_manifest["archives"][archive_id]
            resumed_txn = self.m._load_latest_txn_for_archive(
                resumed_entry, output_root
            )

            self.assertEqual(
                [os.path.abspath(archive_path)], resumed_processor.successful_archives
            )
            self.assertEqual([], resumed_processor.failed_archives)
            self.assertEqual("succeeded", resumed_entry["state"])
            self.assertEqual("success:asis", resumed_entry["final_disposition"])
            self.assertIsNone(resumed_entry["error"])
            self.assertEqual(crashed_txn_id, resumed_entry["last_txn_id"])
            self.assertEqual(self.m.TXN_STATE_DONE, resumed_txn["state"])
            self.assertTrue(os.path.exists(os.path.join(output_root, "a.txt")))
            self.assertTrue(os.path.exists(os.path.join(output_root, "b.txt")))

    def test_delete_barrier_failure_preserves_source_and_nonterminal_manifest_state(
        self,
    ):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            archive_path = os.path.join(input_root, "alpha.zip")
            with open(archive_path, "wb") as f:
                f.write(b"alpha")

            args = self._make_processing_args(
                input_root,
                output=output_root,
                decompress_policy="only-file-content-direct",
                success_policy="delete",
                fsync_files="auto",
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            processor = self._make_transactional_processor_stub()

            def create_payload_tree(
                archive_path,
                password,
                staging_dir,
                zip_decode,
                enable_rar,
                sfx_detector,
                detect_elf_sfx=False,
            ):
                file_content_root = os.path.join(staging_dir, "tree")
                nested_dir = os.path.join(file_content_root, "a", "b")
                os.makedirs(nested_dir, exist_ok=True)
                with open(
                    os.path.join(file_content_root, "root.txt"),
                    "w",
                    encoding="utf-8",
                ) as f:
                    f.write("root")
                with open(
                    os.path.join(nested_dir, "payload.txt"),
                    "w",
                    encoding="utf-8",
                ) as f:
                    f.write("payload")
                return True

            def fail_output_root_fsync(path, debug=False):
                path = os.path.abspath(path)
                if path == os.path.abspath(output_root):
                    return False
                return True

            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m.os, "name", "posix"),
                mock.patch.object(self.m, "_validate_environment_for_output_dir"),
                mock.patch.object(
                    self.m,
                    "try_extract",
                    side_effect=create_payload_tree,
                ),
                mock.patch.object(
                    self.m, "_fsync_dir", side_effect=fail_output_root_fsync
                ),
                mock.patch.object(self.m, "_garbage_collect"),
            ):
                self.m._run_transactional(processor, [archive_path], args=args)

            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            manifest = self.m._load_dataset_manifest(output_root)
            entry = manifest["archives"][archive_id]
            saved_txn = self.m._load_latest_txn_for_archive(entry, output_root)

            self.assertTrue(os.path.exists(archive_path))
            self.assertEqual([], processor.successful_archives)
            self.assertEqual([os.path.abspath(archive_path)], processor.failed_archives)
            self.assertEqual("active", manifest["status"])
            self.assertNotEqual("succeeded", entry["state"])
            self.assertEqual("recoverable", entry["state"])
            self.assertEqual("unknown", entry["final_disposition"])
            self.assertIsNone(entry["finalized_at"])
            self.assertEqual(saved_txn["txn_id"], entry["last_txn_id"])
            self.assertEqual("DURABILITY_FAILED", entry["error"]["type"])
            self.assertEqual(self.m.TXN_STATE_ABORTED, saved_txn["state"])
            self.assertEqual("DURABILITY_FAILED", saved_txn["error"]["type"])
            self.assertTrue(os.path.exists(saved_txn["paths"]["wal"]))
            self.assertTrue(
                os.path.exists(
                    os.path.join(
                        self.m._work_root(output_root, output_root),
                        "journal",
                        saved_txn["txn_id"],
                        "txn.json",
                    )
                )
            )
            self.assertTrue(os.path.exists(self.m._dataset_manifest_path(output_root)))

    def test_main_resume_reports_recover_failure_when_expected_payload_missing(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_delete_barrier_txn_fixture(td)
            archive_path = os.path.abspath(fixture["archive_path"])
            missing_payload = os.path.abspath(fixture["expected_payload_files"][1])
            stdout = io.StringIO()

            def fail_on_payload_dir(path, debug=False):
                path = os.path.abspath(path)
                if path == os.path.abspath(fixture["output_dir"]):
                    return False
                return True

            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m.os, "name", "posix"),
                mock.patch.object(self.m, "_fsync_file", return_value=True),
                mock.patch.object(
                    self.m, "_fsync_dir", side_effect=fail_on_payload_dir
                ),
            ):
                with self.assertRaises(RuntimeError):
                    self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

            os.remove(missing_payload)

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(self.m.os, "name", "posix"),
                mock.patch.object(
                    self.m.sys, "argv", self._argv_for_main(fixture["args"])
                ),
                mock.patch.object(
                    self.m,
                    "safe_subprocess_run",
                    return_value=SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
                ),
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "_fsync_file", return_value=True),
                mock.patch.object(self.m, "_fsync_dir", return_value=True),
                mock.patch.object(self.m, "fix_archive_ext") as fix_archive_ext,
            ):
                exit_code = self.m.main()

            output = stdout.getvalue()
            self.assertEqual(1, exit_code)
            self.assertIn("Recover failed", output)
            self.assertIn("payload_missing:file:", output)
            self.assertIn("Failed to process: 1", output)
            self.assertIn(archive_path, output)
            fix_archive_ext.assert_not_called()

    def test_main_resume_counts_successful_same_txn_recovery_in_summary(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_delete_barrier_txn_fixture(td)
            archive_path = os.path.abspath(fixture["archive_path"])
            stdout = io.StringIO()

            def fail_on_payload_dir(path, debug=False):
                path = os.path.abspath(path)
                if path == os.path.abspath(fixture["output_dir"]):
                    return False
                return True

            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m.os, "name", "posix"),
                mock.patch.object(self.m, "_fsync_file", return_value=True),
                mock.patch.object(
                    self.m, "_fsync_dir", side_effect=fail_on_payload_dir
                ),
            ):
                with self.assertRaises(RuntimeError):
                    self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(self.m.os, "name", "posix"),
                mock.patch.object(
                    self.m.sys, "argv", self._argv_for_main(fixture["args"])
                ),
                mock.patch.object(
                    self.m,
                    "safe_subprocess_run",
                    return_value=SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
                ),
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "_fsync_file", return_value=True),
                mock.patch.object(self.m, "_fsync_dir", return_value=True),
                mock.patch.object(self.m, "fix_archive_ext") as fix_archive_ext,
            ):
                exit_code = self.m.main()

            output = stdout.getvalue()
            self.assertEqual(0, exit_code)
            self.assertIn("Successfully processed: 1", output)
            self.assertIn("Failed to process: 0", output)
            self.assertNotIn("Recover failed", output)
            fix_archive_ext.assert_not_called()

    def test_fsync_dir_returns_false_when_win32_directory_flush_is_unavailable(self):
        with tempfile.TemporaryDirectory() as td:
            with (
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(self.m.ctypes, "windll", None, create=True),
            ):
                self.assertFalse(self.m._fsync_dir(td))

    def test_fsync_dir_uses_win32_directory_handle_on_windows(self):
        class FakeKernel32:
            def __init__(self):
                self.calls = []

            def CreateFileW(self, path, desired_access, share_mode, security, creation, flags, template):
                self.calls.append(
                    (
                        "CreateFileW",
                        path,
                        desired_access,
                        share_mode,
                        creation,
                        flags,
                    )
                )
                return 123

            def FlushFileBuffers(self, handle):
                self.calls.append(("FlushFileBuffers", handle))
                return 1

            def CloseHandle(self, handle):
                self.calls.append(("CloseHandle", handle))
                return 1

        fake_kernel32 = FakeKernel32()
        fake_windll = types.SimpleNamespace(kernel32=fake_kernel32)

        with tempfile.TemporaryDirectory() as td:
            with (
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(self.m.ctypes, "windll", fake_windll, create=True),
            ):
                self.assertTrue(self.m._fsync_dir(td))

        create_call = fake_kernel32.calls[0]
        self.assertEqual("CreateFileW", create_call[0])
        self.assertEqual(0x40000000, create_call[2])
        self.assertEqual(0x00000001 | 0x00000002 | 0x00000004, create_call[3])
        self.assertEqual(3, create_call[4])
        self.assertEqual(0x02000000, create_call[5])
        self.assertEqual(123, fake_kernel32.calls[1][1])
        self.assertEqual(123, fake_kernel32.calls[2][1])

    def test_txn_create_surfaces_win32_directory_flush_error_code(self):
        class FakeKernel32:
            def CreateFileW(
                self,
                path,
                desired_access,
                share_mode,
                security,
                creation,
                flags,
                template,
            ):
                return 123

            def FlushFileBuffers(self, handle):
                return 0

            def CloseHandle(self, handle):
                return 1

            def GetLastError(self):
                return 50

        fake_windll = types.SimpleNamespace(kernel32=FakeKernel32())

        with tempfile.TemporaryDirectory() as td:
            output_base = os.path.join(td, "out")
            output_dir = os.path.join(output_base, "placed")
            archive_path = os.path.join(td, "input.zip")
            with open(archive_path, "wb") as f:
                f.write(b"zip")

            with (
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(self.m.ctypes, "windll", fake_windll, create=True),
                self.assertRaises(RuntimeError) as ctx,
            ):
                self.m._txn_create(
                    archive_path=archive_path,
                    volumes=[archive_path],
                    output_dir=output_dir,
                    output_base=output_base,
                    policy="direct",
                    wal_fsync_every=1,
                    snapshot_every=1,
                    durability_enabled=False,
                )

        self.assertIn("journal_dir_fsync_failed:parent:", str(ctx.exception))
        self.assertIn("FlushFileBuffers", str(ctx.exception))
        self.assertIn("winerr=50", str(ctx.exception))

    def test_fsync_dir_real_windows_tempdir_probe_reports_capability(self):
        if os.name != "nt":
            self.skipTest("Windows-only runtime probe")

        with tempfile.TemporaryDirectory() as td:
            result = self.m._fsync_dir(td)

        self.assertTrue(hasattr(result, "detail"))
        if not result:
            detail = result.detail
            self.assertIsInstance(detail, str)
            self.assertIn("winerr=", detail)

    def test_concurrent_journal_fsync_failures_keep_per_call_detail_isolated(self):
        class FakeDirResult:
            def __init__(self, ok, detail=None):
                self.ok = ok
                self.detail = detail

            def __bool__(self):
                return self.ok

        with tempfile.TemporaryDirectory() as td:
            output_base = os.path.join(td, "out")
            txns = {}

            with mock.patch.object(self.m, "_fsync_dir", return_value=True):
                for name in ("alpha", "beta"):
                    output_dir = os.path.join(output_base, name)
                    archive_path = os.path.join(td, f"{name}.zip")
                    with open(archive_path, "wb") as f:
                        f.write(b"zip")
                    txns[name] = self.m._txn_create(
                        archive_path=archive_path,
                        volumes=[archive_path],
                        output_dir=output_dir,
                        output_base=output_base,
                        policy="direct",
                        wal_fsync_every=1,
                        snapshot_every=1,
                        durability_enabled=False,
                    )

            parent_paths = {
                name: os.path.dirname(txn["paths"]["journal_dir"])
                for name, txn in txns.items()
            }
            detail_alpha = "FlushFileBuffers:winerr=111"
            detail_beta = "FlushFileBuffers:winerr=222"
            alpha_ready = threading.Event()
            release_alpha = threading.Event()
            errors = {}

            def fake_fsync_dir_result(path, debug=False):
                path = os.path.abspath(path)
                if path == os.path.abspath(parent_paths["alpha"]):
                    alpha_ready.set()
                    self.assertTrue(
                        release_alpha.wait(timeout=5),
                        "beta detail did not arrive before alpha resumed",
                    )
                    return FakeDirResult(False, detail_alpha)
                if path == os.path.abspath(parent_paths["beta"]):
                    self.assertTrue(
                        alpha_ready.wait(timeout=5),
                        "alpha detail did not start before beta",
                    )
                    release_alpha.set()
                    return FakeDirResult(False, detail_beta)
                return FakeDirResult(True)

            def run_checkpoint(name):
                try:
                    self.m._fsync_journal_checkpoint(txns[name], include_parent=True)
                except Exception as e:
                    errors[name] = str(e)

            with mock.patch.object(self.m, "_fsync_dir", side_effect=fake_fsync_dir_result):
                threads = [
                    threading.Thread(
                        target=run_checkpoint,
                        args=(name,),
                        name=f"journal-fsync-{name}",
                    )
                    for name in ("alpha", "beta")
                ]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=5)

            self.assertIn(detail_alpha, errors["alpha"])
            self.assertNotIn(detail_beta, errors["alpha"])
            self.assertIn(detail_beta, errors["beta"])
            self.assertNotIn(detail_alpha, errors["beta"])

    def test_txn_create_succeeds_on_windows_when_directory_handle_flush_succeeds(self):
        class FakeKernel32:
            def CreateFileW(self, path, desired_access, share_mode, security, creation, flags, template):
                return 123

            def FlushFileBuffers(self, handle):
                return 1

            def CloseHandle(self, handle):
                return 1

        fake_windll = types.SimpleNamespace(kernel32=FakeKernel32())

        with tempfile.TemporaryDirectory() as td:
            output_base = os.path.join(td, "out")
            output_dir = os.path.join(output_base, "placed")
            archive_path = os.path.join(td, "input.zip")
            with open(archive_path, "wb") as f:
                f.write(b"zip")

            with (
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(self.m.ctypes, "windll", fake_windll, create=True),
            ):
                txn = self.m._txn_create(
                    archive_path=archive_path,
                    volumes=[archive_path],
                    output_dir=output_dir,
                    output_base=output_base,
                    policy="direct",
                    wal_fsync_every=1,
                    snapshot_every=1,
                    durability_enabled=False,
                )

            self.assertEqual(self.m.TXN_STATE_INIT, txn["state"])
            self.assertTrue(os.path.exists(txn["paths"]["txn_json"]))

    def test_empty_wal_close_force_fsyncs_journal_dir_on_windows(self):
        class FakeKernel32:
            def __init__(self):
                self.calls = []

            def CreateFileW(self, path, desired_access, share_mode, security, creation, flags, template):
                self.calls.append(("CreateFileW", path))
                return 123

            def FlushFileBuffers(self, handle):
                self.calls.append(("FlushFileBuffers", handle))
                return 1

            def CloseHandle(self, handle):
                self.calls.append(("CloseHandle", handle))
                return 1

        fake_kernel32 = FakeKernel32()
        fake_windll = types.SimpleNamespace(kernel32=fake_kernel32)

        with tempfile.TemporaryDirectory() as td:
            wal_path = os.path.join(td, "journal", "txn.wal")

            with (
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(self.m.ctypes, "windll", fake_windll, create=True),
            ):
                wal_writer = self.m.WalWriter(wal_path, fsync_every=1, debug=False)
                wal_writer.close(force_fsync=True)

        self.assertIn(("FlushFileBuffers", 123), fake_kernel32.calls)

    def test_run_transactional_allows_windows_transactional_delete_without_extra_flag(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            args = self._make_processing_args(
                input_root,
                output=output_root,
                success_policy="delete",
                fsync_files="auto",
            )
            processor = types.SimpleNamespace(
                successful_archives=[],
                failed_archives=[],
                skipped_archives=[],
            )
            stdout = io.StringIO()

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(self.m.os, "name", "nt"),
            ):
                result = self.m._run_transactional(processor, [], args=args)

            self.assertIsNone(result)
            self.assertNotIn("--unsafe-windows-delete is required", stdout.getvalue())

    def test_run_transactional_allows_windows_legacy_delete_without_extra_flag(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            args = self._make_processing_args(
                input_root,
                output=output_root,
                success_policy="delete",
                fsync_files="auto",
                legacy=True,
            )
            processor = types.SimpleNamespace(
                successful_archives=[],
                failed_archives=[],
                skipped_archives=[],
            )
            stdout = io.StringIO()

            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(self.m.os, "name", "nt"),
            ):
                result = self.m._run_transactional(processor, [], args=args)

            self.assertIsNone(result)
            self.assertNotIn("--unsafe-windows-delete is required", stdout.getvalue())

    def test_delete_durability_barrier_fsyncs_empty_created_directories(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_empty_dir_barrier_txn_fixture(td)
            fsynced_dirs = []
            expected_empty_dirs = [
                os.path.abspath(path) for path in fixture["expected_empty_dirs"]
            ]

            def record_fsync_dir(path, debug=False):
                fsynced_dirs.append(os.path.abspath(path))
                return True

            with mock.patch.object(self.m, "_fsync_dir", side_effect=record_fsync_dir):
                self.m._place_and_finalize_txn(fixture["txn"], args=fixture["args"])

            for path in expected_empty_dirs:
                self.assertIn(path, fsynced_dirs)

    def test_gc_deletes_done_journal(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            txn = self.m._txn_create(
                archive_path=fixture["archive"]["archive_path"],
                volumes=fixture["archive"]["volumes"],
                output_dir=fixture["archive"]["output_dir"],
                output_base=fixture["output_root"],
                policy=fixture["args"].decompress_policy,
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_DONE
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                fixture["archive"]["archive_path"],
                state="succeeded",
                last_txn_id=txn["txn_id"],
                final_disposition="success:asis",
                error=None,
                finalized_at=self.m._now_iso(),
            )
            self._age_txn_journal(txn)

            self.m._garbage_collect(
                fixture["archive"]["output_dir"],
                output_base=fixture["output_root"],
                keep_journal_days=7,
            )

            self.assertFalse(os.path.exists(txn["paths"]["journal_dir"]))

    def test_gc_deletes_manifest_confirmed_failed_journal(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            txn = self.m._txn_create(
                archive_path=fixture["archive"]["archive_path"],
                volumes=fixture["archive"]["volumes"],
                output_dir=fixture["archive"]["output_dir"],
                output_base=fixture["output_root"],
                policy=fixture["args"].decompress_policy,
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            self.m._txn_fail(txn, "PLACE_FAILED", "boom")
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                fixture["archive"]["archive_path"],
                state="failed",
                last_txn_id=txn["txn_id"],
                final_disposition="failure:asis",
                error=txn["error"],
                finalized_at=self.m._now_iso(),
            )
            self._age_txn_journal(txn)

            self.m._garbage_collect(
                fixture["archive"]["output_dir"],
                output_base=fixture["output_root"],
                keep_journal_days=7,
            )

            self.assertFalse(os.path.exists(txn["paths"]["journal_dir"]))

    def test_gc_keeps_failed_journal_with_incomplete_failure_move_finalization(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            txn = self.m._txn_create(
                archive_path=fixture["archive"]["archive_path"],
                volumes=fixture["archive"]["volumes"],
                output_dir=fixture["archive"]["output_dir"],
                output_base=fixture["output_root"],
                policy=fixture["args"].decompress_policy,
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            self.m._set_source_finalization_plan(
                txn,
                manifest_state="failed",
                final_disposition="failure:move",
                txn_terminal_state=self.m.TXN_STATE_FAILED,
            )
            txn["state"] = self.m.TXN_STATE_FAILED
            txn["error"] = {
                "type": "PLACE_FAILED",
                "message": "boom",
                "at": self.m._now_iso(),
            }
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                fixture["archive"]["archive_path"],
                state="failed",
                last_txn_id=txn["txn_id"],
                final_disposition="failure:move",
                error=txn["error"],
                finalized_at=self.m._now_iso(),
            )
            self._age_txn_journal(txn)

            self.assertTrue(self.m._txn_has_recovery_responsibility(txn))
            self.assertFalse(self.m._txn_is_closed_terminal_outcome(txn))

            self.m._garbage_collect(
                fixture["archive"]["output_dir"],
                output_base=fixture["output_root"],
                keep_journal_days=7,
            )

            self.assertTrue(os.path.exists(txn["paths"]["journal_dir"]))

    def test_gc_deletes_historical_cleaned_journal_after_ttl(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            txn = self.m._txn_create(
                archive_path=fixture["archive"]["archive_path"],
                volumes=fixture["archive"]["volumes"],
                output_dir=fixture["archive"]["output_dir"],
                output_base=fixture["output_root"],
                policy=fixture["args"].decompress_policy,
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_CLEANED
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                fixture["archive"]["archive_path"],
                state="succeeded",
                last_txn_id=txn["txn_id"],
                final_disposition="success:asis",
                error=None,
                finalized_at=self.m._now_iso(),
            )
            self._age_txn_journal(txn)

            self.assertFalse(self.m._txn_has_recovery_responsibility(txn))
            self.assertTrue(self.m._txn_is_closed_terminal_outcome(txn))

            self.m._garbage_collect(
                fixture["archive"]["output_dir"],
                output_base=fixture["output_root"],
                keep_journal_days=7,
            )

            self.assertFalse(os.path.exists(txn["paths"]["journal_dir"]))

    def test_gc_keeps_active_aborted_journal(self):
        for manifest_state in ("recoverable", "retryable"):
            with self.subTest(manifest_state=manifest_state):
                with tempfile.TemporaryDirectory() as td:
                    fixture = self._make_aborted_manifest_txn_fixture(
                        td,
                        manifest_state=manifest_state,
                    )
                    self._age_txn_journal(fixture["txn"])

                    self.m._garbage_collect(
                        fixture["archive"]["output_dir"],
                        output_base=fixture["output_root"],
                        keep_journal_days=7,
                    )

                    self.assertTrue(
                        os.path.exists(fixture["txn"]["paths"]["journal_dir"])
                    )

    def test_gc_deletes_stale_aborted_after_manifest_converges(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_aborted_manifest_txn_fixture(
                td,
                manifest_state="retryable",
            )
            stale_txn = fixture["txn"]
            self._age_txn_journal(stale_txn)

            self.m._garbage_collect(
                fixture["archive"]["output_dir"],
                output_base=fixture["output_root"],
                keep_journal_days=7,
            )
            self.assertTrue(os.path.exists(stale_txn["paths"]["journal_dir"]))

            terminal_txn = self.m._txn_create(
                archive_path=fixture["archive"]["archive_path"],
                volumes=fixture["archive"]["volumes"],
                output_dir=fixture["archive"]["output_dir"],
                output_base=fixture["output_root"],
                policy=fixture["args"].decompress_policy,
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            terminal_txn["state"] = self.m.TXN_STATE_DONE
            self.m._txn_snapshot(terminal_txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                fixture["archive"]["archive_path"],
                state="succeeded",
                last_txn_id=terminal_txn["txn_id"],
                final_disposition="success:asis",
                error=None,
                finalized_at=self.m._now_iso(),
            )

            self.m._garbage_collect(
                fixture["archive"]["output_dir"],
                output_base=fixture["output_root"],
                keep_journal_days=7,
            )

            self.assertFalse(os.path.exists(stale_txn["paths"]["journal_dir"]))
            self.assertTrue(os.path.exists(terminal_txn["paths"]["journal_dir"]))

    def test_gc_deletes_done_journal_without_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            output_root = os.path.join(td, "output")
            output_dir = os.path.join(output_root, "placed")
            archive_path = os.path.join(td, "alpha.zip")
            os.makedirs(output_root)
            with open(archive_path, "wb") as f:
                f.write(b"archive")

            txn = self.m._txn_create(
                archive_path=archive_path,
                volumes=[archive_path],
                output_dir=output_dir,
                output_base=output_root,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_DONE
            self.m._txn_snapshot(txn)
            self._age_txn_journal(txn)

            self.assertIsNone(self.m._load_dataset_manifest(output_root))

            self.m._garbage_collect(
                output_dir,
                output_base=output_root,
                keep_journal_days=7,
            )

            self.assertFalse(os.path.exists(txn["paths"]["journal_dir"]))

    def test_cleanup_workdir_removes_staging_incoming_and_trash_but_keeps_journal(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            archive = fixture["archive"]
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            os.makedirs(os.path.dirname(txn["paths"]["staging_extracted"]), exist_ok=True)
            os.makedirs(os.path.dirname(txn["paths"]["incoming_dir"]), exist_ok=True)
            os.makedirs(txn["paths"]["trash_dir"], exist_ok=True)
            os.makedirs(txn["paths"]["journal_dir"], exist_ok=True)

            self.m._cleanup_workdir(txn)

            self.assertFalse(os.path.exists(os.path.dirname(txn["paths"]["staging_extracted"])))
            self.assertFalse(os.path.exists(os.path.dirname(txn["paths"]["incoming_dir"])))
            self.assertFalse(os.path.exists(txn["paths"]["trash_dir"]))
            self.assertTrue(os.path.exists(txn["paths"]["journal_dir"]))

    def test_cleanup_workdir_warns_when_subtree_delete_returns_false(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td)
            archive = fixture["archive"]
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            with (
                mock.patch.object(self.m, "safe_rmtree", return_value=False),
                contextlib.redirect_stdout(io.StringIO()) as stdout,
            ):
                self.m._cleanup_workdir(txn)

            self.assertIn("Warning: Could not clean transactional subtree", stdout.getvalue())

    def test_gc_keeps_orphan_aborted_journal_without_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            output_root = os.path.join(td, "output")
            output_dir = os.path.join(output_root, "placed")
            archive_path = os.path.join(td, "alpha.zip")
            os.makedirs(output_root)
            with open(archive_path, "wb") as f:
                f.write(b"archive")

            txn = self.m._txn_create(
                archive_path=archive_path,
                volumes=[archive_path],
                output_dir=output_dir,
                output_base=output_root,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            self.m._txn_abort(txn, "ABORTED", "interrupted")
            self._age_txn_journal(txn)

            self.assertIsNone(self.m._load_dataset_manifest(output_root))

            self.m._garbage_collect(
                output_dir,
                output_base=output_root,
                keep_journal_days=7,
            )

            self.assertTrue(os.path.exists(txn["paths"]["journal_dir"]))

    def test_manifest_failure_stays_retryable_when_failure_finalize_fails(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            fail_to = os.path.join(td, "failed")
            os.makedirs(input_root)
            os.makedirs(output_root)

            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                ["alpha.zip"],
            )
            args = self._make_processing_args(
                input_root,
                output=output_root,
                fail_policy="move",
                fail_to=fail_to,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=discovered,
                command_fingerprint=self.m._build_command_fingerprint(args),
            )

            archive_path = discovered[0]["archive_path"]
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            processor = types.SimpleNamespace(
                sfx_detector=None,
                get_all_volumes=lambda path: [os.path.abspath(path)],
            )

            with (
                mock.patch.object(self.m, "_validate_environment_for_output_dir"),
                mock.patch.object(self.m, "try_extract", return_value=False),
                mock.patch.object(
                    self.m,
                    "_finalize_sources_failure",
                    side_effect=RuntimeError("fail policy move failed"),
                ),
            ):
                result = self.m._extract_phase(
                    processor,
                    archive_path,
                    args=args,
                    output_base=output_root,
                )

            result_processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            self.m._handle_transactional_result(
                result,
                processor=result_processor,
                args=args,
                output_base=output_root,
                touched_output_dirs=set(),
            )

            manifest = self.m._load_dataset_manifest(output_root)
            entry = manifest["archives"][archive_id]
            with open(result["txn"]["paths"]["txn_json"], "r", encoding="utf-8") as f:
                saved_txn = json.load(f)

            self.assertEqual([archive_path], result_processor.failed_archives)
            self.assertEqual("retryable", entry["state"])
            self.assertEqual("unknown", entry["final_disposition"])
            self.assertIsNone(entry["finalized_at"])
            self.assertEqual("FAIL_FINALIZE_FAILED", entry["error"]["type"])
            self.assertEqual(self.m.TXN_STATE_ABORTED, saved_txn["state"])
            self.assertEqual("FAIL_FINALIZE_FAILED", saved_txn["error"]["type"])

    def test_run_transactional_dry_run_does_not_create_manifest_or_workdir(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            archive_path = os.path.join(input_root, "dry-run.zip")
            with open(archive_path, "wb") as f:
                f.write(b"dry-run")

            args = self._make_processing_args(
                input_root,
                output=output_root,
                dry_run=True,
            )
            processor = self._make_transactional_processor_stub()
            processor.successful_archives = []
            processor.failed_archives = []
            processor.skipped_archives = []

            with (
                mock.patch.object(
                    self.m,
                    "_recover_all_outputs",
                    side_effect=AssertionError(
                        "dry-run should not start transactional recovery"
                    ),
                ),
                mock.patch.object(
                    self.m,
                    "_garbage_collect",
                    side_effect=AssertionError(
                        "dry-run should not garbage collect transactional workdirs"
                    ),
                ),
            ):
                self.m._run_transactional(processor, [archive_path], args=args)

            self.assertEqual(
                [os.path.abspath(archive_path)], processor.skipped_archives
            )
            self.assertEqual([], processor.successful_archives)
            self.assertEqual([], processor.failed_archives)
            self.assertFalse(os.path.exists(self.m._dataset_manifest_path(output_root)))
            self.assertFalse(os.path.exists(self.m._work_base(output_root)))

    def test_handle_transactional_result_dry_run_leaves_existing_manifest_unchanged(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                ["dry-run.zip", "skipped.zip"],
            )
            args = self._make_processing_args(
                input_root,
                output=output_root,
                dry_run=True,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=discovered,
                command_fingerprint=self.m._build_command_fingerprint(args),
            )

            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            touched_output_dirs = set()
            dry_run_archive = discovered[0]["archive_path"]
            skipped_archive = discovered[1]["archive_path"]
            manifest_path = self.m._dataset_manifest_path(output_root)

            with open(manifest_path, "rb") as f:
                manifest_before = f.read()

            self.m._handle_transactional_result(
                {"kind": "dry_run", "archive_path": dry_run_archive},
                processor=processor,
                args=args,
                output_base=output_root,
                touched_output_dirs=touched_output_dirs,
            )
            self.m._handle_transactional_result(
                {
                    "kind": "skipped",
                    "archive_path": skipped_archive,
                    "reason": "not_archive",
                },
                processor=processor,
                args=args,
                output_base=output_root,
                touched_output_dirs=touched_output_dirs,
            )

            with open(manifest_path, "rb") as f:
                self.assertEqual(manifest_before, f.read())

            self.assertCountEqual(
                [dry_run_archive, skipped_archive], processor.skipped_archives
            )
            self.assertEqual([], processor.successful_archives)
            self.assertEqual([], processor.failed_archives)

    def test_extract_failure_asis_terminalizes_txn_for_gc(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                ["alpha.zip"],
            )
            archive_path = discovered[0]["archive_path"]
            args = self._make_processing_args(
                input_root,
                output=output_root,
                fail_policy="asis",
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=discovered,
                command_fingerprint=self.m._build_command_fingerprint(args),
            )

            processor = types.SimpleNamespace(
                sfx_detector=None,
                get_all_volumes=lambda path: [os.path.abspath(path)],
            )

            with (
                mock.patch.object(self.m, "_validate_environment_for_output_dir"),
                mock.patch.object(self.m, "try_extract", return_value=False),
            ):
                result = self.m._extract_phase(
                    processor,
                    archive_path,
                    args=args,
                    output_base=output_root,
                )

            result_processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            self.m._handle_transactional_result(
                result,
                processor=result_processor,
                args=args,
                output_base=output_root,
                touched_output_dirs=set(),
            )

            with open(result["txn"]["paths"]["txn_json"], "r", encoding="utf-8") as f:
                saved_txn = json.load(f)

            self.assertEqual(self.m.TXN_STATE_FAILED, saved_txn["state"])
            self._age_txn_journal(result["txn"])
            self.m._garbage_collect(
                discovered[0]["output_dir"],
                output_base=output_root,
                keep_journal_days=7,
            )
            self.assertFalse(os.path.exists(result["txn"]["paths"]["journal_dir"]))

    def test_no_password_asis_terminalizes_txn_for_gc(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                ["secret.zip"],
            )
            archive_path = discovered[0]["archive_path"]
            password_file = os.path.join(td, "passwords.txt")
            with open(password_file, "w", encoding="utf-8") as f:
                f.write("guess\n")

            args = self._make_processing_args(
                input_root,
                output=output_root,
                password_file=password_file,
                fail_policy="asis",
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=discovered,
                command_fingerprint=self.m._build_command_fingerprint(args),
            )

            processor = types.SimpleNamespace(
                sfx_detector=None,
                find_correct_password=lambda archive_path, encryption_status=None: None,
                get_all_volumes=lambda path: [os.path.abspath(path)],
            )

            with (
                mock.patch.object(self.m, "_validate_environment_for_output_dir"),
                mock.patch.object(
                    self.m, "check_encryption", return_value="encrypted_header"
                ),
            ):
                result = self.m._extract_phase(
                    processor,
                    archive_path,
                    args=args,
                    output_base=output_root,
                )

            result_processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            self.m._handle_transactional_result(
                result,
                processor=result_processor,
                args=args,
                output_base=output_root,
                touched_output_dirs=set(),
            )

            with open(result["txn"]["paths"]["txn_json"], "r", encoding="utf-8") as f:
                saved_txn = json.load(f)

            self.assertEqual(self.m.TXN_STATE_FAILED, saved_txn["state"])
            self._age_txn_journal(result["txn"])
            self.m._garbage_collect(
                discovered[0]["output_dir"],
                output_base=output_root,
                keep_journal_days=7,
            )
            self.assertFalse(os.path.exists(result["txn"]["paths"]["journal_dir"]))

    def test_extract_failure_move_terminalizes_txn_for_gc(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            fail_to = os.path.join(td, "failed")
            os.makedirs(input_root)
            os.makedirs(output_root)

            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                ["alpha.zip"],
            )
            archive_path = discovered[0]["archive_path"]
            args = self._make_processing_args(
                input_root,
                output=output_root,
                fail_policy="move",
                fail_to=fail_to,
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=discovered,
                command_fingerprint=self.m._build_command_fingerprint(args),
            )

            processor = types.SimpleNamespace(
                sfx_detector=None,
                get_all_volumes=lambda path: [os.path.abspath(path)],
            )

            with (
                mock.patch.object(self.m, "_validate_environment_for_output_dir"),
                mock.patch.object(self.m, "try_extract", return_value=False),
            ):
                result = self.m._extract_phase(
                    processor,
                    archive_path,
                    args=args,
                    output_base=output_root,
                )

            result_processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            self.m._handle_transactional_result(
                result,
                processor=result_processor,
                args=args,
                output_base=output_root,
                touched_output_dirs=set(),
            )

            with open(result["txn"]["paths"]["txn_json"], "r", encoding="utf-8") as f:
                saved_txn = json.load(f)

            self.assertEqual(self.m.TXN_STATE_FAILED, saved_txn["state"])
            self._age_txn_journal(result["txn"])
            self.m._garbage_collect(
                discovered[0]["output_dir"],
                output_base=output_root,
                keep_journal_days=7,
            )
            self.assertFalse(os.path.exists(result["txn"]["paths"]["journal_dir"]))

    def test_no_password_move_terminalizes_txn_for_gc(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            fail_to = os.path.join(td, "failed")
            os.makedirs(input_root)
            os.makedirs(output_root)

            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                ["secret.zip"],
            )
            archive_path = discovered[0]["archive_path"]
            password_file = os.path.join(td, "passwords.txt")
            with open(password_file, "w", encoding="utf-8") as f:
                f.write("guess\n")

            args = self._make_processing_args(
                input_root,
                output=output_root,
                password_file=password_file,
                fail_policy="move",
                fail_to=fail_to,
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=discovered,
                command_fingerprint=self.m._build_command_fingerprint(args),
            )

            processor = types.SimpleNamespace(
                sfx_detector=None,
                find_correct_password=lambda archive_path, encryption_status=None: None,
                get_all_volumes=lambda path: [os.path.abspath(path)],
            )

            with (
                mock.patch.object(self.m, "_validate_environment_for_output_dir"),
                mock.patch.object(
                    self.m, "check_encryption", return_value="encrypted_header"
                ),
            ):
                result = self.m._extract_phase(
                    processor,
                    archive_path,
                    args=args,
                    output_base=output_root,
                )

            result_processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            self.m._handle_transactional_result(
                result,
                processor=result_processor,
                args=args,
                output_base=output_root,
                touched_output_dirs=set(),
            )

            with open(result["txn"]["paths"]["txn_json"], "r", encoding="utf-8") as f:
                saved_txn = json.load(f)

            self.assertEqual(self.m.TXN_STATE_FAILED, saved_txn["state"])
            self._age_txn_journal(result["txn"])
            self.m._garbage_collect(
                discovered[0]["output_dir"],
                output_base=output_root,
                keep_journal_days=7,
            )
            self.assertFalse(os.path.exists(result["txn"]["paths"]["journal_dir"]))

    def test_no_password_failure_stays_retryable_when_failure_finalize_fails(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            fail_to = os.path.join(td, "failed")
            os.makedirs(input_root)
            os.makedirs(output_root)

            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                ["secret.zip"],
            )
            archive_path = discovered[0]["archive_path"]
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            password_file = os.path.join(td, "passwords.txt")
            with open(password_file, "w", encoding="utf-8") as f:
                f.write("guess\n")

            args = self._make_processing_args(
                input_root,
                output=output_root,
                password_file=password_file,
                fail_policy="move",
                fail_to=fail_to,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=discovered,
                command_fingerprint=self.m._build_command_fingerprint(args),
            )

            processor = types.SimpleNamespace(
                sfx_detector=None,
                find_correct_password=lambda archive_path, encryption_status=None: None,
                get_all_volumes=lambda path: [os.path.abspath(path)],
            )

            with (
                mock.patch.object(self.m, "_validate_environment_for_output_dir"),
                mock.patch.object(
                    self.m, "check_encryption", return_value="encrypted_header"
                ),
                mock.patch.object(
                    self.m,
                    "_finalize_sources_failure",
                    side_effect=RuntimeError("fail policy move failed"),
                ),
            ):
                result = self.m._extract_phase(
                    processor,
                    archive_path,
                    args=args,
                    output_base=output_root,
                )

            result_processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            self.m._handle_transactional_result(
                result,
                processor=result_processor,
                args=args,
                output_base=output_root,
                touched_output_dirs=set(),
            )

            manifest = self.m._load_dataset_manifest(output_root)
            entry = manifest["archives"][archive_id]

            self.assertEqual("failed", result["kind"])
            self.assertEqual([archive_path], result_processor.failed_archives)
            self.assertEqual("retryable", entry["state"])
            self.assertEqual("unknown", entry["final_disposition"])
            self.assertIsNone(entry["finalized_at"])
            self.assertEqual("FAIL_FINALIZE_FAILED", entry["error"]["type"])

    def test_replay_wal(self):
        with tempfile.TemporaryDirectory() as td:
            wal = os.path.join(td, "txn.wal")
            records = [
                {"t": "MOVE_PLAN", "id": 1, "src": "a", "dst": "b"},
                {"t": "MOVE_DONE", "id": 1},
                {"t": "MOVE_PLAN", "id": 2, "src": "c", "dst": "d"},
            ]
            with open(wal, "w", encoding="utf-8") as f:
                for r in records:
                    f.write(json.dumps(r) + "\n")

            # Simulate crash: last line half-written (should be treated as EOF).
            with open(wal, "a", encoding="utf-8") as f:
                f.write('{"t":"MOVE_DONE","id":')

            plans, done = self.m._replay_wal(wal)
            self.assertIn(1, plans)
            self.assertIn(2, plans)
            self.assertIn(1, done)
            self.assertNotIn(2, done)

    def test_txn_create_fsyncs_journal_parent_and_journal_dir(self):
        with tempfile.TemporaryDirectory() as td:
            output_base = os.path.join(td, "out")
            output_dir = os.path.join(output_base, "placed")
            archive_path = os.path.join(td, "input.zip")
            with open(archive_path, "wb") as f:
                f.write(b"zip")
            observed = []

            def fake_fsync_dir(path, debug=False):
                observed.append(os.path.abspath(path))
                return True

            with mock.patch.object(self.m, "_fsync_dir", side_effect=fake_fsync_dir):
                txn = self.m._txn_create(
                    archive_path=archive_path,
                    volumes=[archive_path],
                    output_dir=output_dir,
                    output_base=output_base,
                    policy="direct",
                    wal_fsync_every=1,
                    snapshot_every=1,
                    durability_enabled=False,
                )

            self.assertIn(os.path.dirname(txn["paths"]["journal_dir"]), observed)
            self.assertIn(txn["paths"]["journal_dir"], observed)

    def test_execute_plans_persists_move_plan_and_done_snapshots(self):
        with tempfile.TemporaryDirectory() as td:
            output_base = os.path.join(td, "out")
            output_dir = os.path.join(output_base, "placed")
            os.makedirs(output_dir, exist_ok=True)
            incoming_dir = os.path.join(output_base, "incoming")
            os.makedirs(incoming_dir, exist_ok=True)
            src = os.path.join(incoming_dir, "a.txt")
            with open(src, "w", encoding="utf-8") as f:
                f.write("a")
            archive_path = os.path.join(td, "input.zip")
            with open(archive_path, "wb") as f:
                f.write(b"zip")

            txn = self.m._txn_create(
                archive_path=archive_path,
                volumes=[archive_path],
                output_dir=output_dir,
                output_base=output_base,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            plans = [
                {
                    "t": "MOVE_PLAN",
                    "id": 1,
                    "src": src,
                    "dst": os.path.join(output_dir, "a.txt"),
                }
            ]
            wal_writer = self.m.WalWriter(txn["paths"]["wal"], fsync_every=1, debug=False)
            try:
                self.m._execute_plans(
                    txn,
                    plans,
                    wal_writer=wal_writer,
                    degrade_cross_volume=False,
                )
            finally:
                wal_writer.close(force_fsync=True)

            placement = txn["placement"]
            self.assertEqual(
                [{"id": 1, "src": src, "dst": os.path.join(output_dir, "a.txt")}],
                placement["move_plan_snapshot"],
            )
            self.assertEqual([1], placement["move_done_ids_snapshot"])

    def test_execute_plans_zero_move_plan_persists_empty_snapshots(self):
        with tempfile.TemporaryDirectory() as td:
            output_base = os.path.join(td, "out")
            output_dir = os.path.join(output_base, "placed")
            archive_path = os.path.join(td, "input.zip")
            with open(archive_path, "wb") as f:
                f.write(b"zip")

            txn = self.m._txn_create(
                archive_path=archive_path,
                volumes=[archive_path],
                output_dir=output_dir,
                output_base=output_base,
                policy="only-file-content-direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            os.makedirs(os.path.join(txn["paths"]["incoming_dir"], "a", "b", "c"))
            resolved = self.m._resolve_policy_under_lock(txn, "fail")
            self.m._freeze_policy(txn, resolved)
            plans = self.m._plan_only_file_content_direct_moves(txn)

            self.assertEqual([], plans)

            wal_writer = self.m.WalWriter(txn["paths"]["wal"], fsync_every=1, debug=False)
            try:
                self.m._execute_plans(
                    txn,
                    plans,
                    wal_writer=wal_writer,
                    degrade_cross_volume=False,
                )
            finally:
                wal_writer.close(force_fsync=True)

            self.assertEqual([], txn["placement"]["move_plan_snapshot"])
            self.assertEqual([], txn["placement"]["move_done_ids_snapshot"])

    def test_empty_wal_close_force_fsyncs_journal_dir(self):
        with tempfile.TemporaryDirectory() as td:
            wal_path = os.path.join(td, "journal", "txn.wal")
            observed = []

            def fake_fsync_dir(path, debug=False):
                observed.append(os.path.abspath(path))
                return True

            with mock.patch.object(self.m, "_fsync_dir", side_effect=fake_fsync_dir):
                wal_writer = self.m.WalWriter(wal_path, fsync_every=1, debug=False)
                wal_writer.close(force_fsync=True)

            self.assertIn(os.path.abspath(os.path.dirname(wal_path)), observed)

    def test_success_move_fsync_failure_after_parent_dir_flush_keeps_manifest_non_terminal_on_windows(self):
        class FakeKernel32:
            def CreateFileW(self, path, desired_access, share_mode, security, creation, flags, template):
                return 123

            def FlushFileBuffers(self, handle):
                return 1

            def CloseHandle(self, handle):
                return 1

        fake_windll = types.SimpleNamespace(kernel32=FakeKernel32())

        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            archive_id = self.m._dataset_manifest_archive_id(archive["archive_path"])
            args = fixture["args"]
            args.success_policy = "move"
            args.success_to = os.path.join(td, "success")

            class DummyLock:
                def __init__(self, path, timeout_ms, retry_ms, debug):
                    self.path = path

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

            with (
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(self.m.ctypes, "windll", fake_windll, create=True),
                mock.patch.object(self.m, "same_volume", return_value=True),
                mock.patch.object(self.m, "FileLock", DummyLock),
            ):
                txn = self.m._txn_create(
                    archive_path=archive["archive_path"],
                    volumes=archive["volumes"],
                    output_dir=archive["output_dir"],
                    output_base=fixture["output_root"],
                    policy="direct",
                    wal_fsync_every=1,
                    snapshot_every=1,
                    durability_enabled=True,
                )
                txn["state"] = self.m.TXN_STATE_PLACED
                self.m._txn_snapshot(txn)

                def fail_on_moved_archive(path, debug=False):
                    return not path.endswith(".zip")

                with mock.patch.object(self.m, "_fsync_file", side_effect=fail_on_moved_archive):
                    with self.assertRaises(RuntimeError):
                        self.m._place_and_finalize_txn(txn, args=args)

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][archive_id]
            self.assertEqual(self.m.TXN_STATE_ABORTED, txn["state"])
            self.assertEqual("DURABILITY_FAILED", txn["error"]["type"])
            self.assertEqual("recoverable", entry["state"])
            self.assertEqual("unknown", entry["final_disposition"])
            self.assertIsNone(entry["finalized_at"])

    def test_fail_move_fsync_failure_after_parent_dir_flush_keeps_manifest_retryable_on_windows(self):
        class FakeKernel32:
            def CreateFileW(self, path, desired_access, share_mode, security, creation, flags, template):
                return 123

            def FlushFileBuffers(self, handle):
                return 1

            def CloseHandle(self, handle):
                return 1

        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        fake_windll = types.SimpleNamespace(kernel32=FakeKernel32())

        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            fail_to = os.path.join(td, "failed")
            os.makedirs(input_root)
            os.makedirs(output_root)
            archive_path = os.path.join(input_root, "alpha.zip")
            with open(archive_path, "wb") as f:
                f.write(b"zip")
            args = self._make_processing_args(
                input_root, output=output_root, fail_policy="move", fail_to=fail_to
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=[
                    {
                        "archive_path": archive_path,
                        "output_dir": output_root,
                        "volumes": [archive_path],
                        "requested_policy": args.decompress_policy,
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            processor = self.m.ArchiveProcessor(args)

            with (
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(self.m.ctypes, "windll", fake_windll, create=True),
                mock.patch.object(self.m, "same_volume", return_value=True),
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "try_extract", return_value=False),
                mock.patch.object(
                    self.m,
                    "_fsync_file",
                    side_effect=lambda path, debug=False: not path.endswith(".zip"),
                ),
            ):
                result = self.m._extract_phase(
                    processor, archive_path, args=args, output_base=output_root
                )

            self.assertEqual("txn_failed", result["kind"])
            self.assertEqual(self.m.TXN_STATE_ABORTED, result["txn"]["state"])
            self.assertEqual("FAIL_FINALIZE_FAILED", result["txn"]["error"]["type"])
            manifest = self.m._load_dataset_manifest(output_root)
            entry = manifest["archives"][archive_id]
            self.assertEqual("retryable", entry["state"])
            self.assertEqual("unknown", entry["final_disposition"])
            self.assertIsNone(entry["finalized_at"])

    def test_traditional_zip_move_fsync_failure_after_parent_dir_flush_returns_retryable_result_on_windows(self):
        class FakeKernel32:
            def CreateFileW(self, path, desired_access, share_mode, security, creation, flags, template):
                return 123

            def FlushFileBuffers(self, handle):
                return 1

            def CloseHandle(self, handle):
                return 1

        fake_windll = types.SimpleNamespace(kernel32=FakeKernel32())

        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            trad_to = os.path.join(td, "traditional")
            os.makedirs(input_root)
            os.makedirs(output_root)
            archive_path = os.path.join(input_root, "legacy.zip")
            with open(archive_path, "wb") as f:
                f.write(b"legacy")
            args = self._make_processing_args(
                input_root,
                output=output_root,
                traditional_zip_policy="move",
                traditional_zip_to=trad_to,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=[
                    {
                        "archive_path": archive_path,
                        "output_dir": output_root,
                        "volumes": [archive_path],
                        "requested_policy": args.decompress_policy,
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            archive_id = self.m._dataset_manifest_archive_id(archive_path)
            processor = self.m.ArchiveProcessor(args)

            class DummyLock:
                def __init__(self, path, timeout_ms, retry_ms, debug):
                    self.path = path

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

            with (
                mock.patch.object(self.m.os, "name", "nt"),
                mock.patch.object(self.m.ctypes, "windll", fake_windll, create=True),
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "is_zip_format", return_value=True),
                mock.patch.object(self.m, "is_traditional_zip", return_value=True),
                mock.patch.object(
                    self.m,
                    "_fsync_file",
                    side_effect=lambda path, debug=False: not path.endswith(".zip"),
                ),
            ):
                result = self.m._extract_phase(
                    processor, archive_path, args=args, output_base=output_root
                )
                self.m._handle_transactional_result(
                    result,
                    processor=types.SimpleNamespace(
                        successful_archives=[], failed_archives=[], skipped_archives=[]
                    ),
                    args=args,
                    output_base=output_root,
                    touched_output_dirs=set(),
                )

            self.assertEqual("txn_failed", result["kind"])
            self.assertEqual("FAIL_FINALIZE_FAILED", result["txn"]["error"]["type"])
            manifest = self.m._load_dataset_manifest(output_root)
            entry = manifest["archives"][archive_id]
            self.assertEqual("retryable", entry["state"])
            self.assertEqual("unknown", entry["final_disposition"])
            self.assertIsNone(entry["finalized_at"])

    def test_missing_wal_with_zero_plan_snapshots_allows_startup_resume_for_placing_txn(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)
            archive_path = os.path.join(input_root, "alpha.zip")
            with open(archive_path, "wb") as f:
                f.write(b"zip")

            args = self._make_processing_args(
                input_root,
                output=output_root,
                decompress_policy="only-file-content-direct",
                threads=1,
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=[
                    {
                        "archive_path": archive_path,
                        "output_dir": output_root,
                        "volumes": [archive_path],
                        "requested_policy": args.decompress_policy,
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )

            txn = self.m._txn_create(
                archive_path=archive_path,
                volumes=[archive_path],
                output_dir=output_root,
                output_base=output_root,
                policy=args.decompress_policy,
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            os.makedirs(os.path.join(txn["paths"]["incoming_dir"], "a", "b", "c"))
            resolved = self.m._resolve_policy_under_lock(txn, args.conflict_mode)
            self.m._freeze_policy(txn, resolved)
            txn["state"] = self.m.TXN_STATE_PLACING
            self.m._txn_snapshot(txn)
            plans = self.m._plan_only_file_content_direct_moves(txn)

            self.assertEqual([], plans)

            wal_writer = self.m.WalWriter(txn["paths"]["wal"], fsync_every=1, debug=False)
            try:
                self.m._execute_plans(
                    txn,
                    plans,
                    wal_writer=wal_writer,
                    degrade_cross_volume=False,
                )
            finally:
                wal_writer.close(force_fsync=True)

            self.m._update_dataset_manifest_archive(
                output_root,
                archive_path,
                state="recoverable",
                last_txn_id=txn["txn_id"],
                error=None,
            )
            if os.path.exists(txn["paths"]["wal"]):
                os.remove(txn["paths"]["wal"])

            self.assertTrue(self.m._validate_strict_resume_startup(args))

    def test_empty_wal_with_zero_plan_snapshots_make_startup_ambiguous_for_placing_txn(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)
            archive_path = os.path.join(input_root, "alpha.zip")
            with open(archive_path, "wb") as f:
                f.write(b"zip")

            args = self._make_processing_args(
                input_root,
                output=output_root,
                decompress_policy="only-file-content-direct",
                threads=1,
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=[
                    {
                        "archive_path": archive_path,
                        "output_dir": output_root,
                        "volumes": [archive_path],
                        "requested_policy": args.decompress_policy,
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )

            txn = self.m._txn_create(
                archive_path=archive_path,
                volumes=[archive_path],
                output_dir=output_root,
                output_base=output_root,
                policy=args.decompress_policy,
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            os.makedirs(os.path.join(txn["paths"]["incoming_dir"], "a", "b", "c"))
            resolved = self.m._resolve_policy_under_lock(txn, args.conflict_mode)
            self.m._freeze_policy(txn, resolved)
            txn["state"] = self.m.TXN_STATE_PLACING
            self.m._txn_snapshot(txn)
            plans = self.m._plan_only_file_content_direct_moves(txn)

            self.assertEqual([], plans)

            wal_writer = self.m.WalWriter(txn["paths"]["wal"], fsync_every=1, debug=False)
            try:
                self.m._execute_plans(
                    txn,
                    plans,
                    wal_writer=wal_writer,
                    degrade_cross_volume=False,
                )
            finally:
                wal_writer.close(force_fsync=True)

            self.m._update_dataset_manifest_archive(
                output_root,
                archive_path,
                state="recoverable",
                last_txn_id=txn["txn_id"],
                error=None,
            )

            self.assertTrue(os.path.exists(txn["paths"]["wal"]))
            self.assertEqual(0, os.path.getsize(txn["paths"]["wal"]))
            self.assertFalse(self.m._validate_strict_resume_startup(args))

    def test_empty_wal_with_zero_plan_snapshots_block_run_transactional_resume(self):
        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)
            archive_path = os.path.join(input_root, "alpha.zip")
            with open(archive_path, "wb") as f:
                f.write(b"zip")

            args = self._make_processing_args(
                input_root,
                output=output_root,
                decompress_policy="only-file-content-direct",
                threads=1,
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=[
                    {
                        "archive_path": archive_path,
                        "output_dir": output_root,
                        "volumes": [archive_path],
                        "requested_policy": args.decompress_policy,
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            archive_id = self.m._dataset_manifest_archive_id(archive_path)

            txn = self.m._txn_create(
                archive_path=archive_path,
                volumes=[archive_path],
                output_dir=output_root,
                output_base=output_root,
                policy=args.decompress_policy,
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            os.makedirs(os.path.join(txn["paths"]["incoming_dir"], "a", "b", "c"))
            resolved = self.m._resolve_policy_under_lock(txn, args.conflict_mode)
            self.m._freeze_policy(txn, resolved)
            txn["state"] = self.m.TXN_STATE_PLACING
            self.m._txn_snapshot(txn)
            plans = self.m._plan_only_file_content_direct_moves(txn)

            self.assertEqual([], plans)

            wal_writer = self.m.WalWriter(txn["paths"]["wal"], fsync_every=1, debug=False)
            try:
                self.m._execute_plans(
                    txn,
                    plans,
                    wal_writer=wal_writer,
                    degrade_cross_volume=False,
                )
            finally:
                wal_writer.close(force_fsync=True)

            self.m._update_dataset_manifest_archive(
                output_root,
                archive_path,
                state="recoverable",
                last_txn_id=txn["txn_id"],
                error=None,
            )

            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            with mock.patch.object(
                self.m,
                "_extract_phase",
                side_effect=AssertionError(
                    "ambiguous empty WAL startup must not re-extract"
                ),
            ):
                self.assertFalse(self.m._run_transactional(processor, [], args=args))

            resumed_manifest = self.m._load_dataset_manifest(output_root)
            resumed_entry = resumed_manifest["archives"][archive_id]

            self.assertEqual([], processor.successful_archives)
            self.assertEqual([], processor.failed_archives)
            self.assertEqual("recoverable", resumed_entry["state"])
            self.assertEqual("unknown", resumed_entry["final_disposition"])
            self.assertIsNone(resumed_entry["error"])

    def test_snapshot_resume_state_rejects_zero_plan_with_done_ids(self):
        txn = {
            "placement": {
                "move_plan_snapshot": [],
                "move_done_ids_snapshot": [1],
            }
        }

        self.assertFalse(self.m._txn_has_snapshot_resume_state(txn))

    def test_replayable_wal_allows_startup_resume_for_placing_txn(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_PLACING
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                archive["archive_path"],
                state="recoverable",
                last_txn_id=txn["txn_id"],
                error=None,
            )
            with open(txn["paths"]["wal"], "w", encoding="utf-8") as f:
                f.write(
                    json.dumps(
                        {
                            "t": "MOVE_PLAN",
                            "id": 1,
                            "src": os.path.join(txn["paths"]["incoming_dir"], "payload.txt"),
                            "dst": os.path.join(archive["output_dir"], "payload.txt"),
                        }
                    )
                    + "\n"
                )

            self.assertTrue(self.m._validate_strict_resume_startup(fixture["args"]))

    def test_corrupt_wal_makes_startup_ambiguous_for_placing_txn(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_PLACING
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                archive["archive_path"],
                state="recoverable",
                last_txn_id=txn["txn_id"],
                error=None,
            )
            with open(txn["paths"]["wal"], "w", encoding="utf-8") as f:
                f.write('{"t":"MOVE_PLAN","id":1,"src":"a"')

            self.assertFalse(self.m._validate_strict_resume_startup(fixture["args"]))

    def test_missing_wal_with_snapshots_resumes_placing_without_reextract(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            archive_id = self.m._dataset_manifest_archive_id(archive["archive_path"])
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            incoming_dir = txn["paths"]["incoming_dir"]
            os.makedirs(incoming_dir, exist_ok=True)
            src = os.path.join(incoming_dir, "payload.txt")
            with open(src, "w", encoding="utf-8") as f:
                f.write("payload")
            dst = os.path.join(archive["output_dir"], "payload.txt")
            txn["state"] = self.m.TXN_STATE_PLACING
            txn.setdefault("placement", {})["move_plan_snapshot"] = [
                {"id": 1, "src": src, "dst": dst}
            ]
            txn.setdefault("placement", {})["move_done_ids_snapshot"] = []
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                archive["archive_path"],
                state="recoverable",
                last_txn_id=txn["txn_id"],
                error=None,
            )
            if os.path.exists(txn["paths"]["wal"]):
                os.remove(txn["paths"]["wal"])

            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "snapshot resume must not re-extract"
                    ),
                ),
                mock.patch.object(self.m, "_garbage_collect"),
            ):
                self.m._run_transactional(processor, [], args=fixture["args"])

            resumed_manifest = self.m._load_dataset_manifest(fixture["output_root"])
            resumed_entry = resumed_manifest["archives"][archive_id]

            self.assertTrue(os.path.exists(dst))
            self.assertFalse(os.path.exists(src))
            self.assertEqual(
                [os.path.abspath(archive["archive_path"])],
                processor.successful_archives,
            )
            self.assertEqual("succeeded", resumed_entry["state"])
            self.assertEqual("success:asis", resumed_entry["final_disposition"])
            self.assertIsNone(resumed_entry["error"])

    def test_missing_wal_without_snapshots_makes_startup_ambiguous_for_placing(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_PLACING
            txn.setdefault("placement", {}).pop("move_plan_snapshot", None)
            txn.setdefault("placement", {}).pop("move_done_ids_snapshot", None)
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                archive["archive_path"],
                state="recoverable",
                last_txn_id=txn["txn_id"],
                error=None,
            )
            if os.path.exists(txn["paths"]["wal"]):
                os.remove(txn["paths"]["wal"])

            self.assertFalse(self.m._validate_strict_resume_startup(fixture["args"]))

    def test_missing_wal_snapshot_done_moves_still_participate_in_payload_durability_barrier(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            args = fixture["args"]
            args.success_policy = "delete"
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=True,
            )
            incoming_dir = txn["paths"]["incoming_dir"]
            os.makedirs(incoming_dir, exist_ok=True)
            src_done = os.path.join(incoming_dir, "done.txt")
            src_pending = os.path.join(incoming_dir, "pending.txt")
            with open(src_done, "w", encoding="utf-8") as f:
                f.write("done")
            with open(src_pending, "w", encoding="utf-8") as f:
                f.write("pending")
            dst_done = os.path.join(archive["output_dir"], "done.txt")
            dst_pending = os.path.join(archive["output_dir"], "pending.txt")
            os.makedirs(archive["output_dir"], exist_ok=True)
            os.replace(src_done, dst_done)

            txn["resolved_policy"] = "direct"
            txn["policy_frozen"] = True
            txn["state"] = self.m.TXN_STATE_FAILED
            txn["error"] = {
                "type": "DURABILITY_FAILED",
                "message": "durability failed after partial snapshot fallback",
                "at": self.m._now_iso(),
            }
            txn.setdefault("placement", {})["move_plan_snapshot"] = [
                {"id": 1, "src": src_done, "dst": dst_done},
                {"id": 2, "src": src_pending, "dst": dst_pending},
            ]
            txn["placement"]["move_done_ids_snapshot"] = [1]
            txn["placement"].pop("touched_payload_files", None)
            txn["placement"].pop("touched_payload_dirs", None)
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                archive["archive_path"],
                state="recoverable",
                last_txn_id=txn["txn_id"],
                error=txn["error"],
            )
            if os.path.exists(txn["paths"]["wal"]):
                os.remove(txn["paths"]["wal"])

            seen_fsync_files = []

            def tracking_fsync_file(path, debug=False):
                seen_fsync_files.append(os.path.abspath(path))
                return True

            with mock.patch.object(
                self.m, "_fsync_file", side_effect=tracking_fsync_file
            ):
                self.m._place_and_finalize_txn(txn, args=args, recovery=True)

            self.assertIn(os.path.abspath(dst_done), seen_fsync_files)
            self.assertIn(os.path.abspath(dst_pending), seen_fsync_files)
            self.assertFalse(os.path.exists(archive["archive_path"]))

    def test_failed_durability_txn_with_missing_wal_and_snapshots_resumes_without_reextract(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            archive_id = self.m._dataset_manifest_archive_id(archive["archive_path"])
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            incoming_dir = txn["paths"]["incoming_dir"]
            os.makedirs(incoming_dir, exist_ok=True)
            src = os.path.join(incoming_dir, "payload.txt")
            with open(src, "w", encoding="utf-8") as f:
                f.write("payload")
            dst = os.path.join(archive["output_dir"], "payload.txt")
            txn.setdefault("placement", {})["move_plan_snapshot"] = [
                {"id": 1, "src": src, "dst": dst}
            ]
            txn.setdefault("placement", {})["move_done_ids_snapshot"] = []
            txn["state"] = self.m.TXN_STATE_FAILED
            txn["error"] = {
                "type": "DURABILITY_FAILED",
                "message": "durability failed after rename barrier",
                "at": self.m._now_iso(),
            }
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                archive["archive_path"],
                state="recoverable",
                last_txn_id=txn["txn_id"],
                error=txn["error"],
            )
            if os.path.exists(txn["paths"]["wal"]):
                os.remove(txn["paths"]["wal"])

            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "snapshot resume must not re-extract failed placing txn"
                    ),
                ),
                mock.patch.object(self.m, "_garbage_collect"),
            ):
                self.m._run_transactional(processor, [], args=fixture["args"])

            resumed_manifest = self.m._load_dataset_manifest(fixture["output_root"])
            resumed_entry = resumed_manifest["archives"][archive_id]

            self.assertTrue(os.path.exists(dst))
            self.assertFalse(os.path.exists(src))
            self.assertEqual(
                [os.path.abspath(archive["archive_path"])],
                processor.successful_archives,
            )
            self.assertEqual("succeeded", resumed_entry["state"])
            self.assertEqual("success:asis", resumed_entry["final_disposition"])

    def test_failed_durability_txn_with_corrupt_wal_is_startup_ambiguous(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_FAILED
            txn["error"] = {
                "type": "DURABILITY_FAILED",
                "message": "durability failed after rename barrier",
                "at": self.m._now_iso(),
            }
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                archive["archive_path"],
                state="recoverable",
                last_txn_id=txn["txn_id"],
                error=txn["error"],
            )
            with open(txn["paths"]["wal"], "w", encoding="utf-8") as f:
                f.write('{"t":"MOVE_PLAN","id":1,"src":"a"')

            self.assertFalse(self.m._validate_strict_resume_startup(fixture["args"]))

    def test_aborted_placing_txn_with_missing_wal_and_snapshots_resumes_without_reextract(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            archive_id = self.m._dataset_manifest_archive_id(archive["archive_path"])
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            incoming_dir = txn["paths"]["incoming_dir"]
            os.makedirs(incoming_dir, exist_ok=True)
            src = os.path.join(incoming_dir, "payload.txt")
            with open(src, "w", encoding="utf-8") as f:
                f.write("payload")
            dst = os.path.join(archive["output_dir"], "payload.txt")
            txn.setdefault("placement", {})["move_plan_snapshot"] = [
                {"id": 1, "src": src, "dst": dst}
            ]
            txn.setdefault("placement", {})["move_done_ids_snapshot"] = []
            txn["state"] = self.m.TXN_STATE_ABORTED
            txn["error"] = {
                "type": "ABORTED",
                "message": "interrupted during placing",
                "at": self.m._now_iso(),
            }
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                archive["archive_path"],
                state="recoverable",
                last_txn_id=txn["txn_id"],
                error=txn["error"],
            )
            if os.path.exists(txn["paths"]["wal"]):
                os.remove(txn["paths"]["wal"])

            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(
                    self.m,
                    "_extract_phase",
                    side_effect=AssertionError(
                        "snapshot resume must not re-extract aborted placing txn"
                    ),
                ),
                mock.patch.object(
                    self.m,
                    "_execute_policy_with_wal",
                    side_effect=AssertionError(
                        "aborted snapshot resume must not rebuild placing plan"
                    ),
                ),
                mock.patch.object(self.m, "_garbage_collect"),
            ):
                self.m._run_transactional(processor, [], args=fixture["args"])

            resumed_manifest = self.m._load_dataset_manifest(fixture["output_root"])
            resumed_entry = resumed_manifest["archives"][archive_id]

            self.assertTrue(os.path.exists(dst))
            self.assertFalse(os.path.exists(src))
            self.assertEqual(
                [os.path.abspath(archive["archive_path"])],
                processor.successful_archives,
            )
            self.assertEqual("succeeded", resumed_entry["state"])
            self.assertEqual("success:asis", resumed_entry["final_disposition"])

    def test_aborted_placing_txn_with_corrupt_wal_is_startup_ambiguous(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_ABORTED
            txn["error"] = {
                "type": "ABORTED",
                "message": "interrupted during placing",
                "at": self.m._now_iso(),
            }
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                archive["archive_path"],
                state="recoverable",
                last_txn_id=txn["txn_id"],
                error=txn["error"],
            )
            with open(txn["paths"]["wal"], "w", encoding="utf-8") as f:
                f.write('{"t":"MOVE_PLAN","id":1,"src":"a"')

            self.assertFalse(self.m._validate_strict_resume_startup(fixture["args"]))

    def test_aborted_incoming_resume_ignores_stray_partial_snapshot_metadata(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            incoming_dir = txn["paths"]["incoming_dir"]
            os.makedirs(incoming_dir, exist_ok=True)
            with open(os.path.join(incoming_dir, "payload.txt"), "w", encoding="utf-8") as f:
                f.write("payload")
            txn["state"] = self.m.TXN_STATE_ABORTED
            txn["error"] = {
                "type": "ABORTED",
                "message": "interrupted before placing",
                "at": self.m._now_iso(),
            }
            txn.setdefault("placement", {})["move_plan_snapshot"] = []
            txn["placement"].pop("move_done_ids_snapshot", None)
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                archive["archive_path"],
                state="recoverable",
                last_txn_id=txn["txn_id"],
                error=txn["error"],
            )
            if os.path.exists(txn["paths"]["wal"]):
                os.remove(txn["paths"]["wal"])

            self.assertEqual(
                self.m.TXN_STATE_INCOMING_COMMITTED,
                self.m._recoverable_txn_state_from_aborted(txn),
            )
            self.assertFalse(self.m._txn_requires_wal_resume(txn))
            self.assertIsNone(self.m._wal_dependent_resume_classification(txn))
            self.assertTrue(self.m._validate_strict_resume_startup(fixture["args"]))

    def test_aborted_placing_txn_without_wal_or_snapshots_is_startup_ambiguous(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            incoming_dir = txn["paths"]["incoming_dir"]
            os.makedirs(incoming_dir, exist_ok=True)
            with open(os.path.join(incoming_dir, "payload.txt"), "w", encoding="utf-8") as f:
                f.write("payload")
            txn["policy_frozen"] = True
            txn["resolved_policy"] = "direct"
            txn["state"] = self.m.TXN_STATE_ABORTED
            txn["error"] = {
                "type": "ABORTED",
                "message": "interrupted during placing before WAL snapshot",
                "at": self.m._now_iso(),
            }
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                archive["archive_path"],
                state="recoverable",
                last_txn_id=txn["txn_id"],
                error=txn["error"],
            )
            if os.path.exists(txn["paths"]["wal"]):
                os.remove(txn["paths"]["wal"])

            self.assertIsNone(self.m._recoverable_txn_state_from_aborted(txn))
            self.assertEqual(
                "ambiguous", self.m._wal_dependent_resume_classification(txn)
            )
            self.assertFalse(self.m._validate_strict_resume_startup(fixture["args"]))

    def test_aborted_extracted_resume_ignores_stray_partial_snapshot_metadata(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            staging_dir = txn["paths"]["staging_extracted"]
            os.makedirs(staging_dir, exist_ok=True)
            with open(os.path.join(staging_dir, "payload.txt"), "w", encoding="utf-8") as f:
                f.write("payload")
            txn["state"] = self.m.TXN_STATE_ABORTED
            txn["error"] = {
                "type": "ABORTED",
                "message": "interrupted before incoming commit",
                "at": self.m._now_iso(),
            }
            txn.setdefault("placement", {})["move_done_ids_snapshot"] = []
            txn["placement"].pop("move_plan_snapshot", None)
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                archive["archive_path"],
                state="recoverable",
                last_txn_id=txn["txn_id"],
                error=txn["error"],
            )
            if os.path.exists(txn["paths"]["wal"]):
                os.remove(txn["paths"]["wal"])

            self.assertEqual(
                self.m.TXN_STATE_EXTRACTED,
                self.m._recoverable_txn_state_from_aborted(txn),
            )
            self.assertFalse(self.m._txn_requires_wal_resume(txn))
            self.assertIsNone(self.m._wal_dependent_resume_classification(txn))
            self.assertTrue(self.m._validate_strict_resume_startup(fixture["args"]))

    def test_prefixed_non_wal_recoverable_txn_without_wal_or_snapshots_still_resumes(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_EXTRACTED
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                archive["archive_path"],
                state="recoverable",
                last_txn_id=txn["txn_id"],
                error=None,
            )

            self.assertTrue(self.m._validate_strict_resume_startup(fixture["args"]))

    def test_n_collect_matches_in_txn_mode(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "out")
            os.makedirs(out)
            paths = {"incoming_dir": os.path.join(td, "incoming")}
            os.makedirs(paths["incoming_dir"])
            with open(
                os.path.join(paths["incoming_dir"], "x.txt"), "w", encoding="utf-8"
            ) as f:
                f.write("x")

            txn = {
                "policy_frozen": False,
                "policy": "2-collect",
                "paths": paths,
                "output_dir": out,
                "archive_path": os.path.join(td, "a.7z"),
                "txn_id": "testtxn",
            }
            resolved = self.m._resolve_policy_under_lock(txn, conflict_mode="fail")
            self.assertEqual(resolved, "direct")

    def test_same_volume_basic(self):
        with tempfile.TemporaryDirectory() as td:
            a = os.path.join(td, "a")
            b = os.path.join(td, "b")
            os.makedirs(a)
            os.makedirs(b)
            self.assertTrue(self.m.same_volume(a, b))

    def test_find_file_content_empty_dir_chain(self):
        with tempfile.TemporaryDirectory() as td:
            root = os.path.join(td, "tmp")
            deepest = os.path.join(root, "a", "b", "c")
            os.makedirs(deepest)
            info = self.m.find_file_content(root, debug=False)
            self.assertTrue(info["found"])
            self.assertEqual(os.path.normpath(info["path"]), os.path.normpath(deepest))
            self.assertEqual(info["items"], [])

    def test_file_lock_exclusive_posix(self):
        if os.name == "nt":
            self.skipTest("POSIX-only lock behavior")

        with tempfile.TemporaryDirectory() as td:
            lock_path = os.path.join(td, "lockfile")
            lock1 = self.m.FileLock(
                lock_path, timeout_ms=2000, retry_ms=50, debug=False
            )
            self.assertTrue(lock1.acquire())

            parent_conn, child_conn = Pipe(duplex=False)

            def _try_lock(path, conn):
                m = _load_advdecompress_module()
                lk = m.FileLock(path, timeout_ms=200, retry_ms=50, debug=False)
                ok = lk.acquire()
                if ok:
                    lk.release()
                conn.send(ok)
                conn.close()

            p = Process(target=_try_lock, args=(lock_path, child_conn))
            p.start()
            ok = parent_conn.recv()
            p.join(timeout=5)

            self.assertFalse(ok)
            lock1.release()

            lock2 = self.m.FileLock(
                lock_path, timeout_ms=1000, retry_ms=50, debug=False
            )
            self.assertTrue(lock2.acquire())
            lock2.release()

    def test_collect_resolves_to_separate_on_conflict(self):
        with tempfile.TemporaryDirectory() as td:
            output_dir = os.path.join(td, "out")
            os.makedirs(output_dir)
            paths = self.m._txn_paths(output_dir, td, "testtxn")
            os.makedirs(paths["incoming_dir"])
            with open(
                os.path.join(paths["incoming_dir"], "x.txt"), "w", encoding="utf-8"
            ) as f:
                f.write("x")
            with open(os.path.join(output_dir, "x.txt"), "w", encoding="utf-8") as f:
                f.write("y")

            txn = {
                "policy_frozen": False,
                "policy": "collect",
                "paths": paths,
                "output_dir": output_dir,
                "archive_path": os.path.join(td, "a.zip"),
                "txn_id": "testtxn",
            }
            resolved = self.m._resolve_policy_under_lock(txn, conflict_mode="fail")
            self.assertEqual(resolved, "separate")

    def test_init_txn_not_marked_done(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "out")
            os.makedirs(out)
            txn = self.m._txn_create(
                archive_path=os.path.join(td, "a.7z"),
                volumes=[],
                output_dir=out,
                output_base=td,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_INIT
            self.m._txn_snapshot(txn)

            args = types.SimpleNamespace(
                degrade_cross_volume=False,
                conflict_mode="fail",
                wal_fsync_every=1,
                fsync_files="none",
                success_policy="asis",
                success_to=None,
                fail_policy="asis",
                fail_to=None,
                keep_journal_days=7,
                output_lock_timeout_ms=1000,
                output_lock_retry_ms=10,
                no_durability=True,
            )

            with self.assertRaises(Exception):
                self.m._place_and_finalize_txn(txn, args=args, recovery=True)

            with open(txn["paths"]["txn_json"], "r", encoding="utf-8") as f:
                saved = json.load(f)
            self.assertNotEqual(saved["state"], self.m.TXN_STATE_DONE)

    def test_run_transactional_streams_finalize_in_single_thread(self):
        events = []

        def fake_extract(processor, archive_path, *, args, output_base):
            name = os.path.basename(archive_path)
            events.append(f"extract:{name}")
            return {
                "kind": "txn",
                "txn": {
                    "archive_path": archive_path,
                    "output_dir": os.path.join(output_base, "out"),
                    "state": self.m.TXN_STATE_EXTRACTED,
                    "txn_id": name.replace(".", "_"),
                    "paths": {"work_root": os.path.join(output_base, "work")},
                },
            }

        def fake_finalize(txn, *, args, recovery=False):
            events.append(f"finalize:{os.path.basename(txn['archive_path'])}")

        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                threads=1,
                output_lock_timeout_ms=1000,
                output_lock_retry_ms=10,
                keep_journal_days=7,
                success_clean_journal=False,
                fail_clean_journal=False,
                conflict_mode="fail",
            )
            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            archives = [os.path.join(td, "a.zip"), os.path.join(td, "b.zip")]
            for archive in archives:
                with open(archive, "wb") as f:
                    f.write(b"test")

            with (
                mock.patch.object(self.m, "_extract_phase", side_effect=fake_extract),
                mock.patch.object(
                    self.m, "_place_and_finalize_txn", side_effect=fake_finalize
                ),
                mock.patch.object(self.m, "_recover_all_outputs"),
                mock.patch.object(self.m, "_garbage_collect"),
                mock.patch.object(self.m, "FileLock", DummyLock),
            ):
                self.m._run_transactional(processor, archives, args=args)

        self.assertLess(events.index("finalize:a.zip"), events.index("extract:b.zip"))
        self.assertEqual(archives, processor.successful_archives)

    def test_run_transactional_bounds_inflight_extracts_and_streams_finalize(self):
        events = []
        submitted = []
        tracker = {"outstanding": 0, "max_outstanding": 0}
        allow_b_finish = threading.Event()
        b_started = threading.Event()

        FakeExecutor = self._make_async_executor_class(
            submitted=submitted,
            event_log=events,
            tracker=tracker,
        )

        def fake_extract(processor, archive_path, *, args, output_base):
            name = os.path.basename(archive_path)
            events.append(f"extract-start:{name}")
            if name == "b.zip":
                b_started.set()
                self.assertTrue(allow_b_finish.wait(timeout=1))
            events.append(f"extract-end:{name}")
            return self._make_txn_result(
                archive_path,
                output_dir=os.path.join(output_base, name.replace(".zip", "")),
                output_base=output_base,
            )

        def fake_finalize(txn, *, processor, args, output_base):
            name = os.path.basename(txn["archive_path"])
            events.append(f"finalize:{name}")
            processor.successful_archives.append(txn["archive_path"])
            if name == "a.zip":
                self.assertTrue(b_started.wait(timeout=1))
                allow_b_finish.set()

        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                threads=2,
                output_lock_timeout_ms=1000,
                output_lock_retry_ms=10,
                keep_journal_days=7,
                success_clean_journal=False,
                fail_clean_journal=False,
                conflict_mode="fail",
            )
            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            archives = [
                os.path.join(td, "a.zip"),
                os.path.join(td, "b.zip"),
                os.path.join(td, "c.zip"),
            ]
            for archive in archives:
                with open(archive, "wb") as f:
                    f.write(b"test")

            with (
                mock.patch.object(self.m, "ThreadPoolExecutor", FakeExecutor),
                mock.patch.object(self.m, "_extract_phase", side_effect=fake_extract),
                mock.patch.object(
                    self.m, "_finalize_one_txn", side_effect=fake_finalize
                ),
                mock.patch.object(self.m, "_recover_all_outputs"),
                mock.patch.object(self.m, "_garbage_collect"),
                mock.patch.object(self.m, "FileLock", DummyLock),
            ):
                self.m._run_transactional(processor, archives, args=args)

        self.assertEqual(["a.zip", "b.zip", "c.zip"], submitted)
        self.assertLess(events.index("finalize:a.zip"), events.index("submit:c.zip"))
        self.assertLess(
            events.index("finalize:a.zip"), events.index("extract-end:b.zip")
        )
        self.assertLessEqual(tracker["max_outstanding"], args.threads)
        self.assertCountEqual(archives, processor.successful_archives)

    def test_run_transactional_same_output_finalize_order_follows_extract_completion(
        self,
    ):
        events = []
        b_extract_done = threading.Event()

        class CallbackReadyFuture(Future):
            def __init__(self):
                super().__init__()
                self.callback_registered = threading.Event()

            def add_done_callback(self, fn):
                result = super().add_done_callback(fn)
                self.callback_registered.set()
                return result

        class FakeExecutor:
            def __init__(self, max_workers):
                self.max_workers = max_workers
                self._threads = []
                self._slots = threading.Semaphore(max_workers)

            def submit(self, fn, processor, archive_path, *, args, output_base):
                name = os.path.basename(archive_path)
                events.append(f"submit:{name}")
                future = CallbackReadyFuture()

                def runner():
                    self._slots.acquire()
                    try:
                        if not future.callback_registered.wait(timeout=1):
                            raise AssertionError(
                                f"callback not registered for {name} before execution"
                            )
                        result = fn(
                            processor, archive_path, args=args, output_base=output_base
                        )
                    except BaseException as exc:
                        future.set_exception(exc)
                    else:
                        future.set_result(result)
                    finally:
                        self._slots.release()

                thread = threading.Thread(target=runner, name=f"same-output-{name}")
                thread.start()
                self._threads.append(thread)
                return future

            def shutdown(self, wait=True):
                if not wait:
                    return None
                for thread in self._threads:
                    thread.join(timeout=5)
                return None

        def fake_extract(processor, archive_path, *, args, output_base):
            name = os.path.basename(archive_path)
            events.append(f"extract-start:{name}")
            if name == "a.zip":
                self.assertTrue(b_extract_done.wait(timeout=1))
            events.append(f"extract-end:{name}")
            if name == "b.zip":
                b_extract_done.set()

            return self._make_txn_result(
                archive_path,
                output_dir=os.path.join(output_base, "shared-out"),
                output_base=output_base,
            )

        def fake_finalize(txn, *, processor, args, output_base):
            name = os.path.basename(txn["archive_path"])
            events.append(f"finalize:{name}")
            processor.successful_archives.append(txn["archive_path"])

        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                threads=3,
                output_lock_timeout_ms=1000,
                output_lock_retry_ms=10,
                keep_journal_days=7,
                success_clean_journal=False,
                fail_clean_journal=False,
                conflict_mode="fail",
            )
            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            archives = [
                os.path.join(td, "a.zip"),
                os.path.join(td, "b.zip"),
            ]
            for archive in archives:
                with open(archive, "wb") as f:
                    f.write(b"test")

            with (
                mock.patch.object(self.m, "ThreadPoolExecutor", FakeExecutor),
                mock.patch.object(self.m, "_extract_phase", side_effect=fake_extract),
                mock.patch.object(self.m, "_recover_all_outputs"),
                mock.patch.object(self.m, "_garbage_collect"),
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(
                    self.m, "_finalize_one_txn", side_effect=fake_finalize
                ),
            ):
                self.m._run_transactional(processor, archives, args=args)

        self.assertEqual(
            ["extract-end:b.zip", "extract-end:a.zip"],
            [event for event in events if event.startswith("extract-end:")],
        )
        self.assertLess(
            events.index("extract-end:b.zip"), events.index("finalize:b.zip")
        )
        self.assertEqual(
            ["finalize:b.zip", "finalize:a.zip"],
            [event for event in events if event.startswith("finalize:")],
        )
        self.assertEqual(
            ["b.zip", "a.zip"],
            [os.path.basename(path) for path in processor.successful_archives],
        )

    def test_run_transactional_serializes_finalize_per_output_dir(self):
        active = 0
        max_active = 0
        start_gate = threading.Barrier(2)

        def fake_finalize(txn, *, args, recovery=False):
            nonlocal active, max_active
            active += 1
            max_active = max(max_active, active)
            try:
                threading.Event().wait(0.05)
            finally:
                active -= 1

        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                output_lock_timeout_ms=1000,
                output_lock_retry_ms=5,
            )
            output_base = args.output
            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            output_dir = os.path.join(output_base, "shared")
            txns = [
                self._make_txn(
                    os.path.join(td, name),
                    output_dir=output_dir,
                    output_base=output_base,
                )
                for name in ("a.zip", "b.zip")
            ]

            def run_finalize(txn):
                start_gate.wait(timeout=1)
                self.m._finalize_one_txn(
                    txn,
                    processor=processor,
                    args=args,
                    output_base=output_base,
                )

            with mock.patch.object(
                self.m, "_place_and_finalize_txn", side_effect=fake_finalize
            ):
                threads = [
                    threading.Thread(target=run_finalize, args=(txn,)) for txn in txns
                ]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=5)

        self.assertEqual(1, max_active)
        self.assertCountEqual(
            [os.path.join(td, "a.zip"), os.path.join(td, "b.zip")],
            processor.successful_archives,
        )
        self.assertEqual([], processor.failed_archives)

    def test_finalize_one_txn_uses_existing_output_dir_lock_path(self):
        acquired = []
        finalized = []

        class FakeLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                acquired.append(path)

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                output_lock_timeout_ms=1000,
                output_lock_retry_ms=10,
            )
            output_base = args.output
            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            output_dir = os.path.join(output_base, "target")
            archive_path = os.path.join(td, "a.zip")
            txn = self._make_txn(
                archive_path,
                output_dir=output_dir,
                output_base=output_base,
                work_root=os.path.join(td, "wrong-work-root"),
            )
            expected_lock_path = self.m._output_lock_path(output_dir, output_base)

            with (
                mock.patch.object(self.m, "FileLock", FakeLock),
                mock.patch.object(
                    self.m,
                    "_place_and_finalize_txn",
                    side_effect=lambda txn, *, args, recovery=False: finalized.append(
                        txn["archive_path"]
                    ),
                ),
            ):
                self.m._finalize_one_txn(
                    txn,
                    processor=processor,
                    args=args,
                    output_base=output_base,
                )

        self.assertEqual([expected_lock_path], acquired)
        self.assertEqual([archive_path], finalized)
        self.assertEqual([archive_path], processor.successful_archives)
        self.assertEqual([], processor.failed_archives)

    def test_output_lock_path_is_outside_work_root(self):
        with tempfile.TemporaryDirectory() as td:
            output_base = os.path.join(td, "out")
            output_dir = os.path.join(output_base, "nested")

            token = hashlib.sha1(os.path.abspath(output_dir).encode("utf-8")).hexdigest()[:16]
            expected = os.path.join(
                self.m._work_base(output_base),
                "locks",
                token + ".lock",
            )

            self.assertEqual(expected, self.m._output_lock_path(output_dir, output_base))
            self.assertFalse(
                os.path.commonpath(
                    [
                        self.m._output_lock_path(output_dir, output_base),
                        self.m._work_root(output_dir, output_base),
                    ]
                )
                == self.m._work_root(output_dir, output_base)
            )

    def test_finalize_one_txn_uses_shared_output_lock_path(self):
        with tempfile.TemporaryDirectory() as td:
            output_base = os.path.join(td, "out")
            output_dir = os.path.join(output_base, "nested")
            archive_path = os.path.join(td, "alpha.zip")
            with open(archive_path, "wb") as f:
                f.write(b"zip")

            txn = self._make_txn(
                archive_path,
                output_dir=output_dir,
                output_base=output_base,
                work_root=self.m._work_root(output_dir, output_base),
            )
            observed = {}

            class DummyLock:
                def __init__(self, path, timeout_ms, retry_ms, debug):
                    observed["path"] = path

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

            processor = types.SimpleNamespace(successful_archives=[], failed_archives=[])

            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "_place_and_finalize_txn", return_value=None),
            ):
                self.m._finalize_one_txn(
                    txn,
                    processor=processor,
                    args=self._make_processing_args(td, output=output_base),
                    output_base=output_base,
                )

            self.assertEqual(
                self.m._output_lock_path(output_dir, output_base), observed["path"]
            )

    def test_recover_all_outputs_uses_shared_output_lock_path(self):
        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(td, output=os.path.join(td, "out"))
            output_dir = os.path.join(args.output, "nested")
            observed = []

            class DummyLock:
                def __init__(self, path, timeout_ms, retry_ms, debug):
                    observed.append(path)

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "_recover_output_dir", return_value=None),
                mock.patch.object(self.m, "_garbage_collect", return_value=None),
            ):
                self.m._recover_all_outputs(
                    args.output,
                    args=args,
                    recoverable_archives=[
                        {
                            "archive_path": os.path.join(td, "alpha.zip"),
                            "output_dir": output_dir,
                        }
                    ],
                )

            self.assertEqual([self.m._output_lock_path(output_dir, args.output)], observed)

    def test_run_transactional_finalize_failure_does_not_block_later_txns(self):
        def fake_finalize(txn, *, args, recovery=False):
            if os.path.basename(txn["archive_path"]) == "fail.zip":
                raise RuntimeError("boom")

        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                output_lock_timeout_ms=1000,
                output_lock_retry_ms=10,
            )
            output_base = args.output
            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            touched_output_dirs = set()
            failing_archive = os.path.join(td, "fail.zip")
            succeeding_archive = os.path.join(td, "ok.zip")

            with mock.patch.object(
                self.m, "_place_and_finalize_txn", side_effect=fake_finalize
            ):
                self.m._handle_transactional_result(
                    {
                        "kind": "txn",
                        "txn": self._make_txn(
                            failing_archive,
                            output_dir=os.path.join(output_base, "fail-out"),
                            output_base=output_base,
                        ),
                    },
                    processor=processor,
                    args=args,
                    output_base=output_base,
                    touched_output_dirs=touched_output_dirs,
                )
                self.m._handle_transactional_result(
                    {
                        "kind": "txn",
                        "txn": self._make_txn(
                            succeeding_archive,
                            output_dir=os.path.join(output_base, "ok-out"),
                            output_base=output_base,
                        ),
                    },
                    processor=processor,
                    args=args,
                    output_base=output_base,
                    touched_output_dirs=touched_output_dirs,
                )

        self.assertEqual([failing_archive], processor.failed_archives)
        self.assertEqual([succeeding_archive], processor.successful_archives)
        self.assertEqual(
            {
                os.path.join(output_base, "fail-out"),
                os.path.join(output_base, "ok-out"),
            },
            touched_output_dirs,
        )

    def test_finalize_one_txn_lock_timeout_is_recorded_per_txn(self):
        acquired = []

        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                output_lock_timeout_ms=1000,
                output_lock_retry_ms=10,
            )
            output_base = args.output
            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            touched_output_dirs = set()
            timeout_output_dir = os.path.join(output_base, "timeout-out")
            success_output_dir = os.path.join(output_base, "ok-out")
            timeout_archive = os.path.join(td, "timeout.zip")
            success_archive = os.path.join(td, "ok.zip")
            expected_lock_path = self.m._output_lock_path(timeout_output_dir, output_base)

            class FakeLock:
                def __init__(self, path, timeout_ms, retry_ms, debug):
                    self.path = path
                    acquired.append(path)

                def __enter__(self):
                    if self.path == expected_lock_path:
                        raise TimeoutError(f"Could not acquire lock: {self.path}")
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

            with (
                mock.patch.object(self.m, "FileLock", FakeLock),
                mock.patch.object(self.m, "_place_and_finalize_txn", return_value=None),
            ):
                self.m._handle_transactional_result(
                    {
                        "kind": "txn",
                        "txn": self._make_txn(
                            timeout_archive,
                            output_dir=timeout_output_dir,
                            output_base=output_base,
                        ),
                    },
                    processor=processor,
                    args=args,
                    output_base=output_base,
                    touched_output_dirs=touched_output_dirs,
                )
                self.m._handle_transactional_result(
                    {
                        "kind": "txn",
                        "txn": self._make_txn(
                            success_archive,
                            output_dir=success_output_dir,
                            output_base=output_base,
                        ),
                    },
                    processor=processor,
                    args=args,
                    output_base=output_base,
                    touched_output_dirs=touched_output_dirs,
                )

        self.assertEqual(expected_lock_path, acquired[0])
        self.assertEqual([timeout_archive], processor.failed_archives)
        self.assertEqual([success_archive], processor.successful_archives)
        self.assertEqual(
            {timeout_output_dir, success_output_dir},
            touched_output_dirs,
        )

    def test_run_transactional_recovers_existing_txns_before_new_work(self):
        events = []

        def fake_place_and_finalize(txn, *, args, recovery=False):
            label = "recover" if recovery else "finalize"
            events.append(f"{label}:{os.path.basename(txn['archive_path'])}")

        def fake_extract(processor, archive_path, *, args, output_base):
            events.append(f"extract:{os.path.basename(archive_path)}")
            return {"kind": "dry_run", "archive_path": archive_path}

        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                threads=1,
                output_lock_timeout_ms=1000,
                output_lock_retry_ms=10,
                keep_journal_days=7,
                success_clean_journal=False,
                fail_clean_journal=False,
                conflict_mode="fail",
            )
            output_base = args.output
            output_dir = os.path.join(output_base, "recovered-out")
            stale_archive = os.path.join(td, "stale.zip")
            with open(stale_archive, "wb") as f:
                f.write(b"stale")
            new_archive = os.path.join(td, "new.zip")
            with open(new_archive, "wb") as f:
                f.write(b"new")
            self.m._create_dataset_manifest(
                input_root=td,
                output_root=output_base,
                discovered_archives=[
                    {
                        "archive_path": stale_archive,
                        "output_dir": output_dir,
                        "volumes": [stale_archive],
                        "requested_policy": "direct",
                    },
                    {
                        "archive_path": new_archive,
                        "output_dir": os.path.join(output_base, "new-out"),
                        "volumes": [new_archive],
                        "requested_policy": "direct",
                    },
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            txn = self.m._txn_create(
                archive_path=stale_archive,
                volumes=[],
                output_dir=output_dir,
                output_base=output_base,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_EXTRACTED
            self.m._txn_snapshot(txn)

            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            archives = [new_archive]

            with (
                mock.patch.object(
                    self.m,
                    "_place_and_finalize_txn",
                    side_effect=fake_place_and_finalize,
                ),
                mock.patch.object(self.m, "_extract_phase", side_effect=fake_extract),
                mock.patch.object(self.m, "_garbage_collect"),
                mock.patch.object(self.m, "FileLock", DummyLock),
            ):
                self.m._run_transactional(processor, archives, args=args)

        self.assertEqual(
            ["recover:stale.zip", "extract:new.zip"],
            [
                event
                for event in events
                if event.startswith("recover:") or event.startswith("extract:")
            ],
        )

    def test_run_transactional_retries_persisted_init_txn_instead_of_recovering(self):
        events = []
        observed = {}

        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                threads=1,
                output_lock_timeout_ms=1000,
                output_lock_retry_ms=10,
                keep_journal_days=7,
                success_clean_journal=False,
                fail_clean_journal=False,
                conflict_mode="fail",
            )
            output_base = args.output
            output_dir = os.path.join(output_base, "crash-window-out")
            crash_archive = os.path.join(td, "crash-window.zip")
            with open(crash_archive, "wb") as f:
                f.write(b"crash-window")

            manifest = self.m._create_dataset_manifest(
                input_root=td,
                output_root=output_base,
                discovered_archives=[
                    {
                        "archive_path": crash_archive,
                        "output_dir": output_dir,
                        "volumes": [crash_archive],
                        "requested_policy": "direct",
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            archive_id = self.m._dataset_manifest_archive_id(crash_archive)
            manifest["archives"][archive_id]["state"] = "extracting"
            self.m._save_dataset_manifest(manifest)

            txn = self.m._txn_create(
                archive_path=crash_archive,
                volumes=[crash_archive],
                output_dir=output_dir,
                output_base=output_base,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            self.assertEqual(self.m.TXN_STATE_INIT, txn["state"])

            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )

            def fake_extract(processor, archive_path, *, args, output_base):
                manifest = self.m._load_dataset_manifest(output_base)
                observed["state_at_extract"] = manifest["archives"][archive_id]["state"]
                observed["last_txn_id_at_extract"] = manifest["archives"][archive_id][
                    "last_txn_id"
                ]
                events.append(f"extract:{os.path.basename(archive_path)}")
                return {"kind": "dry_run", "archive_path": archive_path}

            with (
                mock.patch.object(
                    self.m,
                    "_recover_output_dir",
                    side_effect=AssertionError(
                        "persisted INIT crash window should not be treated as recoverable"
                    ),
                ),
                mock.patch.object(self.m, "_extract_phase", side_effect=fake_extract),
                mock.patch.object(self.m, "_garbage_collect"),
                mock.patch.object(self.m, "FileLock", DummyLock),
            ):
                self.m._run_transactional(processor, [], args=args)

            manifest = self.m._load_dataset_manifest(output_base)
            entry = manifest["archives"][archive_id]
            self.assertEqual(["extract:crash-window.zip"], events)
            self.assertEqual([crash_archive], processor.skipped_archives)
            self.assertEqual("retryable", observed["state_at_extract"])
            self.assertEqual(txn["txn_id"], observed["last_txn_id_at_extract"])
            self.assertEqual("retryable", entry["state"])
            self.assertEqual("skipped:dry_run", entry["final_disposition"])
            self.assertEqual(txn["txn_id"], entry["last_txn_id"])

    def test_run_transactional_retires_terminal_failed_work_root(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                threads=1,
                output_lock_timeout_ms=1000,
                output_lock_retry_ms=10,
                keep_journal_days=7,
                success_clean_journal=True,
                fail_clean_journal=False,
                conflict_mode="fail",
            )
            output_base = args.output
            output_dir = os.path.join(output_base, "stale-failed-out")
            stale_failed_archive = os.path.join(td, "stale-failed.zip")
            with open(stale_failed_archive, "wb") as f:
                f.write(b"stale-failed")
            self.m._create_dataset_manifest(
                input_root=td,
                output_root=output_base,
                discovered_archives=[
                    {
                        "archive_path": stale_failed_archive,
                        "output_dir": output_dir,
                        "volumes": [stale_failed_archive],
                        "requested_policy": "direct",
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            txn = self.m._txn_create(
                archive_path=stale_failed_archive,
                volumes=[],
                output_dir=output_dir,
                output_base=output_base,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_FAILED
            txn["error"] = {
                "type": "PLACE_FAILED",
                "message": "stale failure",
                "at": self.m._now_iso(),
            }
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                output_base,
                stale_failed_archive,
                state="failed",
                last_txn_id=txn["txn_id"],
                final_disposition="failure:asis",
                error=txn["error"],
                finalized_at=self.m._now_iso(),
            )

            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            work_root = self.m._work_root(output_dir, output_base)

            with mock.patch.object(self.m, "FileLock", DummyLock):
                result = self.m._run_transactional(processor, [], args=args)

            self.assertIsNone(result)
            self.assertEqual([], processor.successful_archives)
            self.assertEqual([], processor.failed_archives)
            self.assertEqual([], processor.skipped_archives)
            self.assertFalse(os.path.isdir(work_root))
            self.assertFalse(os.path.exists(txn["paths"]["txn_json"]))
            self.assertIsNone(self.m._load_dataset_manifest(output_base))

    def test_run_transactional_preserves_recovery_failed_work_root(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        def fake_place_and_finalize(txn, *, args, recovery=False):
            if recovery:
                raise RuntimeError("boom during recovery")
            self.fail("unexpected non-recovery finalize")

        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                threads=1,
                output_lock_timeout_ms=1000,
                output_lock_retry_ms=10,
                keep_journal_days=7,
                success_clean_journal=True,
                fail_clean_journal=False,
                conflict_mode="fail",
            )
            output_base = args.output
            output_dir = os.path.join(output_base, "recovery-failed-out")
            recover_me_archive = os.path.join(td, "recover-me.zip")
            with open(recover_me_archive, "wb") as f:
                f.write(b"recover-me")
            self.m._create_dataset_manifest(
                input_root=td,
                output_root=output_base,
                discovered_archives=[
                    {
                        "archive_path": recover_me_archive,
                        "output_dir": output_dir,
                        "volumes": [recover_me_archive],
                        "requested_policy": "direct",
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            txn = self.m._txn_create(
                archive_path=recover_me_archive,
                volumes=[],
                output_dir=output_dir,
                output_base=output_base,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_EXTRACTED
            self.m._txn_snapshot(txn)

            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            work_root = self.m._work_root(output_dir, output_base)

            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(
                    self.m,
                    "_place_and_finalize_txn",
                    side_effect=fake_place_and_finalize,
                ),
            ):
                self.m._run_transactional(processor, [], args=args)

            self.assertTrue(os.path.isdir(work_root))
            with open(txn["paths"]["txn_json"], "r", encoding="utf-8") as f:
                saved = json.load(f)
            self.assertEqual(self.m.TXN_STATE_FAILED, saved["state"])
            self.assertEqual("RECOVER_FAILED", saved["error"]["type"])

    def test_fail_clean_journal_removes_closed_terminal_failure_work_root(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                output=os.path.join(td, "out"),
                success_clean_journal=False,
                fail_clean_journal=True,
            )
            output_dir = os.path.join(args.output, "failed-out")
            archive_path = os.path.join(td, "alpha.zip")
            with open(archive_path, "wb") as f:
                f.write(b"zip")
            self.m._create_dataset_manifest(
                input_root=td,
                output_root=args.output,
                discovered_archives=[
                    {
                        "archive_path": archive_path,
                        "output_dir": output_dir,
                        "volumes": [archive_path],
                        "requested_policy": "direct",
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            txn = self.m._txn_create(
                archive_path=archive_path,
                volumes=[archive_path],
                output_dir=output_dir,
                output_base=args.output,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            self.m._mark_txn_failure_terminal(
                txn,
                final_disposition="failure:asis",
                error={"type": "PLACE_FAILED", "message": "boom", "at": self.m._now_iso()},
            )
            work_root = self.m._work_root(output_dir, args.output)

            with mock.patch.object(self.m, "FileLock", DummyLock):
                self.m._cleanup_one_transactional_output_dir(
                    output_dir,
                    output_base=args.output,
                    args=args,
                    should_clean=True,
                    manifest_terminal=True,
                )

            self.assertFalse(os.path.exists(work_root))

    def test_manifest_terminalization_failure_keeps_success_move_txn_terminal(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_success_finalization_txn_fixture(
                td,
                success_policy="move",
            )
            txn = fixture["txn"]
            txn["state"] = self.m.TXN_STATE_PLACED
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                fixture["archive_path"],
                state="recoverable",
                last_txn_id=txn["txn_id"],
                error=None,
            )
            os.makedirs(fixture["output_dir"], exist_ok=True)
            root_payload = os.path.join(fixture["output_dir"], "root.txt")
            nested_dir = os.path.join(fixture["output_dir"], "a", "b")
            nested_payload = os.path.join(nested_dir, "payload.txt")
            os.makedirs(nested_dir, exist_ok=True)
            with open(root_payload, "w", encoding="utf-8") as f:
                f.write("root")
            with open(nested_payload, "w", encoding="utf-8") as f:
                f.write("payload")
            self.m._track_payload_destination(txn, root_payload)
            self.m._track_payload_destination(txn, nested_payload)

            archive_path = os.path.abspath(fixture["archive_path"])
            archive_id = fixture["archive_id"]
            real_update_manifest = self.m._update_dataset_manifest_archive

            def fail_manifest_terminalization(output_base, archive_path_arg, **kwargs):
                if (
                    os.path.abspath(archive_path_arg) == archive_path
                    and kwargs.get("state") == "succeeded"
                ):
                    raise RuntimeError("manifest-save-failed")
                return real_update_manifest(output_base, archive_path_arg, **kwargs)

            with (
                mock.patch.object(self.m, "_fsync_file", return_value=True),
                mock.patch.object(self.m, "_fsync_dir", return_value=True),
                mock.patch.object(
                    self.m,
                    "_update_dataset_manifest_archive",
                    side_effect=fail_manifest_terminalization,
                ),
                self.assertRaisesRegex(RuntimeError, "manifest-save-failed"),
            ):
                self.m._place_and_finalize_txn(txn, args=fixture["args"])

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][archive_id]
            saved_txn = self.m._load_latest_txn_for_archive(
                entry,
                fixture["output_root"],
            )

            self.assertFalse(os.path.exists(archive_path))
            self.assertEqual(self.m.TXN_STATE_DONE, saved_txn["state"])
            self.assertIsNone(saved_txn.get("error"))
            self.assertFalse(self.m._txn_has_recovery_responsibility(saved_txn))
            self.assertFalse(self.m._txn_has_incomplete_source_finalization(saved_txn))
            self.assertTrue(self.m._txn_is_closed_terminal_outcome(saved_txn))
            self.assertEqual("recoverable", entry["state"])
            self.assertEqual("unknown", entry["final_disposition"])
            self.assertIsNone(entry["finalized_at"])
            self.assertEqual(
                "succeeded",
                self.m._reconciled_archive_classification(entry, saved_txn),
            )

    def test_terminal_txn_snapshot_failure_does_not_split_brain_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_success_finalization_txn_fixture(
                td,
                success_policy="move",
            )
            txn = fixture["txn"]
            txn["state"] = self.m.TXN_STATE_SOURCE_FINALIZED
            self.m._set_source_finalization_plan(
                txn,
                manifest_state="succeeded",
                final_disposition="success:move",
                txn_terminal_state=self.m.TXN_STATE_DONE,
            )
            finalized_dst = os.path.join(
                fixture["args"].success_to,
                txn["txn_id"],
                os.path.basename(fixture["archive_path"]),
            )
            os.makedirs(os.path.dirname(finalized_dst), exist_ok=True)
            self.m._plan_finalized_source_destination(
                txn,
                fixture["archive_path"],
                finalized_dst,
            )
            if os.path.exists(fixture["archive_path"]):
                os.replace(fixture["archive_path"], finalized_dst)

            archive_id = fixture["archive_id"]
            self.m._update_dataset_manifest_archive(
                fixture["output_root"],
                fixture["archive_path"],
                state="recoverable",
                last_txn_id=txn["txn_id"],
                error=None,
            )
            real_txn_snapshot = self.m._txn_snapshot
            snapshot_calls = {"count": 0}

            def fail_terminal_txn_snapshot(txn_arg):
                snapshot_calls["count"] += 1
                if snapshot_calls["count"] == 1 and txn_arg.get("state") == self.m.TXN_STATE_DONE:
                    raise RuntimeError("terminal-txn-snapshot-failed")
                return real_txn_snapshot(txn_arg)

            with (
                mock.patch.object(
                    self.m,
                    "_txn_snapshot",
                    side_effect=fail_terminal_txn_snapshot,
                ),
                self.assertRaisesRegex(RuntimeError, "terminal-txn-snapshot-failed"),
            ):
                self.m._complete_source_finalization_plan(txn)

            manifest = self.m._load_dataset_manifest(fixture["output_root"])
            entry = manifest["archives"][archive_id]
            saved_txn = self.m._load_latest_txn_for_archive(
                entry,
                fixture["output_root"],
            )

            self.assertEqual(self.m.TXN_STATE_SOURCE_FINALIZED, saved_txn["state"])
            self.assertNotEqual("FAIL_FINALIZE_FAILED", (saved_txn.get("error") or {}).get("type"))
            self.assertEqual("recoverable", entry["state"])
            self.assertEqual("unknown", entry["final_disposition"])
            self.assertIsNone(entry["finalized_at"])

    def test_cleanup_skips_work_root_with_recoverable_txn(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td, manifest_state="recoverable")
            archive = fixture["archive"]
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_EXTRACTED
            self.m._txn_snapshot(txn)
            self.assertFalse(
                self.m._work_root_cleanup_eligible(txn["paths"]["work_root"], fixture["output_root"])
            )

    def test_cleanup_one_transactional_output_dir_runs_gc_before_eligibility_check(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                output=os.path.join(td, "out"),
                success_clean_journal=False,
                fail_clean_journal=True,
            )
            output_dir = os.path.join(args.output, "failed-out")
            archive_path = os.path.join(td, "alpha.zip")
            with open(archive_path, "wb") as f:
                f.write(b"zip")
            self.m._create_dataset_manifest(
                input_root=td,
                output_root=args.output,
                discovered_archives=[
                    {
                        "archive_path": archive_path,
                        "output_dir": output_dir,
                        "volumes": [archive_path],
                        "requested_policy": "direct",
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            txn = self.m._txn_create(
                archive_path=archive_path,
                volumes=[archive_path],
                output_dir=output_dir,
                output_base=args.output,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            self.m._mark_txn_failure_terminal(
                txn,
                final_disposition="failure:asis",
                error={"type": "PLACE_FAILED", "message": "boom", "at": self.m._now_iso()},
            )
            work_root = self.m._work_root(output_dir, args.output)
            calls = []

            def fake_garbage_collect(*gc_args, **gc_kwargs):
                calls.append("gc")

            def fake_cleanup_eligible(*eligible_args, **eligible_kwargs):
                calls.append("eligible")
                return True

            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "_garbage_collect", side_effect=fake_garbage_collect),
                mock.patch.object(self.m, "_work_root_cleanup_eligible", side_effect=fake_cleanup_eligible),
                mock.patch.object(self.m, "safe_rmtree", side_effect=lambda path, debug=False: self.m.shutil.rmtree(path) or True),
            ):
                cleanup_result = self.m._cleanup_one_transactional_output_dir(
                    output_dir,
                    output_base=args.output,
                    args=args,
                    should_clean=True,
                    manifest_terminal=True,
                )

            self.assertTrue(cleanup_result)
            self.assertEqual(["gc", "eligible"], calls)
            self.assertFalse(os.path.exists(work_root))

    def test_cleanup_skips_work_root_with_failed_txn_pending_source_finalization(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td, manifest_state="retryable")
            archive = fixture["archive"]
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_FAILED
            self.m._set_source_finalization_plan(
                txn,
                manifest_state="failed",
                final_disposition="failure:move",
                txn_terminal_state=self.m.TXN_STATE_FAILED,
            )
            self.m._txn_snapshot(txn)

            self.assertFalse(
                self.m._work_root_cleanup_eligible(
                    txn["paths"]["work_root"], fixture["output_root"]
                )
            )

    def test_cleanup_skips_work_root_with_active_orphan_journal(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td, manifest_state="succeeded")
            orphan_txn = self.m._txn_create(
                archive_path=os.path.join(td, "orphan.zip"),
                volumes=[],
                output_dir=os.path.join(fixture["output_root"], "orphan-out"),
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            orphan_txn["state"] = self.m.TXN_STATE_EXTRACTED
            self.m._txn_snapshot(orphan_txn)
            self.assertFalse(
                self.m._work_root_cleanup_eligible(
                    orphan_txn["paths"]["work_root"], fixture["output_root"]
                )
            )

    def test_cleanup_skips_work_root_with_nonrecoverable_aborted_journal(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td, manifest_state="failed")
            archive = fixture["archive"]
            txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_ABORTED
            txn["error"] = {
                "type": "RECOVER_FAILED",
                "message": "resume failed and no recoverable continuation remains",
                "at": self.m._now_iso(),
            }
            self.m._txn_snapshot(txn)

            self.assertFalse(
                self.m._work_root_cleanup_eligible(
                    txn["paths"]["work_root"], fixture["output_root"]
                )
            )

    def test_place_and_finalize_terminal_failure_runs_per_txn_cleanup(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(td, manifest_state="recoverable")
            txn = self.m._txn_create(
                archive_path=fixture["archive"]["archive_path"],
                volumes=fixture["archive"]["volumes"],
                output_dir=fixture["archive"]["output_dir"],
                output_base=fixture["output_root"],
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            txn["state"] = self.m.TXN_STATE_EXTRACTED
            self.m._txn_snapshot(txn)
            staging_root = os.path.join(txn["paths"]["work_root"], "staging", txn["txn_id"])
            incoming_root = os.path.join(txn["paths"]["work_root"], "incoming", txn["txn_id"])
            os.makedirs(txn["paths"]["staging_extracted"], exist_ok=True)
            os.makedirs(txn["paths"]["incoming_dir"], exist_ok=True)
            with open(os.path.join(txn["paths"]["staging_extracted"], "payload.txt"), "w", encoding="utf-8") as f:
                f.write("payload")
            with open(os.path.join(txn["paths"]["incoming_dir"], "payload.txt"), "w", encoding="utf-8") as f:
                f.write("payload")

            args = fixture["args"]
            args.fail_policy = "asis"

            with self.assertRaises(RuntimeError):
                with mock.patch.object(self.m, "_commit_incoming", side_effect=RuntimeError("boom during placing")):
                    self.m._place_and_finalize_txn(txn, args=args, recovery=True)

            self.assertFalse(os.path.exists(staging_root))
            self.assertFalse(os.path.exists(incoming_root))
            with open(txn["paths"]["txn_json"], "r", encoding="utf-8") as f:
                saved = json.load(f)
            self.assertEqual(self.m.TXN_STATE_FAILED, saved["state"])
            self.assertEqual("failed", self.m._load_dataset_manifest(fixture["output_root"])["archives"][fixture["archive_id"]]["state"])

    def test_cleanup_does_not_gc_away_incomplete_failure_move_before_eligibility_check(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                output=os.path.join(td, "out"),
                success_clean_journal=False,
                fail_clean_journal=True,
                fail_policy="move",
                fail_to=os.path.join(td, "failed"),
                keep_journal_days=7,
            )
            output_dir = os.path.join(args.output, "failed-out")
            archive_path = os.path.join(td, "alpha.zip")
            with open(archive_path, "wb") as f:
                f.write(b"zip")
            self.m._create_dataset_manifest(
                input_root=td,
                output_root=args.output,
                discovered_archives=[
                    {
                        "archive_path": archive_path,
                        "output_dir": output_dir,
                        "volumes": [archive_path],
                        "requested_policy": "direct",
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            txn = self.m._txn_create(
                archive_path=archive_path,
                volumes=[archive_path],
                output_dir=output_dir,
                output_base=args.output,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            self.m._set_source_finalization_plan(
                txn,
                manifest_state="failed",
                final_disposition="failure:move",
                txn_terminal_state=self.m.TXN_STATE_FAILED,
            )
            txn["state"] = self.m.TXN_STATE_FAILED
            txn["error"] = {
                "type": "PLACE_FAILED",
                "message": "boom",
                "at": self.m._now_iso(),
            }
            self.m._txn_snapshot(txn)
            self.m._update_dataset_manifest_archive(
                args.output,
                archive_path,
                state="failed",
                last_txn_id=txn["txn_id"],
                final_disposition="failure:move",
                error=txn["error"],
                finalized_at=self.m._now_iso(),
            )
            self._age_txn_journal(txn)
            work_root = txn["paths"]["work_root"]

            with mock.patch.object(self.m, "FileLock", DummyLock):
                cleanup_result = self.m._cleanup_one_transactional_output_dir(
                    output_dir,
                    output_base=args.output,
                    args=args,
                    should_clean=True,
                    manifest_terminal=True,
                )

            self.assertFalse(cleanup_result)
            self.assertTrue(os.path.isdir(work_root))
            self.assertTrue(os.path.exists(txn["paths"]["txn_json"]))

    def test_top_level_work_base_cleanup_failure_prints_warning(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                output=os.path.join(td, "out"),
                success_clean_journal=True,
                fail_clean_journal=False,
            )
            output_dir = os.path.join(args.output, "ok-out")
            archive_path = os.path.join(td, "alpha.zip")
            with open(archive_path, "wb") as f:
                f.write(b"zip")
            self.m._create_dataset_manifest(
                input_root=td,
                output_root=args.output,
                discovered_archives=[
                    {
                        "archive_path": archive_path,
                        "output_dir": output_dir,
                        "volumes": [archive_path],
                        "requested_policy": "direct",
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            txn = self.m._txn_create(
                archive_path=archive_path,
                volumes=[archive_path],
                output_dir=output_dir,
                output_base=args.output,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            self.m._mark_txn_success_terminal(txn, final_disposition="success:asis")

            processor = types.SimpleNamespace(successful_archives=[], failed_archives=[], skipped_archives=[])
            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "safe_rmtree", side_effect=[True, False]),
                mock.patch.object(self.m, "_run_transactional_extract_phase", return_value=None),
                contextlib.redirect_stdout(io.StringIO()) as stdout,
            ):
                self.m._run_transactional(processor, [], args=args)

            self.assertIn(self.m._work_base(args.output), stdout.getvalue())

    def test_top_level_cleanup_skips_work_base_when_orphan_work_root_is_active(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                output=os.path.join(td, "out"),
                success_clean_journal=True,
                fail_clean_journal=False,
            )
            output_dir = os.path.join(args.output, "ok-out")
            orphan_output_dir = os.path.join(args.output, "orphan-out")
            archive_path = os.path.join(td, "alpha.zip")
            with open(archive_path, "wb") as f:
                f.write(b"zip")
            self.m._create_dataset_manifest(
                input_root=td,
                output_root=args.output,
                discovered_archives=[
                    {
                        "archive_path": archive_path,
                        "output_dir": output_dir,
                        "volumes": [archive_path],
                        "requested_policy": "direct",
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            txn = self.m._txn_create(
                archive_path=archive_path,
                volumes=[archive_path],
                output_dir=output_dir,
                output_base=args.output,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            self.m._mark_txn_success_terminal(txn, final_disposition="success:asis")
            orphan_txn = self.m._txn_create(
                archive_path=os.path.join(td, "orphan.zip"),
                volumes=[],
                output_dir=orphan_output_dir,
                output_base=args.output,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            orphan_txn["state"] = self.m.TXN_STATE_EXTRACTED
            self.m._txn_snapshot(orphan_txn)

            processor = types.SimpleNamespace(successful_archives=[], failed_archives=[], skipped_archives=[])
            work_base = self.m._work_base(args.output)
            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "_run_transactional_extract_phase", return_value=None),
            ):
                self.m._run_transactional(processor, [], args=args)

            self.assertTrue(os.path.isdir(work_base))

    def test_run_transactional_preserves_recovery_only_failed_work_root_when_cleaning_current_run_outputs(
        self,
    ):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                threads=1,
                output_lock_timeout_ms=1000,
                output_lock_retry_ms=10,
                keep_journal_days=7,
                success_clean_journal=True,
                fail_clean_journal=False,
                conflict_mode="fail",
            )
            output_base = args.output
            recovery_output_dir = os.path.join(output_base, "stale-failed-out")
            recovery_archive = os.path.join(td, "stale-failed.zip")
            with open(recovery_archive, "wb") as f:
                f.write(b"stale-failed")
            current_archive = os.path.join(td, "new.zip")
            with open(current_archive, "wb") as f:
                f.write(b"new")
            current_output_dir = os.path.join(output_base, "new-out")
            self.m._create_dataset_manifest(
                input_root=td,
                output_root=output_base,
                discovered_archives=[
                    {
                        "archive_path": recovery_archive,
                        "output_dir": recovery_output_dir,
                        "volumes": [recovery_archive],
                        "requested_policy": "direct",
                    },
                    {
                        "archive_path": current_archive,
                        "output_dir": current_output_dir,
                        "volumes": [current_archive],
                        "requested_policy": "direct",
                    },
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            recovery_txn = self.m._txn_create(
                archive_path=recovery_archive,
                volumes=[],
                output_dir=recovery_output_dir,
                output_base=output_base,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            recovery_txn["state"] = self.m.TXN_STATE_FAILED
            recovery_txn["error"] = {
                "type": "PLACE_FAILED",
                "message": "stale failure",
                "at": self.m._now_iso(),
            }
            self.m._txn_snapshot(recovery_txn)

            def fake_extract(processor, archive_path, *, args, output_base):
                return {
                    "kind": "txn",
                    "txn": self._make_txn(
                        archive_path,
                        output_dir=current_output_dir,
                        output_base=output_base,
                    ),
                }

            def fake_finalize_one_txn(txn, *, processor, args, output_base):
                processor.successful_archives.append(txn["archive_path"])
                return True

            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            recovery_work_root = self.m._work_root(recovery_output_dir, output_base)

            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(self.m, "_extract_phase", side_effect=fake_extract),
                mock.patch.object(
                    self.m,
                    "_finalize_one_txn",
                    side_effect=fake_finalize_one_txn,
                ),
            ):
                self.m._run_transactional(processor, [current_archive], args=args)

            self.assertEqual([current_archive], processor.successful_archives)
            self.assertTrue(os.path.isdir(recovery_work_root))
            with open(recovery_txn["paths"]["txn_json"], "r", encoding="utf-8") as f:
                saved = json.load(f)
            self.assertEqual(self.m.TXN_STATE_FAILED, saved["state"])

    def test_workdir_not_removed_while_dataset_active(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                threads=1,
                output_lock_timeout_ms=1000,
                output_lock_retry_ms=10,
                keep_journal_days=7,
                success_clean_journal=True,
                fail_clean_journal=False,
                conflict_mode="fail",
            )
            output_base = args.output
            current_archive = os.path.join(td, "current.zip")
            recoverable_archive = os.path.join(td, "recoverable.zip")
            for archive_path, payload in (
                (current_archive, b"current"),
                (recoverable_archive, b"recoverable"),
            ):
                with open(archive_path, "wb") as f:
                    f.write(payload)

            current_output_dir = os.path.join(output_base, "current-out")
            recoverable_output_dir = os.path.join(output_base, "recoverable-out")
            self.m._create_dataset_manifest(
                input_root=td,
                output_root=output_base,
                discovered_archives=[
                    {
                        "archive_path": recoverable_archive,
                        "output_dir": recoverable_output_dir,
                        "volumes": [recoverable_archive],
                        "requested_policy": "direct",
                    },
                    {
                        "archive_path": current_archive,
                        "output_dir": current_output_dir,
                        "volumes": [current_archive],
                        "requested_policy": "direct",
                    },
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            recoverable_txn = self.m._txn_create(
                archive_path=recoverable_archive,
                volumes=[recoverable_archive],
                output_dir=recoverable_output_dir,
                output_base=output_base,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            recoverable_txn["state"] = self.m.TXN_STATE_EXTRACTED
            self.m._txn_snapshot(recoverable_txn)
            self.m._update_dataset_manifest_archive(
                output_base,
                recoverable_archive,
                state="recoverable",
                last_txn_id=recoverable_txn["txn_id"],
            )

            current_work_root = self.m._work_root(current_output_dir, output_base)
            os.makedirs(
                os.path.join(current_work_root, "journal", "keep"), exist_ok=True
            )
            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )

            def fake_extract(processor, archive_path, *, args, output_base):
                return self._make_txn_result(
                    archive_path,
                    output_dir=current_output_dir,
                    output_base=output_base,
                )

            def fake_finalize_one_txn(txn, *, processor, args, output_base):
                self.m._update_dataset_manifest_archive(
                    output_base,
                    txn["archive_path"],
                    state="succeeded",
                    last_txn_id=txn["txn_id"],
                    final_disposition="success:asis",
                    error=None,
                    finalized_at=self.m._now_iso(),
                )
                processor.successful_archives.append(txn["archive_path"])
                return True

            with (
                mock.patch.object(self.m, "_recover_all_outputs"),
                mock.patch.object(self.m, "_extract_phase", side_effect=fake_extract),
                mock.patch.object(
                    self.m,
                    "_finalize_one_txn",
                    side_effect=fake_finalize_one_txn,
                ),
                mock.patch.object(self.m, "_garbage_collect"),
                mock.patch.object(self.m, "FileLock", DummyLock),
            ):
                self.m._run_transactional(processor, [current_archive], args=args)

            manifest = self.m._load_dataset_manifest(output_base)
            self.assertEqual("active", manifest["status"])
            self.assertTrue(os.path.isdir(self.m._work_base(output_base)))
            self.assertTrue(os.path.isdir(current_work_root))

    def test_workdir_removed_when_dataset_terminal_and_cleanup_enabled(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                threads=1,
                output_lock_timeout_ms=1000,
                output_lock_retry_ms=10,
                keep_journal_days=7,
                success_clean_journal=True,
                fail_clean_journal=False,
                conflict_mode="fail",
            )
            output_base = args.output
            historical_archive = os.path.join(td, "historical.zip")
            current_archive = os.path.join(td, "current.zip")
            for archive_path, payload in (
                (historical_archive, b"historical"),
                (current_archive, b"current"),
            ):
                with open(archive_path, "wb") as f:
                    f.write(payload)

            historical_output_dir = os.path.join(output_base, "historical-out")
            current_output_dir = os.path.join(output_base, "current-out")
            self.m._create_dataset_manifest(
                input_root=td,
                output_root=output_base,
                discovered_archives=[
                    {
                        "archive_path": historical_archive,
                        "output_dir": historical_output_dir,
                        "volumes": [historical_archive],
                        "requested_policy": "direct",
                    },
                    {
                        "archive_path": current_archive,
                        "output_dir": current_output_dir,
                        "volumes": [current_archive],
                        "requested_policy": "direct",
                    },
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            historical_txn = self.m._txn_create(
                archive_path=historical_archive,
                volumes=[historical_archive],
                output_dir=historical_output_dir,
                output_base=output_base,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            historical_txn["state"] = self.m.TXN_STATE_DONE
            self.m._txn_snapshot(historical_txn)
            self.m._update_dataset_manifest_archive(
                output_base,
                historical_archive,
                state="succeeded",
                last_txn_id=historical_txn["txn_id"],
                final_disposition="success:asis",
                error=None,
                finalized_at=self.m._now_iso(),
            )

            historical_work_root = self.m._work_root(historical_output_dir, output_base)
            current_work_root = self.m._work_root(current_output_dir, output_base)
            os.makedirs(
                os.path.join(historical_work_root, "journal", "keep"), exist_ok=True
            )
            os.makedirs(
                os.path.join(current_work_root, "journal", "keep"), exist_ok=True
            )
            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )

            def fake_extract(processor, archive_path, *, args, output_base):
                return self._make_txn_result(
                    archive_path,
                    output_dir=current_output_dir,
                    output_base=output_base,
                )

            def fake_finalize_one_txn(txn, *, processor, args, output_base):
                self.m._update_dataset_manifest_archive(
                    output_base,
                    txn["archive_path"],
                    state="succeeded",
                    last_txn_id=txn["txn_id"],
                    final_disposition="success:asis",
                    error=None,
                    finalized_at=self.m._now_iso(),
                )
                processor.successful_archives.append(txn["archive_path"])
                return True

            with (
                mock.patch.object(self.m, "_recover_all_outputs"),
                mock.patch.object(self.m, "_extract_phase", side_effect=fake_extract),
                mock.patch.object(
                    self.m,
                    "_finalize_one_txn",
                    side_effect=fake_finalize_one_txn,
                ),
                mock.patch.object(self.m, "_garbage_collect"),
                mock.patch.object(self.m, "FileLock", DummyLock),
            ):
                self.m._run_transactional(processor, [current_archive], args=args)

            self.assertFalse(os.path.exists(historical_work_root))
            self.assertFalse(os.path.exists(current_work_root))
            self.assertFalse(os.path.exists(self.m._work_base(output_base)))

    def test_workdir_not_removed_when_cleanup_lock_fails(self):
        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                threads=1,
                output_lock_timeout_ms=1000,
                output_lock_retry_ms=10,
                keep_journal_days=7,
                success_clean_journal=True,
                fail_clean_journal=False,
                conflict_mode="fail",
            )
            output_base = args.output
            archive_path = os.path.join(td, "done.zip")
            with open(archive_path, "wb") as f:
                f.write(b"done")

            output_dir = os.path.join(output_base, "done-out")
            self.m._create_dataset_manifest(
                input_root=td,
                output_root=output_base,
                discovered_archives=[
                    {
                        "archive_path": archive_path,
                        "output_dir": output_dir,
                        "volumes": [archive_path],
                        "requested_policy": "direct",
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )
            self.m._update_dataset_manifest_archive(
                output_base,
                archive_path,
                state="succeeded",
                final_disposition="success:asis",
                error=None,
                finalized_at=self.m._now_iso(),
            )

            work_base = self.m._work_base(output_base)
            work_root = self.m._work_root(output_dir, output_base)
            cleanup_lock_path = self.m._output_lock_path(output_dir, output_base)
            os.makedirs(os.path.join(work_root, "journal", "keep"), exist_ok=True)

            class FailingCleanupLock:
                def __init__(self, path, timeout_ms, retry_ms, debug):
                    self.path = path

                def __enter__(self):
                    if self.path == cleanup_lock_path:
                        raise TimeoutError(f"Could not acquire lock: {self.path}")
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )

            with mock.patch.object(self.m, "FileLock", FailingCleanupLock):
                self.m._run_transactional(processor, [], args=args)

            self.assertFalse(os.path.isdir(work_base))
            self.assertFalse(os.path.isdir(work_root))

    def test_run_transactional_uses_selected_last_txn_id_for_recovery(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            fixture = self._make_single_archive_manifest_fixture(
                td, manifest_state="recoverable"
            )
            archive = fixture["archive"]
            output_root = fixture["output_root"]

            selected_txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=output_root,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            selected_txn["state"] = self.m.TXN_STATE_EXTRACTED
            self.m._txn_snapshot(selected_txn)

            newer_txn = self.m._txn_create(
                archive_path=archive["archive_path"],
                volumes=archive["volumes"],
                output_dir=archive["output_dir"],
                output_base=output_root,
                policy="direct",
                wal_fsync_every=1,
                snapshot_every=1,
                durability_enabled=False,
            )
            newer_txn["state"] = self.m.TXN_STATE_DONE
            self.m._txn_snapshot(newer_txn)

            self.m._update_dataset_manifest_archive(
                output_root,
                archive["archive_path"],
                state="recoverable",
                last_txn_id=selected_txn["txn_id"],
                error=None,
            )

            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            observed = {}

            def fake_recover_output_dir(
                output_dir,
                *,
                args,
                allowed_archive_paths=None,
                failed_archives=None,
                successful_archives=None,
            ):
                work_root = self.m._work_root(output_dir, output_root)
                journal_root = os.path.join(work_root, "journal")
                archive_paths = sorted(
                    os.path.abspath(path) for path in (allowed_archive_paths or [])
                )
                selected = []
                for archive_path in archive_paths:
                    txn = self.m._load_latest_txn_by_archive_path(
                        archive_path,
                        output_dir,
                        output_root,
                    )
                    if txn is not None:
                        selected.append(txn["txn_id"])
                observed["selected_txn_ids"] = selected
                observed["journal_ids"] = sorted(os.listdir(journal_root))

            with (
                mock.patch.object(self.m, "FileLock", DummyLock),
                mock.patch.object(
                    self.m,
                    "_recover_output_dir",
                    side_effect=fake_recover_output_dir,
                ),
                mock.patch.object(self.m, "_run_transactional_extract_phase"),
                mock.patch.object(self.m, "_garbage_collect"),
            ):
                self.m._run_transactional(processor, [], args=fixture["args"])

            self.assertEqual(
                [selected_txn["txn_id"]],
                observed.get("selected_txn_ids"),
            )
            self.assertEqual(
                sorted([selected_txn["txn_id"], newer_txn["txn_id"]]),
                observed.get("journal_ids"),
            )

    def test_terminal_noop_resume_runs_gc_for_manifest_output_dirs_when_cleanup_disabled(
        self,
    ):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            input_root = os.path.join(td, "input")
            output_root = os.path.join(td, "output")
            os.makedirs(input_root)
            os.makedirs(output_root)

            args = self._make_processing_args(
                input_root,
                output=output_root,
                threads=1,
                keep_journal_days=7,
                success_clean_journal=False,
                fail_clean_journal=False,
            )
            discovered = self._make_discovered_archives(
                input_root,
                output_root,
                [os.path.join("one", "alpha.zip"), os.path.join("two", "beta.zip")],
            )
            self.m._create_dataset_manifest(
                input_root=input_root,
                output_root=output_root,
                discovered_archives=discovered,
                command_fingerprint=self.m._build_command_fingerprint(args),
            )

            txns = []
            for item in discovered:
                txn = self.m._txn_create(
                    archive_path=item["archive_path"],
                    volumes=item["volumes"],
                    output_dir=item["output_dir"],
                    output_base=output_root,
                    policy=args.decompress_policy,
                    wal_fsync_every=1,
                    snapshot_every=1,
                    durability_enabled=False,
                )
                txn["state"] = self.m.TXN_STATE_DONE
                self.m._txn_snapshot(txn)
                self.m._update_dataset_manifest_archive(
                    output_root,
                    item["archive_path"],
                    state="succeeded",
                    last_txn_id=txn["txn_id"],
                    final_disposition="success:asis",
                    error=None,
                    finalized_at=self.m._now_iso(),
                )
                self._age_txn_journal(txn)
                txns.append(txn)

            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )

            with mock.patch.object(self.m, "FileLock", DummyLock):
                self.m._run_transactional(processor, [], args=args)

            self.assertFalse(os.path.isdir(self.m._work_base(output_root)))
            for txn in txns:
                self.assertFalse(os.path.exists(txn["paths"]["journal_dir"]))

    def test_workdir_retained_when_cleanup_disabled(self):
        class DummyLock:
            def __init__(self, path, timeout_ms, retry_ms, debug):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                threads=1,
                output_lock_timeout_ms=1000,
                output_lock_retry_ms=10,
                keep_journal_days=7,
                success_clean_journal=False,
                fail_clean_journal=False,
                conflict_mode="fail",
            )
            output_base = args.output
            current_archive = os.path.join(td, "current.zip")
            with open(current_archive, "wb") as f:
                f.write(b"current")

            current_output_dir = os.path.join(output_base, "current-out")
            self.m._create_dataset_manifest(
                input_root=td,
                output_root=output_base,
                discovered_archives=[
                    {
                        "archive_path": current_archive,
                        "output_dir": current_output_dir,
                        "volumes": [current_archive],
                        "requested_policy": "direct",
                    }
                ],
                command_fingerprint=self.m._build_command_fingerprint(args),
            )

            current_work_root = self.m._work_root(current_output_dir, output_base)
            os.makedirs(
                os.path.join(current_work_root, "journal", "keep"), exist_ok=True
            )
            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )

            def fake_extract(processor, archive_path, *, args, output_base):
                return self._make_txn_result(
                    archive_path,
                    output_dir=current_output_dir,
                    output_base=output_base,
                )

            def fake_finalize_one_txn(txn, *, processor, args, output_base):
                self.m._update_dataset_manifest_archive(
                    output_base,
                    txn["archive_path"],
                    state="succeeded",
                    last_txn_id=txn["txn_id"],
                    final_disposition="success:asis",
                    error=None,
                    finalized_at=self.m._now_iso(),
                )
                processor.successful_archives.append(txn["archive_path"])
                return True

            with (
                mock.patch.object(self.m, "_recover_all_outputs"),
                mock.patch.object(self.m, "_extract_phase", side_effect=fake_extract),
                mock.patch.object(
                    self.m,
                    "_finalize_one_txn",
                    side_effect=fake_finalize_one_txn,
                ),
                mock.patch.object(self.m, "_garbage_collect"),
                mock.patch.object(self.m, "FileLock", DummyLock),
            ):
                self.m._run_transactional(processor, [current_archive], args=args)

            manifest = self.m._load_dataset_manifest(output_base)
            self.assertEqual("completed", manifest["status"])
            self.assertTrue(os.path.isdir(current_work_root))
            self.assertTrue(os.path.isdir(self.m._work_base(output_base)))

    def test_run_transactional_garbage_collects_touched_output_dirs_under_lock(self):
        gc_calls = []
        work_root_cleanup_calls = []
        active_locks = set()

        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                threads=1,
                output_lock_timeout_ms=1000,
                output_lock_retry_ms=10,
                keep_journal_days=7,
                success_clean_journal=False,
                fail_clean_journal=True,
                conflict_mode="fail",
            )
            output_base = args.output
            success_archive = os.path.join(td, "ok.zip")
            failed_archive = os.path.join(td, "fail.zip")
            success_output_dir = os.path.join(output_base, "ok-out")
            failed_output_dir = os.path.join(output_base, "fail-out")
            expected_lock_paths = {
                success_output_dir: self.m._output_lock_path(
                    success_output_dir, output_base
                ),
                failed_output_dir: self.m._output_lock_path(
                    failed_output_dir, output_base
                ),
            }
            work_root_to_output_dir = {
                self.m._work_root(success_output_dir, output_base): success_output_dir,
                self.m._work_root(failed_output_dir, output_base): failed_output_dir,
            }

            def fake_extract(processor, archive_path, *, args, output_base):
                name = os.path.basename(archive_path)
                if name == "ok.zip":
                    return {
                        "kind": "txn",
                        "txn": self._make_txn(
                            archive_path,
                            output_dir=success_output_dir,
                            output_base=output_base,
                        ),
                    }
                if name == "fail.zip":
                    return {
                        "kind": "txn_failed",
                        "archive_path": archive_path,
                        "txn": self._make_txn(
                            archive_path,
                            output_dir=failed_output_dir,
                            output_base=output_base,
                        ),
                    }
                self.fail(f"unexpected archive: {archive_path}")

            def fake_finalize_one_txn(txn, *, processor, args, output_base):
                processor.successful_archives.append(txn["archive_path"])
                return True

            class FakeLock:
                def __init__(self, path, timeout_ms, retry_ms, debug):
                    self.path = path

                def __enter__(self):
                    active_locks.add(self.path)
                    return self

                def __exit__(self, exc_type, exc, tb):
                    active_locks.remove(self.path)
                    return False

            def fake_garbage_collect(output_dir, *, output_base, keep_journal_days):
                gc_calls.append((output_dir, set(active_locks)))

            def fake_rmtree(path, debug=False):
                output_dir = work_root_to_output_dir.get(path)
                if output_dir is not None:
                    work_root_cleanup_calls.append((path, set(active_locks)))
                return True

            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            archives = [success_archive, failed_archive]
            for archive in archives:
                with open(archive, "wb") as f:
                    f.write(b"test")

            with (
                mock.patch.object(self.m, "_recover_all_outputs"),
                mock.patch.object(self.m, "_extract_phase", side_effect=fake_extract),
                mock.patch.object(
                    self.m, "_finalize_one_txn", side_effect=fake_finalize_one_txn
                ),
                mock.patch.object(
                    self.m, "_garbage_collect", side_effect=fake_garbage_collect
                ),
                mock.patch.object(self.m, "safe_rmtree", side_effect=fake_rmtree),
                mock.patch.object(self.m, "FileLock", FakeLock),
            ):
                self.m._run_transactional(processor, archives, args=args)

        self.assertEqual([success_archive], processor.successful_archives)
        self.assertEqual([failed_archive], processor.failed_archives)
        self.assertCountEqual(
            [
                (success_output_dir, {expected_lock_paths[success_output_dir]}),
                (failed_output_dir, {expected_lock_paths[failed_output_dir]}),
            ],
            gc_calls,
        )
        self.assertEqual([], work_root_cleanup_calls)

    def test_run_transactional_cleanup_lock_timeout_stays_best_effort(self):
        gc_calls = []

        with tempfile.TemporaryDirectory() as td:
            args = self._make_processing_args(
                td,
                threads=1,
                output_lock_timeout_ms=1000,
                output_lock_retry_ms=10,
                keep_journal_days=7,
                success_clean_journal=False,
                fail_clean_journal=False,
                conflict_mode="fail",
            )
            output_base = args.output
            timeout_archive = os.path.join(td, "timeout.zip")
            success_archive = os.path.join(td, "ok.zip")
            timeout_output_dir = os.path.join(output_base, "a-timeout-out")
            success_output_dir = os.path.join(output_base, "z-ok-out")
            timeout_lock_path = self.m._output_lock_path(timeout_output_dir, output_base)

            def fake_extract(processor, archive_path, *, args, output_base):
                if archive_path == timeout_archive:
                    return {
                        "kind": "txn",
                        "txn": self._make_txn(
                            archive_path,
                            output_dir=timeout_output_dir,
                            output_base=output_base,
                        ),
                    }
                if archive_path == success_archive:
                    return {
                        "kind": "txn",
                        "txn": self._make_txn(
                            archive_path,
                            output_dir=success_output_dir,
                            output_base=output_base,
                        ),
                    }
                self.fail(f"unexpected archive: {archive_path}")

            class FakeLock:
                def __init__(self, path, timeout_ms, retry_ms, debug):
                    self.path = path

                def __enter__(self):
                    if self.path == timeout_lock_path:
                        raise TimeoutError(f"Could not acquire lock: {self.path}")
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

            def fake_garbage_collect(output_dir, *, output_base, keep_journal_days):
                gc_calls.append(output_dir)

            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            for archive in (timeout_archive, success_archive):
                with open(archive, "wb") as f:
                    f.write(b"test")

            with (
                mock.patch.object(self.m, "_recover_all_outputs"),
                mock.patch.object(self.m, "_extract_phase", side_effect=fake_extract),
                mock.patch.object(self.m, "_place_and_finalize_txn", return_value=None),
                mock.patch.object(
                    self.m, "_garbage_collect", side_effect=fake_garbage_collect
                ),
                mock.patch.object(self.m, "FileLock", FakeLock),
            ):
                result = self.m._run_transactional(
                    processor,
                    [timeout_archive, success_archive],
                    args=args,
                )

        self.assertIsNone(result)
        self.assertEqual([timeout_archive], processor.failed_archives)
        self.assertEqual([success_archive], processor.successful_archives)
        self.assertEqual([success_output_dir], gc_calls)

    def test_find_archives_recognizes_single_zip(self):
        with tempfile.TemporaryDirectory() as td:
            archive = os.path.join(td, "a.zip")
            with zipfile.ZipFile(archive, "w") as z:
                z.writestr("hello.txt", "hi")

            args = SimpleNamespace(
                verbose=False,
                password=None,
                password_file=None,
                traditional_zip_policy="decode-auto",
            )
            processor = self.m.ArchiveProcessor(args)
            found = processor.find_archives(td)
            self.assertEqual([os.path.abspath(archive)], found)

    def test_is_archive_single_or_volume_recognizes_single_rar(self):
        with tempfile.TemporaryDirectory() as td:
            archive = os.path.join(td, "a.rar")
            with open(archive, "wb") as f:
                f.write(b"")  # extension-based detection

            args = SimpleNamespace(
                verbose=False,
                password=None,
                password_file=None,
                traditional_zip_policy="decode-auto",
            )
            processor = self.m.ArchiveProcessor(args)
            self.assertEqual("single", processor.is_archive_single_or_volume(archive))

    def test_rar_part_with_part_exe_not_treated_as_single(self):
        with tempfile.TemporaryDirectory() as td:
            base = os.path.join(td, "a")
            exe = base + ".part1.exe"
            part2 = base + ".part2.rar"
            for p in (exe, part2):
                with open(p, "wb") as f:
                    f.write(b"")

            args = SimpleNamespace(
                verbose=False,
                password=None,
                password_file=None,
                traditional_zip_policy="decode-auto",
            )
            processor = self.m.ArchiveProcessor(args)
            kind = processor.is_archive_single_or_volume(part2)
            self.assertNotEqual("single", kind)

    def test_get_all_volumes_zip_accepts_variable_digits(self):
        with tempfile.TemporaryDirectory() as td:
            base = os.path.join(td, "a")
            main = base + ".zip"
            part1 = base + ".z01"
            part2 = base + ".z001"
            for p in (main, part1, part2):
                with open(p, "wb") as f:
                    f.write(b"")

            args = SimpleNamespace(
                verbose=False,
                password=None,
                password_file=None,
                traditional_zip_policy="decode-auto",
            )
            processor = self.m.ArchiveProcessor(args)
            vols = processor.get_all_volumes(part1)
            self.assertEqual(
                {os.path.abspath(p) for p in (main, part1, part2)}, set(vols)
            )

    def test_get_all_volumes_7z_accepts_short_digits(self):
        with tempfile.TemporaryDirectory() as td:
            base = os.path.join(td, "a")
            part1 = base + ".7z.1"
            part2 = base + ".7z.01"
            part3 = base + ".7z.001"
            for p in (part1, part2, part3):
                with open(p, "wb") as f:
                    f.write(b"")

            args = SimpleNamespace(
                verbose=False,
                password=None,
                password_file=None,
                traditional_zip_policy="decode-auto",
            )
            processor = self.m.ArchiveProcessor(args)
            vols = processor.get_all_volumes(part2)
            self.assertEqual(
                {os.path.abspath(p) for p in (part1, part2, part3)}, set(vols)
            )

    def test_get_all_volumes_rar4_accepts_variable_digits(self):
        with tempfile.TemporaryDirectory() as td:
            base = os.path.join(td, "a")
            main = base + ".rar"
            part1 = base + ".r0"
            part2 = base + ".r00"
            part3 = base + ".r000"
            for p in (main, part1, part2, part3):
                with open(p, "wb") as f:
                    f.write(b"")

            args = SimpleNamespace(
                verbose=False,
                password=None,
                password_file=None,
                traditional_zip_policy="decode-auto",
            )
            processor = self.m.ArchiveProcessor(args)
            vols = processor.get_all_volumes(part2)
            self.assertEqual(
                {os.path.abspath(p) for p in (main, part1, part2, part3)}, set(vols)
            )

    def test_exe_split_volume_detection(self):
        with tempfile.TemporaryDirectory() as td:
            base = os.path.join(td, "a")
            exe = base + ".exe"
            v1 = base + ".exe.001"
            v2 = base + ".exe.002"

            # Without base .exe, split parts shouldn't be treated as volume.
            for p in (v1, v2):
                with open(p, "wb") as f:
                    f.write(b"")

            args = SimpleNamespace(
                verbose=False,
                password=None,
                password_file=None,
                traditional_zip_policy="decode-auto",
            )
            processor = self.m.ArchiveProcessor(args)
            self.assertEqual("notarchive", processor.is_archive_single_or_volume(v1))

            # With base .exe present, .exe.001 is main volume, others are secondary.
            with open(exe, "wb") as f:
                f.write(b"")  # presence is enough for classifier
            self.assertEqual("volume", processor.is_archive_single_or_volume(v1))
            self.assertTrue(processor.is_main_volume(v1))
            self.assertTrue(processor.is_secondary_volume(v2))

            # Base name normalization should strip .exe.NNN
            self.assertEqual("a", self.m.get_archive_base_name(v1))

    def test_find_archives_recognizes_tar_family_suffixes(self):
        names = [
            "a.tar",
            "b.tar.gz",
            "c.tgz",
            "d.tar.bz2",
            "e.tbz2",
            "f.tar.xz",
            "g.txz",
            "H.TAR",
            "I.TGZ",
            "J.Tar.Xz",
        ]

        with tempfile.TemporaryDirectory() as td:
            for name in names + ["ignore.txt"]:
                with open(os.path.join(td, name), "wb") as f:
                    f.write(b"")

            processor = self.m.ArchiveProcessor(self._make_processor_args())
            found = {os.path.basename(path) for path in processor.find_archives(td)}

        self.assertEqual(set(names), found)

    def test_get_archive_base_name_normalizes_tar_family(self):
        cases = {
            "a.tar": "a",
            "a.tar.gz": "a",
            "a.tgz": "a",
            "a.tar.bz2": "a",
            "a.tbz2": "a",
            "a.tar.xz": "a",
            "a.txz": "a",
            "A.TAR.GZ": "A",
        }

        for archive_name, expected in cases.items():
            with self.subTest(archive_name=archive_name):
                self.assertEqual(expected, self.m.get_archive_base_name(archive_name))

    def test_is_archive_single_or_volume_recognizes_tar_family_as_single(self):
        names = [
            "a.tar",
            "b.tar.gz",
            "c.tgz",
            "d.tar.bz2",
            "e.tbz2",
            "f.tar.xz",
            "g.txz",
            "H.TAR",
            "I.TGZ",
            "J.Tar.Xz",
        ]

        with tempfile.TemporaryDirectory() as td:
            processor = self.m.ArchiveProcessor(self._make_processor_args())
            for name in names:
                path = os.path.join(td, name)
                with open(path, "wb") as f:
                    f.write(b"")
                with self.subTest(path=path):
                    self.assertEqual(
                        "single", processor.is_archive_single_or_volume(path)
                    )

    def test_parse_archive_filename_understands_tar_double_suffixes(self):
        cases = {
            "a.tar.gz": {
                "base_filename": "a",
                "file_ext": "gz",
                "file_ext_extend": "tar",
            },
            "a.tar.bz2": {
                "base_filename": "a",
                "file_ext": "bz2",
                "file_ext_extend": "tar",
            },
            "a.tar.xz": {
                "base_filename": "a",
                "file_ext": "xz",
                "file_ext_extend": "tar",
            },
            "a.tgz": {
                "base_filename": "a",
                "file_ext": "tgz",
                "file_ext_extend": "",
            },
        }

        for filename, expected in cases.items():
            with self.subTest(filename=filename):
                self.assertEqual(expected, self.m.parse_archive_filename(filename))

    def test_validate_args_sets_skip_tar_default_false(self):
        processor = self.m.ArchiveProcessor(self._make_processor_args())
        self.assertFalse(processor.args.skip_tar)

    def test_should_skip_single_archive_honors_skip_tar_only_for_tar_family(self):
        with tempfile.TemporaryDirectory() as td:
            tar_path = os.path.join(td, "a.tar.gz")
            zip_path = os.path.join(td, "a.zip")
            for path in (tar_path, zip_path):
                with open(path, "wb") as f:
                    f.write(b"")

            processor = self.m.ArchiveProcessor(
                self._make_processor_args(skip_tar=True)
            )

            self.assertEqual(
                (True, "单个TAR文件被跳过 (--skip-tar)"),
                processor._should_skip_single_archive(tar_path),
            )
            self.assertEqual(
                (False, ""), processor._should_skip_single_archive(zip_path)
            )

    def test_get_all_volumes_returns_single_path_for_tar_family(self):
        names = [
            "a.tar",
            "b.tar.gz",
            "c.tgz",
            "d.tar.bz2",
            "e.tbz2",
            "f.tar.xz",
            "g.txz",
        ]

        with tempfile.TemporaryDirectory() as td:
            processor = self.m.ArchiveProcessor(self._make_processor_args())
            for name in names:
                path = os.path.join(td, name)
                with open(path, "wb") as f:
                    f.write(b"")
                with self.subTest(path=path):
                    self.assertEqual([path], processor.get_all_volumes(path))

    def test_process_archive_tar_skips_encryption_probe(self):
        with tempfile.TemporaryDirectory() as td:
            tar_path = os.path.join(td, "a.tar.gz")
            zip_path = os.path.join(td, "a.zip")
            password_file = os.path.join(td, "passwords.txt")
            for path in (tar_path, zip_path):
                with open(path, "wb") as f:
                    f.write(b"")
            with open(password_file, "w", encoding="utf-8") as f:
                f.write("secret\n")

            tar_args = self._make_processing_args(td, password_file=password_file)
            tar_processor = self.m.ArchiveProcessor(tar_args)
            with (
                mock.patch.object(self.m, "is_zip_format", return_value=False),
                mock.patch.object(tar_processor, "apply_decompress_policy"),
                mock.patch.object(self.m, "try_extract", return_value=True),
                mock.patch.object(
                    self.m, "validate_extracted_tree", return_value=(True, "")
                ),
                mock.patch.object(
                    self.m, "count_items_in_dir", side_effect=[(1, 0), (0, 0)]
                ),
                mock.patch.object(self.m, "clean_temp_dir"),
                mock.patch.object(
                    self.m, "check_encryption", return_value="plain"
                ) as tar_check_encryption,
            ):
                self.assertTrue(tar_processor.process_archive(tar_path))
                tar_check_encryption.assert_not_called()

            zip_args = self._make_processing_args(td, password_file=password_file)
            zip_processor = self.m.ArchiveProcessor(zip_args)
            with (
                mock.patch.object(self.m, "is_zip_format", return_value=False),
                mock.patch.object(zip_processor, "apply_decompress_policy"),
                mock.patch.object(self.m, "try_extract", return_value=True),
                mock.patch.object(
                    self.m, "validate_extracted_tree", return_value=(True, "")
                ),
                mock.patch.object(
                    self.m, "count_items_in_dir", side_effect=[(1, 0), (0, 0)]
                ),
                mock.patch.object(self.m, "clean_temp_dir"),
                mock.patch.object(
                    self.m, "check_encryption", return_value="plain"
                ) as zip_check_encryption,
            ):
                self.assertTrue(zip_processor.process_archive(zip_path))
                zip_check_encryption.assert_called_once_with(os.path.abspath(zip_path))

    def test_txn_extract_tar_skips_encryption_probe(self):
        with tempfile.TemporaryDirectory() as td:
            tar_path = os.path.join(td, "a.tar.gz")
            zip_path = os.path.join(td, "a.zip")
            password_file = os.path.join(td, "passwords.txt")
            for path in (tar_path, zip_path):
                with open(path, "wb") as f:
                    f.write(b"")
            with open(password_file, "w", encoding="utf-8") as f:
                f.write("secret\n")

            tar_args = self._make_processing_args(td, password_file=password_file)
            tar_processor = self.m.ArchiveProcessor(tar_args)
            with (
                mock.patch.object(self.m, "is_zip_format", return_value=False),
                mock.patch.object(self.m, "_validate_environment_for_output_dir"),
                mock.patch.object(self.m, "try_extract", return_value=True),
                mock.patch.object(
                    self.m, "validate_extracted_tree", return_value=(True, "")
                ),
                mock.patch.object(self.m, "count_items_in_dir", return_value=(1, 0)),
                mock.patch.object(
                    self.m, "check_encryption", return_value="plain"
                ) as tar_check_encryption,
            ):
                result = self.m._extract_phase(
                    tar_processor,
                    tar_path,
                    args=tar_args,
                    output_base=tar_args.output,
                )
                self.assertEqual("txn", result["kind"])
                tar_check_encryption.assert_not_called()

            zip_args = self._make_processing_args(td, password_file=password_file)
            zip_processor = self.m.ArchiveProcessor(zip_args)
            with (
                mock.patch.object(self.m, "is_zip_format", return_value=False),
                mock.patch.object(self.m, "_validate_environment_for_output_dir"),
                mock.patch.object(self.m, "try_extract", return_value=True),
                mock.patch.object(
                    self.m, "validate_extracted_tree", return_value=(True, "")
                ),
                mock.patch.object(self.m, "count_items_in_dir", return_value=(1, 0)),
                mock.patch.object(
                    self.m, "check_encryption", return_value="plain"
                ) as zip_check_encryption,
            ):
                result = self.m._extract_phase(
                    zip_processor,
                    zip_path,
                    args=zip_args,
                    output_base=zip_args.output,
                )
                self.assertEqual("txn", result["kind"])
                zip_check_encryption.assert_called_once_with(os.path.abspath(zip_path))

    def _write_minimal_tar(self, path):
        data = bytearray(512)
        data[257:263] = b"ustar\x00"
        with open(path, "wb") as f:
            f.write(data)

    def test_try_extract_tar_plain_uses_one_stage_7z(self):
        with tempfile.TemporaryDirectory() as td:
            archive_path = os.path.join(td, "a.tar")
            with open(archive_path, "wb") as f:
                f.write(b"")
            tmp_dir = os.path.join(td, "tmp")

            calls = []

            def _fake_run(cmd, **kwargs):
                calls.append(cmd)
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            with mock.patch.object(
                self.m, "safe_subprocess_run", side_effect=_fake_run
            ):
                ok = self.m.try_extract(archive_path, None, tmp_dir)

            self.assertTrue(ok)
            self.assertEqual(1, len(calls))
            out_dir = next(
                t for t in calls[0] if isinstance(t, str) and t.startswith("-o")
            )[2:]
            self.assertEqual(tmp_dir, out_dir)

    def test_try_extract_tarball_uses_two_stage_7z_and_cleans_stage(self):
        with tempfile.TemporaryDirectory() as td:
            archive_path = os.path.join(td, "a.tar.gz")
            with open(archive_path, "wb") as f:
                f.write(b"")
            tmp_dir = os.path.join(td, "tmp")

            calls = []

            def _fake_run(cmd, **kwargs):
                calls.append(cmd)
                out_arg = next(
                    (t for t in cmd if isinstance(t, str) and t.startswith("-o")), None
                )
                if out_arg and len(calls) == 1:
                    out_dir = out_arg[2:]
                    self._write_minimal_tar(os.path.join(out_dir, "inner.tar"))
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            with (
                mock.patch.object(self.m, "safe_subprocess_run", side_effect=_fake_run),
                mock.patch.object(
                    self.m, "should_use_rar_extractor", return_value=True
                ),
            ):
                ok = self.m.try_extract(
                    archive_path,
                    None,
                    tmp_dir,
                    zip_decode=932,
                    enable_rar=True,
                    sfx_detector=None,
                )

            self.assertTrue(ok)
            self.assertEqual(2, len(calls))

            out1 = next(
                t for t in calls[0] if isinstance(t, str) and t.startswith("-o")
            )[2:]
            out2 = next(
                t for t in calls[1] if isinstance(t, str) and t.startswith("-o")
            )[2:]

            self.assertEqual(tmp_dir, out2)
            self.assertNotEqual(tmp_dir, out1)
            self.assertEqual(os.path.dirname(tmp_dir), os.path.dirname(out1))
            self.assertFalse(out1.startswith(tmp_dir + os.sep))

            for cmd in calls:
                self.assertEqual("7z", cmd[0])
                self.assertEqual("x", cmd[1])
                self.assertIn("-pDUMMYPASSWORD", cmd)
                self.assertFalse(
                    any(isinstance(t, str) and t.startswith("-mcp=") for t in cmd)
                )

            self.assertFalse(os.path.exists(out1))

    def test_try_extract_tarball_accepts_valid_inner_tar_without_tar_suffix(self):
        with tempfile.TemporaryDirectory() as td:
            archive_path = os.path.join(td, "a.tar.gz")
            with open(archive_path, "wb") as f:
                f.write(b"")
            tmp_dir = os.path.join(td, "tmp")

            calls = []

            def _fake_run(cmd, **kwargs):
                calls.append(cmd)
                out_arg = next(
                    (t for t in cmd if isinstance(t, str) and t.startswith("-o")), None
                )
                if out_arg and len(calls) == 1:
                    out_dir = out_arg[2:]
                    self._write_minimal_tar(os.path.join(out_dir, "oddname"))
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            with mock.patch.object(
                self.m, "safe_subprocess_run", side_effect=_fake_run
            ):
                ok = self.m.try_extract(archive_path, None, tmp_dir)

            self.assertTrue(ok)
            self.assertEqual(2, len(calls))
            stage_dir = next(
                t for t in calls[0] if isinstance(t, str) and t.startswith("-o")
            )[2:]
            self.assertEqual(os.path.join(stage_dir, "oddname"), calls[1][2])

    def test_try_extract_tarball_fails_when_stage_dir_creation_fails(self):
        with tempfile.TemporaryDirectory() as td:
            archive_path = os.path.join(td, "a.tgz")
            with open(archive_path, "wb") as f:
                f.write(b"")
            tmp_dir = os.path.join(td, "tmp")

            fixed_uuid = SimpleNamespace(hex="fixed")
            stage_basename = (
                os.path.basename(tmp_dir) + ".tarball_stage." + fixed_uuid.hex
            )
            stage_dir = os.path.join(os.path.dirname(tmp_dir), stage_basename)

            def _fake_makedirs(path, exist_ok=True, debug=False):
                if path == stage_dir:
                    return False
                os.makedirs(path, exist_ok=True)
                return True

            with (
                mock.patch.object(self.m.uuid, "uuid4", return_value=fixed_uuid),
                mock.patch.object(self.m, "safe_makedirs", side_effect=_fake_makedirs),
                mock.patch.object(self.m, "safe_subprocess_run") as run,
            ):
                self.assertFalse(self.m.try_extract(archive_path, None, tmp_dir))
                run.assert_not_called()

    def test_try_extract_tarball_fails_when_outer_extract_command_fails(self):
        with tempfile.TemporaryDirectory() as td:
            archive_path = os.path.join(td, "a.tar.gz")
            with open(archive_path, "wb") as f:
                f.write(b"")
            tmp_dir = os.path.join(td, "tmp")

            fixed_uuid = SimpleNamespace(hex="fixed")
            calls = []

            def _fake_run(cmd, **kwargs):
                calls.append(cmd)
                return SimpleNamespace(returncode=2, stdout=b"", stderr=b"boom")

            with (
                mock.patch.object(self.m.uuid, "uuid4", return_value=fixed_uuid),
                mock.patch.object(self.m, "safe_subprocess_run", side_effect=_fake_run),
            ):
                self.assertFalse(self.m.try_extract(archive_path, None, tmp_dir))

            self.assertEqual(1, len(calls))
            out_dir = next(
                t for t in calls[0] if isinstance(t, str) and t.startswith("-o")
            )[2:]
            self.assertNotEqual(tmp_dir, out_dir)
            self.assertEqual(os.path.dirname(tmp_dir), os.path.dirname(out_dir))
            self.assertFalse(out_dir.startswith(tmp_dir + os.sep))

    def test_try_extract_tarball_inner_tar_cleanup_failure_returns_false(self):
        with tempfile.TemporaryDirectory() as td:
            archive_path = os.path.join(td, "a.txz")
            with open(archive_path, "wb") as f:
                f.write(b"")
            tmp_dir = os.path.join(td, "tmp")

            calls = []

            def _fake_run(cmd, **kwargs):
                calls.append(cmd)
                out_arg = next(
                    (t for t in cmd if isinstance(t, str) and t.startswith("-o")),
                    None,
                )
                if out_arg and len(calls) == 1:
                    out_dir = out_arg[2:]
                    self._write_minimal_tar(os.path.join(out_dir, "inner.tar"))
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            with (
                mock.patch.object(self.m, "safe_subprocess_run", side_effect=_fake_run),
                mock.patch.object(self.m, "safe_remove", return_value=False) as rm,
                mock.patch.object(self.m, "safe_rmtree", return_value=True),
            ):
                self.assertFalse(self.m.try_extract(archive_path, None, tmp_dir))

            self.assertEqual(2, len(calls))
            self.assertEqual(1, rm.call_count)

    def test_try_extract_tarball_stage_requires_single_regular_file(self):
        with tempfile.TemporaryDirectory() as td:
            archive_path = os.path.join(td, "a.tgz")
            with open(archive_path, "wb") as f:
                f.write(b"")
            tmp_dir = os.path.join(td, "tmp")

            def _fake_run_no_output(cmd, **kwargs):
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            with mock.patch.object(
                self.m, "safe_subprocess_run", side_effect=_fake_run_no_output
            ) as run:
                self.assertFalse(self.m.try_extract(archive_path, None, tmp_dir))
                self.assertEqual(1, run.call_count)

            def _fake_run_multiple(cmd, **kwargs):
                out_dir = next(
                    t for t in cmd if isinstance(t, str) and t.startswith("-o")
                )[2:]
                with open(os.path.join(out_dir, "a.tar"), "wb") as f1:
                    f1.write(b"")
                with open(os.path.join(out_dir, "b.tar"), "wb") as f2:
                    f2.write(b"")
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            with mock.patch.object(
                self.m, "safe_subprocess_run", side_effect=_fake_run_multiple
            ) as run:
                self.assertFalse(self.m.try_extract(archive_path, None, tmp_dir))
                self.assertEqual(1, run.call_count)

            def _fake_run_directory(cmd, **kwargs):
                out_dir = next(
                    t for t in cmd if isinstance(t, str) and t.startswith("-o")
                )[2:]
                os.makedirs(os.path.join(out_dir, "inner"))
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            with mock.patch.object(
                self.m, "safe_subprocess_run", side_effect=_fake_run_directory
            ) as run:
                self.assertFalse(self.m.try_extract(archive_path, None, tmp_dir))
                self.assertEqual(1, run.call_count)

            def _fake_run_non_tar(cmd, **kwargs):
                out_dir = next(
                    t for t in cmd if isinstance(t, str) and t.startswith("-o")
                )[2:]
                with open(
                    os.path.join(out_dir, "inner.txt"), "w", encoding="utf-8"
                ) as f3:
                    f3.write("x")
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            with mock.patch.object(
                self.m, "safe_subprocess_run", side_effect=_fake_run_non_tar
            ) as run:
                self.assertFalse(self.m.try_extract(archive_path, None, tmp_dir))
                self.assertEqual(1, run.call_count)

    def test_try_extract_tarball_stage_rejects_inner_tar_with_bogus_header(self):
        with tempfile.TemporaryDirectory() as td:
            archive_path = os.path.join(td, "a.tgz")
            with open(archive_path, "wb") as f:
                f.write(b"")
            tmp_dir = os.path.join(td, "tmp")

            calls = []

            def _fake_run(cmd, **kwargs):
                calls.append(cmd)
                out_dir = next(
                    t for t in cmd if isinstance(t, str) and t.startswith("-o")
                )[2:]
                if len(calls) == 1:
                    with open(os.path.join(out_dir, "inner.tar"), "wb") as f:
                        f.write(b"X" * 512)
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            with mock.patch.object(
                self.m, "safe_subprocess_run", side_effect=_fake_run
            ) as run:
                ok = self.m.try_extract(archive_path, None, tmp_dir)

            self.assertEqual(1, run.call_count)
            self.assertFalse(ok)

    def test_try_extract_tarball_stage2_failure_returns_false(self):
        with tempfile.TemporaryDirectory() as td:
            archive_path = os.path.join(td, "a.txz")
            with open(archive_path, "wb") as f:
                f.write(b"")
            tmp_dir = os.path.join(td, "tmp")

            calls = []

            def _fake_run(cmd, **kwargs):
                calls.append(cmd)
                if len(calls) == 1:
                    out_dir = next(
                        t for t in cmd if isinstance(t, str) and t.startswith("-o")
                    )[2:]
                    self._write_minimal_tar(os.path.join(out_dir, "inner.tar"))
                    return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
                return SimpleNamespace(returncode=2, stdout=b"", stderr=b"boom")

            with mock.patch.object(
                self.m, "safe_subprocess_run", side_effect=_fake_run
            ):
                self.assertFalse(self.m.try_extract(archive_path, None, tmp_dir))
            self.assertEqual(2, len(calls))

    def test_try_extract_tarball_cleanup_failure_returns_false(self):
        with tempfile.TemporaryDirectory() as td:
            archive_path = os.path.join(td, "a.tbz2")
            with open(archive_path, "wb") as f:
                f.write(b"")
            tmp_dir = os.path.join(td, "tmp")

            calls = []

            def _fake_run(cmd, **kwargs):
                calls.append(cmd)
                if len(calls) == 1:
                    out_dir = next(
                        t for t in cmd if isinstance(t, str) and t.startswith("-o")
                    )[2:]
                    self._write_minimal_tar(os.path.join(out_dir, "inner.tar"))
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            with (
                mock.patch.object(self.m, "safe_subprocess_run", side_effect=_fake_run),
                mock.patch.object(self.m, "safe_rmtree", return_value=False),
            ):
                self.assertFalse(self.m.try_extract(archive_path, None, tmp_dir))
            self.assertEqual(2, len(calls))

    def test_try_extract_tarball_cleanup_does_not_delete_payload_named_like_stage(self):
        with tempfile.TemporaryDirectory() as td:
            archive_path = os.path.join(td, "a.tar.xz")
            with open(archive_path, "wb") as f:
                f.write(b"")
            tmp_dir = os.path.join(td, "tmp")
            os.makedirs(tmp_dir)

            fixed_uuid = SimpleNamespace(hex="fixed")
            stage_basename = (
                os.path.basename(tmp_dir) + ".tarball_stage." + fixed_uuid.hex
            )
            collision_dir = os.path.join(tmp_dir, stage_basename)
            os.makedirs(collision_dir)

            calls = []

            def _fake_run(cmd, **kwargs):
                calls.append(cmd)
                if len(calls) == 1:
                    out_dir = next(
                        t for t in cmd if isinstance(t, str) and t.startswith("-o")
                    )[2:]
                    self._write_minimal_tar(os.path.join(out_dir, "inner.tar"))
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            with (
                mock.patch.object(self.m, "safe_subprocess_run", side_effect=_fake_run),
                mock.patch.object(self.m.uuid, "uuid4", return_value=fixed_uuid),
            ):
                ok = self.m.try_extract(archive_path, None, tmp_dir)

            self.assertTrue(ok)
            self.assertTrue(os.path.isdir(collision_dir))
            self.assertEqual(2, len(calls))


class TestZipEncodingHelpers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = _load_advdecompress_module()

    def test_has_valid_extension_ascii_rules(self):
        self.assertTrue(self.m.has_valid_extension("a.zip"))
        self.assertFalse(self.m.has_valid_extension("a.z-p"))
        self.assertFalse(self.m.has_valid_extension("a.z p"))
        self.assertTrue(self.m.has_valid_extension("a.中"))
        self.assertFalse(self.m.has_valid_extension("a.中-"))

    def test_traditional_zip_allows_data_descriptor(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "dd.zip")
            info = zipfile.ZipInfo("a.txt")
            info.flag_bits |= 0x08
            info.compress_type = zipfile.ZIP_DEFLATED
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr(info, "hello")
            self.assertTrue(self.m.is_traditional_zip(path))

    def test_traditional_zip_rejects_utf8_flag(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "utf8.zip")
            info = zipfile.ZipInfo("中文.txt")
            info.compress_type = zipfile.ZIP_DEFLATED
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr(info, "hello")
            self.assertFalse(self.m.is_traditional_zip(path))

    def test_traditional_zip_rejects_unicode_path_extra(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "extra.zip")
            info = zipfile.ZipInfo("a.txt")
            info.extra = b"\x75\x70\x01\x00\x00"
            info.compress_type = zipfile.ZIP_DEFLATED
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr(info, "hello")
            self.assertFalse(self.m.is_traditional_zip(path))

    def test_smart_meaningful_score_ordering(self):
        score = self.m.get_smart_meaningful_score
        self.assertGreater(score("Project_Report"), score("1029384756"))
        self.assertGreater(score("apple"), score("aaaaaa"))
        self.assertGreater(score("My_Vacation_Photos"), score("DCIM"))
        self.assertGreater(score("2024_Report"), score("20241231"))
        self.assertGreater(score("Backup"), score("a$#k@!"))


if __name__ == "__main__":
    unittest.main()
