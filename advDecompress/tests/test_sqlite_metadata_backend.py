import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


def _load_advdecompress_module():
    here = os.path.dirname(__file__)
    script_path = os.path.abspath(os.path.join(here, "..", "advDecompress.py"))
    spec = importlib.util.spec_from_file_location("advDecompress_script", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    module.VERBOSE = False
    return module


def _load_benchmark_module():
    here = os.path.dirname(__file__)
    script_path = os.path.abspath(
        os.path.join(here, "benchmark_sqlite_metadata_backend.py")
    )
    spec = importlib.util.spec_from_file_location(
        "benchmark_sqlite_metadata_backend_script", script_path
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class TestSqliteMetadataBackend(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = _load_advdecompress_module()
        cls.benchmark = _load_benchmark_module()

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.output_root = os.path.join(self._tmp.name, "output")
        os.makedirs(self.output_root, exist_ok=True)

        self.command_fingerprint = {
            "version": 1,
            "sha256": "command-sha256",
            "fields": {
                "path": os.path.join(self._tmp.name, "input"),
                "output": os.path.abspath(self.output_root),
            },
        }

        self.output_dir = os.path.join(self.output_root, "archives")
        os.makedirs(self.output_dir, exist_ok=True)

        self.input_root = os.path.join(self._tmp.name, "input")
        os.makedirs(self.input_root, exist_ok=True)
        self.discovered_archives = []
        for name in ("a1.zip", "a2.zip"):
            archive_path = os.path.join(self.input_root, name)
            with open(archive_path, "wb") as f:
                f.write(name.encode("utf-8"))
            self.discovered_archives.append(
                {
                    "archive_path": archive_path,
                    "output_dir": self.output_dir,
                    "requested_policy": "direct",
                    "resolved_policy": "direct",
                    "volumes": [archive_path],
                }
            )

        self.external_db_path = os.path.join(self._tmp.name, "external", "metadata.sqlite")

        self.unusable_parent = os.path.join(self._tmp.name, "unusable-parent")
        with open(self.unusable_parent, "w", encoding="utf-8") as f:
            f.write("not-a-directory")
        self.unusable_db_path = os.path.join(self.unusable_parent, "metadata.sqlite")

    def tearDown(self):
        self._tmp.cleanup()

    def test_default_metadata_db_path_is_workdir_sqlite(self):
        cfg = self.m._resolve_metadata_backend_config(
            SimpleNamespace(metadata_db=None),
            self.output_root,
        )
        self.assertEqual("local", cfg["mode"])
        self.assertEqual(
            os.path.join(self.output_root, ".advdecompress_work", "metadata.sqlite"),
            cfg["db_path"],
        )

    def test_external_backend_marker_does_not_store_db_path(self):
        marker = self.m._build_metadata_backend_marker(
            mode="external",
            schema_version=1,
            db_instance_id="db-1",
            db_fingerprint="fingerprint-1",
        )
        self.assertEqual("external", marker["mode"])
        self.assertNotIn("db_path", marker)

    def test_external_mode_resume_requires_metadata_db_flag(self):
        self.m._write_metadata_backend_marker(
            self.output_root,
            mode="external",
            schema_version=1,
            db_instance_id="db-1",
            db_fingerprint="fingerprint-1",
        )
        with self.assertRaisesRegex(RuntimeError, "requires --metadata-db"):
            self.m._resolve_resume_metadata_backend(
                SimpleNamespace(metadata_db=None),
                self.output_root,
            )

    def test_local_mode_resume_rejects_metadata_db_flag(self):
        self.m._write_metadata_backend_marker(
            self.output_root,
            mode="local",
            schema_version=1,
            db_instance_id="db-1",
            db_fingerprint="fingerprint-1",
        )
        with self.assertRaisesRegex(RuntimeError, "backend-mode mismatch"):
            self.m._resolve_resume_metadata_backend(
                SimpleNamespace(metadata_db="/tmp/external.sqlite"),
                self.output_root,
            )

    def test_missing_backend_marker_is_rejected_as_incompatible(self):
        with self.assertRaisesRegex(RuntimeError, "incompatible"):
            self.m._resolve_resume_metadata_backend(
                SimpleNamespace(metadata_db=None),
                self.output_root,
            )

    def test_malformed_backend_marker_is_rejected(self):
        self.m._write_raw_backend_marker(self.output_root, {"backend": "sqlite"})
        with self.assertRaisesRegex(RuntimeError, "incompatible"):
            self.m._resolve_resume_metadata_backend(
                SimpleNamespace(metadata_db=None),
                self.output_root,
            )

    def test_backend_marker_rejects_path_hint_locator_field(self):
        self.m._write_raw_backend_marker(
            self.output_root,
            {
                "backend": "sqlite",
                "mode": "external",
                "schema_version": 1,
                "db_instance_id": "db-1",
                "db_fingerprint": "fingerprint-1",
                "path_hint": "/tmp/external.sqlite",
            },
        )
        with self.assertRaisesRegex(RuntimeError, "incompatible"):
            self.m._load_metadata_backend_marker(self.output_root)

    def test_backend_marker_rejects_fallback_discovery_path_field(self):
        self.m._write_raw_backend_marker(
            self.output_root,
            {
                "backend": "sqlite",
                "mode": "external",
                "schema_version": 1,
                "db_instance_id": "db-1",
                "db_fingerprint": "fingerprint-1",
                "fallback_discovery_path": "/tmp/fallback.sqlite",
            },
        )
        with self.assertRaisesRegex(RuntimeError, "incompatible"):
            self.m._load_metadata_backend_marker(self.output_root)

    def test_local_mode_marker_with_missing_local_db_is_rejected_without_creating_new_db(
        self,
    ):
        db_path = os.path.join(
            self.output_root,
            ".advdecompress_work",
            "metadata.sqlite",
        )
        self.m._write_metadata_backend_marker(
            self.output_root,
            mode="local",
            schema_version=1,
            db_instance_id="db-1",
            db_fingerprint="fingerprint-1",
        )
        self.assertFalse(os.path.exists(db_path))
        with self.assertRaisesRegex(RuntimeError, "metadata-missing"):
            self.m._resolve_resume_metadata_backend(
                SimpleNamespace(metadata_db=None),
                self.output_root,
            )
        self.assertFalse(os.path.exists(db_path))

    def test_metadata_store_bootstrap_persists_schema_output_root_and_mode(self):
        backend = self.m._open_metadata_backend_for_new_run(
            SimpleNamespace(metadata_db=None),
            self.output_root,
        )
        store = self.m._metadata_load_store(backend["conn"])
        self.assertIsInstance(store["schema_version"], int)
        self.assertGreater(store["schema_version"], 0)
        self.assertEqual(os.path.abspath(self.output_root), store["output_root"])
        self.assertEqual("local", store["mode"])

    def test_archive_discovery_and_state_update_round_trip_through_sqlite(self):
        backend = self.m._open_metadata_backend_for_new_run(
            SimpleNamespace(metadata_db=None),
            self.output_root,
        )
        self.m._metadata_create_dataset(
            backend["conn"],
            output_root=self.output_root,
            command_fingerprint=self.command_fingerprint,
            discovered_archives=self.discovered_archives,
        )
        self.m._metadata_update_archive(
            backend["conn"],
            self.discovered_archives[0]["archive_path"],
            state="recoverable",
            last_txn_id="txn-1",
            final_disposition="unknown",
        )
        archive = self.m._metadata_load_archive(
            backend["conn"],
            self.discovered_archives[0]["archive_path"],
        )
        self.assertEqual("recoverable", archive["state"])
        self.assertEqual("txn-1", archive["last_txn_id"])

    def test_old_json_workdir_is_rejected_before_sqlite_bootstrap(self):
        work_base = self.m._work_base(self.output_root)
        os.makedirs(work_base, exist_ok=True)
        with open(
            os.path.join(work_base, "dataset_manifest.json"), "w", encoding="utf-8"
        ) as f:
            json.dump({"schema_version": 2}, f)
        with self.assertRaisesRegex(RuntimeError, "incompatible"):
            self.m._open_metadata_backend_for_new_run(
                SimpleNamespace(metadata_db=None),
                self.output_root,
            )

    def test_external_mode_rejects_db_identity_mismatch(self):
        backend = self.m._open_metadata_backend_for_new_run(
            SimpleNamespace(metadata_db=self.external_db_path),
            self.output_root,
        )
        backend["conn"].close()
        marker = self.m._load_metadata_backend_marker(self.output_root)
        self.m._rewrite_metadata_store_identity(
            self.external_db_path,
            output_root=self.output_root,
            mode="external",
            schema_version=marker["schema_version"],
            db_instance_id=marker["db_instance_id"],
            db_fingerprint="wrong-fingerprint",
        )
        with self.assertRaisesRegex(RuntimeError, "mismatch"):
            self.m._resolve_resume_metadata_backend(
                SimpleNamespace(metadata_db=self.external_db_path),
                self.output_root,
            )

    def test_supplied_db_with_wrong_output_root_is_rejected_after_marker_validation(self):
        backend = self.m._open_metadata_backend_for_new_run(
            SimpleNamespace(metadata_db=self.external_db_path),
            self.output_root,
        )
        backend["conn"].close()
        marker = self.m._load_metadata_backend_marker(self.output_root)
        self.m._rewrite_metadata_store_identity(
            self.external_db_path,
            output_root="/tmp/other-output-root",
            mode="external",
            schema_version=marker["schema_version"],
            db_instance_id=marker["db_instance_id"],
            db_fingerprint=marker["db_fingerprint"],
        )
        with self.assertRaisesRegex(RuntimeError, "different output root"):
            self.m._resolve_resume_metadata_backend(
                SimpleNamespace(metadata_db=self.external_db_path),
                self.output_root,
            )

    def test_supplied_db_with_wrong_schema_version_is_rejected_after_marker_validation(
        self,
    ):
        backend = self.m._open_metadata_backend_for_new_run(
            SimpleNamespace(metadata_db=self.external_db_path),
            self.output_root,
        )
        backend["conn"].close()
        marker = self.m._load_metadata_backend_marker(self.output_root)
        self.m._rewrite_metadata_store_identity(
            self.external_db_path,
            output_root=self.output_root,
            mode="external",
            schema_version=999,
            db_instance_id=marker["db_instance_id"],
            db_fingerprint=marker["db_fingerprint"],
        )
        with self.assertRaisesRegex(RuntimeError, "schema"):
            self.m._resolve_resume_metadata_backend(
                SimpleNamespace(metadata_db=self.external_db_path),
                self.output_root,
            )

    def test_unreadable_or_unwritable_db_path_fails_before_transactional_work(self):
        with self.assertRaisesRegex(RuntimeError, "unreadable|unwritable"):
            self.m._open_metadata_backend_for_new_run(
                SimpleNamespace(metadata_db=self.unusable_db_path),
                self.output_root,
            )

    def test_malformed_or_schema_incompatible_sqlite_metadata_is_rejected(self):
        backend = self.m._open_metadata_backend_for_new_run(
            SimpleNamespace(metadata_db=self.external_db_path),
            self.output_root,
        )
        backend["conn"].close()
        self.m._write_invalid_sqlite_store(self.external_db_path)
        with self.assertRaisesRegex(RuntimeError, "incompatible"):
            self.m._resolve_resume_metadata_backend(
                SimpleNamespace(metadata_db=self.external_db_path),
                self.output_root,
            )

    def test_resume_rejects_unsupported_schema_even_when_marker_and_store_match(self):
        backend = self.m._open_metadata_backend_for_new_run(
            SimpleNamespace(metadata_db=self.external_db_path),
            self.output_root,
        )
        backend["conn"].close()
        marker = self.m._load_metadata_backend_marker(self.output_root)

        self.m._rewrite_metadata_store_identity(
            self.external_db_path,
            output_root=self.output_root,
            mode="external",
            schema_version=999,
            db_instance_id=marker["db_instance_id"],
            db_fingerprint=marker["db_fingerprint"],
        )
        self.m._write_metadata_backend_marker(
            self.output_root,
            mode="external",
            schema_version=999,
            db_instance_id=marker["db_instance_id"],
            db_fingerprint=marker["db_fingerprint"],
        )

        with self.assertRaisesRegex(RuntimeError, "schema.*incompatible"):
            self.m._resolve_resume_metadata_backend(
                SimpleNamespace(metadata_db=self.external_db_path),
                self.output_root,
            )

    def test_new_run_rejects_malformed_preexisting_external_db_as_incompatible(self):
        os.makedirs(os.path.dirname(self.external_db_path), exist_ok=True)
        with open(self.external_db_path, "wb") as f:
            f.write(b"not-a-valid-sqlite-db")

        with self.assertRaisesRegex(RuntimeError, "incompatible"):
            self.m._open_metadata_backend_for_new_run(
                SimpleNamespace(metadata_db=self.external_db_path),
                self.output_root,
            )

    def test_reusing_external_db_for_new_output_root_is_rejected(self):
        backend_a = self.m._open_metadata_backend_for_new_run(
            SimpleNamespace(metadata_db=self.external_db_path),
            self.output_root,
        )
        self.m._metadata_create_dataset(
            backend_a["conn"],
            output_root=self.output_root,
            command_fingerprint=self.command_fingerprint,
            discovered_archives=self.discovered_archives,
        )
        with backend_a["conn"]:
            backend_a["conn"].execute(
                "INSERT OR REPLACE INTO txns(txn_id, archive_path, output_dir, output_base, state, updated_at_epoch, terminal_state, txn_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "stale-txn",
                    os.path.abspath(self.discovered_archives[0]["archive_path"]),
                    os.path.abspath(self.output_dir),
                    os.path.abspath(self.output_root),
                    "failed",
                    0.0,
                    1,
                    "{}",
                ),
            )
        backend_a["conn"].close()

        output_root_b = os.path.join(self._tmp.name, "output-second")
        os.makedirs(output_root_b, exist_ok=True)
        with self.assertRaisesRegex(RuntimeError, "different output root"):
            self.m._open_metadata_backend_for_new_run(
                SimpleNamespace(metadata_db=self.external_db_path),
                output_root_b,
            )

        conn = self.m._metadata_connect(self.external_db_path, create_if_missing=False)
        try:
            store = self.m._metadata_load_store(conn)
            self.assertEqual(os.path.abspath(self.output_root), store["output_root"])
            self.assertEqual(
                1,
                conn.execute("SELECT COUNT(*) AS c FROM txns").fetchone()["c"],
            )
        finally:
            conn.close()

    def test_create_dataset_manifest_honors_external_metadata_db_mode(self):
        manifest = self.m._create_dataset_manifest(
            input_root=self.input_root,
            output_root=self.output_root,
            discovered_archives=self.discovered_archives,
            command_fingerprint=self.command_fingerprint,
            metadata_db=self.external_db_path,
        )

        self.assertIsInstance(manifest, dict)
        marker = self.m._load_metadata_backend_marker(self.output_root)
        self.assertEqual("external", marker["mode"])
        self.assertTrue(os.path.exists(self.external_db_path))
        self.assertFalse(
            os.path.exists(
                os.path.join(
                    self.output_root,
                    ".advdecompress_work",
                    "metadata.sqlite",
                )
            )
        )

    def test_load_sqlite_progress_reads_authoritative_metadata_state(self):
        backend = self.m._open_metadata_backend_for_new_run(
            SimpleNamespace(metadata_db=None),
            self.output_root,
        )
        self.m._metadata_create_dataset(
            backend["conn"],
            output_root=self.output_root,
            command_fingerprint=self.command_fingerprint,
            discovered_archives=self.discovered_archives,
        )
        self.m._metadata_update_archive(
            backend["conn"],
            self.discovered_archives[0]["archive_path"],
            state="succeeded",
            last_txn_id="txn-1",
            final_disposition="success:delete",
        )
        self.m._metadata_update_archive(
            backend["conn"],
            self.discovered_archives[1]["archive_path"],
            state="failed",
            last_txn_id="txn-2",
            final_disposition="failure:move",
        )

        progress = self.benchmark._load_sqlite_progress(self.output_root)

        self.assertEqual("failed", progress["status"])
        self.assertEqual(1, progress["counts"]["succeeded"])
        self.assertEqual(1, progress["counts"]["failed"])

    def test_persist_archive_tracking_keeps_sqlite_authoritative_when_manifest_cache_save_fails(
        self,
    ):
        manifest = self.m._create_dataset_manifest(
            input_root=self.input_root,
            output_root=self.output_root,
            discovered_archives=self.discovered_archives,
            command_fingerprint=self.command_fingerprint,
        )
        self.assertIsInstance(manifest, dict)

        with mock.patch.object(
            self.m,
            "_save_dataset_manifest_if_dirty",
            side_effect=OSError("manifest cache fsync failed"),
        ):
            self.m._persist_archive_tracking(
                self.output_root,
                self.discovered_archives[0]["archive_path"],
                metadata_db_path=os.path.join(
                    self.output_root,
                    ".advdecompress_work",
                    "metadata.sqlite",
                ),
                state="extracting",
                last_txn_id="txn-cache-failure",
                attempts_increment=1,
                final_disposition="unknown",
                error=None,
            )

        conn = self.m._metadata_connect(
            os.path.join(
                self.output_root,
                ".advdecompress_work",
                "metadata.sqlite",
            ),
            create_if_missing=False,
        )
        try:
            archive = self.m._metadata_load_archive(
                conn,
                self.discovered_archives[0]["archive_path"],
            )
        finally:
            conn.close()

        self.assertEqual("extracting", archive["state"])
        self.assertEqual("txn-cache-failure", archive["last_txn_id"])
        self.assertEqual(1, archive["attempts"])

    def test_update_dataset_manifest_archive_keeps_sqlite_authoritative_when_manifest_cache_save_fails(
        self,
    ):
        manifest = self.m._create_dataset_manifest(
            input_root=self.input_root,
            output_root=self.output_root,
            discovered_archives=self.discovered_archives,
            command_fingerprint=self.command_fingerprint,
        )
        self.assertIsInstance(manifest, dict)

        with mock.patch.object(
            self.m,
            "_save_dataset_manifest_if_dirty",
            side_effect=OSError("manifest cache write failed"),
        ):
            self.m._update_dataset_manifest_archive(
                self.output_root,
                self.discovered_archives[1]["archive_path"],
                state="failed",
                last_txn_id="txn-terminal-cache-failure",
                final_disposition="failure:move",
                error={"type": "PLACE_FAILED"},
                finalized_at="2026-04-24T00:00:00Z",
            )

        conn = self.m._metadata_connect(
            os.path.join(
                self.output_root,
                ".advdecompress_work",
                "metadata.sqlite",
            ),
            create_if_missing=False,
        )
        try:
            archive = self.m._metadata_load_archive(
                conn,
                self.discovered_archives[1]["archive_path"],
            )
        finally:
            conn.close()

        self.assertEqual("failed", archive["state"])
        self.assertEqual("txn-terminal-cache-failure", archive["last_txn_id"])
        self.assertEqual("failure:move", archive["final_disposition"])
        self.assertEqual({"type": "PLACE_FAILED"}, archive["error"])

    def test_benchmark_runner_emits_candidate_and_baseline_summary(self):
        resumed = subprocess.CompletedProcess(
            args=["python3"],
            returncode=0,
            stdout="Successfully processed: 4\n",
            stderr="",
        )
        with mock.patch.object(
            self.benchmark,
            "_run_interrupt_then_resume",
            return_value=(
                {"interrupted": True, "returncode": 130, "stdout": "", "stderr": ""},
                (resumed, 1.25),
            ),
        ) as run_case, mock.patch.object(
            self.benchmark.subprocess,
            "check_output",
            return_value="abc123\n",
        ):
            summary = self.benchmark.run_case_summary(
                label="candidate",
                repo_root="/tmp/repo",
                work_root="/tmp/bench-work",
                archives=4,
                measure_syscalls=False,
            )

        run_case.assert_called_once_with(
            "/tmp/repo",
            work_root="/tmp/bench-work",
            archives=4,
            measure_syscalls=False,
        )
        self.assertEqual("candidate", summary["label"])
        self.assertEqual("abc123", summary["branch_or_commit"])
        self.assertIn("wall_time_seconds", summary)
        self.assertIn("returncode", summary)
        self.assertIn("recovery_outcome", summary)
        self.assertIn("success_outcome", summary)
        self.assertIn("scenario_wall_time_seconds", summary)

    def test_benchmark_runner_executes_interrupted_run_then_resume(self):
        streamed = {"interrupted": True, "returncode": 130, "stdout": "", "stderr": ""}
        resumed = subprocess.CompletedProcess(
            args=["python3"],
            returncode=0,
            stdout="Successfully processed: 4\n",
            stderr="",
        )
        with mock.patch.object(
            self.benchmark,
            "_create_small_archive_corpus",
            return_value="/tmp/bench-work/input",
        ), mock.patch.object(
            self.benchmark,
            "run_streamed_case",
            return_value=streamed,
        ) as streamed_case, mock.patch.object(
            self.benchmark,
            "run_completed_case",
            return_value=(resumed, 2.5),
        ) as completed_case:
            initial, resumed_result = self.benchmark._run_interrupt_then_resume(
                "/tmp/repo",
                work_root="/tmp/bench-work",
                archives=4,
                measure_syscalls=False,
            )

        self.assertEqual("/tmp/bench-work/input", streamed_case.call_args.kwargs["input_root"])
        self.assertEqual(
            "/tmp/bench-work/output", streamed_case.call_args.kwargs["output_root"]
        )
        self.assertTrue(callable(streamed_case.call_args.kwargs["stop_when"]))
        completed_case.assert_called_once_with(
            "/tmp/repo",
            input_root="/tmp/bench-work/input",
            output_root="/tmp/bench-work/output",
            measure_syscalls=False,
        )
        self.assertTrue(initial["interrupted"])
        self.assertEqual(0, resumed_result[0].returncode)

    def test_benchmark_baseline_guard_rejects_attached_branch_checkout(self):
        with mock.patch.object(
            self.benchmark.subprocess,
            "check_output",
            side_effect=["testing\n"],
        ):
            with self.assertRaisesRegex(RuntimeError, "detached"):
                self.benchmark.assert_json_baseline_checkout(
                    "/tmp/not-detached-baseline"
                )

    def test_benchmark_baseline_guard_rejects_wrong_detached_commit(self):
        with mock.patch.object(
            self.benchmark.subprocess,
            "check_output",
            side_effect=["\n", "deadbeef\n"],
        ):
            with self.assertRaisesRegex(RuntimeError, "aa3227b98c60e328ab475300c07848cdff18c5c2"):
                self.benchmark.assert_json_baseline_checkout(
                    "/tmp/wrong-detached-baseline"
                )

    def test_benchmark_baseline_guard_rejects_dirty_detached_checkout(self):
        with mock.patch.object(
            self.benchmark.subprocess,
            "check_output",
            side_effect=[
                "\n",
                "aa3227b98c60e328ab475300c07848cdff18c5c2\n",
                " M advDecompress/advDecompress.py\n",
            ],
        ):
            with self.assertRaisesRegex(RuntimeError, "clean"):
                self.benchmark.assert_json_baseline_checkout(
                    "/tmp/dirty-detached-baseline"
                )

    def test_benchmark_baseline_guard_accepts_clean_pinned_detached_checkout(self):
        with mock.patch.object(
            self.benchmark.subprocess,
            "check_output",
            side_effect=[
                "\n",
                "aa3227b98c60e328ab475300c07848cdff18c5c2\n",
                "",
            ],
        ):
            self.benchmark.assert_json_baseline_checkout(
                "/tmp/clean-detached-baseline"
            )

    def test_benchmark_interrupt_helper_signals_once_snapshot_exists(self):
        work_base = os.path.join(self.output_root, ".advdecompress_work")
        journal_dir = os.path.join(work_base, "outputs", "token", "journal", "txn-1")
        os.makedirs(journal_dir, exist_ok=True)
        with open(os.path.join(journal_dir, "txn.json"), "w", encoding="utf-8") as f:
            f.write("{}")

        process = mock.Mock()

        with mock.patch.object(self.benchmark, "_send_interrupt", return_value=True) as send_interrupt:
            interrupted = self.benchmark._terminate_after_first_txn_snapshot(
                "",
                process,
                output_root=self.output_root,
            )

        self.assertTrue(interrupted)
        send_interrupt.assert_called_once_with(process)

    def test_resume_safe_interrupt_waits_for_recoverable_non_extracting_sample(self):
        work_base = os.path.join(self.output_root, ".advdecompress_work")
        os.makedirs(work_base, exist_ok=True)
        with open(
            os.path.join(work_base, "dataset_manifest.json"),
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(
                {
                    "status": "active",
                    "progress": {
                        "counts": {
                            "recoverable": 1,
                            "extracting": 0,
                            "retryable": 0,
                            "pending": 39,
                            "succeeded": 1,
                            "failed": 0,
                        }
                    },
                },
                f,
        )

        process = mock.Mock()

        with mock.patch.object(self.benchmark, "_send_interrupt", return_value=True) as send_interrupt:
            interrupted = self.benchmark._interrupt_when_resume_safe(
                "",
                process,
                output_root=self.output_root,
            )

        self.assertTrue(interrupted)
        send_interrupt.assert_called_once_with(process)

    def test_send_interrupt_targets_process_group_when_available(self):
        process = mock.Mock(pid=12345)
        process.poll.return_value = None

        with mock.patch.object(self.benchmark.os, "getpgid", return_value=12345), mock.patch.object(
            self.benchmark.os,
            "killpg",
        ) as killpg:
            interrupted = self.benchmark._send_interrupt(process)

        self.assertTrue(interrupted)
        killpg.assert_called_once_with(12345, self.benchmark.signal.SIGINT)
        process.send_signal.assert_not_called()

    def test_case_summary_uses_sqlite_progress_for_terminal_success_contract(self):
        resumed = subprocess.CompletedProcess(
            args=["python3"],
            returncode=0,
            stdout="Successfully processed: 39\n",
            stderr="",
        )
        with mock.patch.object(
            self.benchmark,
            "_run_interrupt_then_resume",
            return_value=(
                {
                    "interrupted": True,
                    "returncode": 1,
                    "stdout": "",
                    "stderr": "",
                    "wall_time_seconds": 0.75,
                    "syscalls": {
                        "calls_by_syscall": {"openat": 5},
                        "total_calls": 5,
                    },
                },
                (resumed, 1.25),
            ),
        ), mock.patch.object(
            self.benchmark.subprocess,
            "check_output",
            return_value="abc123\n",
        ), mock.patch.object(
            self.benchmark,
            "_load_manifest_progress",
            side_effect=AssertionError("manifest progress must not drive benchmark parity"),
        ), mock.patch.object(
            self.benchmark,
            "_load_sqlite_progress",
            return_value={
                "status": "completed",
                "counts": {"succeeded": 40, "failed": 0},
            },
            create=True,
        ):
            summary = self.benchmark.run_case_summary(
                label="candidate",
                repo_root="/tmp/repo",
                work_root="/tmp/bench-work",
                archives=40,
                measure_syscalls=False,
            )

        self.assertEqual(40, summary["success_outcome"]["success_count"])
        self.assertTrue(summary["recovery_outcome"]["completed_terminal_state"])
        self.assertEqual(2.0, summary["scenario_wall_time_seconds"])
        self.assertEqual(
            {"status": "completed", "counts": {"succeeded": 40, "failed": 0}},
            summary["final_progress"],
        )
        self.assertIsNone(summary["syscalls"])

    def test_case_summary_falls_back_to_manifest_progress_when_sqlite_is_absent(self):
        resumed = subprocess.CompletedProcess(
            args=["python3"],
            returncode=0,
            stdout="Successfully processed: 39\n",
            stderr="",
        )
        with mock.patch.object(
            self.benchmark,
            "_run_interrupt_then_resume",
            return_value=(
                {
                    "interrupted": True,
                    "returncode": 1,
                    "stdout": "",
                    "stderr": "",
                    "wall_time_seconds": 0.5,
                    "syscalls": None,
                },
                (resumed, 1.5),
            ),
        ), mock.patch.object(
            self.benchmark.subprocess,
            "check_output",
            return_value="abc123\n",
        ), mock.patch.object(
            self.benchmark,
            "_load_sqlite_progress",
            return_value=None,
        ), mock.patch.object(
            self.benchmark,
            "_load_manifest_progress",
            return_value={
                "status": "completed",
                "counts": {"succeeded": 40, "failed": 0},
            },
        ):
            summary = self.benchmark.run_case_summary(
                label="baseline",
                repo_root="/tmp/repo",
                work_root="/tmp/bench-work",
                archives=40,
                measure_syscalls=False,
            )

        self.assertEqual(40, summary["success_outcome"]["success_count"])
        self.assertTrue(summary["recovery_outcome"]["completed_terminal_state"])
        self.assertEqual("completed", summary["final_progress"]["status"])

    def test_case_summary_combines_initial_and_resume_syscalls(self):
        resumed = subprocess.CompletedProcess(
            args=["python3"],
            returncode=0,
            stdout="Successfully processed: 39\n",
            stderr="",
        )
        with mock.patch.object(
            self.benchmark,
            "_run_interrupt_then_resume",
            return_value=(
                {
                    "interrupted": True,
                    "returncode": 1,
                    "stdout": "",
                    "stderr": "",
                    "wall_time_seconds": 0.4,
                    "syscalls": {
                        "calls_by_syscall": {"openat": 4, "read": 6},
                        "total_calls": 10,
                    },
                },
                (resumed, 1.6),
            ),
        ), mock.patch.object(
            self.benchmark.subprocess,
            "check_output",
            return_value="abc123\n",
        ), mock.patch.object(
            self.benchmark,
            "_load_sqlite_progress",
            return_value={
                "status": "completed",
                "counts": {"succeeded": 40, "failed": 0},
            },
        ), mock.patch.object(
            self.benchmark,
            "_load_manifest_progress",
            side_effect=AssertionError("manifest progress must not drive benchmark parity"),
        ), mock.patch.object(
            self.benchmark,
            "_metadata_churn_syscalls",
            return_value={
                "calls_by_syscall": {"openat": 8, "read": 2, "close": 3},
                "total_calls": 13,
            },
        ):
            summary = self.benchmark.run_case_summary(
                label="candidate",
                repo_root="/tmp/repo",
                work_root="/tmp/bench-work",
                archives=40,
                measure_syscalls=True,
            )

        self.assertEqual(2.0, summary["scenario_wall_time_seconds"])
        self.assertEqual(23, summary["syscalls"]["total_calls"])
        self.assertEqual(12, summary["syscalls"]["calls_by_syscall"]["openat"])
        self.assertEqual(8, summary["syscalls"]["calls_by_syscall"]["read"])
        self.assertEqual(3, summary["syscalls"]["calls_by_syscall"]["close"])

    def test_collect_valid_case_samples_discards_invalid_attempts(self):
        invalid = {
            "label": "candidate",
            "branch_or_commit": "abc123",
            "returncode": 1,
            "wall_time_seconds": 5.0,
            "initial_outcome": {"phase": "interrupted", "returncode": 1},
            "resume_outcome": {
                "returncode": 1,
                "success_count": 0,
                "failed_archives": ["/tmp/a.zip"],
            },
            "success_outcome": {
                "returncode": 1,
                "success_count": 0,
                "failed_archives_present": True,
            },
            "recovery_outcome": {
                "resume_errors_present": True,
                "completed_terminal_state": False,
            },
            "final_progress": {"status": "active", "counts": {"succeeded": 0}},
            "syscalls": {"calls_by_syscall": {}, "total_calls": 999},
        }
        valid = {
            "label": "candidate",
            "branch_or_commit": "abc123",
            "returncode": 0,
            "wall_time_seconds": 1.5,
            "initial_outcome": {"phase": "interrupted", "returncode": 1},
            "resume_outcome": {
                "returncode": 0,
                "success_count": 39,
                "failed_archives": [],
            },
            "success_outcome": {
                "returncode": 0,
                "success_count": 40,
                "failed_archives_present": False,
            },
            "recovery_outcome": {
                "resume_errors_present": False,
                "completed_terminal_state": True,
            },
            "final_progress": {"status": "completed", "counts": {"succeeded": 40}},
            "syscalls": {"calls_by_syscall": {}, "total_calls": 123},
        }
        with mock.patch.object(
            self.benchmark,
            "run_case_summary",
            side_effect=[invalid, valid, valid],
        ):
            case = self.benchmark._collect_valid_case_samples(
                "candidate",
                "/tmp/repo",
                work_root="/tmp/bench-work",
                archives=40,
                measure_syscalls=True,
                required_valid_samples=2,
                max_attempts=3,
            )

        self.assertEqual(3, case["total_attempts"])
        self.assertEqual(2, len(case["valid_samples"]))
        self.assertTrue(case["attempts"][0]["invalid_reasons"])

    def test_aggregate_case_samples_reports_medians_from_valid_samples(self):
        case = {
            "label": "candidate",
            "branch_or_commit": "abc123",
            "required_valid_samples": 2,
            "total_attempts": 3,
            "valid_samples": [
                {
                    "wall_time_seconds": 3.0,
                    "scenario_wall_time_seconds": 3.5,
                    "syscalls": {"total_calls": 100},
                    "success_outcome": {"returncode": 0, "success_count": 40},
                    "resume_outcome": {"failed_archives": []},
                    "recovery_outcome": {
                        "completed_terminal_state": True,
                        "resume_errors_present": False,
                    },
                    "initial_outcome": {"phase": "interrupted"},
                },
                {
                    "wall_time_seconds": 5.0,
                    "scenario_wall_time_seconds": 6.5,
                    "syscalls": {"total_calls": 300},
                    "success_outcome": {"returncode": 0, "success_count": 40},
                    "resume_outcome": {"failed_archives": []},
                    "recovery_outcome": {
                        "completed_terminal_state": True,
                        "resume_errors_present": False,
                    },
                    "initial_outcome": {"phase": "interrupted"},
                },
            ],
        }

        aggregated = self.benchmark._aggregate_case_samples(case)

        self.assertEqual(4.0, aggregated["wall_time_seconds"]["median"])
        self.assertEqual(5.0, aggregated["scenario_wall_time_seconds"]["median"])
        self.assertEqual(200.0, aggregated["syscalls"]["median"])


if __name__ == "__main__":
    unittest.main()
