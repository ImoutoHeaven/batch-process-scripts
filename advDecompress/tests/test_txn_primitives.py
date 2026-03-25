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
        args = {
            "verbose": False,
            "password": None,
            "password_file": None,
            "traditional_zip_policy": "decode-auto",
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
            "decompress_policy": "direct",
            "degrade_cross_volume": False,
            "wal_fsync_every": 1,
            "snapshot_every": 1,
            "no_durability": True,
        }
        args.update(overrides)
        return SimpleNamespace(**args)

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

    def test_atomic_write_json(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "txn.json")
            data = {"a": 1, "b": {"c": "x"}}
            self.m.atomic_write_json(path, data, debug=False)
            with open(path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            self.assertEqual(loaded, data)
            self.assertFalse(os.path.exists(path + ".tmp"))

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
            expected_lock_path = os.path.join(
                self.m._work_root(output_dir, output_base),
                "locks",
                "output_dir.lock",
            )

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
            expected_lock_path = os.path.join(
                self.m._work_root(timeout_output_dir, output_base),
                "locks",
                "output_dir.lock",
            )

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
            archives = [os.path.join(td, "new.zip")]

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

    def test_run_transactional_preserves_recovery_only_failed_work_root(self):
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
            txn = self.m._txn_create(
                archive_path=os.path.join(td, "stale-failed.zip"),
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

            processor = types.SimpleNamespace(
                successful_archives=[], failed_archives=[], skipped_archives=[]
            )
            work_root = self.m._work_root(output_dir, output_base)

            with mock.patch.object(self.m, "FileLock", DummyLock):
                self.m._run_transactional(processor, [], args=args)

            self.assertTrue(os.path.isdir(work_root))
            with open(txn["paths"]["txn_json"], "r", encoding="utf-8") as f:
                saved = json.load(f)
            self.assertEqual(self.m.TXN_STATE_FAILED, saved["state"])

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
            txn = self.m._txn_create(
                archive_path=os.path.join(td, "recover-me.zip"),
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
            recovery_txn = self.m._txn_create(
                archive_path=os.path.join(td, "stale-failed.zip"),
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

            current_archive = os.path.join(td, "new.zip")
            current_output_dir = os.path.join(output_base, "new-out")

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
                success_output_dir: os.path.join(
                    self.m._work_root(success_output_dir, output_base),
                    "locks",
                    "output_dir.lock",
                ),
                failed_output_dir: os.path.join(
                    self.m._work_root(failed_output_dir, output_base),
                    "locks",
                    "output_dir.lock",
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
        self.assertCountEqual(
            [
                (
                    self.m._work_root(success_output_dir, output_base),
                    {expected_lock_paths[success_output_dir]},
                ),
                (
                    self.m._work_root(failed_output_dir, output_base),
                    {expected_lock_paths[failed_output_dir]},
                ),
            ],
            work_root_cleanup_calls,
        )

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
            timeout_lock_path = os.path.join(
                self.m._work_root(timeout_output_dir, output_base),
                "locks",
                "output_dir.lock",
            )

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
                mock.patch.object(
                    tar_processor,
                    "handle_traditional_zip_policy",
                    return_value={
                        "should_continue": True,
                        "zip_decode": None,
                        "reason": "",
                    },
                ),
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
                mock.patch.object(
                    zip_processor,
                    "handle_traditional_zip_policy",
                    return_value={
                        "should_continue": True,
                        "zip_decode": None,
                        "reason": "",
                    },
                ),
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
                mock.patch.object(
                    tar_processor,
                    "handle_traditional_zip_policy",
                    return_value={
                        "should_continue": True,
                        "zip_decode": None,
                        "reason": "",
                    },
                ),
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
                mock.patch.object(
                    zip_processor,
                    "handle_traditional_zip_policy",
                    return_value={
                        "should_continue": True,
                        "zip_decode": None,
                        "reason": "",
                    },
                ),
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
