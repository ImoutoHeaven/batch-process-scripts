import json
import os
import tempfile
import unittest
import importlib.util
import types
from multiprocessing import Process, Pipe


def _load_advdecompress_module():
    here = os.path.dirname(__file__)
    script_path = os.path.abspath(os.path.join(here, "..", "advDecompress.py"))
    spec = importlib.util.spec_from_file_location("advDecompress_script", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    module.VERBOSE = False
    return module


class TestTxnPrimitives(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = _load_advdecompress_module()

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
            with open(os.path.join(paths["incoming_dir"], "x.txt"), "w", encoding="utf-8") as f:
                f.write("x")

            txn = {"policy_frozen": False, "policy": "2-collect", "paths": paths, "output_dir": out}
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
            lock1 = self.m.FileLock(lock_path, timeout_ms=2000, retry_ms=50, debug=False)
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

            lock2 = self.m.FileLock(lock_path, timeout_ms=1000, retry_ms=50, debug=False)
            self.assertTrue(lock2.acquire())
            lock2.release()

    def test_collect_resolves_to_separate_on_conflict(self):
        with tempfile.TemporaryDirectory() as td:
            output_dir = os.path.join(td, "out")
            os.makedirs(output_dir)
            paths = self.m._txn_paths(output_dir, "testtxn")
            os.makedirs(paths["incoming_dir"])
            with open(os.path.join(paths["incoming_dir"], "x.txt"), "w", encoding="utf-8") as f:
                f.write("x")
            with open(os.path.join(output_dir, "x.txt"), "w", encoding="utf-8") as f:
                f.write("y")

            txn = {
                "policy_frozen": False,
                "policy": "collect",
                "paths": paths,
                "output_dir": output_dir,
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


if __name__ == "__main__":
    unittest.main()
