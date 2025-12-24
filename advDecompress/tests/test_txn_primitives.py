import json
import os
import tempfile
import unittest
import importlib.util
import types
from multiprocessing import Process, Pipe
from types import SimpleNamespace
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
            paths = self.m._txn_paths(output_dir, td, "testtxn")
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
            self.assertEqual({os.path.abspath(p) for p in (main, part1, part2)}, set(vols))

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
            self.assertEqual({os.path.abspath(p) for p in (part1, part2, part3)}, set(vols))

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
            self.assertEqual({os.path.abspath(p) for p in (main, part1, part2, part3)}, set(vols))

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


if __name__ == "__main__":
    unittest.main()
