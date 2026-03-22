import json
import os
import tempfile
import unittest
import importlib.util
import types
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
