import io
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock


class PartialReadIO(io.BytesIO):
    def __init__(self, data: bytes, max_read: int):
        super().__init__(data)
        self._max_read = max_read

    def read(self, size=None):
        if size is None or size < 0:
            size = self._max_read
        return super().read(min(size, self._max_read))


class TestCliHelp(unittest.TestCase):
    def test_help_exit_zero(self):
        script_path = Path(__file__).resolve().parents[1] / "ed2k115_calc.py"
        p = subprocess.run(
            [sys.executable, str(script_path), "--help"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(p.returncode, 0)
        self.assertIn("--keep-dirs", p.stdout)
        self.assertIn("--url-encode", p.stdout)


class TestCliValidation(unittest.TestCase):
    def test_out_required_when_input_is_provided(self):
        script_path = Path(__file__).resolve().parents[1] / "ed2k115_calc.py"

        with tempfile.TemporaryDirectory() as td:
            input_file = Path(td) / "one.bin"
            input_file.write_bytes(b"x")
            run = subprocess.run(
                [sys.executable, str(script_path), str(input_file)],
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(run.returncode, 0)
        self.assertIn("--out is required when input is provided", run.stderr)


class TestMd4(unittest.TestCase):
    def test_md4_vectors(self):
        from python_port.ed2k115_calc import md4_raw

        self.assertEqual(md4_raw(b"").hex().upper(), "31D6CFE0D16AE931B73C59D7E0C089C0")
        self.assertEqual(md4_raw(b"a").hex().upper(), "BDE52CB31DE33E46245E05FBDBD6FB24")
        self.assertEqual(md4_raw(b"abc").hex().upper(), "A448017AAF21D8525FC10AE87AA6729D")
        self.assertEqual(
            md4_raw(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890").hex().upper(),
            "E33B4DDC9C38F2199C3E7B164FCC0536",
        )


class TestEd2k115Core(unittest.TestCase):
    def test_stream_tiny_input_uses_single_md4(self):
        from python_port.ed2k115_calc import ed2k_115_stream, md4_raw

        data = b"a"
        self.assertEqual(ed2k_115_stream(io.BytesIO(data), len(data)), md4_raw(data).hex().upper())

    def test_small_file_uses_nested_md4(self):
        from python_port.ed2k115_calc import ed2k_115_bytes, md4_raw

        data = b"a"
        self.assertEqual(ed2k_115_bytes(data), md4_raw(md4_raw(data)).hex().upper())

    def test_chunk_boundary_vectors(self):
        from python_port.ed2k115_calc import ED2K_CHUNK_SIZE, ed2k_115_stream

        d1 = bytes([0]) * (ED2K_CHUNK_SIZE - 1)
        d2 = bytes([0]) * ED2K_CHUNK_SIZE
        d3 = bytes([0]) * (ED2K_CHUNK_SIZE + 1)

        self.assertEqual(ed2k_115_stream(io.BytesIO(d1), len(d1)), "AC44B93FC9AFF773AB0005C911F8396F")
        self.assertEqual(ed2k_115_stream(io.BytesIO(d2), len(d2)), "FC21D9AF828F92A8DF64BEAC3357425D")
        self.assertEqual(ed2k_115_stream(io.BytesIO(d3), len(d3)), "06329E9DBA1373512C06386FE29E3C65")

    def test_stream_small_file_handles_partial_reads(self):
        from python_port.ed2k115_calc import ed2k_115_stream, md4_raw

        data = b"abcdef"
        stream = PartialReadIO(data, max_read=2)
        self.assertEqual(ed2k_115_stream(stream, len(data)), md4_raw(data).hex().upper())

    def test_stream_chunked_file_handles_partial_reads_without_boundary_drift(self):
        from python_port.ed2k115_calc import ED2K_CHUNK_SIZE, ed2k_115_bytes, ed2k_115_stream

        data = (b"a" * ED2K_CHUNK_SIZE) + b"b"
        stream = PartialReadIO(data, max_read=131072)
        self.assertEqual(ed2k_115_stream(stream, len(data)), ed2k_115_bytes(data))


class TestFilenameEncoding(unittest.TestCase):
    def test_default_mode_encodes_only_unsafe_delimiters(self):
        from python_port.ed2k115_calc import encode_name_for_ed2k

        name = "中 文|a\n\rb\tc"
        out = encode_name_for_ed2k(name, url_encode_all=False)
        self.assertEqual(out, "中 文%7Ca%0A%0Db%09c")
        self.assertIn("中 文", out)
        self.assertIn("%7C", out)
        self.assertIn("%0A", out)
        self.assertIn("%0D", out)
        self.assertIn("%09", out)

    def test_default_mode_preserves_literal_percent(self):
        from python_port.ed2k115_calc import encode_name_for_ed2k

        out = encode_name_for_ed2k("100%|done", url_encode_all=False)
        self.assertEqual(out, "100%%7Cdone")

    def test_url_encode_all_mode(self):
        from python_port.ed2k115_calc import encode_name_for_ed2k

        out = encode_name_for_ed2k("日本語 file|x", url_encode_all=True)
        self.assertNotIn("日本語", out)
        self.assertNotIn(" ", out)
        self.assertIn("%7C", out)


class TestOutputModes(unittest.TestCase):
    def test_flat_mode_single_log(self):
        from python_port.ed2k115_calc import md4_raw

        script_path = Path(__file__).resolve().parents[1] / "ed2k115_calc.py"

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "input"
            root.mkdir()
            (root / "b.txt").write_bytes(b"bbb")
            (root / "sub").mkdir()
            (root / "sub" / "a.txt").write_bytes(b"a")

            out_log = Path(td) / "flat.ed2k.log"
            run = subprocess.run(
                [sys.executable, str(script_path), str(root), "--out", str(out_log)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(run.returncode, 0, msg=run.stderr)
            self.assertTrue(out_log.exists())

            lines = out_log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 2)
            self.assertIn(f"|b.txt|3|{md4_raw(b'bbb').hex().upper()}|/", lines[0])
            self.assertIn(f"|a.txt|1|{md4_raw(b'a').hex().upper()}|/", lines[1])

    def test_keep_dirs_mode_one_log_per_dir(self):
        from python_port.ed2k115_calc import md4_raw

        script_path = Path(__file__).resolve().parents[1] / "ed2k115_calc.py"

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "input"
            root.mkdir()
            (root / "root.txt").write_bytes(b"r")
            (root / "sub").mkdir()
            (root / "sub" / "child.txt").write_bytes(b"cc")

            out_dir = Path(td) / "out"
            run = subprocess.run(
                [sys.executable, str(script_path), str(root), "--out", str(out_dir), "--keep-dirs"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(run.returncode, 0, msg=run.stderr)

            root_log = out_dir / "files.ed2k.log"
            sub_log = out_dir / "sub" / "files.ed2k.log"
            self.assertTrue(root_log.exists())
            self.assertTrue(sub_log.exists())

            root_lines = root_log.read_text(encoding="utf-8").splitlines()
            sub_lines = sub_log.read_text(encoding="utf-8").splitlines()

            self.assertEqual(len(root_lines), 1)
            self.assertIn(f"|root.txt|1|{md4_raw(b'r').hex().upper()}|/", root_lines[0])

            self.assertEqual(len(sub_lines), 1)
            self.assertIn(f"|child.txt|2|{md4_raw(b'cc').hex().upper()}|/", sub_lines[0])

    def test_single_file_input_flat_mode_writes_out_file(self):
        from python_port.ed2k115_calc import md4_raw

        script_path = Path(__file__).resolve().parents[1] / "ed2k115_calc.py"

        with tempfile.TemporaryDirectory() as td:
            input_file = Path(td) / "one.bin"
            input_file.write_bytes(b"x")
            out_log = Path(td) / "single.ed2k.log"

            run = subprocess.run(
                [sys.executable, str(script_path), str(input_file), "--out", str(out_log)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(run.returncode, 0, msg=run.stderr)
            self.assertTrue(out_log.exists())

            lines = out_log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            self.assertIn(f"|one.bin|1|{md4_raw(b'x').hex().upper()}|/", lines[0])

    def test_single_file_input_keep_dirs_writes_files_log(self):
        from python_port.ed2k115_calc import md4_raw

        script_path = Path(__file__).resolve().parents[1] / "ed2k115_calc.py"

        with tempfile.TemporaryDirectory() as td:
            input_file = Path(td) / "one.bin"
            input_file.write_bytes(b"x")
            out_dir = Path(td) / "out"

            run = subprocess.run(
                [sys.executable, str(script_path), str(input_file), "--out", str(out_dir), "--keep-dirs"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(run.returncode, 0, msg=run.stderr)

            out_log = out_dir / "files.ed2k.log"
            self.assertTrue(out_log.exists())
            lines = out_log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            self.assertIn(f"|one.bin|1|{md4_raw(b'x').hex().upper()}|/", lines[0])

    def test_cli_url_encode_option_affects_emitted_link_name(self):
        script_path = Path(__file__).resolve().parents[1] / "ed2k115_calc.py"

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "input"
            root.mkdir()
            file_name = "日本語 file|x.txt"
            (root / file_name).write_bytes(b"x")

            out_default = Path(td) / "default.ed2k.log"
            run_default = subprocess.run(
                [sys.executable, str(script_path), str(root), "--out", str(out_default)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(run_default.returncode, 0, msg=run_default.stderr)
            default_line = out_default.read_text(encoding="utf-8").splitlines()[0]
            self.assertIn("|日本語 file%7Cx.txt|", default_line)

            out_encoded = Path(td) / "encoded.ed2k.log"
            run_encoded = subprocess.run(
                [sys.executable, str(script_path), str(root), "--out", str(out_encoded), "--url-encode"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(run_encoded.returncode, 0, msg=run_encoded.stderr)
            encoded_line = out_encoded.read_text(encoding="utf-8").splitlines()[0]
            self.assertIn("|%E6%97%A5%E6%9C%AC%E8%AA%9E%20file%7Cx.txt|", encoded_line)

    def test_flat_mode_does_not_self_ingest_output_file_inside_input_tree(self):
        script_path = Path(__file__).resolve().parents[1] / "ed2k115_calc.py"

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "input"
            root.mkdir()
            (root / "payload.bin").write_bytes(b"abc")

            out_dir = root / "logs"
            out_dir.mkdir()
            out_log = out_dir / "flat.ed2k.log"

            first = subprocess.run(
                [sys.executable, str(script_path), str(root), "--out", str(out_log)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(first.returncode, 0, msg=first.stderr)

            second = subprocess.run(
                [sys.executable, str(script_path), str(root), "--out", str(out_log)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(second.returncode, 0, msg=second.stderr)

            lines = out_log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            self.assertIn("|payload.bin|", lines[0])

    def test_keep_dirs_mode_does_not_self_ingest_generated_logs_inside_input_tree(self):
        script_path = Path(__file__).resolve().parents[1] / "ed2k115_calc.py"

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "input"
            root.mkdir()
            (root / "root.bin").write_bytes(b"r")
            (root / "sub").mkdir()
            (root / "sub" / "child.bin").write_bytes(b"c")

            out_dir = root / "out"

            first = subprocess.run(
                [sys.executable, str(script_path), str(root), "--out", str(out_dir), "--keep-dirs"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(first.returncode, 0, msg=first.stderr)

            second = subprocess.run(
                [sys.executable, str(script_path), str(root), "--out", str(out_dir), "--keep-dirs"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(second.returncode, 0, msg=second.stderr)

            root_log = out_dir / "files.ed2k.log"
            sub_log = out_dir / "sub" / "files.ed2k.log"
            nested_generated = out_dir / "out" / "files.ed2k.log"

            self.assertTrue(root_log.exists())
            self.assertTrue(sub_log.exists())
            self.assertFalse(nested_generated.exists())

            root_lines = root_log.read_text(encoding="utf-8").splitlines()
            sub_lines = sub_log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(root_lines), 1)
            self.assertEqual(len(sub_lines), 1)
            self.assertIn("|root.bin|", root_lines[0])
            self.assertIn("|child.bin|", sub_lines[0])


class TestCheckpointResume(unittest.TestCase):
    def make_task_key(self, label: str) -> str:
        return f"task6-{label}-{uuid.uuid4().hex}"

    def checkpoint_db_path(self, task_key: str) -> Path:
        return Path(tempfile.gettempdir()) / "ed2k115-checkpoints" / f"{task_key}.sqlite3"

    def cleanup_checkpoint_db(self, task_key: str):
        db_path = self.checkpoint_db_path(task_key)
        if db_path.exists():
            db_path.unlink()

    def test_resume_after_interruption_skips_completed_unchanged_files(self):
        from python_port import ed2k115_calc as calc

        task_key = self.make_task_key("resume-interrupt")
        self.cleanup_checkpoint_db(task_key)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "input"
            root.mkdir()
            (root / "one.bin").write_bytes(b"111")
            (root / "two.bin").write_bytes(b"2222")
            out_log = Path(td) / "flat.ed2k.log"

            with mock.patch.object(calc, "build_task_key", return_value=task_key):
                with mock.patch.object(
                    calc,
                    "ed2k_115_stream",
                    side_effect=["A" * 32, RuntimeError("simulated interruption")],
                ) as hasher:
                    with self.assertRaisesRegex(RuntimeError, "simulated interruption"):
                        calc.main([str(root), "--out", str(out_log)])
                    self.assertEqual(hasher.call_count, 2)

                with mock.patch.object(
                    calc,
                    "ed2k_115_stream",
                    return_value="B" * 32,
                ) as hasher:
                    second_rc = calc.main([str(root), "--out", str(out_log)])
                    self.assertEqual(second_rc, 0)
                    self.assertEqual(hasher.call_count, 1)

            lines = out_log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 2)
            self.assertTrue(any("A" * 32 in line for line in lines))
            self.assertTrue(any("B" * 32 in line for line in lines))

            db_path = self.checkpoint_db_path(task_key)
            with sqlite3.connect(db_path) as conn:
                row_count = conn.execute("SELECT COUNT(*) FROM file_state").fetchone()[0]
            self.assertEqual(row_count, 2)

        self.cleanup_checkpoint_db(task_key)

    def test_file_change_triggers_rehash_and_record_replacement(self):
        from python_port import ed2k115_calc as calc

        task_key = self.make_task_key("rehash")
        self.cleanup_checkpoint_db(task_key)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "input"
            root.mkdir()
            file_path = root / "changed.bin"
            file_path.write_bytes(b"first")
            out_log = Path(td) / "flat.ed2k.log"

            with mock.patch.object(calc, "build_task_key", return_value=task_key):
                with mock.patch.object(calc, "ed2k_115_stream", return_value="A" * 32) as hasher:
                    first_rc = calc.main([str(root), "--out", str(out_log)])
                    self.assertEqual(first_rc, 0)
                    self.assertEqual(hasher.call_count, 1)

                file_path.write_bytes(b"second-version")

                with mock.patch.object(calc, "ed2k_115_stream", return_value="B" * 32) as hasher:
                    second_rc = calc.main([str(root), "--out", str(out_log)])
                    self.assertEqual(second_rc, 0)
                    self.assertEqual(hasher.call_count, 1)

            line = out_log.read_text(encoding="utf-8").strip()
            self.assertIn("B" * 32, line)
            self.assertNotIn("A" * 32, line)

            db_path = self.checkpoint_db_path(task_key)
            with sqlite3.connect(db_path) as conn:
                row_count = conn.execute("SELECT COUNT(*) FROM file_state WHERE rel_path = ?", ("changed.bin",)).fetchone()[0]
                row = conn.execute(
                    "SELECT size, hash_hex FROM file_state WHERE rel_path = ?",
                    ("changed.bin",),
                ).fetchone()
            self.assertEqual(row_count, 1)
            self.assertEqual(row[0], len(b"second-version"))
            self.assertEqual(row[1], "B" * 32)

        self.cleanup_checkpoint_db(task_key)


class TestDryRun(unittest.TestCase):
    def test_dry_run_no_state_and_no_log_written(self):
        from python_port.ed2k115_calc import build_task_key

        script_path = Path(__file__).resolve().parents[1] / "ed2k115_calc.py"

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "input"
            root.mkdir()
            (root / "one.bin").write_bytes(b"111")
            (root / "sub").mkdir()
            (root / "sub" / "two.bin").write_bytes(b"22")

            out_log = Path(td) / "logs" / "flat.ed2k.log"
            task_key = build_task_key(root, out_log, keep_dirs=False, url_encode=False)
            db_path = Path(tempfile.gettempdir()) / "ed2k115-checkpoints" / f"{task_key}.sqlite3"
            if db_path.exists():
                db_path.unlink()
            self.addCleanup(lambda: db_path.unlink() if db_path.exists() else None)

            run = subprocess.run(
                [sys.executable, str(script_path), str(root), "--out", str(out_log), "--dry-run"],
                capture_output=True,
                text=True,
            )

            self.assertEqual(run.returncode, 0, msg=run.stderr)
            self.assertEqual(
                run.stdout.splitlines(),
                [
                    "planned files: 2",
                    "planned targets: 1",
                    str(out_log),
                ],
            )
            self.assertFalse(out_log.exists())
            self.assertFalse(out_log.parent.exists())
            self.assertFalse(db_path.exists())

    def test_dry_run_keep_dirs_multi_targets_no_state_and_no_logs(self):
        from python_port.ed2k115_calc import build_task_key

        script_path = Path(__file__).resolve().parents[1] / "ed2k115_calc.py"

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "input"
            root.mkdir()
            (root / "root.bin").write_bytes(b"r")
            (root / "sub").mkdir()
            (root / "sub" / "child.bin").write_bytes(b"c")

            out_dir = Path(td) / "out"
            root_target = out_dir / "files.ed2k.log"
            sub_target = out_dir / "sub" / "files.ed2k.log"

            task_key = build_task_key(root, out_dir, keep_dirs=True, url_encode=False)
            db_path = Path(tempfile.gettempdir()) / "ed2k115-checkpoints" / f"{task_key}.sqlite3"
            if db_path.exists():
                db_path.unlink()
            self.addCleanup(lambda: db_path.unlink() if db_path.exists() else None)

            run = subprocess.run(
                [sys.executable, str(script_path), str(root), "--out", str(out_dir), "--keep-dirs", "--dry-run"],
                capture_output=True,
                text=True,
            )

            self.assertEqual(run.returncode, 0, msg=run.stderr)
            self.assertEqual(
                run.stdout.splitlines(),
                [
                    "planned files: 2",
                    "planned targets: 2",
                    str(root_target),
                    str(sub_target),
                ],
            )
            self.assertFalse(root_target.exists())
            self.assertFalse(sub_target.exists())
            self.assertFalse(out_dir.exists())
            self.assertFalse(db_path.exists())
