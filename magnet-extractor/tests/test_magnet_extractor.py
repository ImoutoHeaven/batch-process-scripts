import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "magnet_extractor.py"
README = SCRIPT.parent / "README.md"
WORKTREE_ROOT = SCRIPT.parents[1]
README_FLAT_COMMAND = "python3 magnet-extractor/magnet_extractor.py /tmp/torf-test -o /tmp/torf-test-flat/files.magnet.txt"
README_KEEP_COMMAND = "python3 magnet-extractor/magnet_extractor.py /tmp/torf-test --keep-dirs -o /tmp/torf-test-keep"
MODULE_SPEC = importlib.util.spec_from_file_location("magnet_extractor", SCRIPT)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
magnet_extractor = importlib.util.module_from_spec(MODULE_SPEC)
sys.modules[MODULE_SPEC.name] = magnet_extractor
MODULE_SPEC.loader.exec_module(magnet_extractor)


def remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def bencode(value):
    if isinstance(value, int):
        return b"i" + str(value).encode("ascii") + b"e"
    if isinstance(value, bytes):
        return str(len(value)).encode("ascii") + b":" + value
    if isinstance(value, str):
        return bencode(value.encode("utf-8"))
    if isinstance(value, list):
        return b"l" + b"".join(bencode(item) for item in value) + b"e"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda item: item[0])
        return b"d" + b"".join(bencode(key) + bencode(item) for key, item in items) + b"e"
    raise TypeError(type(value))


def make_v1_torrent_bytes(name: str) -> bytes:
    info = {
        b"length": 1,
        b"name": name.encode("utf-8"),
        b"piece length": 16384,
        b"pieces": b"\x00" * 20,
    }
    return bencode({b"announce": b"https://tracker.invalid/announce", b"info": info})


def make_v1_torrent_bytes_with_raw_names(name: bytes, name_utf8: bytes | None = None) -> bytes:
    info = {
        b"length": 1,
        b"name": name,
        b"piece length": 16384,
        b"pieces": b"\x00" * 20,
    }
    if name_utf8 is not None:
        info[b"name.utf-8"] = name_utf8
    return bencode({b"info": info})


def make_v2_torrent_bytes(name: str) -> bytes:
    info = {
        b"file tree": {name.encode("utf-8"): {b"": {b"length": 1, b"pieces root": b"\x11" * 32}}},
        b"meta version": 2,
        b"name": name.encode("utf-8"),
        b"piece length": 16384,
    }
    return bencode({b"info": info})


def make_hybrid_torrent_bytes(name: str) -> bytes:
    info = {
        b"file tree": {name.encode("utf-8"): {b"": {b"length": 1, b"pieces root": b"\x22" * 32}}},
        b"length": 1,
        b"meta version": 2,
        b"name": name.encode("utf-8"),
        b"piece length": 16384,
        b"pieces": b"\x00" * 20,
    }
    return bencode({b"info": info})


def magnet_for_payload(payload: bytes) -> str:
    meta = magnet_extractor.extract_torrent_metadata_from_bytes(payload)
    return magnet_extractor.build_magnet(meta)


class TestCliContract(unittest.TestCase):
    def test_help_mentions_keep_dirs_and_output(self):
        run = subprocess.run([sys.executable, str(SCRIPT), "--help"], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0)
        self.assertIn("--keep-dirs", run.stdout)
        self.assertIn("-o", run.stdout)

    def test_missing_input_dir_fails(self):
        with tempfile.TemporaryDirectory() as td:
            missing_dir = Path(td) / "does-not-exist"
            run = subprocess.run([sys.executable, str(SCRIPT), str(missing_dir)], capture_output=True, text=True)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("input directory does not exist", run.stderr)


class TestMetadataExtraction(unittest.TestCase):
    def test_v1_only_outputs_btih_and_dn(self):
        meta = magnet_extractor.extract_torrent_metadata_from_bytes(make_v1_torrent_bytes("movie.mkv"))
        magnet = magnet_extractor.build_magnet(meta)

        self.assertTrue(meta.has_v1)
        self.assertFalse(meta.has_v2)
        self.assertEqual(meta.dn, "movie.mkv")
        self.assertEqual(meta.btih, "42bc335394a1f2ff5c4f6af7d35dd4d5baa82f06")
        self.assertIsNone(meta.btmh)
        self.assertEqual(magnet, "magnet:?xt=urn:btih:42bc335394a1f2ff5c4f6af7d35dd4d5baa82f06&dn=movie.mkv")

    def test_v2_only_outputs_btmh_and_dn(self):
        meta = magnet_extractor.extract_torrent_metadata_from_bytes(make_v2_torrent_bytes("album"))
        magnet = magnet_extractor.build_magnet(meta)

        self.assertFalse(meta.has_v1)
        self.assertTrue(meta.has_v2)
        self.assertEqual(meta.dn, "album")
        self.assertIsNone(meta.btih)
        self.assertEqual(meta.btmh, "122021a27ae24a7a6dbdd453f52b1a881527f0d80b1e2756818a0641972c22d7bd58")
        self.assertEqual(magnet, "magnet:?xt=urn:btmh:122021a27ae24a7a6dbdd453f52b1a881527f0d80b1e2756818a0641972c22d7bd58&dn=album")

    def test_hybrid_outputs_both_xt_values(self):
        meta = magnet_extractor.extract_torrent_metadata_from_bytes(make_hybrid_torrent_bytes("bundle"))
        magnet = magnet_extractor.build_magnet(meta)

        self.assertEqual(meta.btih, "a680ef4b50cf1bb1a6d9c91c0c7ba8bc78ba9cd8")
        self.assertEqual(meta.btmh, "1220d1814b1f1ec8afb51514770eec1dba272fd962e7667ca9c73c233b1f8558bbc1")
        self.assertEqual(
            magnet,
            "magnet:?xt=urn:btih:a680ef4b50cf1bb1a6d9c91c0c7ba8bc78ba9cd8&xt=urn:btmh:1220d1814b1f1ec8afb51514770eec1dba272fd962e7667ca9c73c233b1f8558bbc1&dn=bundle",
        )

    def test_name_utf8_wins_over_name(self):
        info = {
            b"length": 1,
            b"name": b"fallback.bin",
            b"name.utf-8": "日本語.bin".encode("utf-8"),
            b"piece length": 16384,
            b"pieces": b"\x00" * 20,
        }
        payload = bencode({b"info": info})

        meta = magnet_extractor.extract_torrent_metadata_from_bytes(payload)

        self.assertEqual(meta.dn, "日本語.bin")
        self.assertEqual(meta.btih, "5476c282dc20cd77a28ae21bfb220fb6df8c9c87")
        self.assertEqual(
            magnet_extractor.build_magnet(meta),
            "magnet:?xt=urn:btih:5476c282dc20cd77a28ae21bfb220fb6df8c9c87&dn=%E6%97%A5%E6%9C%AC%E8%AA%9E.bin",
        )

    def test_rejects_torrent_with_neither_v1_nor_v2_metadata(self):
        payload = bencode({b"info": {b"name": b"plain", b"piece length": 16384}})

        with self.assertRaisesRegex(ValueError, "torrent has neither v1 nor v2 metadata"):
            magnet_extractor.extract_torrent_metadata_from_bytes(payload)

    def test_invalid_display_name_utf8_raises_value_error(self):
        payload = make_v1_torrent_bytes_with_raw_names(b"fallback.bin", name_utf8=b"\xffbad")

        with self.assertRaisesRegex(ValueError, "torrent name must be valid UTF-8"):
            magnet_extractor._extract_torrent_metadata_from_bytes_py(payload)


class TestNativeParity(unittest.TestCase):
    def assert_native_matches_python_on_payload(self, payload: bytes):
        native = magnet_extractor._load_native_parser()
        if native is None:
            self.skipTest("native module unavailable; run maturin develop --manifest-path magnet-extractor/native/Cargo.toml")

        py_meta = magnet_extractor._extract_torrent_metadata_from_bytes_py(payload)
        native_meta = magnet_extractor._extract_torrent_metadata_from_bytes_native(payload)
        self.assertEqual(py_meta, native_meta)

    def test_loader_falls_back_when_native_is_missing(self):
        payload = make_hybrid_torrent_bytes("bundle")

        with mock.patch.object(magnet_extractor, "_load_native_parser", return_value=None):
            meta = magnet_extractor.extract_torrent_metadata_from_bytes(payload)

        self.assertTrue(meta.has_v1)
        self.assertTrue(meta.has_v2)
        self.assertEqual(meta.dn, "bundle")

    def test_loader_falls_back_when_native_extraction_raises(self):
        payload = make_hybrid_torrent_bytes("bundle")
        expected = magnet_extractor._extract_torrent_metadata_from_bytes_py(payload)
        native = mock.Mock()
        native.extract_torrent_metadata.side_effect = RuntimeError("native exploded")

        with mock.patch.object(magnet_extractor, "_load_native_parser", return_value=native):
            meta = magnet_extractor.extract_torrent_metadata_from_bytes(payload)

        self.assertEqual(meta, expected)

    def test_native_matches_python_on_v1_fixture(self):
        self.assert_native_matches_python_on_payload(make_v1_torrent_bytes("movie.mkv"))

    def test_native_matches_python_on_v2_fixture(self):
        self.assert_native_matches_python_on_payload(make_v2_torrent_bytes("album"))

    def test_native_matches_python_on_hybrid_fixture(self):
        self.assert_native_matches_python_on_payload(make_hybrid_torrent_bytes("bundle"))

    def test_native_matches_python_error_on_invalid_display_name(self):
        native = magnet_extractor._load_native_parser()
        if native is None:
            self.skipTest("native module unavailable; run maturin develop --manifest-path magnet-extractor/native/Cargo.toml")

        payload = make_v1_torrent_bytes_with_raw_names(b"fallback.bin", name_utf8=b"\xffbad")

        for extractor in (
            magnet_extractor._extract_torrent_metadata_from_bytes_py,
            magnet_extractor._extract_torrent_metadata_from_bytes_native,
        ):
            with self.subTest(extractor=extractor.__name__):
                with self.assertRaisesRegex(ValueError, "torrent name must be valid UTF-8"):
                    extractor(payload)


class TestOutputModes(unittest.TestCase):
    def test_flat_mode_writes_single_files_magnet_txt(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "input"
            root.mkdir()

            alpha_payload = make_v1_torrent_bytes("alpha.bin")
            zulu_payload = make_v2_torrent_bytes("zulu")
            child_payload = make_hybrid_torrent_bytes("child")

            (root / "Z.TORRENT").write_bytes(zulu_payload)
            (root / "alpha.torrent").write_bytes(alpha_payload)
            (root / "sub").mkdir()
            (root / "sub" / "child.torrent").write_bytes(child_payload)
            out_file = Path(td) / "flat" / "files.magnet.txt"

            run = subprocess.run(
                [sys.executable, str(SCRIPT), str(root), "-o", str(out_file)],
                capture_output=True,
                text=True,
            )

            self.assertEqual(run.returncode, 0, msg=run.stderr)
            self.assertEqual(
                out_file.read_text(encoding="utf-8").splitlines(),
                [
                    magnet_for_payload(alpha_payload),
                    magnet_for_payload(zulu_payload),
                    magnet_for_payload(child_payload),
                ],
            )

    def test_keep_dirs_writes_one_file_per_directory(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "input"
            root.mkdir()

            alpha_payload = make_v1_torrent_bytes("alpha.bin")
            beta_payload = make_v2_torrent_bytes("beta")
            child_payload = make_hybrid_torrent_bytes("child")
            grand_payload = make_v2_torrent_bytes("grand")

            (root / "Beta.TORRENT").write_bytes(beta_payload)
            (root / "alpha.torrent").write_bytes(alpha_payload)
            (root / "sub").mkdir()
            (root / "sub" / "child.torrent").write_bytes(child_payload)
            (root / "sub" / "deep").mkdir()
            (root / "sub" / "deep" / "grand.torrent").write_bytes(grand_payload)
            out_dir = Path(td) / "out"

            run = subprocess.run(
                [sys.executable, str(SCRIPT), str(root), "--keep-dirs", "-o", str(out_dir)],
                capture_output=True,
                text=True,
            )

            self.assertEqual(run.returncode, 0, msg=run.stderr)
            self.assertEqual(
                (out_dir / "files.magnet.txt").read_text(encoding="utf-8").splitlines(),
                [magnet_for_payload(alpha_payload), magnet_for_payload(beta_payload)],
            )
            self.assertEqual(
                (out_dir / "sub" / "files.magnet.txt").read_text(encoding="utf-8").splitlines(),
                [magnet_for_payload(child_payload)],
            )
            self.assertEqual(
                (out_dir / "sub" / "deep" / "files.magnet.txt").read_text(encoding="utf-8").splitlines(),
                [magnet_for_payload(grand_payload)],
            )

    def test_default_flat_output_is_input_dir_files_magnet_txt(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "input"
            root.mkdir()

            only_payload = make_v1_torrent_bytes("only.bin")
            (root / "only.torrent").write_bytes(only_payload)

            run = subprocess.run([sys.executable, str(SCRIPT), str(root)], capture_output=True, text=True)

            self.assertEqual(run.returncode, 0, msg=run.stderr)
            self.assertEqual(
                (root / "files.magnet.txt").read_text(encoding="utf-8").splitlines(),
                [magnet_for_payload(only_payload)],
            )

    def test_default_keep_dirs_output_is_written_under_input_tree(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "input"
            root.mkdir()

            root_payload = make_v1_torrent_bytes("root.bin")
            child_payload = make_v2_torrent_bytes("child")

            (root / "root.torrent").write_bytes(root_payload)
            (root / "sub").mkdir()
            (root / "sub" / "child.torrent").write_bytes(child_payload)

            run = subprocess.run([sys.executable, str(SCRIPT), str(root), "--keep-dirs"], capture_output=True, text=True)

            self.assertEqual(run.returncode, 0, msg=run.stderr)
            self.assertEqual(
                (root / "files.magnet.txt").read_text(encoding="utf-8").splitlines(),
                [magnet_for_payload(root_payload)],
            )
            self.assertEqual(
                (root / "sub" / "files.magnet.txt").read_text(encoding="utf-8").splitlines(),
                [magnet_for_payload(child_payload)],
            )

    def test_flat_mode_rejects_directory_output_target(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "input"
            root.mkdir()
            (root / "only.torrent").write_bytes(make_v1_torrent_bytes("only.bin"))
            out_dir = Path(td) / "existing-dir"
            out_dir.mkdir()

            run = subprocess.run(
                [sys.executable, str(SCRIPT), str(root), "-o", str(out_dir)],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(run.returncode, 0)
            self.assertIn("flat mode output path must be a file, not a directory", run.stderr)
            self.assertNotIn("Traceback", run.stderr)

    def test_keep_dirs_rejects_file_output_target(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "input"
            root.mkdir()
            (root / "only.torrent").write_bytes(make_v1_torrent_bytes("only.bin"))
            out_file = Path(td) / "existing-file.txt"
            out_file.write_text("already a file\n", encoding="utf-8")

            run = subprocess.run(
                [sys.executable, str(SCRIPT), str(root), "--keep-dirs", "-o", str(out_file)],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(run.returncode, 0)
            self.assertIn("--keep-dirs output path must be a directory, not a file", run.stderr)
            self.assertNotIn("Traceback", run.stderr)

    def test_flat_mode_rejects_output_path_under_file_ancestor(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "input"
            root.mkdir()
            (root / "only.torrent").write_bytes(make_v1_torrent_bytes("only.bin"))
            blocker = Path(td) / "blocker"
            blocker.write_text("already a file\n", encoding="utf-8")

            run = subprocess.run(
                [sys.executable, str(SCRIPT), str(root), "-o", str(blocker / "child.txt")],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(run.returncode, 0)
            self.assertIn("flat mode output path must be under directories, not under a file", run.stderr)
            self.assertNotIn("Traceback", run.stderr)

    def test_keep_dirs_rejects_output_root_under_file_ancestor(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "input"
            root.mkdir()
            (root / "only.torrent").write_bytes(make_v1_torrent_bytes("only.bin"))
            blocker = Path(td) / "blocker"
            blocker.write_text("already a file\n", encoding="utf-8")

            run = subprocess.run(
                [sys.executable, str(SCRIPT), str(root), "--keep-dirs", "-o", str(blocker / "out-root")],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(run.returncode, 0)
            self.assertIn("--keep-dirs output path must be under directories, not under a file", run.stderr)
            self.assertNotIn("Traceback", run.stderr)

    def test_flat_mode_rejects_output_path_under_broken_symlink_ancestor(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "input"
            root.mkdir()
            (root / "only.torrent").write_bytes(make_v1_torrent_bytes("only.bin"))
            broken = Path(td) / "broken-link"
            broken.symlink_to(Path(td) / "missing-target")

            run = subprocess.run(
                [sys.executable, str(SCRIPT), str(root), "-o", str(broken / "child.txt")],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(run.returncode, 0)
            self.assertIn("flat mode output path must be under directories, not under a broken symlink", run.stderr)
            self.assertNotIn("Traceback", run.stderr)

    def test_keep_dirs_rejects_output_root_under_broken_symlink_ancestor(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "input"
            root.mkdir()
            (root / "only.torrent").write_bytes(make_v1_torrent_bytes("only.bin"))
            broken = Path(td) / "broken-link"
            broken.symlink_to(Path(td) / "missing-target")

            run = subprocess.run(
                [sys.executable, str(SCRIPT), str(root), "--keep-dirs", "-o", str(broken / "out-root")],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(run.returncode, 0)
            self.assertIn("--keep-dirs output path must be under directories, not under a broken symlink", run.stderr)
            self.assertNotIn("Traceback", run.stderr)


class TestStrictBencodeParsing(unittest.TestCase):
    def test_rejects_malformed_integer(self):
        payload = b"d4:infod6:lengthi01e4:name4:test12:piece lengthi16384e6:pieces20:" + bytes(20) + b"ee"

        with self.assertRaises(ValueError):
            magnet_extractor.extract_torrent_metadata_from_bytes(payload)

    def test_rejects_malformed_string_length(self):
        payload = b"d4:infod6:lengthi1e4:name5:test12:piece lengthi16384e6:pieces20:" + bytes(20) + b"ee"

        with self.assertRaises(ValueError):
            magnet_extractor.extract_torrent_metadata_from_bytes(payload)

    def test_rejects_unsorted_dictionary_keys(self):
        payload = (
            b"d4:infod4:name4:test6:lengthi1e12:piece lengthi16384e6:pieces20:"
            + bytes(20)
            + b"ee"
        )

        with self.assertRaises(ValueError):
            magnet_extractor.extract_torrent_metadata_from_bytes(payload)


class TestTmpTorfSmoke(unittest.TestCase):
    def test_readme_quickstart_commands_work_against_tmp_fixture(self):
        readme_text = README.read_text(encoding="utf-8")
        self.assertIn(README_FLAT_COMMAND, readme_text)
        self.assertIn(README_KEEP_COMMAND, readme_text)

        root = Path("/tmp/torf-test")
        flat_out = Path("/tmp/torf-test-flat/files.magnet.txt")
        keep_out = Path("/tmp/torf-test-keep")

        for path in (root, flat_out.parent, keep_out):
            remove_path(path)

        root.mkdir(parents=True)
        root_payload = make_v1_torrent_bytes("root.bin")
        child_payload = make_hybrid_torrent_bytes("child")
        (root / "root.torrent").write_bytes(root_payload)
        (root / "sub").mkdir()
        (root / "sub" / "child.torrent").write_bytes(child_payload)

        flat = subprocess.run(
            [
                sys.executable,
                "magnet-extractor/magnet_extractor.py",
                str(root),
                "-o",
                str(flat_out),
            ],
            cwd=WORKTREE_ROOT,
            capture_output=True,
            text=True,
        )
        keep = subprocess.run(
            [
                sys.executable,
                "magnet-extractor/magnet_extractor.py",
                str(root),
                "--keep-dirs",
                "-o",
                str(keep_out),
            ],
            cwd=WORKTREE_ROOT,
            capture_output=True,
            text=True,
        )

        self.assertEqual(flat.returncode, 0, msg=flat.stderr)
        self.assertEqual(keep.returncode, 0, msg=keep.stderr)
        self.assertEqual(
            flat_out.read_text(encoding="utf-8").splitlines(),
            [magnet_for_payload(root_payload), magnet_for_payload(child_payload)],
        )
        self.assertEqual(
            (keep_out / "files.magnet.txt").read_text(encoding="utf-8").splitlines(),
            [magnet_for_payload(root_payload)],
        )
        self.assertEqual(
            (keep_out / "sub" / "files.magnet.txt").read_text(encoding="utf-8").splitlines(),
            [magnet_for_payload(child_payload)],
        )
