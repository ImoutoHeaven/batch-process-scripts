import contextlib
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
import zipfile


def _load_cli():
    here = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "advdecompress_lite_cli_test_module",
        here / "advDecompress_lite.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.path.insert(0, str(here))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


class FakeLayout:
    @staticmethod
    def validate_policy(_policy):
        return None

    @staticmethod
    def place_output(extracted, output_dir, _archive_name, _policy, _conflict_mode):
        output_dir.mkdir(parents=True, exist_ok=True)
        introduced = []
        for item in list(extracted.iterdir()):
            destination = output_dir / item.name
            os.replace(str(item), str(destination))
            introduced.append(destination)
        return tuple(introduced)


class FakeArchiveIO:
    extract_calls = 0
    password_calls = 0
    fix_calls = 0
    action = "extract"
    extract_error = None
    inspection_error = None

    @classmethod
    def reset(cls):
        cls.extract_calls = 0
        cls.password_calls = 0
        cls.fix_calls = 0
        cls.action = "extract"
        cls.extract_error = None
        cls.inspection_error = None

    @staticmethod
    def parse_depth_range(value):
        return value

    @staticmethod
    def parse_file_size(value):
        return value

    @classmethod
    def discover_archives(cls, args):
        root = Path(args.path)
        archive = root / "archive.zip"
        return [
            SimpleNamespace(
                entry=archive,
                volumes=(archive,),
                stem="archive",
                kind="zip",
                multi=False,
                format="zip",
                error=None,
            )
        ]

    @classmethod
    def PasswordCandidates(cls, _args):
        cls.password_calls += 1
        return object()

    @classmethod
    def inspect_zip_policy(cls, _group, _args):
        if cls.inspection_error:
            raise cls.inspection_error
        return cls.action, None, "test policy"

    @classmethod
    def extract_archive(cls, _group, destination, _args, _passwords, zip_codepage=None):
        cls.extract_calls += 1
        if cls.extract_error:
            raise cls.extract_error
        (destination / "payload.txt").write_text("payload", encoding="utf-8")

    @classmethod
    def fix_extensions(cls, _args):
        cls.fix_calls += 1
        return ()


class TestLiteCli(unittest.TestCase):
    def setUp(self):
        self.cli = _load_cli()
        self.real_archive_io = self.cli.archive_io
        self.real_layout = self.cli.layout
        self.cli.archive_io = FakeArchiveIO
        self.cli.layout = FakeLayout
        FakeArchiveIO.reset()

    def _root_with_archive(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        (root / "archive.zip").write_bytes(b"archive")
        return td, root

    def test_default_output_equal_to_input_is_valid(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "archive.zip").write_bytes(b"archive")
            args = self.cli.parse_args([str(root), "--no-lock"])
            self.cli._validate_paths(args)
            self.assertEqual(root.resolve(), Path(args.output_base).resolve())

    def test_reparse_ancestor_blocks_extension_fix_before_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            junction = root / "junction"
            source = junction / "existing" / "input"
            source.mkdir(parents=True)
            original = source / "keep.bad"
            original.write_bytes(b"source")
            output = root / "output"

            def mark_junction(path):
                return path == junction

            with mock.patch.object(
                self.cli, "_is_reparse_point", side_effect=mark_junction
            ):
                result = self.cli.main(
                    [
                        str(source),
                        "--output",
                        str(output),
                        "--fix-ext",
                        "--fix-extension-threshold",
                        "0",
                        "--no-lock",
                    ]
                )

            self.assertEqual(1, result)
            self.assertEqual(0, FakeArchiveIO.fix_calls)
            self.assertTrue(original.exists())
            self.assertFalse((source / "keep.zip").exists())
            self.assertFalse(output.exists())

    def test_invalid_password_utf8_is_rejected_before_extension_fix(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            malformed_archive = root / "keep.data"
            with zipfile.ZipFile(str(malformed_archive), "w") as stream:
                stream.writestr("payload.txt", "payload")
            password_file = root / "passwords.txt"
            password_file.write_bytes(b"\xff\n")

            self.cli.archive_io = self.real_archive_io
            self.cli.layout = self.real_layout
            with mock.patch.object(self.cli.shutil, "which", return_value="7z"):
                result = self.cli.main(
                    [
                        str(root),
                        "--password-file",
                        str(password_file),
                        "--fix-ext",
                        "--fix-extension-threshold",
                        "0",
                        "--no-lock",
                    ]
                )

            self.assertEqual(1, result)
            self.assertTrue(malformed_archive.exists())
            self.assertFalse((root / "keep.zip").exists())

    def test_regular_file_destination_ancestor_blocks_extension_fix(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "input"
            source.mkdir()
            original = source / "keep.data"
            original.write_bytes(b"source")
            existing_file = root / "existing-file"
            existing_file.write_bytes(b"cannot contain a child")
            output = existing_file / "child"

            with mock.patch.object(self.cli.shutil, "which", return_value="7z"):
                result = self.cli.main(
                    [
                        str(source),
                        "--output",
                        str(output),
                        "--fix-ext",
                        "--fix-extension-threshold",
                        "0",
                        "--no-lock",
                    ]
                )

            self.assertEqual(1, result)
            self.assertEqual(0, FakeArchiveIO.fix_calls)
            self.assertTrue(original.exists())
            self.assertFalse(output.exists())

    def test_dry_run_does_not_fix_extract_or_create_workspace(self):
        td, root = self._root_with_archive()
        try:
            with mock.patch.object(self.cli.shutil, "which", return_value="7z"):
                result = self.cli.main(
                    [str(root), "--dry-run", "--fix-ext", "--no-lock"]
                )
            self.assertEqual(0, result)
            self.assertEqual(1, FakeArchiveIO.fix_calls)
            self.assertEqual(0, FakeArchiveIO.password_calls)
            self.assertEqual(0, FakeArchiveIO.extract_calls)
            self.assertTrue((root / "archive.zip").exists())
            self.assertFalse((root / ".advdecompress_lite_tmp").exists())
        finally:
            td.cleanup()

    def test_extraction_failure_moves_group_to_failure_destination(self):
        td, root = self._root_with_archive()
        failure = root / "failed"
        FakeArchiveIO.extract_error = RuntimeError("bad archive")
        try:
            with mock.patch.object(self.cli.shutil, "which", return_value="7z"):
                result = self.cli.main(
                    [
                        str(root),
                        "--no-lock",
                        "--fail-policy",
                        "move",
                        "--fail-to",
                        str(failure),
                    ]
                )
            self.assertEqual(1, result)
            self.assertFalse((root / "archive.zip").exists())
            self.assertTrue((failure / "archive.zip").exists())
        finally:
            td.cleanup()

    def test_skip_does_not_run_source_policies(self):
        td, root = self._root_with_archive()
        FakeArchiveIO.action = "skip"
        try:
            with mock.patch.object(self.cli.shutil, "which", return_value="7z"):
                result = self.cli.main(
                    [
                        str(root),
                        "--no-lock",
                        "--success-policy",
                        "delete",
                    ]
                )
            self.assertEqual(0, result)
            self.assertTrue((root / "archive.zip").exists())
            self.assertEqual(0, FakeArchiveIO.extract_calls)
        finally:
            td.cleanup()

    def test_dry_run_orphan_does_not_move_sources_or_remove_workspace_root(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            orphan = root / "orphan.7z.002"
            orphan.write_bytes(b"orphan")
            workspace_root = root / ".advdecompress_lite_tmp"
            workspace_root.mkdir()
            failure = root / "failed"
            args = self.cli.parse_args(
                [
                    str(root),
                    "--dry-run",
                    "--no-lock",
                    "--fail-policy",
                    "move",
                    "--fail-to",
                    str(failure),
                ]
            )
            self.cli._validate_paths(args)
            group = SimpleNamespace(
                entry=None,
                volumes=(orphan,),
                stem="orphan",
                kind="7z",
                multi=True,
                format="7z",
                error="missing primary 7z volume",
            )
            result = self.cli._process_group(group, args, None)
            self.assertEqual("dry-run", result["status"])
            self.assertTrue(orphan.exists())
            self.assertTrue(workspace_root.exists())
            self.assertFalse(failure.exists())

    def test_malformed_utf8_zip_inspection_dry_run_keeps_sources(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            archive = root / "malformed.zip"
            with zipfile.ZipFile(str(archive), "w") as stream:
                stream.writestr("name.txt", "payload")
            data = bytearray(archive.read_bytes())
            for signature, name_offset, flag_offset in (
                (b"PK\x03\x04", 30, 6),
                (b"PK\x01\x02", 46, 8),
            ):
                header = data.index(signature)
                data[header + flag_offset] |= 0x00
                data[header + flag_offset + 1] |= 0x08
                data[header + name_offset : header + name_offset + 8] = b"\xffame.txt"
            archive.write_bytes(data)

            self.cli.archive_io = self.real_archive_io
            self.cli.layout = self.real_layout
            failure = root / "failed"
            with mock.patch.object(self.cli.shutil, "which", return_value="7z"):
                self.cli.main(
                    [
                        str(root),
                        "--dry-run",
                        "--no-lock",
                        "--fail-policy",
                        "move",
                        "--fail-to",
                        str(failure),
                    ]
                )

            self.assertTrue(archive.exists())
            self.assertFalse(failure.exists())
            self.assertFalse((root / ".advdecompress_lite_tmp").exists())

    def test_dry_run_inspection_error_does_not_apply_failure_move(self):
        td, root = self._root_with_archive()
        failure = root / "failed"
        FakeArchiveIO.inspection_error = RuntimeError("inspection failed")
        try:
            with mock.patch.object(self.cli.shutil, "which", return_value="7z"):
                result = self.cli.main(
                    [
                        str(root),
                        "--dry-run",
                        "--no-lock",
                        "--fail-policy",
                        "move",
                        "--fail-to",
                        str(failure),
                    ]
                )
            self.assertEqual(1, result)
            self.assertTrue((root / "archive.zip").exists())
            self.assertFalse(failure.exists())
            self.assertFalse((root / ".advdecompress_lite_tmp").exists())
        finally:
            td.cleanup()

    def test_delete_failure_warns_but_success_is_retained(self):
        td, root = self._root_with_archive()
        output = io.StringIO()
        try:
            with mock.patch.object(self.cli.shutil, "which", return_value="7z"):
                with mock.patch.object(
                    self.cli.Path,
                    "unlink",
                    side_effect=OSError("delete denied"),
                ):
                    with contextlib.redirect_stdout(output):
                        result = self.cli.main(
                            [str(root), "--no-lock", "--success-policy", "delete"]
                        )
            self.assertEqual(0, result)
            self.assertIn("Warning: could not delete", output.getvalue())
            self.assertIn("Successfully processed: 1", output.getvalue())
        finally:
            td.cleanup()

    def test_group_collision_uses_one_container_for_all_volumes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source_root = root / "source"
            destination = root / "destination"
            source_root.mkdir()
            destination.mkdir()
            folder = source_root / "nested"
            folder.mkdir()
            first = folder / "set.zip"
            second = folder / "set.z01"
            first.write_bytes(b"first")
            second.write_bytes(b"second")
            (destination / "nested").mkdir()
            (destination / "nested" / "set.zip").write_bytes(b"existing")
            group = SimpleNamespace(volumes=(first, second))

            moved = self.cli._move_group(group, destination, source_root)
            containers = {pair[1].parent.parent for pair in moved}
            self.assertEqual(1, len(containers))
            self.assertNotEqual(destination, next(iter(containers)))
            self.assertEqual(b"first", (next(iter(containers)) / "nested" / "set.zip").read_bytes())
            self.assertEqual(b"second", (next(iter(containers)) / "nested" / "set.z01").read_bytes())


if __name__ == "__main__":
    unittest.main()
