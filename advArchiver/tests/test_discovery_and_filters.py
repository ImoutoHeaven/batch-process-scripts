import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from advArchiver.advArchiver.common import discovery, fs, locking


class DiscoveryTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()


class TestDiscoveryAndFilters(DiscoveryTestCase):
    def test_skip_extension_filter_is_case_insensitive(self):
        self.assertTrue(discovery.should_skip_file("movie.MKV", ["mkv"]))
        self.assertFalse(discovery.should_skip_file("movie.txt", ["zip"]))

    def test_ext_skip_folder_tree_skips_matching_folder(self):
        folder = self.root / "collection"
        nested = folder / "nested"
        nested.mkdir(parents=True)
        (nested / "episode.ZIP").write_text("archive", encoding="utf-8")

        self.assertTrue(
            discovery.folder_contains_skip_extensions(str(folder), ["zip"], debug=False)
        )

    def test_get_items_at_depth_applies_depth_and_filters(self):
        (self.root / "keep.txt").write_text("keep", encoding="utf-8")
        (self.root / "skip.ZIP").write_text("skip", encoding="utf-8")
        (self.root / "empty").mkdir()
        keep_folder = self.root / "keep-folder"
        keep_folder.mkdir()
        (keep_folder / "child.txt").write_text("child", encoding="utf-8")
        skip_folder = self.root / "skip-folder"
        (skip_folder / "nested").mkdir(parents=True)
        (skip_folder / "nested" / "archive.zip").write_text(
            "nested-archive", encoding="utf-8"
        )

        items = discovery.get_items_at_depth(
            str(self.root),
            1,
            skip_files=False,
            skip_folders=False,
            skip_extensions=["zip"],
            ext_skip_folder_tree=True,
            debug=False,
        )

        self.assertEqual(items["files"], [str((self.root / "keep.txt").resolve())])
        self.assertEqual(items["folders"], [str(keep_folder.resolve())])


class TestLocking(unittest.TestCase):
    def test_lock_file_path_uses_platform_specific_temp_dir(self):
        with mock.patch("platform.system", return_value="Linux"):
            self.assertEqual(locking.get_lock_file_path(), "/tmp/advarchiver_comp_lock")

        with mock.patch("platform.system", return_value="Windows"):
            self.assertEqual(
                locking.get_lock_file_path(),
                r"C:\Windows\Temp\advarchiver_comp_lock",
            )


class TestFilesystemHelpers(DiscoveryTestCase):
    def test_validate_input_path_returns_normalized_metadata(self):
        input_dir = self.root / "input"
        input_dir.mkdir()

        result = fs.validate_input_path(str(input_dir), debug=False)

        self.assertEqual(result.path, str(input_dir.resolve()))
        self.assertFalse(result.is_file)
        self.assertTrue(result.is_dir)

    def test_validate_input_path_rejects_missing_paths(self):
        with self.assertRaises(ValueError):
            fs.validate_input_path(str(self.root / "missing"), debug=False)

    def test_output_directory_calculation_honors_out(self):
        nested = self.root / "source" / "nested"
        nested.mkdir(parents=True)
        item_path = nested / "file.txt"
        item_path.write_text("payload", encoding="utf-8")
        out_dir = self.root / "out"

        result = fs.compute_final_output_dir(
            str(item_path), str(self.root / "source"), str(out_dir)
        )

        self.assertEqual(result, str((out_dir / "nested").resolve()))

    def test_temp_directory_is_created_and_cleaned(self):
        tmp_dir = fs.create_unique_tmp_dir(str(self.root), debug=False)

        self.assertIsNotNone(tmp_dir)
        tmp_dir = str(tmp_dir)
        self.assertTrue(os.path.isdir(tmp_dir))
        self.assertTrue(fs.cleanup_tmp_dir(tmp_dir, debug=False))
        self.assertFalse(os.path.exists(tmp_dir))

    def test_move_artifacts_uses_provided_final_output_dir(self):
        source_dir = self.root / "tmp"
        source_dir.mkdir()
        source_file = source_dir / "artifact.7z"
        source_file.write_text("archive", encoding="utf-8")
        final_output_dir = self.root / "out" / "nested"

        moved, moved_files = fs.move_files_to_final_destination(
            [str(source_file)],
            str(final_output_dir),
            os.path.join("nested", "file.txt"),
        )

        self.assertTrue(moved)
        self.assertEqual(
            moved_files, [str((final_output_dir / "artifact.7z").resolve())]
        )
        self.assertFalse(source_file.exists())

    def test_output_dir_and_move_helpers_compose_without_duplicate_nesting(self):
        source_root = self.root / "source"
        nested = source_root / "nested"
        nested.mkdir(parents=True)
        item_path = nested / "file.txt"
        item_path.write_text("payload", encoding="utf-8")
        source_dir = self.root / "tmp"
        source_dir.mkdir()
        source_file = source_dir / "artifact.7z"
        source_file.write_text("archive", encoding="utf-8")
        rel_path = os.path.join("nested", "file.txt")

        final_output_dir = fs.compute_final_output_dir(
            str(item_path), str(source_root), str(self.root / "out")
        )

        moved, moved_files = fs.move_files_to_final_destination(
            [str(source_file)], final_output_dir, rel_path
        )

        self.assertTrue(moved)
        self.assertEqual(
            moved_files,
            [str((self.root / "out" / "nested" / "artifact.7z").resolve())],
        )

    def test_move_artifacts_fails_if_any_expected_source_is_missing(self):
        source_dir = self.root / "tmp"
        source_dir.mkdir()
        archive_file = source_dir / "artifact.7z"
        archive_file.write_text("archive", encoding="utf-8")
        missing_file = source_dir / "artifact.par2"
        final_output_dir = self.root / "out"

        moved, moved_files = fs.move_files_to_final_destination(
            [str(archive_file), str(missing_file)],
            str(final_output_dir),
            os.path.join("nested", "file.txt"),
        )

        self.assertFalse(moved)
        self.assertEqual(moved_files, [])
        self.assertTrue(archive_file.exists())
        self.assertFalse((final_output_dir / "artifact.7z").exists())

    def test_move_artifacts_preserves_completed_moves_when_later_move_fails(self):
        source_dir = self.root / "tmp"
        source_dir.mkdir()
        archive_file = source_dir / "artifact.7z"
        archive_file.write_text("archive", encoding="utf-8")
        recovery_file = source_dir / "artifact.par2"
        recovery_file.write_text("recovery", encoding="utf-8")
        final_output_dir = self.root / "out"
        original_safe_move = fs.safe_move

        call_count = {"value": 0}

        def fail_on_second_move(src, dst, debug=False):
            call_count["value"] += 1
            if call_count["value"] == 1:
                return original_safe_move(src, dst, debug=debug)
            return False

        with mock.patch(
            "advArchiver.advArchiver.common.fs.safe_move",
            side_effect=fail_on_second_move,
        ):
            moved, moved_files = fs.move_files_to_final_destination(
                [str(archive_file), str(recovery_file)],
                str(final_output_dir),
                os.path.join("nested", "file.txt"),
            )

        self.assertFalse(moved)
        self.assertEqual(
            moved_files,
            [str((final_output_dir / "artifact.7z").resolve())],
        )
        self.assertTrue((final_output_dir / "artifact.7z").exists())
        self.assertFalse((final_output_dir / "artifact.par2").exists())
        self.assertTrue(recovery_file.exists())

    def test_empty_directory_cleanup_only_removes_empty_dirs(self):
        empty_dir = self.root / "empty"
        empty_dir.mkdir()
        non_empty_dir = self.root / "non-empty"
        non_empty_dir.mkdir()
        (non_empty_dir / "payload.txt").write_text("payload", encoding="utf-8")

        self.assertTrue(fs.safe_delete_folder(str(empty_dir), dry_run=False))
        self.assertFalse(empty_dir.exists())
        self.assertFalse(fs.safe_delete_folder(str(non_empty_dir), dry_run=False))
        self.assertTrue(non_empty_dir.exists())
