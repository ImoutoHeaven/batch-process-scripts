from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import advDecompress_lite.layout as layout
from advDecompress_lite.layout import PlacementError, place_output, validate_policy, validate_tree


class LayoutTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def tree(self, name="extracted", output="output"):
        extracted = self.root / name
        output_dir = self.root / output
        extracted.mkdir(parents=True)
        output_dir.mkdir(parents=True)
        return extracted, output_dir

    def test_policy_validation_keeps_plain_zero_collect(self):
        for policy in (
            "separate",
            "direct",
            "collect",
            "0-collect",
            "12-collect",
            "file-content-1-collect",
            "file-content-auto-folder-1-collect-len",
            "file-content-auto-folder-1-collect-meaningful",
            "file-content-auto-folder-1-collect-meaningful-ent",
        ):
            self.assertEqual(validate_policy(policy), policy)
        for policy in ("file-content-0-collect", "file-content-auto-folder-0-collect-len", "nope"):
            with self.assertRaises(ValueError):
                validate_policy(policy)

    def test_validate_tree_accepts_empty_and_rejects_links(self):
        extracted, _ = self.tree()
        (extracted / "empty").mkdir()
        validate_tree(extracted)
        link = extracted / "link"
        try:
            link.symlink_to(extracted / "empty", target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(ValueError):
            validate_tree(extracted)

    def test_reparse_output_ancestor_is_rejected_before_creation(self):
        flag = getattr(layout.stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if not flag:
            self.skipTest("reparse metadata is unavailable")
        extracted = self.root / "extracted"
        extracted.mkdir()
        (extracted / "file.txt").write_text("x", encoding="utf-8")
        reparse_parent = self.root / "junction"
        reparse_parent.mkdir()
        output = reparse_parent / "output"
        real_lstat = layout._lstat

        def fake_lstat(path):
            metadata = real_lstat(path)
            if Path(path) == reparse_parent:
                return SimpleNamespace(
                    st_mode=metadata.st_mode,
                    st_file_attributes=flag,
                )
            return metadata

        with mock.patch.object(layout, "_lstat", side_effect=fake_lstat):
            with self.assertRaises(ValueError):
                place_output(extracted, output, "archive", "direct", "fail")
        self.assertFalse(output.exists())

    def test_reparse_descendant_blocks_merge_and_falls_back_to_container(self):
        flag = getattr(layout.stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if not flag:
            self.skipTest("reparse metadata is unavailable")
        extracted, output = self.tree()
        source_branch = extracted / "branch"
        source_branch.mkdir()
        (source_branch / "new.txt").write_text("new", encoding="utf-8")
        (extracted / "marker.txt").write_text("marker", encoding="utf-8")
        destination_branch = output / "branch"
        destination_branch.mkdir()
        real_lstat = layout.os.lstat

        def fake_lstat(path):
            metadata = real_lstat(path)
            if Path(path) == destination_branch:
                return SimpleNamespace(
                    st_mode=metadata.st_mode,
                    st_file_attributes=flag,
                )
            return metadata

        with mock.patch.object(layout.os, "lstat", side_effect=fake_lstat):
            with self.assertRaises(PlacementError):
                layout._preflight_item(source_branch, destination_branch, True)
            with self.assertRaises(PlacementError):
                layout._merge_item(
                    source_branch,
                    destination_branch,
                    "fail",
                    lambda: None,
                    merge_dirs=True,
                )
            locations = place_output(
                extracted,
                output,
                "archive",
                "only-file-content-direct",
                "fail",
            )
        self.assertEqual(locations, (output / "archive",))
        self.assertFalse((destination_branch / "new.txt").exists())
        self.assertTrue((output / "archive" / "branch" / "new.txt").exists())

    def test_separate_moves_whole_tree_including_empty_directories(self):
        extracted, output = self.tree()
        (extracted / "folder" / "empty").mkdir(parents=True)
        (extracted / "folder" / "file.txt").write_text("ok", encoding="utf-8")
        locations = place_output(extracted, output, "archive", "separate", "fail")
        self.assertEqual(locations, (output / "archive",))
        self.assertTrue((output / "archive" / "folder" / "empty").is_dir())
        self.assertEqual((output / "archive" / "folder" / "file.txt").read_text(encoding="utf-8"), "ok")
        self.assertFalse(extracted.exists())

    def test_direct_preflights_type_conflicts_and_suffixes_files(self):
        extracted, output = self.tree()
        (extracted / "item").mkdir()
        (extracted / "item" / "new.txt").write_text("new", encoding="utf-8")
        (output / "item").write_text("existing", encoding="utf-8")
        with self.assertRaises(PlacementError) as caught:
            place_output(extracted, output, "archive", "direct", "fail")
        self.assertEqual(caught.exception.placed, ())
        self.assertTrue(extracted.exists())
        locations = place_output(extracted, output, "archive", "direct", "suffix")
        self.assertEqual(locations, (output / "item_1",))
        self.assertEqual((output / "item_1" / "new.txt").read_text(encoding="utf-8"), "new")

    def test_direct_conflicting_directory_is_a_whole_item_conflict(self):
        extracted, output = self.tree()
        (extracted / "item" / "new.txt").mkdir(parents=True)
        (extracted / "item" / "new.txt" / "payload").write_text("new", encoding="utf-8")
        (output / "item").mkdir()
        (output / "item" / "old.txt").write_text("old", encoding="utf-8")
        with self.assertRaises(PlacementError):
            place_output(extracted, output, "archive", "direct", "fail")
        place_output(extracted, output, "archive", "direct", "suffix")
        self.assertTrue((output / "item_1" / "new.txt" / "payload").exists())
        self.assertTrue((output / "item" / "old.txt").exists())

    def test_only_file_content_removes_shell_and_retains_branching_content(self):
        extracted, output = self.tree()
        (extracted / "shell" / "payload").mkdir(parents=True)
        (extracted / "shell" / "payload" / "file.txt").write_text("x", encoding="utf-8")
        (extracted / "shell" / "empty").mkdir()
        locations = place_output(extracted, output, "archive", "only-file-content", "fail")
        self.assertEqual(locations, (output / "archive",))
        self.assertTrue((output / "archive" / "payload" / "file.txt").exists())
        self.assertTrue((output / "archive" / "empty").is_dir())

    def test_only_file_content_direct_merges_compatible_directories(self):
        extracted, output = self.tree()
        (extracted / "one").mkdir()
        (extracted / "one" / "new.txt").write_text("new", encoding="utf-8")
        (extracted / "two").mkdir()
        (output / "one").mkdir()
        (output / "one" / "old.txt").write_text("old", encoding="utf-8")
        locations = place_output(extracted, output, "archive", "only-file-content-direct", "fail")
        self.assertEqual(set(locations), {output / "one", output / "two"})
        self.assertTrue((output / "one" / "old.txt").exists())
        self.assertTrue((output / "one" / "new.txt").exists())
        self.assertTrue((output / "two").is_dir())

    def test_only_file_content_direct_falls_back_on_file_collision(self):
        extracted, output = self.tree()
        (extracted / "file.txt").write_text("new", encoding="utf-8")
        (output / "file.txt").write_text("old", encoding="utf-8")
        locations = place_output(extracted, output, "archive", "only-file-content-direct", "suffix")
        self.assertEqual(locations, (output / "archive",))
        self.assertEqual((output / "archive" / "file.txt").read_text(encoding="utf-8"), "new")
        self.assertEqual((output / "file.txt").read_text(encoding="utf-8"), "old")

    def test_wrapped_policies_choose_a_unique_container_even_in_fail_mode(self):
        extracted, output = self.tree()
        (extracted / "file.txt").write_text("new", encoding="utf-8")
        (output / "archive").mkdir()
        locations = place_output(extracted, output, "archive", "separate", "fail")
        self.assertEqual(locations, (output / "archive_1",))
        self.assertTrue((output / "archive_1" / "file.txt").exists())

    def test_collect_wraps_conflicts_in_suffix_mode(self):
        extracted, output = self.tree()
        (extracted / "file.txt").write_text("new", encoding="utf-8")
        (output / "file.txt").write_text("old", encoding="utf-8")
        locations = place_output(extracted, output, "archive", "1-collect", "suffix")
        self.assertEqual(locations, (output / "archive",))
        self.assertTrue((output / "archive" / "file.txt").exists())

    def test_n_collect_below_threshold_suffixes_the_whole_top_level_item(self):
        extracted, output = self.tree()
        (extracted / "file.txt").write_text("new", encoding="utf-8")
        (output / "file.txt").write_text("old", encoding="utf-8")
        locations = place_output(extracted, output, "archive", "2-collect", "suffix")
        self.assertEqual(locations, (output / "file_1.txt",))
        self.assertEqual((output / "file_1.txt").read_text(encoding="utf-8"), "new")

    def test_file_content_collect_wraps_incompatible_merge_in_suffix_mode(self):
        extracted, output = self.tree()
        (extracted / "shell").mkdir()
        (extracted / "shell" / "file.txt").write_text("new", encoding="utf-8")
        (output / "file.txt").write_text("old", encoding="utf-8")
        locations = place_output(extracted, output, "archive", "file-content-2-collect", "suffix")
        self.assertEqual(locations, (output / "archive",))
        self.assertEqual((output / "archive" / "file.txt").read_text(encoding="utf-8"), "new")

    def test_file_content_folder_layouts_and_scores(self):
        for policy, expected in (
            ("file-content-with-folder", ("inner", "file.txt")),
            ("file-content-with-folder-separate", ("arc", "inner", "file.txt")),
            ("file-content-auto-folder-1-collect-len", ("inner", "file.txt")),
            ("file-content-auto-folder-1-collect-meaningful", ("inner", "file.txt")),
            ("file-content-auto-folder-1-collect-meaningful-ent", ("inner", "file.txt")),
        ):
            with self.subTest(policy=policy):
                extracted, output = self.tree(name="extracted_" + policy.replace("/", "_"), output="output_" + policy.replace("/", "_"))
                (extracted / "outer" / "inner").mkdir(parents=True)
                (extracted / "outer" / "inner" / "file.txt").write_text("x", encoding="utf-8")
                locations = place_output(extracted, output, "arc", policy, "fail")
                self.assertEqual(locations[0], output / expected[0])
                self.assertTrue((output.joinpath(*expected)).exists())

    def test_recursive_counts_include_directories(self):
        extracted, output = self.tree()
        (extracted / "one" / "two").mkdir(parents=True)
        (extracted / "one" / "two" / "file.txt").write_text("x", encoding="utf-8")
        place_output(extracted, output, "archive", "2-collect", "fail")
        self.assertTrue((output / "archive" / "one" / "two" / "file.txt").exists())

    def test_output_ancestor_of_workspace_is_allowed(self):
        output = self.root / "output"
        extracted = output / ".tmp" / "job"
        extracted.mkdir(parents=True)
        output.mkdir(exist_ok=True)
        (extracted / "file.txt").write_text("x", encoding="utf-8")
        place_output(extracted, output, "archive", "direct", "fail")
        self.assertTrue((output / "file.txt").exists())


if __name__ == "__main__":
    unittest.main()
