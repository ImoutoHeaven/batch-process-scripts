import tempfile
import unittest
from pathlib import Path
from unittest import mock

from advArchiver.advArchiver import cli


class TestCliContract(unittest.TestCase):
    def test_top_level_lists_expected_subcommands(self):
        parser = cli.build_parser()
        subparsers = [
            action for action in parser._actions if getattr(action, "choices", None)
        ]
        self.assertEqual(
            sorted(subparsers[0].choices.keys()), ["7z", "rar", "tar", "zip"]
        )

    def test_tar_requires_format(self):
        parser = cli.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["tar", "input"])

    def test_tar_password_option_is_rejected(self):
        parser = cli.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(
                ["tar", "input", "--format", "tar", "--password", "secret"]
            )

    def test_tar_profile_option_is_rejected(self):
        parser = cli.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["tar", "input", "--format", "tar", "--profile", "best"])

    def test_rec_threads_default_uses_half_cpu_floor(self):
        with mock.patch("os.cpu_count", return_value=12):
            args = cli.build_parser().parse_args(["zip", "input", "--profile", "best"])
        self.assertEqual(args.rec_threads, 6)

    def test_rec_threads_default_falls_back_to_four(self):
        with mock.patch("os.cpu_count", return_value=None):
            args = cli.build_parser().parse_args(["zip", "input", "--profile", "best"])
        self.assertEqual(args.rec_threads, 4)

    def test_dynamic_skip_extensions_are_collected(self):
        args = cli.build_parser().parse_args(
            [
                "7z",
                "input",
                "--profile",
                "best",
                "--skip-rar",
                "--skip-7z",
                "--skip-zip",
                "--skip-tar",
            ]
        )
        self.assertEqual(args.skip_extensions, ["rar", "7z", "zip", "tar"])

    def test_dynamic_skip_tokens_do_not_steal_known_option_values(self):
        args = cli.build_parser().parse_args(
            ["zip", "input", "--profile", "best", "--out", "--skip-rar"]
        )
        self.assertEqual(args.out, "--skip-rar")
        self.assertEqual(args.skip_extensions, [])

    def test_7z_parser_exposes_no_emb_flag(self):
        args = cli.build_parser().parse_args(
            ["7z", "input", "--profile", "best", "--no-emb"]
        )
        self.assertTrue(args.no_emb)

    def test_rar_parser_accepts_inline_comments(self):
        args = cli.build_parser().parse_args(
            ["rar", "input", "--profile", "best", "-c", "note"]
        )
        self.assertEqual(args.comments, "note")
        self.assertIsNone(args.comments_path)

    def test_rar_parser_accepts_existing_comments_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            comments_path = Path(temp_dir) / "note.txt"
            comments_path.write_text("note", encoding="utf-8")

            args = cli.build_parser().parse_args(
                ["rar", "input", "--profile", "best", "-cp", str(comments_path)]
            )

        self.assertIsNone(args.comments)
        self.assertEqual(args.comments_path, str(comments_path))

    def test_rar_parser_rejects_conflicting_comment_sources(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            comments_path = Path(temp_dir) / "note.txt"
            comments_path.write_text("note", encoding="utf-8")

            with self.assertRaises(SystemExit):
                cli.build_parser().parse_args(
                    [
                        "rar",
                        "input",
                        "--profile",
                        "best",
                        "-c",
                        "note",
                        "-cp",
                        str(comments_path),
                    ]
                )

    def test_rar_parser_rejects_missing_comments_path(self):
        with self.assertRaises(SystemExit):
            cli.build_parser().parse_args(
                ["rar", "input", "--profile", "best", "-cp", "missing-note.txt"]
            )

    def test_zip_parser_exposes_code_page_flag(self):
        args = cli.build_parser().parse_args(
            ["zip", "input", "--profile", "best", "--code-page", "65001"]
        )
        self.assertEqual(args.code_page, "65001")

    def test_shared_argument_surface_exists_on_all_subcommands(self):
        args = cli.build_parser().parse_args(
            [
                "tar",
                "input",
                "--format",
                "tar",
                "--threads",
                "2",
                "--rec-threads",
                "3",
                "--depth",
                "1",
                "--skip-files",
                "--no-rec",
                "--out",
                "out",
            ]
        )
        self.assertEqual(
            (
                args.threads,
                args.rec_threads,
                args.depth,
                args.skip_files,
                args.no_rec,
                args.out,
            ),
            (2, 3, 1, True, True, "out"),
        )

    def test_all_shared_flags_parse_on_each_subcommand(self):
        for argv in [
            ["7z", "input", "--profile", "best"],
            ["rar", "input", "--profile", "best"],
            ["zip", "input", "--profile", "best"],
            ["tar", "input", "--format", "tar"],
        ]:
            args = cli.build_parser().parse_args(
                argv
                + [
                    "--dry-run",
                    "-d",
                    "--debug",
                    "--no-lock",
                    "--lock-timeout",
                    "9",
                    "--skip-folders",
                    "--ext-skip-folder-tree",
                ]
            )
            self.assertTrue(
                args.dry_run
                and args.delete
                and args.debug
                and args.no_lock
                and args.skip_folders
                and args.ext_skip_folder_tree
            )
            self.assertEqual(args.lock_timeout, 9)

    def test_run_validates_rar_args_before_empty_selection_return(self):
        args = cli.build_parser().parse_args(["rar", "input", "--profile", "best"])
        args.comments_path = "missing-note.txt"

        with mock.patch(
            "advArchiver.advArchiver.cli.select_item_paths",
            return_value=([], "."),
        ) as select_item_paths:
            with self.assertRaises(ValueError):
                cli.run(args)

        select_item_paths.assert_not_called()
