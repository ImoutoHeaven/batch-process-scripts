import importlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ADVARCHIVER_ROOT = Path(__file__).resolve().parents[1]
WORKTREE_ROOT = ADVARCHIVER_ROOT.parent
ENTRYPOINT = ADVARCHIVER_ROOT / "advArchiver.py"
WORKFLOW_PATH = WORKTREE_ROOT / ".github" / "workflows" / "advarchiver-integration.yml"
REQUIRED_GUARDRAIL_CASES = {
    "test_7z_real_archive_creation",
    "test_7z_out_root_preserves_legacy_placement",
    "test_assert_tar_directory_members_are_contents_only_rejects_top_level_input_folder",
    "test_compressed_tar_family_suffix_matrix_matches_maintained_aliases",
    "test_rar_real_archive_creation",
    "test_zip_real_archive_creation",
    "test_tar_directory_input_archives_contents_only",
    "test_tar_real_archive_creation",
    "test_tgz_real_archive_creation_is_readable_as_tar_family",
    "test_output_suffix_and_location_checks",
    "test_7z_split_recovery_external_only",
    "test_tar_alias_suffixes_preserved",
    "test_no_rec_vs_default_recovery_behavior",
}


def tar_backend_module():
    return importlib.import_module("advArchiver.advArchiver.backends.tar")


def require_tools_or_skip(testcase, *tool_names):
    missing = [tool_name for tool_name in tool_names if shutil.which(tool_name) is None]
    if missing:
        testcase.skipTest("missing required binaries: " + ", ".join(sorted(missing)))


def require_tar_format_or_skip(testcase, format_name):
    module = tar_backend_module()
    backend = module.TarBackend()
    required = backend.required_tools_for_format(format_name)
    require_tools_or_skip(testcase, *required)


def compressed_tar_family_suffixes():
    module = tar_backend_module()
    return {
        format_name: suffix
        for format_name, suffix in module.FORMAT_TO_SUFFIX.items()
        if format_name != "tar"
    }


def assert_tar_directory_members_are_contents_only(
    testcase, member_names, top_level_name
):
    normalized_names = [name.rstrip("/") for name in member_names]
    testcase.assertTrue(
        all(
            name != top_level_name and not name.startswith(f"{top_level_name}/")
            for name in normalized_names
        ),
        msg=f"unexpected top-level tar members: {normalized_names}",
    )


def write_source_file(root, rel_path, content):
    file_path = root / rel_path
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(content, encoding="utf-8")
    return file_path


def cli_args_from_options(options):
    args = []
    for name, value in options.items():
        flag = f"--{name.replace('_', '-')}"
        if isinstance(value, bool):
            if value:
                args.append(flag)
            continue
        if value is None:
            continue
        args.extend([flag, str(value)])
    return args


def run_cli_once(testcase, backend_name, source_file, out_dir, **options):
    command = [
        sys.executable,
        str(ENTRYPOINT),
        backend_name,
        str(source_file),
        *cli_args_from_options(options),
        "--out",
        str(out_dir),
        "--no-lock",
    ]
    result = subprocess.run(
        command,
        cwd=str(WORKTREE_ROOT),
        capture_output=True,
        text=True,
    )
    testcase.assertEqual(
        result.returncode,
        0,
        msg=(
            "command failed: "
            + " ".join(command)
            + "\nstdout:\n"
            + result.stdout
            + "\nstderr:\n"
            + result.stderr
        ),
    )
    return result


class TestRealCliGuardrails(unittest.TestCase):
    def _assert_real_tar_family_archive(self, format_name, suffix):
        require_tar_format_or_skip(self, format_name)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_file = write_source_file(source_root, "movie.txt", "payload")
            out_dir = root / "out"

            run_cli_once(
                self,
                "tar",
                source_file,
                out_dir,
                format=format_name,
                no_rec=True,
            )

            archive_path = out_dir / f"movie{suffix}"
            self.assertTrue(archive_path.exists())
            self.assertTrue(archive_path.name.endswith(suffix))
            with tarfile.open(archive_path, "r:*") as handle:
                self.assertEqual(handle.getnames(), ["movie.txt"])

    def test_compressed_tar_family_suffix_matrix_matches_maintained_aliases(self):
        self.assertEqual(
            compressed_tar_family_suffixes(),
            {
                "tar.gz": ".tar.gz",
                "tgz": ".tgz",
                "tar.xz": ".tar.xz",
                "txz": ".txz",
                "tar.bz2": ".tar.bz2",
                "tbz2": ".tbz2",
            },
        )

    def test_assert_tar_directory_members_are_contents_only_rejects_top_level_input_folder(
        self,
    ):
        for member_names in (["foo", "nested/file.txt"], ["foo/nested/file.txt"]):
            with self.subTest(member_names=member_names):
                with self.assertRaises(AssertionError):
                    assert_tar_directory_members_are_contents_only(
                        self,
                        member_names,
                        top_level_name="foo",
                    )

    def test_guardrails_cover_required_real_binary_cases(self):
        declared_cases = {
            name
            for name in dir(type(self))
            if name.startswith("test_")
            and name
            not in {
                "test_blocking_workflow_runs_build_and_guardrails",
                "test_guardrails_cover_required_real_binary_cases",
                "test_tar_guardrail_skips_without_7z",
            }
        }
        self.assertTrue(REQUIRED_GUARDRAIL_CASES.issubset(declared_cases))

    def test_blocking_workflow_runs_build_and_guardrails(self):
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn("real-cli-guardrails", workflow)
        self.assertIn("self-hosted", workflow)
        self.assertIn('required = ["7z", "rar", "parpar"]', workflow)
        self.assertNotIn('"tar"', workflow)
        self.assertNotIn('"gzip"', workflow)
        self.assertNotIn('"xz"', workflow)
        self.assertNotIn('"bzip2"', workflow)
        self.assertIn("advArchiver/scripts/build_single_file.py", workflow)
        self.assertIn("advArchiver.tests.test_build_single_file", workflow)
        self.assertIn("advArchiver.tests.test_real_cli_guardrails", workflow)
        self.assertIn("advArchiver/advArchiver.py --help", workflow)

    def test_tar_guardrail_skips_without_7z(self):
        with self.assertRaises(unittest.SkipTest):
            with mock.patch(
                "shutil.which",
                side_effect=lambda name: None if name == "7z" else f"/bin/{name}",
            ):
                require_tar_format_or_skip(self, "tar.gz")

    def test_7z_real_archive_creation(self):
        require_tools_or_skip(self, "7z")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_file = write_source_file(source_root, "movie.txt", "payload")
            out_dir = root / "out"

            run_cli_once(self, "7z", source_file, out_dir, no_rec=True, profile="best")

            archive_path = out_dir / "movie.7z"
            self.assertTrue(archive_path.exists())
            self.assertEqual(archive_path.suffix, ".7z")

    def test_7z_out_root_preserves_legacy_placement(self):
        require_tools_or_skip(self, "7z")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            nested = source_root / "nested"
            nested.mkdir(parents=True)
            write_source_file(nested, "movie.txt", "payload")
            out_dir = root / "out"

            run_cli_once(
                self,
                "7z",
                source_root,
                out_dir,
                depth=2,
                skip_folders=True,
                no_rec=True,
                profile="best",
            )

            self.assertTrue((out_dir / "movie.7z").exists())
            self.assertFalse((out_dir / "nested" / "movie.7z").exists())

    def test_rar_real_archive_creation(self):
        require_tools_or_skip(self, "rar")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_file = write_source_file(source_root, "movie.txt", "payload")
            out_dir = root / "out"

            run_cli_once(self, "rar", source_file, out_dir, no_rec=True)

            archive_path = out_dir / "movie.rar"
            self.assertTrue(archive_path.exists())
            self.assertEqual(archive_path.suffix, ".rar")

    def test_zip_real_archive_creation(self):
        require_tools_or_skip(self, "7z")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_file = write_source_file(source_root, "movie.txt", "payload")
            out_dir = root / "out"

            run_cli_once(self, "zip", source_file, out_dir, no_rec=True)

            archive_path = out_dir / "movie.zip"
            self.assertTrue(archive_path.exists())
            self.assertEqual(archive_path.suffix, ".zip")

    def test_tar_real_archive_creation(self):
        require_tar_format_or_skip(self, "tar")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_file = write_source_file(source_root, "movie.txt", "payload")
            out_dir = root / "out"

            run_cli_once(self, "tar", source_file, out_dir, format="tar", no_rec=True)

            archive_path = out_dir / "movie.tar"
            self.assertTrue(archive_path.exists())
            self.assertEqual(archive_path.suffix, ".tar")
            with tarfile.open(archive_path, "r") as handle:
                self.assertEqual(handle.getnames(), ["movie.txt"])

    def test_tar_directory_input_archives_contents_only(self):
        require_tar_format_or_skip(self, "tar")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            nested = source_root / "foo" / "nested"
            write_source_file(nested, "file.txt", "payload")
            out_dir = root / "out"

            run_cli_once(
                self,
                "tar",
                source_root / "foo",
                out_dir,
                format="tar",
                no_rec=True,
            )

            with tarfile.open(out_dir / "foo.tar", "r") as handle:
                members = handle.getmembers()

            member_names = [member.name for member in members]
            file_names = [member.name for member in members if member.isfile()]

            assert_tar_directory_members_are_contents_only(
                self,
                member_names,
                top_level_name="foo",
            )
            self.assertEqual(file_names, ["nested/file.txt"])

    def test_output_suffix_and_location_checks(self):
        requirements = {
            "7z": (".7z", {"no_rec": True, "profile": "best"}, ("7z",)),
            "rar": (".rar", {"no_rec": True}, ("rar",)),
            "zip": (".zip", {"no_rec": True}, ("7z",)),
            "tar": (
                ".tar.gz",
                {"format": "tar.gz", "no_rec": True},
                ("7z",),
            ),
        }
        for backend_name, (suffix, options, tools) in requirements.items():
            with self.subTest(backend=backend_name):
                require_tools_or_skip(self, *tools)
                with tempfile.TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    source_root = root / "source"
                    source_file = write_source_file(
                        source_root,
                        "sample.txt",
                        f"payload for {backend_name}",
                    )
                    out_dir = root / "out"

                    run_cli_once(self, backend_name, source_file, out_dir, **options)

                    expected_path = out_dir / f"sample{suffix}"
                    self.assertTrue(expected_path.exists())

    def test_7z_split_recovery_external_only(self):
        require_tools_or_skip(self, "7z", "parpar")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_file = write_source_file(source_root, "movie.bin", "x" * 16384)
            out_dir = root / "out"

            run_cli_once(self, "7z", source_file, out_dir, profile="parted-1k")

            archive_files = sorted(out_dir.glob("movie.7z.*"))
            recovery_files = sorted(out_dir.glob("*.par2"))
            self.assertGreaterEqual(len(archive_files), 2)
            self.assertTrue(
                all(path.name.startswith("movie.7z.") for path in archive_files)
            )
            self.assertTrue(recovery_files)
            self.assertTrue(all(path.suffix == ".par2" for path in recovery_files))
            self.assertTrue(
                all(path.exists() for path in archive_files + recovery_files)
            )

    def test_tar_alias_suffixes_preserved(self):
        cases = {
            "tgz": ".tgz",
            "txz": ".txz",
            "tbz2": ".tbz2",
        }
        for format_name, suffix in cases.items():
            with self.subTest(format=format_name):
                require_tar_format_or_skip(self, format_name)
                with tempfile.TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    source_root = root / "source"
                    source_file = write_source_file(
                        source_root,
                        "sample.txt",
                        f"payload for {format_name}",
                    )
                    out_dir = root / "out"

                    run_cli_once(
                        self,
                        "tar",
                        source_file,
                        out_dir,
                        format=format_name,
                        no_rec=True,
                    )

                    archive_path = out_dir / f"sample{suffix}"
                    self.assertTrue(archive_path.exists())
                    self.assertTrue(archive_path.name.endswith(suffix))
                    with tarfile.open(archive_path, "r:*") as handle:
                        self.assertEqual(handle.getnames(), ["sample.txt"])

    def test_tgz_real_archive_creation_is_readable_as_tar_family(self):
        for format_name, suffix in compressed_tar_family_suffixes().items():
            with self.subTest(format=format_name):
                self._assert_real_tar_family_archive(format_name, suffix)

    def test_no_rec_vs_default_recovery_behavior(self):
        require_tools_or_skip(self, "7z", "parpar")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_file = write_source_file(source_root, "data.txt", "payload")
            no_rec_out = root / "out-no-rec"
            default_out = root / "out-default"

            run_cli_once(
                self, "tar", source_file, no_rec_out, format="tar", no_rec=True
            )
            run_cli_once(self, "tar", source_file, default_out, format="tar")

            no_rec_recovery_files = sorted(no_rec_out.glob("*.par2"))
            default_recovery_files = sorted(default_out.glob("*.par2"))

            self.assertEqual(no_rec_recovery_files, [])
            self.assertTrue(default_recovery_files)
            self.assertTrue(
                all(path.suffix == ".par2" for path in default_recovery_files)
            )
