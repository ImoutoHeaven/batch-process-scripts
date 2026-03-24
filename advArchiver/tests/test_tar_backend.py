import argparse
import importlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock


def args_for(**overrides):
    defaults = {
        "debug": False,
        "delete": False,
        "dry_run": False,
        "format": "tar",
        "no_rec": False,
        "out": None,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def backend_module():
    try:
        return importlib.import_module("advArchiver.advArchiver.backends.tar")
    except ModuleNotFoundError:
        return None


class TestTarBackend(unittest.TestCase):
    def _build_file_job(self, module, format_name):
        backend = module.TarBackend()
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)

        root = Path(temp_dir.name)
        source_root = root / "source"
        source_root.mkdir()
        source_file = source_root / "sample.txt"
        source_file.write_text("payload", encoding="utf-8")

        job = backend.build_job(
            str(source_file),
            args_for(format=format_name),
            str(source_root),
        )
        job.tmp_dir = str(root / "tmp")
        return job

    def _assert_two_stage_plan(self, format_name, expected_type, expected_suffix):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None

        job = self._build_file_job(module, format_name)
        command_plan = module.build_command_plan(job, args_for(format=format_name))

        self.assertEqual(len(command_plan), 2)
        self.assertEqual(command_plan[0][0:3], ["7z", "a", "-ttar"])
        self.assertEqual(command_plan[1][0:3], ["7z", "a", expected_type])
        self.assertTrue(command_plan[0][3].endswith("temp_archive.tar"))
        self.assertTrue(command_plan[1][3].endswith(expected_suffix))
        self.assertEqual(command_plan[1][4], command_plan[0][3])

    def test_tgz_output_keeps_tgz_suffix(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None

        self.assertEqual(module.output_name("sample", "tgz"), "sample.tgz")

    def test_tar_builds_single_stage_7z_tar_command(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None

        job = self._build_file_job(module, "tar")
        command_plan = module.build_command_plan(job, args_for(format="tar"))

        self.assertEqual(len(command_plan), 1)
        self.assertEqual(command_plan[0][0:3], ["7z", "a", "-ttar"])
        self.assertTrue(command_plan[0][3].endswith("temp_archive.tar"))
        self.assertTrue(command_plan[0][4].endswith("sample.txt"))

    def test_tar_gz_builds_two_stage_7z_pipeline(self):
        self._assert_two_stage_plan("tar.gz", "-tgzip", "temp_archive.tar.gz")

    def test_tgz_builds_two_stage_7z_pipeline(self):
        self._assert_two_stage_plan("tgz", "-tgzip", "temp_archive.tgz")

    def test_tar_xz_builds_two_stage_7z_pipeline(self):
        self._assert_two_stage_plan("tar.xz", "-txz", "temp_archive.tar.xz")

    def test_txz_builds_two_stage_7z_pipeline(self):
        self._assert_two_stage_plan("txz", "-txz", "temp_archive.txz")

    def test_tar_bz2_builds_two_stage_7z_pipeline(self):
        self._assert_two_stage_plan("tar.bz2", "-tbzip2", "temp_archive.tar.bz2")

    def test_tbz2_builds_two_stage_7z_pipeline(self):
        self._assert_two_stage_plan("tbz2", "-tbzip2", "temp_archive.tbz2")

    def test_tar_folder_mode_archives_contents_not_top_level_folder(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.TarBackend()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            folder = source_root / "foo"
            nested = folder / "nested"
            nested.mkdir(parents=True)
            (nested / "file.txt").write_text("payload", encoding="utf-8")

            job = backend.build_job(
                str(folder),
                args_for(format="tar"),
                str(source_root),
            )
            job.tmp_dir = str(root / "tmp")

            command_plan = module.build_command_plan(job, args_for(format="tar"))

        self.assertEqual(len(command_plan), 1)
        self.assertEqual(command_plan[0][0:3], ["7z", "a", "-ttar"])
        self.assertEqual(command_plan[0][4], str(folder / "*"))

    def test_tar_backend_no_longer_exposes_native_command_builder(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None

        self.assertFalse(hasattr(module, "build_command"))

    def test_tar_command_plan_keeps_dashed_basename_as_source_path(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.TarBackend()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            source_file = source_root / "-danger.txt"
            source_file.write_text("payload", encoding="utf-8")

            job = backend.build_job(
                str(source_file),
                args_for(format="tar"),
                str(source_root),
            )
            job.tmp_dir = str(root / "tmp")

            command_plan = module.build_command_plan(job, args_for(format="tar"))

        self.assertEqual(command_plan[0][0:3], ["7z", "a", "-ttar"])
        self.assertTrue(command_plan[0][4].endswith("-danger.txt"))

    def test_tar_rejects_unsupported_zstd_aliases(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None

        with self.assertRaises(ValueError):
            module.validate_format("tar.zst")

        with self.assertRaises(ValueError):
            module.validate_format("tzst")

    def test_tar_format_specific_tool_check_fails_early(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.TarBackend()

        with mock.patch.object(backend, "has_tooling_for_format", return_value=False):
            with self.assertRaises(module.process.MissingToolError):
                backend.check_required_tools(args_for(format="tar.xz"))

    def test_required_tools_for_tar_gz_is_7z_only(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None

        self.assertEqual(
            module.process.required_tools_for_tar_format("tar.gz"), ("7z",)
        )

    def test_required_tools_for_every_tar_format_are_7z_only(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None

        for format_name in module.FORMAT_TO_SUFFIX:
            with self.subTest(format=format_name):
                self.assertEqual(
                    module.process.required_tools_for_tar_format(format_name),
                    ("7z",),
                )

    def test_check_required_tools_requires_parpar_only_when_recovery_enabled(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.TarBackend()

        with mock.patch.object(backend, "has_tooling_for_format", return_value=True):
            with mock.patch.object(module.process, "require_tool") as require_tool:
                backend.check_required_tools(args_for(format="tar", no_rec=True))

        require_tool.assert_not_called()

        with mock.patch.object(backend, "has_tooling_for_format", return_value=True):
            with mock.patch.object(module.process, "require_tool") as require_tool:
                backend.check_required_tools(args_for(format="tar"))

        require_tool.assert_called_once_with("parpar")

    def test_tar_command_plan_uses_7z_binary(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None

        job = self._build_file_job(module, "tar")
        command_plan = module.build_command_plan(job, args_for(format="tar"))

        self.assertEqual(command_plan[0][0], "7z")

    def test_tar_defaults_to_external_parpar_recovery(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.TarBackend()

        provider = backend.select_recovery_provider(args_for(), None)

        self.assertTrue(provider.uses_recovery_executor)
        self.assertEqual(provider.mode, "external")

    def test_tar_no_rec_disables_external_recovery(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.TarBackend()

        provider = backend.select_recovery_provider(args_for(no_rec=True), None)

        self.assertIsNone(provider)

    def test_tgz_dry_run_reports_full_pipeline_and_skips_subprocess(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.TarBackend()

        job = self._build_file_job(module, "tgz")

        with mock.patch(
            "advArchiver.advArchiver.backends.tar.process.run_command"
        ) as run_command:
            result = backend.execute_job(job, args_for(format="tgz", dry_run=True))

        run_command.assert_not_called()
        self.assertIn("7z a -ttar", result.archive_result.command)
        self.assertIn("&&", result.archive_result.command)
        self.assertIn("7z a -tgzip", result.archive_result.command)

    def test_execute_job_returns_only_final_tgz_artifact(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.TarBackend()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            source_file = source_root / "sample.txt"
            source_file.write_text("payload", encoding="utf-8")

            job = backend.build_job(
                str(source_file),
                args_for(format="tgz"),
                str(source_root),
            )
            job.tmp_dir = str(root / "tmp")
            Path(job.tmp_dir).mkdir()

            def fake_run(command, debug=False):
                del debug
                output_path = Path(command[3])
                if output_path.is_absolute():
                    output_path.write_text("artifact", encoding="utf-8")
                return mock.Mock(returncode=0, stdout="", stderr="")

            with mock.patch(
                "advArchiver.advArchiver.backends.tar.process.run_command",
                side_effect=fake_run,
            ) as run_command:
                result = backend.execute_job(job, args_for(format="tgz"))

            self.assertEqual(run_command.call_count, 2)
            self.assertEqual(
                result.archive_result.archive_files,
                [str((Path(job.tmp_dir) / "sample.tgz").resolve())],
            )

    def test_execute_job_stops_after_first_stage_failure_and_reports_specific_command(
        self,
    ):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.TarBackend()

        job = self._build_file_job(module, "tgz")
        command_plan = module.build_command_plan(job, args_for(format="tgz"))

        def fake_run(command, debug=False):
            del debug
            self.assertEqual(command, command_plan[0])
            return mock.Mock(returncode=17, stdout="", stderr="stage 1 failed")

        with mock.patch(
            "advArchiver.advArchiver.backends.tar.process.run_command",
            side_effect=fake_run,
        ) as run_command:
            result = backend.execute_job(job, args_for(format="tgz"))

        run_command.assert_called_once()
        self.assertEqual(result.archive_result.error_code, 17)
        self.assertEqual(result.archive_result.error_msg, "stage 1 failed")
        self.assertEqual(result.archive_result.archive_files, [])
        self.assertEqual(
            result.archive_result.command,
            module.process.format_command(command_plan[0]),
        )

    def test_execute_job_stops_after_second_stage_failure_and_reports_specific_command(
        self,
    ):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None
        backend = module.TarBackend()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            source_file = source_root / "sample.txt"
            source_file.write_text("payload", encoding="utf-8")

            job = backend.build_job(
                str(source_file),
                args_for(format="tgz"),
                str(source_root),
            )
            job.tmp_dir = str(root / "tmp")
            Path(job.tmp_dir).mkdir()
            command_plan = module.build_command_plan(job, args_for(format="tgz"))

            call_count = 0

            def fake_run(command, debug=False):
                nonlocal call_count
                del debug
                call_count += 1
                if call_count == 1:
                    self.assertEqual(command, command_plan[0])
                    Path(command[3]).write_text("artifact", encoding="utf-8")
                    return mock.Mock(returncode=0, stdout="", stderr="")
                if call_count == 2:
                    self.assertEqual(command, command_plan[1])
                    return mock.Mock(returncode=23, stdout="", stderr="stage 2 failed")
                self.fail("unexpected subprocess call after second-stage failure")

            with mock.patch(
                "advArchiver.advArchiver.backends.tar.process.run_command",
                side_effect=fake_run,
            ) as run_command:
                result = backend.execute_job(job, args_for(format="tgz"))

            self.assertEqual(run_command.call_count, 2)
            self.assertEqual(result.archive_result.error_code, 23)
            self.assertEqual(result.archive_result.error_msg, "stage 2 failed")
            self.assertEqual(result.archive_result.archive_files, [])
            self.assertEqual(
                result.archive_result.command,
                module.process.format_command(command_plan[1]),
            )
            self.assertFalse((Path(job.tmp_dir) / "sample.tgz").exists())

    def test_find_and_rename_tar_file_allows_identical_source_and_target(self):
        module = backend_module()
        self.assertIsNotNone(module)
        assert module is not None

        with tempfile.TemporaryDirectory() as temp_dir:
            workdir = Path(temp_dir)
            archive_path = workdir / "temp_archive.tar"
            archive_path.write_text("archive", encoding="utf-8")

            success, renamed_files = module.find_and_rename_tar_file(
                "temp_archive",
                "temp_archive",
                str(workdir),
                "tar",
            )

            self.assertTrue(success)
            self.assertEqual(renamed_files, [str(archive_path.resolve())])
            self.assertTrue(archive_path.exists())
