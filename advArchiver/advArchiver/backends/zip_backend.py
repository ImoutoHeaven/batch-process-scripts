from __future__ import annotations

import importlib
import os

from advArchiver.advArchiver import models
from advArchiver.advArchiver.common import fs

process = importlib.import_module("advArchiver.advArchiver.common.process")
ParparRecoveryProvider = importlib.import_module(
    "advArchiver.advArchiver.recovery.parpar"
).ParparRecoveryProvider
BackendBase = importlib.import_module(
    "advArchiver.advArchiver.backends.base"
).BackendBase


def build_zip_switches(profile, password, code_page, delete_files=False):
    switches = ["-tzip"]
    if delete_files:
        switches.append("-sdel")

    if code_page == "mcu":
        switches.append("-mcu=on")
    else:
        switches.append(f"-mcp={code_page}")

    if profile == "store":
        switches.append("-mx=0")
    elif profile == "fastest":
        switches.extend(["-mx=1", "-mfb=32"])
    else:
        switches.extend(["-mx=9", "-mfb=256"])

    if password:
        switches.append(f"-p{password}")

    return switches


def _job_output_stem(job):
    if job.item_type == "file":
        return os.path.splitext(os.path.basename(job.rel_path))[0]
    return os.path.basename(job.rel_path)


def _build_archive_command(job, args):
    archive_path = os.path.join(job.tmp_dir, "temp_archive.zip")
    source_path = job.item_path
    if job.item_type == "folder":
        source_path = os.path.join(job.item_path, "*")

    return [
        "7z",
        "a",
        *build_zip_switches(
            getattr(args, "profile", "best"),
            getattr(args, "password", None),
            getattr(args, "code_page", "mcu"),
            delete_files=getattr(args, "delete", False),
        ),
        archive_path,
        source_path,
    ]


def find_and_rename_zip_file(
    temp_name_prefix, target_name_prefix, search_dir, debug=False
):
    del debug
    search_root = fs.safe_abspath(search_dir)
    source_file = os.path.join(search_root, f"{temp_name_prefix}.zip")
    if not fs.safe_exists(source_file):
        return False, []

    target_file = fs.safe_abspath(
        os.path.join(search_root, f"{target_name_prefix}.zip")
    )
    if not fs.safe_move(source_file, target_file):
        return False, []
    return True, [target_file]


class ZipBackend(BackendBase):
    name = "zip"

    def register_arguments(self, subparser):
        subparser.add_argument("-p", "--password")
        subparser.add_argument("--profile", default="best")
        subparser.add_argument("--code-page", default="mcu")
        return subparser

    def capabilities(self):
        return models.BackendCapabilities(
            supports_password=True,
            supports_split_volumes=False,
            supports_native_recovery=False,
            supports_external_recovery=True,
            supports_embedded_recovery=False,
            supports_comments=False,
            supports_explicit_format=False,
        )

    def validate_args(self, args):
        del args

    def check_required_tools(self, args):
        process.require_tool("7z")
        if not getattr(args, "no_rec", False):
            process.require_tool("parpar")

    def build_job(self, item_path, args, base_path):
        normalized_path = fs.safe_abspath(item_path)
        item_type = "folder" if fs.safe_isdir(normalized_path) else "file"
        return models.ArchiveJob(
            backend_name=self.name,
            item_path=normalized_path,
            item_type=item_type,
            rel_path=fs.get_relative_path(normalized_path, base_path).replace(
                os.sep, "/"
            ),
            final_output_dir=fs.compute_final_output_dir(
                normalized_path, base_path, getattr(args, "out", None)
            ),
        )

    def execute_job(self, job, args):
        command = _build_archive_command(job, args)
        command_string = process.format_command(command)
        if getattr(args, "dry_run", False):
            return models.BackendExecutionResult(
                archive_result=models.ArchiveExecutionResult(command=command_string)
            )

        result = process.run_command(command, debug=getattr(args, "debug", False))
        if result.returncode != 0:
            return models.BackendExecutionResult(
                archive_result=models.ArchiveExecutionResult(
                    error_code=result.returncode,
                    error_msg=(
                        result.stderr or result.stdout or "zip command failed"
                    ).strip(),
                    command=command_string,
                )
            )

        renamed, archive_files = find_and_rename_zip_file(
            "temp_archive",
            _job_output_stem(job),
            job.tmp_dir,
            debug=getattr(args, "debug", False),
        )
        if not renamed or not archive_files:
            return models.BackendExecutionResult(
                archive_result=models.ArchiveExecutionResult(
                    error_msg="failed to locate and rename zip output artifact",
                    command=command_string,
                )
            )

        return models.BackendExecutionResult(
            archive_result=models.ArchiveExecutionResult(
                archive_files=archive_files,
                command=command_string,
            )
        )

    def select_recovery_provider(self, args, execution_result):
        del execution_result
        if getattr(args, "no_rec", False):
            return None
        return ParparRecoveryProvider(mode="external")
