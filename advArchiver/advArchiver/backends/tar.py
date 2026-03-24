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


FORMAT_TO_SUFFIX = {
    "tar": ".tar",
    "tar.gz": ".tar.gz",
    "tgz": ".tgz",
    "tar.xz": ".tar.xz",
    "txz": ".txz",
    "tar.bz2": ".tar.bz2",
    "tbz2": ".tbz2",
}
FORMAT_TO_7Z_TYPE = {
    "tar": None,
    "tar.gz": "-tgzip",
    "tgz": "-tgzip",
    "tar.xz": "-txz",
    "txz": "-txz",
    "tar.bz2": "-tbzip2",
    "tbz2": "-tbzip2",
}


def validate_format(format_name):
    if format_name in FORMAT_TO_SUFFIX:
        return format_name
    raise ValueError(f"unsupported tar format: {format_name}")


def output_name(stem, format_name):
    return f"{stem}{FORMAT_TO_SUFFIX[validate_format(format_name)]}"


def _job_output_stem(job):
    if job.item_type == "file":
        return os.path.splitext(os.path.basename(job.rel_path))[0]
    return os.path.basename(job.rel_path.rstrip("/\\"))


def _archive_source_path(job):
    if job.item_type == "folder":
        return os.path.join(job.item_path, "*")
    return job.item_path


def build_command_plan(job, args):
    format_name = validate_format(getattr(args, "format", None))
    temp_tar = os.path.join(job.tmp_dir, "temp_archive.tar")
    source_path = _archive_source_path(job)
    plan = [["7z", "a", "-ttar", temp_tar, source_path]]

    compression_type = FORMAT_TO_7Z_TYPE[format_name]
    if compression_type is not None:
        final_temp = os.path.join(job.tmp_dir, output_name("temp_archive", format_name))
        plan.append(["7z", "a", compression_type, final_temp, temp_tar])

    return plan


def find_and_rename_tar_file(
    temp_name_prefix, target_name_prefix, search_dir, format_name, debug=False
):
    del debug
    suffix = FORMAT_TO_SUFFIX[validate_format(format_name)]
    search_root = fs.safe_abspath(search_dir)
    source_file = os.path.join(search_root, f"{temp_name_prefix}{suffix}")
    if not fs.safe_exists(source_file):
        return False, []

    target_file = fs.safe_abspath(
        os.path.join(search_root, f"{target_name_prefix}{suffix}")
    )
    if fs.safe_abspath(source_file) == target_file:
        return True, [target_file]
    if not fs.safe_move(source_file, target_file):
        return False, []
    return True, [target_file]


class TarBackend(BackendBase):
    name = "tar"

    def register_arguments(self, subparser):
        subparser.add_argument("--format", required=True)
        return subparser

    def capabilities(self):
        return models.BackendCapabilities(
            supports_password=False,
            supports_split_volumes=False,
            supports_native_recovery=False,
            supports_external_recovery=True,
            supports_embedded_recovery=False,
            supports_comments=False,
            supports_explicit_format=True,
        )

    def validate_args(self, args):
        validate_format(getattr(args, "format", None))

    def required_tools_for_format(self, format_name):
        return process.required_tools_for_tar_format(validate_format(format_name))

    def has_tooling_for_format(self, format_name):
        return process.has_tools(self.required_tools_for_format(format_name))

    def missing_tools_for_format(self, format_name):
        return process.missing_tools(self.required_tools_for_format(format_name))

    def check_required_tools(self, args):
        format_name = validate_format(getattr(args, "format", None))
        if not self.has_tooling_for_format(format_name):
            missing = self.missing_tools_for_format(format_name)
            raise process.MissingToolError(
                "required tool not found on PATH for tar format "
                f"{format_name}: {', '.join(missing)}"
            )
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
        format_name = validate_format(getattr(args, "format", None))
        command_plan = build_command_plan(job, args)
        preview = " && ".join(
            process.format_command(command) for command in command_plan
        )
        if getattr(args, "dry_run", False):
            return models.BackendExecutionResult(
                archive_result=models.ArchiveExecutionResult(command=preview)
            )

        for command in command_plan:
            result = process.run_command(command, debug=getattr(args, "debug", False))
            if result.returncode != 0:
                return models.BackendExecutionResult(
                    archive_result=models.ArchiveExecutionResult(
                        error_code=result.returncode,
                        error_msg=(
                            result.stderr or result.stdout or "tar command failed"
                        ).strip(),
                        command=process.format_command(command),
                    )
                )

        renamed, archive_files = find_and_rename_tar_file(
            "temp_archive",
            _job_output_stem(job),
            job.tmp_dir,
            format_name,
            debug=getattr(args, "debug", False),
        )
        if not renamed or not archive_files:
            return models.BackendExecutionResult(
                archive_result=models.ArchiveExecutionResult(
                    error_msg="failed to locate and rename tar output artifact",
                    command=preview,
                )
            )

        return models.BackendExecutionResult(
            archive_result=models.ArchiveExecutionResult(
                archive_files=archive_files,
                command=preview,
            )
        )

    def select_recovery_provider(self, args, execution_result):
        del execution_result
        if getattr(args, "no_rec", False):
            return None
        return ParparRecoveryProvider(mode="external")
