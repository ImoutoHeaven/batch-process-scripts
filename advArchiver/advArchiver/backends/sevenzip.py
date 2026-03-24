from __future__ import annotations

import glob
import importlib
import os
import re

from advArchiver.advArchiver import models
from advArchiver.advArchiver.common import fs

process = importlib.import_module("advArchiver.advArchiver.common.process")
ParparRecoveryProvider = importlib.import_module(
    "advArchiver.advArchiver.recovery.parpar"
).ParparRecoveryProvider
BackendBase = importlib.import_module(
    "advArchiver.advArchiver.backends.base"
).BackendBase


SPLIT_PROFILE_PATTERN = re.compile(
    r"^(parted|best)-(\d+)(g|gb|m|mb|k|kb)$",
    re.IGNORECASE,
)
SPLIT_VOLUME_PATTERN = re.compile(r"\.7z\.\d+$", re.IGNORECASE)


def normalize_volume_size(size, unit):
    normalized_unit = unit.lower()
    if normalized_unit in {"g", "gb"}:
        return f"{size}g"
    if normalized_unit in {"m", "mb"}:
        return f"{size}m"
    if normalized_unit in {"k", "kb"}:
        return f"{size}k"
    return f"{size}{normalized_unit}"


def build_7z_switches(profile, password, delete_files=False):
    switches = []
    if delete_files:
        switches.append("-sdel")

    if profile == "store":
        switches.extend(["-m0=Copy", "-ms=off"])
    elif profile == "fastest":
        switches.extend(["-mx=1", "-ms=off", "-md=256m"])
    elif profile.startswith("parted-"):
        switches.extend(["-m0=Copy", "-ms=off"])
        match = SPLIT_PROFILE_PATTERN.match(profile)
        if match is not None:
            switches.append(
                f"-v{normalize_volume_size(match.group(2), match.group(3))}"
            )
    else:
        switches.extend(["-mx=9", "-ms=on", "-md=256m"])
        match = SPLIT_PROFILE_PATTERN.match(profile)
        if match is not None:
            switches.append(
                f"-v{normalize_volume_size(match.group(2), match.group(3))}"
            )

    if password:
        switches.extend([f"-p{password}", "-mhe=on"])

    return switches


def is_split_volume_output(archive_files):
    return any(
        SPLIT_VOLUME_PATTERN.search(os.path.basename(path)) for path in archive_files
    )


def _archive_files_from(execution_result):
    if isinstance(execution_result, models.BackendExecutionResult):
        return list(execution_result.archive_result.archive_files)
    if isinstance(execution_result, models.ArchiveExecutionResult):
        return list(execution_result.archive_files)
    return list(execution_result)


def _job_output_stem(job):
    if job.item_type == "file":
        return os.path.splitext(os.path.basename(job.rel_path))[0]
    return os.path.basename(job.rel_path)


def _resolve_final_output_dir(item_path, args):
    out_dir = getattr(args, "out", None)
    if out_dir:
        return fs.safe_abspath(out_dir)
    return os.path.dirname(fs.safe_abspath(item_path))


def _build_archive_command(job, args):
    archive_path = os.path.join(job.tmp_dir, "temp_archive.7z")
    source_path = job.item_path
    if job.item_type == "folder":
        source_path = os.path.join(job.item_path, "*")

    return [
        "7z",
        "a",
        *build_7z_switches(
            getattr(args, "profile", "best"),
            getattr(args, "password", None),
            delete_files=getattr(args, "delete", False),
        ),
        archive_path,
        source_path,
    ]


def find_and_rename_7z_files(
    temp_name_prefix, target_name_prefix, search_dir, debug=False
):
    del debug
    search_root = fs.safe_abspath(search_dir)
    single_file = os.path.join(search_root, f"{temp_name_prefix}.7z")

    if fs.safe_exists(single_file):
        target_file = fs.safe_abspath(
            os.path.join(search_root, f"{target_name_prefix}.7z")
        )
        if fs.safe_move(single_file, target_file):
            return True, [target_file]
        return False, []

    pattern = os.path.join(search_root, f"{temp_name_prefix}.7z.*")
    part_files = []
    for candidate in sorted(set(glob.glob(pattern))):
        filename = os.path.basename(candidate)
        match = re.match(
            rf"^{re.escape(temp_name_prefix)}\.7z\.(\d+)$",
            filename,
            re.IGNORECASE,
        )
        if match is not None:
            part_files.append((int(match.group(1)), match.group(1), candidate))

    if not part_files:
        return False, []

    renamed_files = []
    for _, volume_number, part_file in sorted(part_files):
        target_file = fs.safe_abspath(
            os.path.join(search_root, f"{target_name_prefix}.7z.{volume_number}")
        )
        if not fs.safe_move(part_file, target_file):
            return False, renamed_files
        renamed_files.append(target_file)

    return True, renamed_files


class SevenZipBackend(BackendBase):
    name = "7z"

    def register_arguments(self, subparser):
        subparser.add_argument("-p", "--password")
        subparser.add_argument("--profile", default="best")
        subparser.add_argument("--no-emb", action="store_true")
        return subparser

    def capabilities(self):
        return models.BackendCapabilities(
            supports_password=True,
            supports_split_volumes=True,
            supports_native_recovery=False,
            supports_external_recovery=True,
            supports_embedded_recovery=True,
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
            final_output_dir=_resolve_final_output_dir(normalized_path, args),
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
                        result.stderr or result.stdout or "7z command failed"
                    ).strip(),
                    command=command_string,
                )
            )

        renamed, archive_files = find_and_rename_7z_files(
            "temp_archive",
            _job_output_stem(job),
            job.tmp_dir,
            debug=getattr(args, "debug", False),
        )
        if not renamed or not archive_files:
            return models.BackendExecutionResult(
                archive_result=models.ArchiveExecutionResult(
                    error_msg="failed to locate and rename 7z output artifacts",
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
        if getattr(args, "no_rec", False):
            return None

        archive_files = _archive_files_from(execution_result)
        if is_split_volume_output(archive_files):
            return ParparRecoveryProvider(mode="external")
        if getattr(args, "no_emb", False):
            return ParparRecoveryProvider(mode="external")
        return ParparRecoveryProvider(mode="append-embed")
