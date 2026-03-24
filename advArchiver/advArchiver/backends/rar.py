from __future__ import annotations

import glob
import importlib
import os
import platform
import re
import shutil

from advArchiver.advArchiver import models
from advArchiver.advArchiver.common import fs

process = importlib.import_module("advArchiver.advArchiver.common.process")
BackendBase = importlib.import_module(
    "advArchiver.advArchiver.backends.base"
).BackendBase
RarNativeRecoveryProvider = importlib.import_module(
    "advArchiver.advArchiver.recovery.rar_native"
).RarNativeRecoveryProvider


SPLIT_PROFILE_PATTERN = re.compile(
    r"^(parted|best)-(\d+)(g|gb|m|mb|k|kb)$",
    re.IGNORECASE,
)
RECOVERY_RECORD_SIGNAL_PATTERN = re.compile(
    r"(?:data\s+)?recovery\s+record",
    re.IGNORECASE,
)
RAR_WARNING_EXIT_CODE = 1


def _validate_comments_path(comments_path):
    if not comments_path:
        return

    resolved_path = fs.safe_abspath(comments_path)
    if not fs.safe_isfile(resolved_path):
        raise ValueError(f"comments path does not exist: {comments_path}")


def normalize_volume_size(size, unit):
    normalized_unit = unit.lower()
    if normalized_unit in {"g", "gb"}:
        return f"{size}g"
    if normalized_unit in {"m", "mb"}:
        return f"{size}m"
    if normalized_unit in {"k", "kb"}:
        return f"{size}k"
    return f"{size}{normalized_unit}"


def _resolve_rar_command():
    if shutil.which("rar") is not None:
        return "rar"
    if platform.system() == "Windows" and shutil.which("winrar") is not None:
        return "winrar"
    return None


def get_rar_command():
    return _resolve_rar_command() or "rar"


def build_comment_switch(comment_file_path):
    return f"-z{comment_file_path}"


def build_switches(args, comment_switch=None):
    profile = getattr(args, "profile", "best")
    switches = []

    if getattr(args, "delete", False):
        switches.append("-df")

    if profile == "store":
        switches.extend(["-m0", "-md32m", "-s-", "-htb", "-qo+", "-oi:1"])
    elif profile == "fastest":
        switches.extend(["-m1", "-md256m", "-s-", "-htb", "-qo+", "-oi:1"])
    elif profile.startswith("parted-"):
        switches.extend(["-m0", "-md32m", "-s-", "-htb", "-qo+", "-oi:1"])
        match = SPLIT_PROFILE_PATTERN.match(profile)
        if match is not None:
            switches.append(
                f"-v{normalize_volume_size(match.group(2), match.group(3))}"
            )
    else:
        switches.extend(["-m5", "-md256m", "-s", "-htb", "-qo+", "-oi:1"])
        match = SPLIT_PROFILE_PATTERN.match(profile)
        if match is not None:
            switches.append(
                f"-v{normalize_volume_size(match.group(2), match.group(3))}"
            )

    if not getattr(args, "no_rec", False):
        switches.append("-rr5p")
    switches.extend(["-ma5", "-ep1"])

    password = getattr(args, "password", None)
    if password:
        switches.extend([f"-p{password}", "-hp"])

    if comment_switch:
        switches.append(comment_switch)

    return switches


def _job_output_stem(job):
    if job.item_type == "file":
        return os.path.splitext(os.path.basename(job.rel_path))[0]
    return os.path.basename(job.rel_path)


def _prepare_folder_path_for_rar(folder_path):
    normalized = fs.safe_abspath(folder_path).rstrip("/\\")
    separator = "\\" if platform.system() == "Windows" else "/"
    return normalized + separator


def _comment_switch_for(job, args):
    comments = getattr(args, "comments", None)
    comments_path = getattr(args, "comments_path", None)

    if comments and comments_path:
        raise ValueError("cannot specify both inline comments and comments_path")
    if comments:
        comment_file_path = os.path.join(job.tmp_dir, "rar-comment.txt")
        with open(comment_file_path, "w", encoding="utf-8") as handle:
            handle.write(comments)
        return build_comment_switch(comment_file_path)
    if comments_path:
        _validate_comments_path(comments_path)
        return build_comment_switch(fs.safe_abspath(comments_path))
    return None


def _build_archive_command(job, args):
    comment_switch = _comment_switch_for(job, args)
    command = [get_rar_command(), "a"]
    if job.item_type == "folder":
        command.append("-r")
    command.extend(build_switches(args, comment_switch=comment_switch))

    archive_path = os.path.join(job.tmp_dir, "temp_archive.rar")
    source_path = job.item_path
    if job.item_type == "folder":
        source_path = _prepare_folder_path_for_rar(job.item_path)

    command.extend([archive_path, source_path])
    return command


def _is_native_recovery_warning(result):
    if result.returncode != RAR_WARNING_EXIT_CODE:
        return False
    stderr = (result.stderr or "").strip()
    return bool(stderr) and bool(RECOVERY_RECORD_SIGNAL_PATTERN.search(stderr))


def find_and_rename_rar_files(
    temp_name_prefix, target_name_prefix, search_dir, debug=False
):
    del debug
    search_root = fs.safe_abspath(search_dir)
    single_file = os.path.join(search_root, f"{temp_name_prefix}.rar")
    if fs.safe_exists(single_file):
        target_file = fs.safe_abspath(
            os.path.join(search_root, f"{target_name_prefix}.rar")
        )
        if fs.safe_move(single_file, target_file):
            return True, [target_file]
        return False, []

    candidates = []
    for pattern in (
        os.path.join(search_root, f"{temp_name_prefix}.part*.rar"),
        os.path.join(search_root, f"{temp_name_prefix}.part*.RAR"),
    ):
        candidates.extend(glob.glob(pattern))

    part_files = []
    for candidate in sorted(set(candidates)):
        match = re.match(
            rf"^{re.escape(temp_name_prefix)}\.(part\d+)\.rar$",
            os.path.basename(candidate),
            re.IGNORECASE,
        )
        if match is None:
            continue
        suffix = match.group(1)
        digits = re.search(r"(\d+)$", suffix)
        order = int(digits.group(1)) if digits is not None else 0
        part_files.append((order, suffix, candidate))

    if not part_files:
        return False, []

    renamed_files = []
    for _, suffix, candidate in sorted(part_files):
        target_file = fs.safe_abspath(
            os.path.join(search_root, f"{target_name_prefix}.{suffix}.rar")
        )
        if not fs.safe_move(candidate, target_file):
            return False, renamed_files
        renamed_files.append(target_file)

    return True, renamed_files


class RarBackend(BackendBase):
    name = "rar"

    def register_arguments(self, subparser):
        subparser.add_argument("-p", "--password")
        subparser.add_argument("--profile", default="best")
        comment_group = subparser.add_mutually_exclusive_group()
        comment_group.add_argument("-c", "--comments")
        comment_group.add_argument("-cp", "--comments-path")
        return subparser

    def capabilities(self):
        return models.BackendCapabilities(
            supports_password=True,
            supports_split_volumes=True,
            supports_native_recovery=True,
            supports_external_recovery=False,
            supports_embedded_recovery=True,
            supports_comments=True,
            supports_explicit_format=False,
        )

    def validate_args(self, args):
        if getattr(args, "comments", None) and getattr(args, "comments_path", None):
            raise ValueError("cannot specify both --comments and --comments-path")
        _validate_comments_path(getattr(args, "comments_path", None))

    def check_required_tools(self, args):
        del args
        if _resolve_rar_command() is None:
            raise process.MissingToolError("required tool not found on PATH: rar")

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
            recovery_result = None
            if not getattr(args, "no_rec", False):
                recovery_result = models.RecoveryExecutionResult(
                    command=command_string,
                    embedded=True,
                )
            return models.BackendExecutionResult(
                archive_result=models.ArchiveExecutionResult(command=command_string),
                recovery_result=recovery_result,
            )

        result = process.run_command(command, debug=getattr(args, "debug", False))
        renamed, archive_files = find_and_rename_rar_files(
            "temp_archive",
            _job_output_stem(job),
            job.tmp_dir,
            debug=getattr(args, "debug", False),
        )
        error_msg = (result.stderr or result.stdout or "rar command failed").strip()

        if result.returncode == 0:
            if not renamed or not archive_files:
                return models.BackendExecutionResult(
                    archive_result=models.ArchiveExecutionResult(
                        error_msg="failed to locate and rename rar output artifacts",
                        command=command_string,
                    )
                )

            recovery_result = None
            if not getattr(args, "no_rec", False):
                recovery_result = models.RecoveryExecutionResult(
                    command=command_string,
                    embedded=True,
                )
            return models.BackendExecutionResult(
                archive_result=models.ArchiveExecutionResult(
                    archive_files=archive_files,
                    command=command_string,
                ),
                recovery_result=recovery_result,
            )

        if (
            not getattr(args, "no_rec", False)
            and renamed
            and archive_files
            and _is_native_recovery_warning(result)
        ):
            return models.BackendExecutionResult(
                archive_result=models.ArchiveExecutionResult(
                    archive_files=archive_files,
                    command=command_string,
                ),
                recovery_result=models.RecoveryExecutionResult(
                    error_msg=error_msg,
                    command=command_string,
                    embedded=True,
                ),
            )

        return models.BackendExecutionResult(
            archive_result=models.ArchiveExecutionResult(
                error_code=result.returncode,
                error_msg=error_msg,
                command=command_string,
            )
        )

    def select_recovery_provider(self, args, execution_result):
        del execution_result
        if getattr(args, "no_rec", False):
            return None
        return RarNativeRecoveryProvider()
