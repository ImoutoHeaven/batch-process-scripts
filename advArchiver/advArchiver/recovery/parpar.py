from __future__ import annotations

import importlib

from advArchiver.advArchiver import models
from advArchiver.advArchiver.common import fs

process = importlib.import_module("advArchiver.advArchiver.common.process")
RecoveryProviderBase = importlib.import_module(
    "advArchiver.advArchiver.recovery.base"
).RecoveryProviderBase


APPEND_EMBED_MODE = "append-embed"
EXTERNAL_MODE = "external"


def _archive_files_from(execution_result):
    if isinstance(execution_result, models.BackendExecutionResult):
        return list(execution_result.archive_result.archive_files)
    if isinstance(execution_result, models.ArchiveExecutionResult):
        return list(execution_result.archive_files)
    return list(execution_result)


def build_parpar_command(archive_file, output_file):
    return [
        "parpar",
        "-s",
        "0.6w",
        "--noindex",
        "-r",
        "5%",
        "--unicode",
        "--recovery-files",
        "1",
        "-R",
        "-o",
        output_file,
        archive_file,
    ]


def _cleanup(paths):
    for path in paths:
        fs.safe_remove(path)


def _generated_recovery_files(generated_files):
    return [generated_file for _, generated_file in generated_files]


def _append_file_contents(target_file, source_file):
    try:
        with open(source_file, "rb") as source_handle:
            payload = source_handle.read()
        with open(target_file, "ab") as target_handle:
            target_handle.write(payload)
        return True
    except OSError:
        return False


class ParparRecoveryProvider(RecoveryProviderBase):
    uses_recovery_executor = True

    def __init__(self, mode):
        if mode not in {APPEND_EMBED_MODE, EXTERNAL_MODE}:
            raise ValueError(f"unsupported parpar mode: {mode}")
        self.mode = mode

    def check_required_tools(self, args):
        del args
        process.require_tool("parpar")

    def apply(self, job, execution_result, args):
        del job
        debug = getattr(args, "debug", False)
        archive_files = _archive_files_from(execution_result)
        if not archive_files:
            return models.RecoveryExecutionResult(
                error_msg="no archive artifacts available for parpar recovery",
                embedded=self.mode == APPEND_EMBED_MODE,
            )

        generated_files = []
        command_strings = [
            process.format_command(
                build_parpar_command(archive_file, f"{archive_file}.par2")
            )
            for archive_file in archive_files
        ]

        if getattr(args, "dry_run", False):
            return models.RecoveryExecutionResult(
                command="; ".join(command_strings),
                embedded=self.mode == APPEND_EMBED_MODE,
            )

        for archive_file in archive_files:
            par2_file = f"{archive_file}.par2"
            command = build_parpar_command(archive_file, par2_file)
            command_string = process.format_command(command)
            try:
                result = process.run_command(command, debug=debug)
            except Exception:
                _cleanup(_generated_recovery_files(generated_files) + [par2_file])
                raise
            if result.returncode != 0 or not fs.safe_exists(par2_file):
                _cleanup(_generated_recovery_files(generated_files) + [par2_file])
                return models.RecoveryExecutionResult(
                    error_msg=(
                        result.stderr or result.stdout or "parpar failed"
                    ).strip(),
                    command=command_string,
                    embedded=self.mode == APPEND_EMBED_MODE,
                )
            generated_files.append((archive_file, par2_file))

        if self.mode == APPEND_EMBED_MODE:
            for archive_file, par2_file in generated_files:
                if not _append_file_contents(archive_file, par2_file):
                    _cleanup(_generated_recovery_files(generated_files))
                    return models.RecoveryExecutionResult(
                        error_msg=f"failed to append recovery data to {archive_file}",
                        command="; ".join(command_strings),
                        embedded=True,
                    )

            _cleanup(_generated_recovery_files(generated_files))
            return models.RecoveryExecutionResult(
                command="; ".join(command_strings),
                embedded=True,
            )

        return models.RecoveryExecutionResult(
            recovery_files=[generated_file for _, generated_file in generated_files],
            command="; ".join(command_strings),
            embedded=False,
        )
