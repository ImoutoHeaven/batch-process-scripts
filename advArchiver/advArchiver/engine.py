from __future__ import annotations

import os
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass, field

from advArchiver.advArchiver import models
from advArchiver.advArchiver.common import fs, locking, stats as stats_module


GENERAL_FAILURE_EXIT_CODE = 1
LOCK_FAILURE_EXIT = 2
RECOVERY_WARNING_EXIT_CODE = 3


@dataclass
class LockLease:
    path: str
    acquired: bool
    skipped: bool = False
    released: bool = False

    def release(self) -> bool:
        if self.released or self.skipped or not self.acquired:
            self.released = True
            return True
        self.released = True
        if not os.path.exists(self.path):
            return True
        return fs.safe_remove(self.path)


@dataclass
class RunFailureRecord:
    error_msg: str
    item_path: str = ""
    command: str = ""


@dataclass
class JobExecutionResult:
    job: models.ArchiveJob
    archive_result: models.ArchiveExecutionResult
    recovery_result: models.RecoveryExecutionResult | None = None
    final_artifacts: models.ArchiveArtifacts = field(
        default_factory=models.ArchiveArtifacts
    )
    source_deleted: bool = False
    hard_failure: bool = False
    failure_error_code: int = 0
    failure_error_msg: str = ""
    failure_command: str = ""

    @property
    def has_recovery_warning(self) -> bool:
        return (
            not self.hard_failure
            and self.archive_result.succeeded
            and self.recovery_result is not None
            and not self.recovery_result.succeeded
        )


@dataclass
class EngineRunSummary:
    stats: stats_module.CompressionStats = field(
        default_factory=stats_module.CompressionStats
    )
    job_results: list[JobExecutionResult] = field(default_factory=list)
    run_failures: list[RunFailureRecord] = field(default_factory=list)
    exit_code: int = 0
    lock_acquired: bool = False

    @property
    def hard_failure_count(self) -> int:
        return self.stats.hard_failure_count + len(self.run_failures)

    @property
    def warning_count(self) -> int:
        return self.stats.recovery_warning_count

    @property
    def success_count(self) -> int:
        return self.stats.success_files + self.stats.success_folders


@dataclass
class PendingRecovery:
    job: models.ArchiveJob
    execution_result: models.BackendExecutionResult
    provider: object


def final_exit_code(hard_failures, recovery_warnings):
    if hard_failures:
        return GENERAL_FAILURE_EXIT_CODE
    if recovery_warnings:
        return RECOVERY_WARNING_EXIT_CODE
    return 0


def lock_failure_exit_code():
    return LOCK_FAILURE_EXIT


def should_delete_source(archive_ok, recovery_ok):
    return archive_ok and recovery_ok


def schedule_order(events):
    return list(events)


def should_skip_lock(no_lock):
    return bool(no_lock)


def lock_attempt_budget(lock_timeout):
    return max(1, int(lock_timeout))


def acquire_lock(lock_path=None, max_attempts=30, sleep_interval=0.05):
    resolved_path = os.path.abspath(lock_path or locking.get_lock_file_path())
    parent = os.path.dirname(resolved_path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    attempts = lock_attempt_budget(max_attempts)
    for attempt in range(attempts):
        try:
            with open(resolved_path, "x", encoding="utf-8") as handle:
                handle.write(str(os.getpid()))
            return LockLease(path=resolved_path, acquired=True)
        except FileExistsError:
            if attempt == attempts - 1:
                break
            if sleep_interval:
                time.sleep(sleep_interval)

    return LockLease(path=resolved_path, acquired=False)


@contextmanager
def optional_lock(no_lock=False, lock_timeout=30, lock_path=None, sleep_interval=0.05):
    if should_skip_lock(no_lock):
        yield LockLease(
            path=os.path.abspath(lock_path or locking.get_lock_file_path()),
            acquired=False,
            skipped=True,
        )
        return

    lease = acquire_lock(
        lock_path=lock_path,
        max_attempts=lock_attempt_budget(lock_timeout),
        sleep_interval=sleep_interval,
    )
    try:
        yield lease
    finally:
        lease.release()


def prepare_job(backend, item_path, args, base_path):
    debug = getattr(args, "debug", False)
    input_info = fs.validate_input_path(item_path, debug=debug)
    job = backend.build_job(input_info.path, args, base_path)
    if not isinstance(job, models.ArchiveJob):
        raise TypeError("backend.build_job() must return ArchiveJob")

    job.item_path = input_info.path
    if not job.backend_name:
        job.backend_name = getattr(backend, "name", "")
    if not job.item_type:
        job.item_type = "file" if input_info.is_file else "folder"
    if not job.rel_path:
        job.rel_path = fs.get_relative_path(job.item_path, base_path).replace(
            os.sep, "/"
        )
    if not job.final_output_dir:
        job.final_output_dir = fs.compute_final_output_dir(
            job.item_path,
            base_path,
            getattr(args, "out", None),
        )

    return job


def run(item_paths, backend, args, base_path, lock_path=None, temp_root=None):
    summary = EngineRunSummary()
    temp_root = temp_root or tempfile.gettempdir()

    try:
        backend.validate_args(args)
        backend.check_required_tools(args)

        with optional_lock(
            no_lock=getattr(args, "no_lock", False),
            lock_timeout=getattr(args, "lock_timeout", 30),
            lock_path=lock_path,
        ) as lease:
            if not lease.acquired and not lease.skipped:
                summary.exit_code = lock_failure_exit_code()
                return summary

            summary.lock_acquired = lease.acquired
            archive_workers = max(1, int(getattr(args, "threads", 1)))
            recovery_workers = max(1, int(getattr(args, "rec_threads", 1)))

            with ThreadPoolExecutor(max_workers=archive_workers) as archive_executor:
                with ThreadPoolExecutor(
                    max_workers=recovery_workers
                ) as recovery_executor:
                    archive_futures = [
                        archive_executor.submit(
                            _run_archive_phase,
                            item_path,
                            backend,
                            args,
                            base_path,
                            temp_root,
                        )
                        for item_path in item_paths
                    ]
                    recovery_futures = []

                    for future in as_completed(archive_futures):
                        try:
                            outcome = future.result()
                        except Exception as exc:
                            _record_run_failure(summary, _error_message(exc))
                            continue

                        if isinstance(outcome, PendingRecovery):
                            recovery_futures.append(
                                recovery_executor.submit(
                                    _finish_external_recovery,
                                    outcome,
                                    args,
                                )
                            )
                            continue

                        _record_job_result(summary.stats, outcome)
                        summary.job_results.append(outcome)

                    for future in as_completed(recovery_futures):
                        try:
                            outcome = future.result()
                        except Exception as exc:
                            _record_run_failure(summary, _error_message(exc))
                            continue

                        _record_job_result(summary.stats, outcome)
                        summary.job_results.append(outcome)

    except Exception as exc:
        _record_run_failure(summary, _error_message(exc))

    summary.job_results.sort(key=lambda result: result.job.item_path)
    summary.exit_code = final_exit_code(
        summary.hard_failure_count,
        summary.warning_count,
    )
    return summary


def _run_archive_phase(item_path, backend, args, base_path, temp_root):
    debug = getattr(args, "debug", False)
    job = None
    defer_cleanup = False

    try:
        job = prepare_job(backend, item_path, args, base_path)
        job.tmp_dir = fs.create_unique_tmp_dir(temp_root, debug=debug) or ""
        if not job.tmp_dir:
            return _hard_failure(
                job,
                failure_error_msg="unable to create temporary working directory",
            )

        execution_result = _ensure_backend_execution_result(
            backend.execute_job(job, args)
        )
        archive_result = execution_result.archive_result
        if _is_dry_run_preview(args, archive_result):
            return _preview_success(
                job, archive_result, execution_result.recovery_result
            )

        if not archive_result.succeeded:
            return _hard_failure(
                job,
                archive_result=archive_result,
                failure_error_code=archive_result.error_code
                or GENERAL_FAILURE_EXIT_CODE,
                failure_error_msg=_archive_failure_message(archive_result),
                failure_command=archive_result.command,
            )

        provider = backend.select_recovery_provider(args, execution_result)
        if provider is None:
            if execution_result.recovery_result is not None:
                return _hard_failure(
                    job,
                    archive_result=archive_result,
                    failure_error_msg=(
                        "backend returned a recovery result without a recovery provider"
                    ),
                    failure_command=archive_result.command,
                )
            return _finalize_job(job, execution_result, None, args)

        if getattr(provider, "uses_recovery_executor", True):
            defer_cleanup = True
            return PendingRecovery(
                job=job,
                execution_result=execution_result,
                provider=provider,
            )

        recovery_result = _apply_recovery(provider, job, execution_result, args)
        return _finalize_job(job, execution_result, recovery_result, args)
    except Exception as exc:
        if job is None:
            job = _fallback_job(backend, item_path, args, base_path)
        return _hard_failure(job, failure_error_msg=_error_message(exc))
    finally:
        if job is not None and not defer_cleanup:
            fs.cleanup_tmp_dir(job.tmp_dir, debug=debug)


def _finish_external_recovery(pending, args):
    debug = getattr(args, "debug", False)
    try:
        recovery_result = _apply_recovery(
            pending.provider,
            pending.job,
            pending.execution_result,
            args,
        )
        return _finalize_job(
            pending.job,
            pending.execution_result,
            recovery_result,
            args,
        )
    except Exception as exc:
        return _hard_failure(
            pending.job,
            archive_result=pending.execution_result.archive_result,
            failure_error_msg=_error_message(exc),
            failure_command=pending.execution_result.archive_result.command,
        )
    finally:
        fs.cleanup_tmp_dir(pending.job.tmp_dir, debug=debug)


def _ensure_backend_execution_result(result):
    if not isinstance(result, models.BackendExecutionResult):
        raise TypeError("backend.execute_job() must return BackendExecutionResult")
    if not isinstance(result.archive_result, models.ArchiveExecutionResult):
        raise TypeError(
            "backend.execute_job().archive_result must be ArchiveExecutionResult"
        )
    if result.recovery_result is not None and not isinstance(
        result.recovery_result, models.RecoveryExecutionResult
    ):
        raise TypeError(
            "backend.execute_job().recovery_result must be RecoveryExecutionResult"
        )
    return result


def _ensure_recovery_result(result):
    if not isinstance(result, models.RecoveryExecutionResult):
        raise TypeError("recovery provider must return RecoveryExecutionResult")
    return result


def _apply_recovery(provider, job, execution_result, args):
    try:
        provider.check_required_tools(args)
        return _ensure_recovery_result(provider.apply(job, execution_result, args))
    except Exception as exc:
        return models.RecoveryExecutionResult(error_msg=_error_message(exc))


def _warning_recovery_result(recovery_result, error_msg=None):
    return models.RecoveryExecutionResult(
        error_msg=error_msg or recovery_result.error_msg,
        command=recovery_result.command,
        embedded=recovery_result.embedded,
    )


def _rollback_artifacts(paths, debug=False):
    failed_paths = []
    for path in paths:
        if not fs.safe_remove(path, debug=debug):
            failed_paths.append(path)
    return failed_paths


def _finalize_job(job, execution_result, recovery_result, args):
    debug = getattr(args, "debug", False)
    archive_result = execution_result.archive_result
    final_artifacts = models.ArchiveArtifacts()
    if not archive_result.archive_files:
        return _hard_failure(
            job,
            archive_result=archive_result,
            failure_error_msg=_archive_failure_message(archive_result),
            failure_command=archive_result.command,
        )

    archive_ok, moved_archives = fs.move_files_to_final_destination(
        archive_result.archive_files,
        job.final_output_dir,
        job.rel_path,
        debug=debug,
    )
    if not archive_ok:
        return _hard_failure(
            job,
            archive_result=archive_result,
            failure_error_msg="failed to move archive artifacts to final output directory",
            failure_command=archive_result.command,
        )

    final_artifacts.archive_files = moved_archives
    recovery_ok = recovery_result is None or recovery_result.succeeded

    if (
        not recovery_ok
        and recovery_result is not None
        and recovery_result.recovery_files
    ):
        recovery_result = _warning_recovery_result(recovery_result)

    if recovery_ok and recovery_result is not None and recovery_result.recovery_files:
        moved, moved_recovery = fs.move_files_to_final_destination(
            recovery_result.recovery_files,
            job.final_output_dir,
            job.rel_path,
            debug=debug,
        )
        if moved:
            final_artifacts.recovery_files = moved_recovery
        else:
            rollback_failures = _rollback_artifacts(moved_recovery, debug=debug)
            if rollback_failures:
                return JobExecutionResult(
                    job=job,
                    archive_result=archive_result,
                    recovery_result=models.RecoveryExecutionResult(
                        error_msg=(
                            "failed to roll back incomplete recovery artifacts: "
                            + ", ".join(rollback_failures)
                        ),
                        command=recovery_result.command,
                        embedded=recovery_result.embedded,
                    ),
                    final_artifacts=models.ArchiveArtifacts(
                        archive_files=moved_archives,
                    ),
                    source_deleted=False,
                    hard_failure=True,
                    failure_error_code=GENERAL_FAILURE_EXIT_CODE,
                    failure_error_msg=(
                        "failed to roll back incomplete recovery artifacts: "
                        + ", ".join(rollback_failures)
                    ),
                    failure_command=recovery_result.command or archive_result.command,
                )
            recovery_ok = False
            recovery_result = _warning_recovery_result(
                recovery_result,
                error_msg="failed to move recovery artifacts to final output directory",
            )

    source_deleted = False
    if getattr(args, "delete", False) and should_delete_source(True, recovery_ok):
        source_deleted = _delete_source(job, dry_run=getattr(args, "dry_run", False))

    return JobExecutionResult(
        job=job,
        archive_result=archive_result,
        recovery_result=recovery_result,
        final_artifacts=final_artifacts,
        source_deleted=source_deleted,
    )


def _delete_source(job, dry_run=False):
    if job.item_type == "file":
        return fs.safe_delete_file(job.item_path, dry_run=dry_run)
    return fs.safe_delete_folder(job.item_path, dry_run=dry_run)


def _is_dry_run_preview(args, archive_result):
    return (
        getattr(args, "dry_run", False)
        and archive_result.error_code == 0
        and not archive_result.error_msg
    )


def _preview_success(job, archive_result, recovery_result=None):
    return JobExecutionResult(
        job=job,
        archive_result=archive_result,
        recovery_result=recovery_result,
        final_artifacts=models.ArchiveArtifacts(),
        source_deleted=False,
    )


def _hard_failure(
    job,
    archive_result=None,
    failure_error_code=GENERAL_FAILURE_EXIT_CODE,
    failure_error_msg="",
    failure_command="",
):
    return JobExecutionResult(
        job=job,
        archive_result=archive_result
        or models.ArchiveExecutionResult(
            error_code=failure_error_code,
            error_msg=failure_error_msg,
            command=failure_command,
        ),
        hard_failure=True,
        failure_error_code=failure_error_code,
        failure_error_msg=failure_error_msg,
        failure_command=failure_command,
    )


def _fallback_job(backend, item_path, args, base_path):
    normalized_path = os.path.abspath(item_path)
    debug = getattr(args, "debug", False)
    item_type = "folder" if fs.safe_isdir(normalized_path, debug=debug) else "file"

    try:
        rel_path = fs.get_relative_path(normalized_path, base_path).replace(os.sep, "/")
    except Exception:
        rel_path = os.path.basename(normalized_path)

    try:
        final_output_dir = fs.compute_final_output_dir(
            normalized_path,
            base_path,
            getattr(args, "out", None),
        )
    except Exception:
        out_dir = getattr(args, "out", None)
        final_output_dir = (
            os.path.abspath(out_dir) if out_dir else os.path.dirname(normalized_path)
        )

    return models.ArchiveJob(
        backend_name=getattr(backend, "name", ""),
        item_path=normalized_path,
        item_type=item_type,
        rel_path=rel_path,
        final_output_dir=final_output_dir,
    )


def _record_job_result(stat_block, outcome):
    if outcome.hard_failure:
        stat_block.add_failure(
            outcome.job.item_type,
            outcome.job.item_path,
            outcome.failure_error_code or GENERAL_FAILURE_EXIT_CODE,
            outcome.failure_error_msg or outcome.archive_result.error_msg,
            outcome.failure_command or outcome.archive_result.command,
        )
        return

    stat_block.add_success(outcome.job.item_type, outcome.job.item_path)
    if outcome.has_recovery_warning:
        stat_block.add_recovery_warning(
            outcome.job.item_type,
            outcome.job.item_path,
            outcome.final_artifacts.archive_files
            or outcome.archive_result.archive_files,
        )


def _record_run_failure(summary, error_msg, item_path="", command=""):
    summary.run_failures.append(
        RunFailureRecord(
            error_msg=error_msg,
            item_path=item_path,
            command=command,
        )
    )


def _archive_failure_message(archive_result):
    if archive_result.error_msg:
        return archive_result.error_msg
    if not archive_result.archive_files:
        return "archive backend reported success without producing archive artifacts"
    return "archive backend failed"


def _error_message(exc):
    return str(exc) or exc.__class__.__name__
