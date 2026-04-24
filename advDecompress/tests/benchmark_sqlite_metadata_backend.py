import argparse
import json
import os
import shutil
import signal
import sqlite3
import statistics
import subprocess
import tempfile
import threading
import time
from pathlib import Path


TARGET_METADATA_SYSCALLS = {
    "close",
    "getdents64",
    "lseek",
    "newfstatat",
    "openat",
    "read",
}

JSON_BASELINE_COMMIT = "aa3227b98c60e328ab475300c07848cdff18c5c2"

INTERRUPT_POLL_SECONDS = 2.0
INTERRUPT_POLL_INTERVAL_SECONDS = 0.005
REQUIRED_VALID_SAMPLES = 3
MAX_SAMPLE_ATTEMPTS = 8
ARCHIVE_PROGRESS_STATES = (
    "pending",
    "extracting",
    "recoverable",
    "retryable",
    "succeeded",
    "failed",
)


def _build_case_command(repo_root, *, input_root, output_root):
    return [
        "python3",
        "-u",
        os.path.join(repo_root, "advDecompress", "advDecompress.py"),
        input_root,
        "-o",
        output_root,
        "-t",
        "1",
        "-dp",
        "direct",
        "-scj",
        "false",
        "-fcj",
        "false",
    ]


def assert_json_baseline_checkout(repo_root):
    branch = subprocess.check_output(
        ["git", "-C", repo_root, "branch", "--show-current"],
        text=True,
    ).strip()
    if branch not in ("", "testing"):
        raise RuntimeError("benchmark baseline must be captured from testing")
    if branch:
        raise RuntimeError(
            "benchmark baseline must be a detached checkout pinned to the JSON baseline commit"
        )

    commit = subprocess.check_output(
        ["git", "-C", repo_root, "rev-parse", "HEAD"],
        text=True,
    ).strip()
    if commit != JSON_BASELINE_COMMIT:
        raise RuntimeError(
            "benchmark baseline must use detached commit "
            f"{JSON_BASELINE_COMMIT}"
        )

    status = subprocess.check_output(
        ["git", "-C", repo_root, "status", "--short"],
        text=True,
    ).strip()
    if status:
        raise RuntimeError(
            "benchmark baseline checkout must be clean before benchmarking"
        )


def _create_small_archive_corpus(work_root, archives):
    input_root = os.path.join(work_root, "input")
    src_root = os.path.join(work_root, "src")
    if os.path.isdir(input_root):
        shutil.rmtree(input_root)
    if os.path.isdir(src_root):
        shutil.rmtree(src_root)
    os.makedirs(input_root, exist_ok=True)
    os.makedirs(src_root, exist_ok=True)
    for index in range(archives):
        src_dir = os.path.join(src_root, f"a{index:03d}")
        os.makedirs(src_dir, exist_ok=True)
        for file_index in range(3):
            with open(
                os.path.join(src_dir, f"f{file_index}.txt"),
                "w",
                encoding="utf-8",
            ) as f:
                f.write("x" * 128)
        subprocess.run(
            ["7z", "a", "-bd", os.path.join(input_root, f"a{index:03d}.zip"), src_dir],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    return input_root


def _summarize_success_outcome(result):
    success_line = next(
        (
            line
            for line in result.stdout.splitlines()
            if line.startswith("Successfully processed:")
        ),
        "Successfully processed: 0",
    )
    return {
        "returncode": result.returncode,
        "success_count": int(success_line.split(":", 1)[1].strip()),
        "failed_archives_present": "Failed archives:" in result.stdout,
    }


def _load_manifest_progress(output_root):
    manifest_path = Path(output_root) / ".advdecompress_work" / "dataset_manifest.json"
    if not manifest_path.exists():
        return None
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    progress = payload.get("progress") or {}
    return {
        "status": payload.get("status"),
        "counts": progress.get("counts") or {},
    }


def _load_sqlite_progress(output_root):
    db_path = Path(output_root) / ".advdecompress_work" / "metadata.sqlite"
    if not db_path.exists():
        return None
    conn = None
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        dataset_row = conn.execute("SELECT status FROM dataset_state").fetchone()
        counts = {state: 0 for state in ARCHIVE_PROGRESS_STATES}
        for row in conn.execute(
            "SELECT state, COUNT(*) AS count FROM archives GROUP BY state"
        ).fetchall():
            counts[str(row["state"])] = int(row["count"])
        return {
            "status": dataset_row["status"] if dataset_row is not None else None,
            "counts": counts,
        }
    except sqlite3.Error as exc:
        raise RuntimeError(
            f"could not read authoritative SQLite benchmark metadata from {db_path}: {exc}"
        ) from exc
    finally:
        if conn is not None:
            conn.close()


def _load_authoritative_progress(output_root):
    progress = _load_sqlite_progress(output_root)
    if progress is not None:
        return progress
    return _load_manifest_progress(output_root)


def _summarize_final_success_outcome(result, *, output_root):
    summary = _summarize_success_outcome(result)
    progress = _load_authoritative_progress(output_root)
    if progress is not None:
        summary["success_count"] = int(progress["counts"].get("succeeded", 0))
        summary["failed_archives_present"] = (
            int(progress["counts"].get("failed", 0)) > 0
            or summary["failed_archives_present"]
        )
    return summary


def _success_parity_contract(summary):
    return {
        "returncode": summary["success_outcome"]["returncode"],
        "success_count": summary["success_outcome"]["success_count"],
        "failed_archives": summary["resume_outcome"]["failed_archives"],
    }


def _recovery_parity_contract(summary):
    return {
        "initial_phase": summary["initial_outcome"]["phase"],
        "completed_terminal_state": summary["recovery_outcome"][
            "completed_terminal_state"
        ],
        "resume_errors_present": summary["recovery_outcome"]["resume_errors_present"],
    }


def _summarize_recovery_outcome(result):
    return {
        "resume_errors_present": (
            "requires --metadata-db" in result.stdout or "recover failed" in result.stdout
        ),
        "completed_terminal_state": "transactional workdir" not in result.stdout,
    }


def _summarize_final_recovery_outcome(result, *, output_root):
    summary = _summarize_recovery_outcome(result)
    progress = _load_authoritative_progress(output_root)
    if progress is not None:
        summary["completed_terminal_state"] = progress["status"] == "completed"
    if result.returncode != 0:
        summary["resume_errors_present"] = True
    return summary


def _metadata_churn_syscalls(stderr_text):
    calls_by_syscall = {}
    for line in stderr_text.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        syscall = parts[-1]
        if syscall not in TARGET_METADATA_SYSCALLS:
            continue
        try:
            calls_by_syscall[syscall] = int(parts[3])
        except ValueError:
            continue
    return {
        "calls_by_syscall": calls_by_syscall,
        "total_calls": sum(calls_by_syscall.values()),
    }


def _merge_syscall_summaries(*summaries):
    calls_by_syscall = {}
    for summary in summaries:
        if summary is None:
            continue
        for syscall, count in (summary.get("calls_by_syscall") or {}).items():
            calls_by_syscall[syscall] = calls_by_syscall.get(syscall, 0) + int(count)
    return {
        "calls_by_syscall": calls_by_syscall,
        "total_calls": sum(calls_by_syscall.values()),
    }


def _send_interrupt(process):
    if process.poll() is not None:
        return False
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGINT)
    except Exception:
        process.send_signal(signal.SIGINT)
    return True


def _extract_failed_archives(stdout):
    failed_archives = []
    collect = False
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if line == "Failed archives:":
            collect = True
            continue
        if not collect:
            continue
        if not line or not line.startswith("-"):
            break
        failed_archives.append(line[1:].strip())
    return failed_archives


def _interrupt_when_resume_safe(stdout_line, process, *, output_root):
    deadline = time.monotonic() + INTERRUPT_POLL_SECONDS
    while time.monotonic() < deadline:
        progress = _load_manifest_progress(output_root)
        if progress is not None:
            counts = progress["counts"]
            if (
                progress["status"] == "active"
                and int(counts.get("recoverable", 0)) >= 1
                and int(counts.get("extracting", 0)) == 0
                and int(counts.get("retryable", 0)) == 0
            ):
                return _send_interrupt(process)
        if process.poll() is not None:
            return False
        time.sleep(INTERRUPT_POLL_INTERVAL_SECONDS)
    return False


def _terminate_after_first_txn_snapshot(stdout_line, process, *, output_root):
    deadline = time.monotonic() + INTERRUPT_POLL_SECONDS
    work_base = Path(output_root) / ".advdecompress_work"
    while time.monotonic() < deadline:
        txn_snapshots = list(work_base.glob("outputs/*/journal/*/txn.json"))
        if txn_snapshots:
            return _send_interrupt(process)
        if process.poll() is not None:
            return False
        time.sleep(INTERRUPT_POLL_INTERVAL_SECONDS)
    return False


def _run_interrupt_then_resume(repo_root, *, work_root, archives, measure_syscalls):
    if os.path.isdir(work_root):
        shutil.rmtree(work_root)
    os.makedirs(work_root, exist_ok=True)

    input_root = _create_small_archive_corpus(work_root, archives)
    output_root = os.path.join(work_root, "output")
    initial = run_streamed_case(
        repo_root,
        input_root=input_root,
        output_root=output_root,
        measure_syscalls=measure_syscalls,
        stop_when=lambda line, process: _interrupt_when_resume_safe(
            line,
            process,
            output_root=output_root,
        ),
    )
    resumed = run_completed_case(
        repo_root,
        input_root=input_root,
        output_root=output_root,
        measure_syscalls=measure_syscalls,
    )
    return initial, resumed


def run_completed_case(repo_root, *, input_root, output_root, measure_syscalls):
    cmd = _build_case_command(
        repo_root,
        input_root=input_root,
        output_root=output_root,
    )
    strace_path = None
    if measure_syscalls:
        with tempfile.NamedTemporaryFile(prefix="advd-bench-", suffix=".strace", delete=False) as f:
            strace_path = f.name
        cmd = ["strace", "-f", "-c", "-o", strace_path] + cmd
    started = time.monotonic()
    result = subprocess.run(cmd, text=True, capture_output=True, check=False)
    if strace_path is not None:
        try:
            result.stderr = Path(strace_path).read_text(encoding="utf-8")
        finally:
            try:
                os.unlink(strace_path)
            except OSError:
                pass
    return result, time.monotonic() - started


def run_streamed_case(repo_root, *, input_root, output_root, stop_when, measure_syscalls=False):
    cmd = _build_case_command(
        repo_root,
        input_root=input_root,
        output_root=output_root,
    )
    strace_path = None
    if measure_syscalls:
        with tempfile.NamedTemporaryFile(prefix="advd-bench-", suffix=".strace", delete=False) as f:
            strace_path = f.name
        cmd = ["strace", "-f", "-c", "-o", strace_path] + cmd
    started = time.monotonic()
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    interrupted = {"value": False}

    def _watch_for_interrupt():
        while process.poll() is None and not interrupted["value"]:
            if stop_when("", process):
                interrupted["value"] = True
                return
            time.sleep(INTERRUPT_POLL_INTERVAL_SECONDS)

    watcher = threading.Thread(target=_watch_for_interrupt, daemon=True)
    watcher.start()
    stdout_text, stderr_text = process.communicate()
    watcher.join(timeout=INTERRUPT_POLL_INTERVAL_SECONDS)
    if strace_path is not None:
        try:
            stderr_text = Path(strace_path).read_text(encoding="utf-8")
        finally:
            try:
                os.unlink(strace_path)
            except OSError:
                pass
    return {
        "returncode": process.wait(),
        "stdout": stdout_text,
        "stderr": stderr_text,
        "interrupted": interrupted["value"],
        "wall_time_seconds": time.monotonic() - started,
        "syscalls": _metadata_churn_syscalls(stderr_text) if measure_syscalls else None,
    }


def run_case_summary(label, repo_root, *, work_root, archives, measure_syscalls):
    initial_result, resumed_result = _run_interrupt_then_resume(
        repo_root,
        work_root=work_root,
        archives=archives,
        measure_syscalls=measure_syscalls,
    )
    resumed_process, resumed_elapsed = resumed_result
    success_outcome = _summarize_final_success_outcome(
        resumed_process,
        output_root=os.path.join(work_root, "output"),
    )
    recovery_outcome = _summarize_final_recovery_outcome(
        resumed_process,
        output_root=os.path.join(work_root, "output"),
    )
    return {
        "label": label,
        "branch_or_commit": subprocess.check_output(
            ["git", "-C", repo_root, "rev-parse", "--short", "HEAD"],
            text=True,
        ).strip(),
        "returncode": resumed_process.returncode,
        "wall_time_seconds": resumed_elapsed,
        "scenario_wall_time_seconds": (
            float(initial_result.get("wall_time_seconds") or 0.0) + resumed_elapsed
        ),
        "initial_outcome": {
            "phase": (
                "interrupted"
                if initial_result["interrupted"]
                else "completed_without_interrupt"
            ),
            "returncode": initial_result["returncode"],
        },
        "resume_outcome": {
            "returncode": resumed_process.returncode,
            "success_count": _summarize_success_outcome(resumed_process)["success_count"],
            "failed_archives": _extract_failed_archives(resumed_process.stdout),
        },
        "success_outcome": success_outcome,
        "recovery_outcome": recovery_outcome,
        "final_progress": _load_authoritative_progress(
            os.path.join(work_root, "output")
        ),
        "syscalls": (
            _merge_syscall_summaries(
                initial_result.get("syscalls"),
                _metadata_churn_syscalls(resumed_process.stderr),
            )
            if measure_syscalls
            else None
        ),
    }


def _sample_invalid_reasons(summary, *, archives):
    reasons = []
    if summary["initial_outcome"]["phase"] != "interrupted":
        reasons.append("initial phase was not interrupted")
    if summary["returncode"] != 0:
        reasons.append("resume returncode was not 0")
    if summary["success_outcome"]["success_count"] != archives:
        reasons.append("overall success_count did not reach archive corpus size")
    if summary["resume_outcome"]["failed_archives"]:
        reasons.append("resume reported failed archives")
    if not summary["recovery_outcome"]["completed_terminal_state"]:
        reasons.append("final recovery outcome was not terminal completed")
    return reasons


def _collect_valid_case_samples(
    label,
    repo_root,
    *,
    work_root,
    archives,
    measure_syscalls,
    required_valid_samples=REQUIRED_VALID_SAMPLES,
    max_attempts=MAX_SAMPLE_ATTEMPTS,
):
    attempts = []
    valid_samples = []
    for attempt in range(1, max_attempts + 1):
        summary = run_case_summary(
            label,
            repo_root,
            work_root=os.path.join(work_root, f"attempt-{attempt:02d}"),
            archives=archives,
            measure_syscalls=measure_syscalls,
        )
        summary["attempt"] = attempt
        summary["invalid_reasons"] = _sample_invalid_reasons(summary, archives=archives)
        summary["sample_valid"] = not summary["invalid_reasons"]
        attempts.append(summary)
        if summary["sample_valid"]:
            valid_samples.append(summary)
        if len(valid_samples) >= required_valid_samples:
            break
    branch_or_commit = (
        attempts[0]["branch_or_commit"]
        if attempts
        else subprocess.check_output(
            ["git", "-C", repo_root, "rev-parse", "--short", "HEAD"],
            text=True,
        ).strip()
    )
    return {
        "label": label,
        "branch_or_commit": branch_or_commit,
        "required_valid_samples": required_valid_samples,
        "total_attempts": len(attempts),
        "valid_samples": valid_samples,
        "attempts": attempts,
    }


def _measurement_summary(values):
    return {
        "samples": values,
        "median": statistics.median(values),
        "min": min(values),
        "max": max(values),
    }


def _aggregate_case_samples(case):
    valid_samples = case["valid_samples"]
    aggregated = {
        "label": case["label"],
        "branch_or_commit": case["branch_or_commit"],
        "required_valid_samples": case["required_valid_samples"],
        "valid_sample_count": len(valid_samples),
        "total_attempts": case["total_attempts"],
        "valid_samples": valid_samples,
        "wall_time_seconds": _measurement_summary(
            [sample["wall_time_seconds"] for sample in valid_samples]
        ),
        "scenario_wall_time_seconds": _measurement_summary(
            [sample["scenario_wall_time_seconds"] for sample in valid_samples]
        ),
    }
    if valid_samples and valid_samples[0]["syscalls"] is not None:
        aggregated["syscalls"] = _measurement_summary(
            [sample["syscalls"]["total_calls"] for sample in valid_samples]
        )
    else:
        aggregated["syscalls"] = None
    return aggregated


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--archives", type=int, default=40)
    parser.add_argument("--work-root", required=True)
    parser.add_argument("--measure-syscalls", action="store_true")
    parser.add_argument("--valid-samples", type=int, default=REQUIRED_VALID_SAMPLES)
    parser.add_argument("--max-attempts", type=int, default=MAX_SAMPLE_ATTEMPTS)
    args = parser.parse_args()

    assert_json_baseline_checkout(args.baseline)
    candidate_case = _collect_valid_case_samples(
        "candidate",
        args.candidate,
        work_root=os.path.join(args.work_root, "candidate"),
        archives=args.archives,
        measure_syscalls=args.measure_syscalls,
        required_valid_samples=args.valid_samples,
        max_attempts=args.max_attempts,
    )
    baseline_case = _collect_valid_case_samples(
        "baseline",
        args.baseline,
        work_root=os.path.join(args.work_root, "baseline"),
        archives=args.archives,
        measure_syscalls=args.measure_syscalls,
        required_valid_samples=args.valid_samples,
        max_attempts=args.max_attempts,
    )

    if len(candidate_case["valid_samples"]) < args.valid_samples:
        raise SystemExit("could not stabilize the required number of valid candidate samples")
    if len(baseline_case["valid_samples"]) < args.valid_samples:
        raise SystemExit("could not stabilize the required number of valid baseline samples")

    candidate = _aggregate_case_samples(candidate_case)
    baseline = _aggregate_case_samples(baseline_case)

    candidate_success_contracts = {
        json.dumps(_success_parity_contract(sample), sort_keys=True)
        for sample in candidate["valid_samples"]
    }
    baseline_success_contracts = {
        json.dumps(_success_parity_contract(sample), sort_keys=True)
        for sample in baseline["valid_samples"]
    }
    if candidate_success_contracts != baseline_success_contracts:
        raise SystemExit("candidate success outcome does not match baseline")
    candidate_recovery_contracts = {
        json.dumps(_recovery_parity_contract(sample), sort_keys=True)
        for sample in candidate["valid_samples"]
    }
    baseline_recovery_contracts = {
        json.dumps(_recovery_parity_contract(sample), sort_keys=True)
        for sample in baseline["valid_samples"]
    }
    if candidate_recovery_contracts != baseline_recovery_contracts:
        raise SystemExit("candidate recovery outcome does not match baseline")
    if (
        candidate["scenario_wall_time_seconds"]["median"]
        >= baseline["scenario_wall_time_seconds"]["median"]
    ):
        raise SystemExit("candidate wall-clock time did not improve over baseline")
    if (
        args.measure_syscalls
        and candidate["syscalls"]["median"] >= baseline["syscalls"]["median"]
    ):
        raise SystemExit(
            "candidate did not reduce measured syscall activity relative to baseline"
        )
    print(json.dumps({"candidate": candidate, "baseline": baseline}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
