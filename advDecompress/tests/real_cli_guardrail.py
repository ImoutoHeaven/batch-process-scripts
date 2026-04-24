from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "advDecompress" / "advDecompress.py"
UNICODE_FIXTURE_ARCHIVE_NAMES = [
    "[Bunnage Works]今日はたくさん回復してね [中国翻訳].zip",
    "「愉快なFactory」モモカの出産[ボテ腹学園]【中文翻译】.zip",
    "[贱兔汉化组][月下カグヤ] futanariri女子校生は寮母さんと…♡[DL版].zip",
    "「愉快なFactory」お礼と感謝の出産(全6P)【中文翻译】.zip",
    "「愉快なFactory」リクエストいただいた絵です【ボテ腹学園シリーズ】【中文翻译】.zip",
    "「愉快なFactory」ご依頼いただきました女教師の出産絵です【中文翻译】.zip",
    "[百瀬真優] ストッキング姉妹に亀頭ズリ撫で3P [Chinese][MTL].zip",
    "「愉快なFactory」[全7P]あけましておめでとうございます【メリークリスマス!】【中文翻译】.zip",
    "[Sion] One Night of Passion with Mika 和彌香的一夜春宵 [Decensored] [AI Generated].zip",
    "「愉快なFactory」リクエストいただきました絵です！【中文翻译】.zip",
]
ASCII_FIXTURE_ARCHIVE_NAMES = [
    "alpha-studio-issue-001.zip",
    "beta-studio-issue-002.zip",
    "gamma-collection-003.zip",
    "delta-content-pack-004.zip",
    "epsilon-release-005.zip",
    "zeta-archive-006.zip",
    "eta-volume-007.zip",
    "theta-special-008.zip",
    "iota-bundle-009.zip",
    "kappa-final-010.zip",
]
MIXED_FIXTURE_ARCHIVE_NAMES = [
    UNICODE_FIXTURE_ARCHIVE_NAMES[0],
    ASCII_FIXTURE_ARCHIVE_NAMES[0],
    UNICODE_FIXTURE_ARCHIVE_NAMES[7],
    ASCII_FIXTURE_ARCHIVE_NAMES[3],
    UNICODE_FIXTURE_ARCHIVE_NAMES[8],
    ASCII_FIXTURE_ARCHIVE_NAMES[5],
    UNICODE_FIXTURE_ARCHIVE_NAMES[2],
    ASCII_FIXTURE_ARCHIVE_NAMES[8],
    UNICODE_FIXTURE_ARCHIVE_NAMES[4],
    ASCII_FIXTURE_ARCHIVE_NAMES[9],
]


def _safe_print(*parts: object) -> None:
    text = " ".join(str(part) for part in parts)
    sys.stdout.buffer.write((text + "\n").encode("utf-8", errors="backslashreplace"))
    sys.stdout.buffer.flush()


def _read_json(path: Path) -> object | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        _safe_print(f"could not parse json {path}: {exc}")
        return None


def _read_sqlite_table(db_path: Path, query: str) -> list[dict[str, object]]:
    conn = sqlite3.connect(str(db_path))
    try:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute(query).fetchall()]
    finally:
        conn.close()


def _collect_metadata_backend_diagnostics(
    work_base: Path,
    *,
    metadata_db_path: str | Path | None = None,
) -> dict[str, object]:
    marker_path = work_base / "metadata.backend.json"
    marker = _read_json(marker_path) if marker_path.exists() else None
    db_path = Path(metadata_db_path) if metadata_db_path else (work_base / "metadata.sqlite")
    sqlite_metadata: dict[str, object] = {
        "metadata_store": None,
        "dataset_state": None,
    }
    if db_path.exists():
        for key, query in (
            ("metadata_store", "SELECT * FROM metadata_store"),
            ("dataset_state", "SELECT * FROM dataset_state"),
        ):
            try:
                sqlite_metadata[key] = _read_sqlite_table(db_path, query)
            except sqlite3.Error as exc:
                sqlite_metadata[key] = {"error": str(exc)}
    return {
        "backend_marker": marker,
        "sqlite_metadata": sqlite_metadata,
    }


def _extract_failed_archives(stdout: str) -> list[str]:
    failed_archives = []
    collect = False
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if line == "Failed archives:":
            collect = True
            continue
        if not collect:
            continue
        if not line:
            if failed_archives:
                break
            continue
        if not line.startswith("-"):
            break
        failed_archives.append(line[1:].strip())
    return failed_archives


def _summarize_txn(txn: object) -> str:
    if not isinstance(txn, dict):
        return repr(txn)
    placement_ops = ((txn.get("placement_v2") or {}).get("ops") or [])
    source_ops = ((txn.get("source_finalization_v2") or {}).get("ops") or [])
    summary = {
        "txn_id": txn.get("txn_id"),
        "state": txn.get("state"),
        "resolved_policy": txn.get("resolved_policy"),
        "payload_durable": txn.get("payload_durable"),
        "pending_final_disposition": txn.get("pending_final_disposition"),
        "terminal_final_disposition": txn.get("terminal_final_disposition"),
        "error": txn.get("error"),
        "placement_phases": [op.get("phase") for op in placement_ops],
        "source_finalization": {
            "policy_kind": (txn.get("source_finalization_v2") or {}).get("policy_kind"),
            "trash_cleanup_failed": (txn.get("source_finalization_v2") or {}).get(
                "trash_cleanup_failed"
            ),
            "phases": [op.get("phase") for op in source_ops],
        },
    }
    return json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True)


def _find_txn_json(work_base: Path, archive_path: str, txn_id: str | None) -> Path | None:
    direct_candidates = []
    if txn_id:
        direct_candidates.extend(work_base.glob(f"outputs/*/journal/{txn_id}/txn.json"))

    for candidate in direct_candidates:
        data = _read_json(candidate)
        if isinstance(data, dict) and data.get("archive_path") == archive_path:
            return candidate

    for candidate in work_base.glob("outputs/*/journal/*/txn.json"):
        data = _read_json(candidate)
        if isinstance(data, dict) and data.get("archive_path") == archive_path:
            return candidate

    return None


def _print_manifest_diagnostics(input_root: Path, failed_archives: list[str]) -> None:
    work_bases = []
    active = input_root / ".advdecompress_work"
    if active.exists():
        work_bases.append(active)
    work_bases.extend(sorted(input_root.glob(".advdecompress_work.retired.*")))

    if not work_bases:
        _safe_print("no transactional workdir found for diagnostics")
        return

    for work_base in work_bases:
        manifest_path = work_base / "dataset_manifest.json"
        _safe_print(f"diagnostic work base: {work_base}")
        _safe_print(
            json.dumps(
                _collect_metadata_backend_diagnostics(work_base),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
        if not manifest_path.exists():
            _safe_print(f"manifest missing: {manifest_path}")
            continue

        manifest = _read_json(manifest_path)
        if not isinstance(manifest, dict):
            continue

        _safe_print(
            json.dumps(
                {
                    "manifest_path": str(manifest_path),
                    "status": manifest.get("status"),
                    "progress": manifest.get("progress"),
                },
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )

        archives = manifest.get("archives")
        if not isinstance(archives, dict):
            _safe_print("manifest archives payload malformed")
            continue

        for archive_path in failed_archives:
            entry = archives.get(archive_path)
            if not isinstance(entry, dict):
                _safe_print(f"manifest entry missing for failed archive: {archive_path}")
                continue

            _safe_print(f"manifest entry for failed archive: {archive_path}")
            _safe_print(
                json.dumps(
                    {
                        "state": entry.get("state"),
                        "final_disposition": entry.get("final_disposition"),
                        "last_txn_id": entry.get("last_txn_id"),
                        "error": entry.get("error"),
                    },
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
            )

            txn_json = _find_txn_json(work_base, archive_path, entry.get("last_txn_id"))
            if txn_json is None:
                _safe_print("no matching txn.json found for failed archive")
                continue

            txn = _read_json(txn_json)
            _safe_print(f"txn json: {txn_json}")
            _safe_print(_summarize_txn(txn))


def _print_subprocess_result(label: str, result: subprocess.CompletedProcess[str]) -> None:
    _safe_print(f"{label} returncode: {result.returncode}")
    _safe_print(f"--- {label} stdout ---")
    _safe_print(result.stdout or "")
    _safe_print(f"--- {label} stderr ---")
    _safe_print(result.stderr or "")


def _run_direct_7z_probe(archive_path: Path, input_root: Path) -> None:
    if shutil.which("7z") is None:
        _safe_print("7z direct probe skipped: 7z not found in PATH")
        return

    probe_root = input_root / "_guardrail_direct_7z_probe"
    if probe_root.exists():
        shutil.rmtree(probe_root)
    probe_root.mkdir(parents=True, exist_ok=True)

    list_result = subprocess.run(
        ["7z", "l", "-slt", str(archive_path), "-pDUMMYPASSWORD", "-y"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    _print_subprocess_result("direct 7z list", list_result)

    extract_dir = probe_root / "extract"
    extract_result = subprocess.run(
        ["7z", "x", str(archive_path), f"-o{extract_dir}", "-pDUMMYPASSWORD", "-y"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    _print_subprocess_result("direct 7z extract", extract_result)


def _run_single_archive_verbose_repro(
    archive_path: Path,
    input_root: Path,
    password_file: Path,
    env: dict[str, str],
) -> None:
    repro_root = input_root / "_guardrail_single_archive_repro"
    if repro_root.exists():
        shutil.rmtree(repro_root)

    archive_rel = archive_path.relative_to(input_root)
    repro_archive = repro_root / archive_rel
    repro_archive.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(archive_path, repro_archive)
    shutil.copy2(password_file, repro_root / password_file.name)

    cmd = [
        sys.executable,
        str(SCRIPT_PATH),
        ".",
        "-t",
        "1",
        "-sp",
        "delete",
        "-pf",
        password_file.name,
        "-er",
        "-dp",
        "file-content-auto-folder-2-collect-meaningful-ent",
        "-v",
    ]
    result = subprocess.run(
        cmd,
        cwd=repro_root,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    _print_subprocess_result("single-archive verbose repro", result)


def _print_failure_diagnostics(
    *,
    input_root: Path,
    stdout: str,
    password_file: Path,
    env: dict[str, str],
) -> None:
    failed_archives = _extract_failed_archives(stdout)
    _safe_print("--- transactional diagnostics ---")
    if failed_archives:
        for failed_archive in failed_archives:
            _safe_print(f"failed archive: {failed_archive}")
    else:
        _safe_print("failed archive list not found in CLI stdout")

    _print_manifest_diagnostics(input_root, failed_archives)

    for failed_archive in failed_archives:
        failed_path = Path(failed_archive)
        if not failed_path.exists():
            _safe_print(f"failed archive no longer exists for probe: {failed_path}")
            continue
        _run_direct_7z_probe(failed_path, input_root)
        _run_single_archive_verbose_repro(failed_path, input_root, password_file, env)


def _temp_parent_dir() -> str | None:
    if os.name != "nt":
        return None

    user_profile = Path(os.environ.get("USERPROFILE", ""))
    if not user_profile:
        return None

    downloads_dir = user_profile / "Downloads"
    downloads_dir.mkdir(parents=True, exist_ok=True)
    return str(downloads_dir)


def _create_fixture_zip(zip_path: Path, index: int) -> tuple[str, str]:
    folder_name = f"album_{index:02d}"
    payload_one = f"payload-{index:02d}-one.txt"
    payload_two = f"payload-{index:02d}-two.txt"

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{folder_name}/{payload_one}", f"payload one for {index}\n")
        zf.writestr(f"{folder_name}/{payload_two}", f"payload two for {index}\n")

    return payload_one, payload_two


def _find_payload_hits(root: Path, filename: str) -> list[Path]:
    hits = []
    for path in root.rglob(filename):
        if ".advdecompress_work" in path.parts:
            continue
        hits.append(path)
    return sorted(hits)


def _summarize_tree(root: Path, *, limit: int = 80) -> str:
    if not root.exists():
        return f"{root} [missing]"

    lines = []
    for path in sorted(root.rglob("*")):
        rel_path = path.relative_to(root)
        suffix = "/" if path.is_dir() else ""
        lines.append(f"{rel_path}{suffix}")
        if len(lines) >= limit:
            lines.append("... [truncated]")
            break
    if not lines:
        return f"{root} [empty]"
    return "\n".join(lines)


def _guardrail_iterations() -> int:
    raw = os.environ.get("ADVD_GUARDRAIL_ITERATIONS", "1").strip() or "1"
    try:
        count = int(raw)
    except ValueError:
        return 1
    return max(1, count)


def _guardrail_threads() -> int:
    raw = os.environ.get("ADVD_GUARDRAIL_THREADS", "10").strip() or "10"
    try:
        count = int(raw)
    except ValueError:
        return 10
    return max(1, count)


def _guardrail_archive_count() -> int:
    raw = os.environ.get("ADVD_GUARDRAIL_ARCHIVE_COUNT", "10").strip() or "10"
    try:
        count = int(raw)
    except ValueError:
        return 10
    return max(1, count)


def _guardrail_decompress_policy() -> str:
    return (
        os.environ.get(
            "ADVD_GUARDRAIL_DECOMPRESS_POLICY",
            "file-content-auto-folder-2-collect-meaningful-ent",
        ).strip()
        or "file-content-auto-folder-2-collect-meaningful-ent"
    )


def _guardrail_fixture_style() -> str:
    return (os.environ.get("ADVD_GUARDRAIL_FIXTURE_STYLE", "unicode").strip() or "unicode").lower()


def _guardrail_path_style() -> str:
    return (os.environ.get("ADVD_GUARDRAIL_PATH_STYLE", "downloads").strip() or "downloads").lower()


def _scenario_fixture_names() -> list[str]:
    style = _guardrail_fixture_style()
    if style == "ascii":
        return list(ASCII_FIXTURE_ARCHIVE_NAMES)
    if style == "mixed":
        return list(MIXED_FIXTURE_ARCHIVE_NAMES)
    return list(UNICODE_FIXTURE_ARCHIVE_NAMES)


def _build_fixture_archive_names() -> list[str]:
    names = _scenario_fixture_names()
    archive_count = _guardrail_archive_count()
    built = []
    for index in range(archive_count):
        base_name = names[index % len(names)]
        stem = Path(base_name).stem
        suffix = Path(base_name).suffix or ".zip"
        built.append(f"{stem}--case-{index:03d}{suffix}")
    return built


def _archive_root(input_root: Path) -> Path:
    style = _guardrail_path_style()
    if style == "flat":
        return input_root
    if style == "nested-deep":
        return input_root / "Downloads" / "JD2E23" / "ENmJJO" / "batch-A" / "batch-B"
    return input_root / "JD2E23" / "ENmJJO"


def main() -> int:
    if not SCRIPT_PATH.exists():
        raise SystemExit(f"advDecompress CLI not found: {SCRIPT_PATH}")

    iterations = _guardrail_iterations()
    threads = _guardrail_threads()
    decompress_policy = _guardrail_decompress_policy()
    fixture_archive_names = _build_fixture_archive_names()
    archive_count = len(fixture_archive_names)
    _safe_print(f"real CLI guardrail iterations: {iterations}")
    _safe_print(f"real CLI guardrail threads: {threads}")
    _safe_print(f"real CLI guardrail archive count: {archive_count}")
    _safe_print(f"real CLI guardrail fixture style: {_guardrail_fixture_style()}")
    _safe_print(f"real CLI guardrail path style: {_guardrail_path_style()}")
    _safe_print(f"real CLI guardrail decompress policy: {decompress_policy}")

    for iteration in range(1, iterations + 1):
        _safe_print(f"=== guardrail iteration {iteration}/{iterations} ===")
        with tempfile.TemporaryDirectory(
            prefix="advd-real-cli-",
            dir=_temp_parent_dir(),
        ) as td:
            input_root = Path(td)
            archive_root = _archive_root(input_root)
            archive_root.mkdir(parents=True, exist_ok=True)

            expected_payloads = []
            archive_paths = []
            for index, archive_name in enumerate(fixture_archive_names):
                archive_path = archive_root / archive_name
                expected_payloads.extend(_create_fixture_zip(archive_path, index))
                archive_paths.append(archive_path)

            password_file = input_root / "pf.txt"
            password_file.write_text("dummy-password\n", encoding="utf-8")

            env = os.environ.copy()
            env.setdefault("PYTHONIOENCODING", "utf-8")
            env.setdefault("PYTHONUTF8", "1")

            cmd = [
                sys.executable,
                str(SCRIPT_PATH),
                ".",
                "-t",
                str(threads),
                "-sp",
                "delete",
                "-pf",
                password_file.name,
                "-er",
                "-dp",
                decompress_policy,
            ]

            result = subprocess.run(
                cmd,
                cwd=input_root,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )

            stdout = result.stdout or ""
            stderr = result.stderr or ""
            work_base = input_root / ".advdecompress_work"

            if result.returncode != 0:
                _safe_print("real CLI guardrail failed: non-zero exit status")
                _safe_print(f"command: {' '.join(cmd)}")
                _safe_print(f"returncode: {result.returncode}")
                _safe_print("--- stdout ---")
                _safe_print(stdout)
                _safe_print("--- stderr ---")
                _safe_print(stderr)
                _print_failure_diagnostics(
                    input_root=input_root,
                    stdout=stdout,
                    password_file=password_file,
                    env=env,
                )
                return 1

            if f"Successfully processed: {archive_count}" not in stdout:
                _safe_print("real CLI guardrail failed: unexpected success summary")
                _safe_print("--- stdout ---")
                _safe_print(stdout)
                return 1

            if "Failed to process: 0" not in stdout or "Skipped: 0" not in stdout:
                _safe_print("real CLI guardrail failed: processing summary not fully green")
                _safe_print("--- stdout ---")
                _safe_print(stdout)
                return 1

            remaining_archives = [str(path) for path in archive_paths if path.exists()]
            if remaining_archives:
                _safe_print(
                    "real CLI guardrail failed: success-delete left source archives behind"
                )
                _safe_print("remaining archives:")
                for path in remaining_archives:
                    _safe_print(path)
                _safe_print("--- stdout ---")
                _safe_print(stdout)
                return 1

            missing_payloads = []
            duplicate_payloads = []
            for payload_name in expected_payloads:
                hits = _find_payload_hits(input_root, payload_name)
                if not hits:
                    missing_payloads.append(payload_name)
                elif len(hits) > 1:
                    duplicate_payloads.append((payload_name, hits))

            if missing_payloads or duplicate_payloads:
                _safe_print(
                    "real CLI guardrail failed: extracted payload verification failed"
                )
                if missing_payloads:
                    _safe_print("missing payloads:")
                    for name in missing_payloads:
                        _safe_print(name)
                if duplicate_payloads:
                    _safe_print("duplicate payloads:")
                    for name, hits in duplicate_payloads:
                        _safe_print(f"{name}: {', '.join(str(hit) for hit in hits)}")
                _safe_print("input tree:")
                _safe_print(_summarize_tree(input_root))
                _safe_print("--- stdout ---")
                _safe_print(stdout)
                return 1

            if work_base.exists():
                _safe_print(
                    "real CLI guardrail failed: extraction succeeded but .advdecompress_work still exists"
                )
                _safe_print(f"work base: {work_base}")
                _safe_print("work base tree:")
                _safe_print(_summarize_tree(work_base))
                _safe_print("--- stdout ---")
                _safe_print(stdout)
                _safe_print("--- stderr ---")
                _safe_print(stderr)
                return 1

            retired_workdirs = sorted(input_root.glob(".advdecompress_work.retired.*"))
            _safe_print(f"iteration {iteration} passed")
            _safe_print(f"retired workdirs: {len(retired_workdirs)}")
            _safe_print("--- stdout ---")
            _safe_print(stdout)
            if stderr.strip():
                _safe_print("--- stderr ---")
                _safe_print(stderr)

    _safe_print("real CLI guardrail passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
