#!/usr/bin/env python3
"""Small, independent batch runtime for advDecompress_lite."""

from __future__ import annotations

import argparse
import contextlib
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import uuid
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

if __package__:
    from . import archive_io, layout
else:
    import archive_io  # type: ignore
    import layout  # type: ignore


_PLACEMENT_LOCK = threading.RLock()
# ponytail: one process-local placement/source lock; use per-output locks only
# if profiling shows independent output trees need more throughput.


class SourceMoveError(RuntimeError):
    """A source-group move failed after zero or more files were moved."""

    def __init__(
        self,
        message: str,
        *,
        moved: Iterable[Tuple[Path, Path]] = (),
        locations: Iterable[Path] = (),
    ) -> None:
        super().__init__(message)
        self.moved = tuple(moved)
        self.locations = tuple(locations)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Batch extract archives with isolated per-job workspaces."
    )
    parser.add_argument("path", help="Input archive file or directory to scan.")
    parser.add_argument("-o", "--output", help="Output directory.")
    parser.add_argument("-p", "--password", help="Explicit archive password.")
    parser.add_argument(
        "-pf",
        "--password-file",
        dest="password_file",
        help="UTF-8 password file, one candidate per line.",
    )
    parser.add_argument(
        "-tzp",
        "--traditional-zip-policy",
        dest="traditional_zip_policy",
        default="decode-auto",
        help="asis, move, decode-auto, or decode-CODEPAGE.",
    )
    parser.add_argument(
        "-tzt",
        "--traditional-zip-to",
        dest="traditional_zip_to",
        help="Destination for traditional ZIP move policy.",
    )
    parser.add_argument(
        "-tzdc",
        "--traditional-zip-decode-confidence",
        dest="traditional_zip_decode_confidence",
        type=int,
        default=90,
        help="Minimum automatic ZIP detection confidence (0..100).",
    )
    parser.add_argument(
        "-tzdm",
        "--traditional-zip-decode-model",
        dest="traditional_zip_decode_model",
        choices=("chardet", "charset_normalizer"),
        default="chardet",
    )
    parser.add_argument(
        "-er",
        "--enable-rar",
        dest="enable_rar",
        action="store_true",
        help="Prefer the RAR CLI for RAR archives when available.",
    )
    parser.add_argument(
        "-des",
        "--detect-elf-sfx",
        dest="detect_elf_sfx",
        action="store_true",
        help="Enable optional ELF SFX detection.",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=1,
        help="Maximum concurrent jobs (default: 1).",
    )
    parser.add_argument(
        "-dp",
        "--decompress-policy",
        dest="decompress_policy",
        default="2-collect",
        help="Decompression layout policy (default: 2-collect).",
    )
    parser.add_argument(
        "-sp",
        "--success-policy",
        dest="success_policy",
        choices=("asis", "delete", "move"),
        default="asis",
    )
    parser.add_argument(
        "-st",
        "--success-to",
        dest="success_to",
        help="Destination for successful source groups.",
    )
    parser.add_argument(
        "-fp",
        "--fail-policy",
        dest="fail_policy",
        choices=("asis", "move"),
        default="asis",
    )
    parser.add_argument(
        "-ft",
        "--fail-to",
        dest="fail_to",
        help="Destination for failed source groups.",
    )
    parser.add_argument(
        "--conflict-mode",
        dest="conflict_mode",
        choices=("fail", "suffix"),
        default="fail",
    )
    parser.add_argument("-n", "--dry-run", dest="dry_run", action="store_true")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true")

    for option, dest, label in (
        ("--skip-7z", "skip_7z", "single 7z"),
        ("--skip-rar", "skip_rar", "single RAR"),
        ("--skip-zip", "skip_zip", "single ZIP"),
        ("--skip-exe", "skip_exe", "single EXE SFX"),
        ("--skip-tar", "skip_tar", "single TAR"),
        ("--skip-7z-multi", "skip_7z_multi", "multipart 7z"),
        ("--skip-rar-multi", "skip_rar_multi", "multipart RAR"),
        ("--skip-zip-multi", "skip_zip_multi", "multipart ZIP"),
        ("--skip-exe-multi", "skip_exe_multi", "multipart EXE SFX"),
    ):
        parser.add_argument(
            option,
            dest=dest,
            action="store_true",
            help="Skip " + label + ".",
        )

    parser.add_argument("--no-lock", dest="no_lock", action="store_true")
    parser.add_argument(
        "--lock-timeout",
        dest="lock_timeout",
        type=int,
        default=30,
        help="Maximum global lock acquisition attempts.",
    )
    parser.add_argument(
        "-dr",
        "--depth-range",
        dest="depth_range",
        help="Single nonnegative depth or inclusive MIN-MAX.",
    )
    extensions = parser.add_mutually_exclusive_group()
    extensions.add_argument("-fe", "--fix-ext", dest="fix_ext", action="store_true")
    extensions.add_argument(
        "-sfe",
        "--safe-fix-ext",
        dest="safe_fix_ext",
        action="store_true",
    )
    parser.add_argument(
        "-fet",
        "--fix-extension-threshold",
        dest="fix_extension_threshold",
        default="10mb",
        help="Integer size followed by k/kb, m/mb, or g/gb; 0 disables filtering.",
    )
    return parser


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def _absolute(path: Any) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(path))))


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(os.path.normpath(str(left))) == os.path.normcase(
        os.path.normpath(str(right))
    )


def _lexists(path: Path) -> bool:
    return os.path.lexists(os.fspath(path))


def _is_reparse_point(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        if os.name == "nt":
            return bool(int(getattr(os.lstat(path), "st_file_attributes", 0) or 0) & 0x400)
    except OSError:
        return False
    return False


def _input_root(args: argparse.Namespace) -> Path:
    cached = getattr(args, "input_root", None)
    if cached:
        return _absolute(cached)
    source = _absolute(args.path)
    return source if source.is_dir() else source.parent


def _output_base(args: argparse.Namespace) -> Path:
    cached = getattr(args, "output_base", None)
    if cached:
        return _absolute(cached)
    return _absolute(args.output) if args.output else _input_root(args)


def _validate_path_ancestry(
    path: Path,
    label: str,
    *,
    allow_file_leaf: bool = False,
) -> None:
    current = path
    leaf = True
    while True:
        if _is_reparse_point(current):
            raise ValueError("{} contains a reparse point: {}".format(label, current))
        if _lexists(current):
            if leaf and allow_file_leaf and current.is_file():
                pass
            elif not current.is_dir():
                raise ValueError(
                    "{} ancestor is not a directory: {}".format(label, current)
                )
        if current.parent == current:
            return
        current = current.parent
        leaf = False


def _validate_destination(path_value: Optional[str], label: str) -> None:
    if not path_value:
        return
    path = _absolute(path_value)
    _validate_path_ancestry(path, label)


def _validate_paths(args: argparse.Namespace) -> None:
    source = _absolute(args.path)
    if not source.exists():
        raise ValueError("path does not exist: {}".format(args.path))
    if not source.is_file() and not source.is_dir():
        raise ValueError("path is not a regular file or directory: {}".format(args.path))
    _validate_path_ancestry(source, "input", allow_file_leaf=True)

    input_root = source if source.is_dir() else source.parent
    output_base = _absolute(args.output) if args.output else input_root
    _validate_path_ancestry(output_base, "output")

    if args.password_file:
        password_file = _absolute(args.password_file)
        if not password_file.is_file():
            raise ValueError("password file does not exist: {}".format(password_file))
        _validate_path_ancestry(password_file, "password file", allow_file_leaf=True)
        if args.dry_run:
            try:
                with password_file.open("r", encoding="utf-8") as stream:
                    stream.read()
            except (OSError, UnicodeError) as exc:
                raise ValueError("password file is not readable UTF-8: {}".format(exc))

    _validate_destination(args.traditional_zip_to, "traditional ZIP destination")
    _validate_destination(args.success_to, "success destination")
    _validate_destination(args.fail_to, "failure destination")

    args.traditional_zip_policy = str(args.traditional_zip_policy).lower()
    if args.success_policy == "move" and not args.success_to:
        raise ValueError("--success-to is required when --success-policy is move")
    if args.fail_policy == "move" and not args.fail_to:
        raise ValueError("--fail-to is required when --fail-policy is move")
    if args.traditional_zip_policy == "move" and not args.traditional_zip_to:
        raise ValueError("--traditional-zip-to is required when ZIP policy is move")
    if args.threads <= 0:
        raise ValueError("--threads must be positive")
    if args.lock_timeout <= 0:
        raise ValueError("--lock-timeout must be positive")
    if not 0 <= args.traditional_zip_decode_confidence <= 100:
        raise ValueError("--traditional-zip-decode-confidence must be between 0 and 100")

    policy = args.traditional_zip_policy
    if policy not in {"asis", "move", "decode-auto"} and not re.fullmatch(
        r"decode-[0-9]+", policy
    ):
        raise ValueError("invalid traditional ZIP policy: " + policy)
    archive_io.parse_depth_range(args.depth_range)
    archive_io.parse_file_size(args.fix_extension_threshold)
    layout.validate_policy(args.decompress_policy)

    # Equal input/output is the documented default and remains valid.  Nested
    # output and source-policy folders are also valid because discovery prunes
    # those dedicated destinations; file-vs-directory conflicts are rejected
    # above before any source mutation.
    args.input_root = str(input_root)
    args.output_base = str(output_base)


def _check_prerequisites(args: argparse.Namespace) -> None:
    if shutil.which("7z") is None and shutil.which("7zz") is None:
        raise RuntimeError("7z command not found; install 7-Zip and retry")
    if args.enable_rar and shutil.which("rar") is None:
        print("Warning: rar command not found; RAR jobs will use 7z.")


class _GlobalLock:
    def __init__(self, attempts: int) -> None:
        self.attempts = attempts
        self.path = (
            Path(r"C:\Windows\Temp\decomp_lock")
            if os.name == "nt"
            else Path("/tmp/decomp_lock")
        )
        self._file = None

    def acquire(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+b")
        if os.name == "nt":
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"0")
                handle.flush()
        try:
            for attempt in range(self.attempts):
                try:
                    if os.name == "nt":
                        import msvcrt

                        handle.seek(0)
                        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self._file = handle
                    return True
                except (OSError, IOError):
                    if attempt + 1 < self.attempts:
                        time.sleep(0.1)
            handle.close()
            return False
        except BaseException:
            handle.close()
            raise

    def release(self) -> None:
        if self._file is None:
            return
        try:
            if os.name == "nt":
                import msvcrt

                self._file.seek(0)
                msvcrt.locking(self._file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
        finally:
            self._file.close()
            self._file = None

    def __enter__(self) -> "_GlobalLock":
        if not self.acquire():
            raise TimeoutError(
                "could not acquire global HDD lock after {} attempts".format(self.attempts)
            )
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.release()
        return False


@contextlib.contextmanager
def _run_lock(args: argparse.Namespace):
    if args.no_lock:
        yield
        return
    with _GlobalLock(args.lock_timeout):
        yield


def _group_value(group: Any, name: str, default: Any = None) -> Any:
    return getattr(group, name, default)


def _group_volumes(group: Any) -> Tuple[Path, ...]:
    return tuple(_absolute(path) for path in (_group_value(group, "volumes", ()) or ()))


def _group_entry(group: Any) -> Optional[Path]:
    entry = _group_value(group, "entry")
    return _absolute(entry) if entry is not None else None


def _group_label(group: Any) -> str:
    entry = _group_entry(group)
    if entry is not None:
        return str(entry)
    volumes = _group_volumes(group)
    if volumes:
        return str(volumes[0])
    return "<missing archive primary>"


def _group_output_dir(group: Any, args: argparse.Namespace) -> Path:
    entry = _group_entry(group)
    output = _output_base(args)
    if entry is None:
        return output
    try:
        relative_parent = entry.parent.relative_to(_input_root(args))
    except ValueError:
        relative_parent = Path()
    return output / relative_parent


def _workspace_root(output_base: Path) -> Path:
    return output_base / ".advdecompress_lite_tmp"


def _new_workspace(output_base: Path) -> Path:
    root = _workspace_root(output_base)
    root.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix="job-", dir=str(root)))


def _remove_empty_workspace_root(output_base: Path) -> None:
    root = _workspace_root(output_base)
    try:
        root.rmdir()
    except OSError:
        pass


def _tree_has_entries(root: Path) -> bool:
    try:
        next(root.iterdir())
        return True
    except (FileNotFoundError, StopIteration, NotADirectoryError):
        return False


def _same_volume(left: Path, right: Path) -> bool:
    try:
        return left.stat().st_dev == right.parent.stat().st_dev
    except OSError:
        return False


def _unique_container(base: Path, group: Any = None) -> Path:
    if group is not None:
        stem = str(_group_value(group, "stem") or "group")
        stem = re.sub(r"[\\\\/]+", "_", stem).strip(" .") or "group"
        candidate = base / stem
        if not _lexists(candidate):
            return candidate
        while True:
            candidate = base / "{}_{}".format(stem, uuid.uuid4().hex[:8])
            if not _lexists(candidate):
                return candidate
    while True:
        candidate = base.parent / "{}_{}".format(base.name, uuid.uuid4().hex[:8])
        if not _lexists(candidate):
            return candidate


def _move_one(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if _same_path(source, destination):
        return
    if _same_volume(source, destination):
        os.rename(str(source), str(destination))
        return
    if source.is_dir():
        shutil.copytree(str(source), str(destination))
        shutil.rmtree(str(source))
    else:
        shutil.copy2(str(source), str(destination))
        source.unlink()


def _move_group(
    group: Any,
    target_base: Any,
    input_root: Any,
    *,
    allow_missing: bool = False,
) -> Tuple[Tuple[Path, Path], ...]:
    """Move a whole source group, choosing one collision container for all volumes."""
    base = _absolute(target_base)
    source_root = _absolute(input_root)
    volumes = list(_group_volumes(group))
    reparse = [path for path in volumes if _is_reparse_point(path)]
    if reparse:
        raise SourceMoveError(
            "source group member is a reparse point: {}".format(reparse[0]),
            locations=(),
        )
    missing = [path for path in volumes if not path.exists()]
    if missing and not allow_missing:
        raise SourceMoveError(
            "source group member is missing: {}".format(missing[0]),
            locations=(),
        )
    volumes = [path for path in volumes if path.exists()]
    if not volumes:
        raise SourceMoveError("source group has no existing volumes", locations=())

    def plan(container: Path) -> List[Tuple[Path, Path]]:
        planned = []
        for source in volumes:
            try:
                relative = source.relative_to(source_root)
            except ValueError:
                relative = Path(source.name)
            planned.append((source, container / relative))
        return planned

    planned = plan(base)
    collisions = set()
    for source, destination in planned:
        if _lexists(destination) and not _same_path(source, destination):
            collisions.add(destination)
            continue
        ancestor = destination.parent
        while True:
            if _is_reparse_point(ancestor) or (
                _lexists(ancestor) and not ancestor.is_dir()
            ):
                collisions.add(ancestor)
                break
            if _same_path(ancestor, base) or ancestor.parent == ancestor:
                break
            ancestor = ancestor.parent
    if collisions:
        base = _unique_container(base, group)
        planned = plan(base)

    moved: List[Tuple[Path, Path]] = []
    locations: List[Path] = []
    try:
        for source, destination in planned:
            _move_one(source, destination)
            moved.append((source, destination))
            locations.append(destination)
    except Exception as exc:
        for _source, destination in planned:
            if destination.exists() and destination not in locations:
                locations.append(destination)
        raise SourceMoveError(
            "could not move source group: {}".format(exc),
            moved=moved,
            locations=locations,
        ) from exc
    if missing and allow_missing:
        print("Warning: source group member already missing: {}".format(missing[0]))
    return tuple(moved)


def _delete_group(group: Any) -> List[str]:
    errors = []
    for volume in _group_volumes(group):
        try:
            volume.unlink()
        except Exception as exc:
            errors.append("{}: {}".format(volume, exc))
            print("Warning: could not delete {}: {}".format(volume, exc))
    return errors


def _result(group: Any) -> Dict[str, Any]:
    return {
        "group": group,
        "status": "failed",
        "error": None,
        "reason": None,
        "source_error": None,
        "introduced": (),
        "locations": (),
        "times": {
            "password/extraction": 0.0,
            "placement": 0.0,
            "source": 0.0,
        },
    }


def _apply_fail_policy(
    group: Any,
    args: argparse.Namespace,
    result: Dict[str, Any],
) -> None:
    if getattr(args, "dry_run", False):
        return
    if args.fail_policy != "move" or not args.fail_to or not _group_volumes(group):
        return
    started = time.monotonic()
    try:
        with _PLACEMENT_LOCK:
            _move_group(
                group,
                args.fail_to,
                _input_root(args),
                allow_missing=True,
            )
    except Exception as exc:
        locations = tuple(getattr(exc, "locations", ()) or ())
        prior = tuple(result.get("introduced") or ())
        result["source_error"] = str(exc)
        result["locations"] = prior + locations
        result["error"] = "{}; failure move failed: {}".format(
            result.get("error") or "job failed", exc
        )
        if locations:
            result["introduced"] = prior + locations
    finally:
        result["times"]["source"] += time.monotonic() - started


def _process_group(
    group: Any,
    args: argparse.Namespace,
    passwords: Any,
) -> Dict[str, Any]:
    result = _result(group)
    label = _group_label(group)
    print("Processing: {}".format(label))
    if args.verbose:
        print(
            "  format={}, kind={}, multipart={}, volumes={}".format(
                _group_value(group, "format", "unknown"),
                _group_value(group, "kind", "unknown"),
                bool(_group_value(group, "multi", False)),
                len(_group_volumes(group)),
            )
        )
    workspace = None
    try:
        group_error = _group_value(group, "error")
        if group_error or _group_entry(group) is None:
            result["error"] = str(group_error or "archive group has no primary volume")
            if args.dry_run:
                result["status"] = "dry-run"
                result["reason"] = result["error"]
                result["error"] = None
                print(
                    "[DRY RUN] Would report failed group: {} ({})".format(
                        label, result["reason"]
                    )
                )
                return result
            _apply_fail_policy(group, args, result)
            print("Error: {}: {}".format(label, result["error"]))
            return result

        action, codepage, reason = archive_io.inspect_zip_policy(group, args)
        action = str(action).lower()
        if action == "skip":
            result["status"] = "skipped"
            result["reason"] = reason
            print("Skipped: {}{}".format(label, " ({})".format(reason) if reason else ""))
            return result
        if action == "move":
            if args.dry_run:
                result["status"] = "dry-run"
                print("[DRY RUN] Would move traditional ZIP: {}".format(label))
                return result
            started = time.monotonic()
            try:
                with _PLACEMENT_LOCK:
                    _move_group(group, args.traditional_zip_to, _input_root(args))
            except Exception as exc:
                locations = tuple(getattr(exc, "locations", ()) or ())
                prior = tuple(result.get("introduced") or ())
                result["error"] = str(exc)
                result["source_error"] = str(exc)
                result["locations"] = prior + locations
                result["introduced"] = prior + locations
                print("Error: {}: {}".format(label, exc))
                return result
            finally:
                result["times"]["source"] += time.monotonic() - started
            result["status"] = "moved"
            print("Moved traditional ZIP: {}".format(label))
            return result
        if action != "extract":
            raise ValueError("unsupported ZIP policy action: {}".format(action))

        if args.dry_run:
            result["status"] = "dry-run"
            print("[DRY RUN] Would extract: {}".format(label))
            return result

        output_base = _output_base(args)
        output_base.mkdir(parents=True, exist_ok=True)
        workspace = _new_workspace(output_base)

        started = time.monotonic()
        try:
            archive_io.extract_archive(
                group,
                workspace,
                args,
                passwords,
                zip_codepage=codepage,
            )
            if not _tree_has_entries(workspace):
                raise RuntimeError("extractor produced no output")
        finally:
            result["times"]["password/extraction"] = time.monotonic() - started

        started = time.monotonic()
        try:
            with _PLACEMENT_LOCK:
                placed = layout.place_output(
                    workspace,
                    _group_output_dir(group, args),
                    str(_group_value(group, "stem") or _group_entry(group).stem),
                    args.decompress_policy,
                    args.conflict_mode,
                )
            result["introduced"] = tuple(placed or ())
        except Exception as exc:
            result["introduced"] = tuple(getattr(exc, "placed", ()) or ())
            result["error"] = "placement failed: {}".format(exc)
            raise
        finally:
            result["times"]["placement"] = time.monotonic() - started

        if args.success_policy == "delete":
            started = time.monotonic()
            try:
                _delete_group(group)
            except Exception as exc:
                print("Warning: could not delete source group: {}".format(exc))
            finally:
                result["times"]["source"] += time.monotonic() - started
        elif args.success_policy == "move":
            started = time.monotonic()
            try:
                with _PLACEMENT_LOCK:
                    _move_group(group, args.success_to, _input_root(args))
            except Exception as exc:
                locations = tuple(getattr(exc, "locations", ()) or ())
                prior = tuple(result.get("introduced") or ())
                result["source_error"] = str(exc)
                result["locations"] = prior + locations
                result["error"] = "success source move failed: {}".format(exc)
                result["introduced"] = prior + locations
                print("Error: {}: {}".format(label, exc))
                return result
            finally:
                result["times"]["source"] += time.monotonic() - started

        result["status"] = "success"
        print("Succeeded: {}".format(label))
        return result
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        if result["error"] is None:
            result["error"] = str(exc)
        if result["source_error"] is None:
            _apply_fail_policy(group, args, result)
        print("Error: {}: {}".format(label, result["error"]))
        return result
    finally:
        if workspace is not None:
            try:
                shutil.rmtree(str(workspace))
            except FileNotFoundError:
                pass
            except OSError as exc:
                print(
                    "Warning: could not clean temporary directory {}: {}".format(
                        workspace, exc
                    )
                )


def _run_groups(
    groups: Sequence[Any],
    args: argparse.Namespace,
    passwords: Any,
) -> List[Dict[str, Any]]:
    if args.threads == 1 or len(groups) <= 1:
        return [_process_group(group, args, passwords) for group in groups]

    results: List[Dict[str, Any]] = []
    executor = ThreadPoolExecutor(max_workers=args.threads)
    pending = set()
    group_iterator = iter(groups)

    def submit_next() -> bool:
        try:
            group = next(group_iterator)
        except StopIteration:
            return False
        pending.add(executor.submit(_process_group, group, args, passwords))
        return True

    for _ in range(min(args.threads, len(groups))):
        submit_next()
    try:
        while pending:
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                results.append(future.result())
                submit_next()
    except KeyboardInterrupt:
        for future in pending:
            future.cancel()
        executor.shutdown(wait=False)
        raise
    finally:
        executor.shutdown(wait=True)
    return results


def _print_summary(
    groups: Sequence[Any],
    results: Sequence[Dict[str, Any]],
    *,
    discovery_time: float,
    extension_pairs: Sequence[Tuple[Any, Any]],
    exit_code: int,
) -> None:
    statuses = [result["status"] for result in results]
    success = sum(status == "success" for status in statuses)
    skipped = sum(status == "skipped" for status in statuses)
    dry_run = sum(status == "dry-run" for status in statuses)
    moved = sum(status == "moved" for status in statuses)
    failed = len(results) - success - skipped - dry_run - moved
    totals = {
        key: sum(result["times"].get(key, 0.0) for result in results)
        for key in ("password/extraction", "placement", "source")
    }
    print("\nPROCESSING SUMMARY")
    print("Total archives found: {}".format(len(groups)))
    print("Successfully processed: {}".format(success))
    print("Failed: {}".format(failed))
    print("Skipped: {}".format(skipped))
    if moved:
        print("Moved without extraction: {}".format(moved))
    if dry_run:
        print("Dry-run actions: {}".format(dry_run))
    if extension_pairs:
        print("Extension repairs: {}".format(len(extension_pairs)))
    print(
        "Stage timings: discovery={:.3f}s, password/extraction (per-job sum)={:.3f}s, "
        "placement (per-job sum)={:.3f}s, source (per-job sum)={:.3f}s".format(
            discovery_time,
            totals["password/extraction"],
            totals["placement"],
            totals["source"],
        )
    )
    errors = []
    for result in results:
        if not result["error"]:
            continue
        message = "{}: {}".format(_group_label(result["group"]), result["error"])
        locations = tuple(result.get("locations") or result.get("introduced") or ())
        if locations:
            message += " (locations: {})".format(
                ", ".join(str(location) for location in locations)
            )
        errors.append(message)
    if errors:
        print("Errors:")
        for error in errors:
            print("  - " + error)
    print("Exit code: {}".format(exit_code))


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        args = parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)

    try:
        _validate_paths(args)
        _check_prerequisites(args)
    except (ValueError, RuntimeError) as exc:
        print("Error: {}".format(exc))
        return 1

    extension_pairs: Sequence[Tuple[Any, Any]] = ()
    groups: List[Any] = []
    cleanup_workspace = False
    passwords = None
    if not args.dry_run:
        try:
            passwords = archive_io.PasswordCandidates(args)
        except Exception as exc:
            print("Error: {}".format(exc))
            return 1
    try:
        with _run_lock(args):
            discovery_started = time.monotonic()
            if args.fix_ext or args.safe_fix_ext:
                extension_pairs = tuple(archive_io.fix_extensions(args) or ())
                if not args.dry_run:
                    if os.path.isfile(os.fspath(args.path)) and extension_pairs:
                        original = _absolute(args.path)
                        for old, new in extension_pairs:
                            if _same_path(_absolute(old), original):
                                args.path = str(_absolute(new))
                                break
            groups = list(archive_io.discover_archives(args) or ())
            discovery_time = time.monotonic() - discovery_started
            if not groups:
                print("No archives found to process.")
                _print_summary(
                    groups,
                    (),
                    discovery_time=discovery_time,
                    extension_pairs=extension_pairs,
                    exit_code=0,
                )
                return 0

            cleanup_workspace = not args.dry_run
            results = _run_groups(groups, args, passwords)
    except KeyboardInterrupt:
        print("Error: processing interrupted")
        return 1
    except Exception as exc:
        print("Error: {}".format(exc))
        return 1
    finally:
        if cleanup_workspace:
            _remove_empty_workspace_root(_output_base(args))

    failed = any(
        result["status"] == "failed" or result.get("source_error")
        for result in results
    )
    exit_code = 1 if failed else 0
    _print_summary(
        groups,
        results,
        discovery_time=discovery_time,
        extension_pairs=extension_pairs,
        exit_code=exit_code,
    )
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
