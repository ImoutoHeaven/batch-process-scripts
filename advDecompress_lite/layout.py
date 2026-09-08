"""Validated output layouts for the lite extractor.

The public API deliberately stays small.  A placement is either a whole-tree
rename or a recursive merge; the latter is only used when two directories are
compatible.
"""

from __future__ import annotations

from collections import Counter
import math
import os
from pathlib import Path
import re
import shutil
import stat
from typing import Callable, Iterable, List, MutableSequence, Optional, Sequence, Tuple


__all__ = ["PlacementError", "validate_tree", "validate_policy", "place_output"]


class PlacementError(OSError):
    """An output placement failed after zero or more paths were introduced."""

    def __init__(self, message: str, placed: Iterable[Path] = ()) -> None:
        self.placed = tuple(Path(path) for path in placed)
        super().__init__(message)


class _Conflict(PlacementError):
    """An expected destination conflict that a policy may resolve by wrapping."""


_STATIC_POLICIES = {
    "separate",
    "direct",
    "collect",
    "only-file-content",
    "only-file-content-direct",
    "file-content-with-folder",
    "file-content-with-folder-separate",
}
_N_COLLECT = re.compile(r"^(\d+)-collect$")
_FILE_CONTENT_COLLECT = re.compile(r"^file-content-(\d+)-collect$")
_AUTO_FOLDER_COLLECT = re.compile(
    r"^file-content-auto-folder-(\d+)-collect-(len|meaningful|meaningful-ent)$"
)


def _as_path(value: object, label: str) -> Path:
    try:
        path = Path(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a filesystem path") from exc
    if not path.is_absolute():
        path = Path(os.path.abspath(os.fspath(path)))
    return path


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _norm(path: Path) -> str:
    return os.path.normcase(os.path.normpath(os.path.abspath(os.fspath(path))))


def _same_path(left: Path, right: Path) -> bool:
    return _norm(left) == _norm(right)


def _within(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath((_norm(path), _norm(root))) == _norm(root)
    except ValueError:
        return False


def _lexists(path: Path) -> bool:
    return os.path.lexists(os.fspath(path))


def _is_reparse_point(metadata: object) -> bool:
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(metadata, "st_file_attributes", 0)
    return bool(flag and attributes & flag)


def _lstat(path: Path) -> os.stat_result:
    try:
        return os.lstat(os.fspath(path))
    except OSError as exc:
        raise ValueError(f"cannot inspect filesystem path {path}: {exc}") from exc


def _is_dir(path: Path) -> bool:
    metadata = os.lstat(os.fspath(path))
    return stat.S_ISDIR(metadata.st_mode) and not _is_reparse_point(metadata)


def _entries(path: Path) -> List[Path]:
    try:
        with os.scandir(os.fspath(path)) as scan:
            return sorted((Path(entry.path) for entry in scan), key=lambda item: item.name)
    except OSError as exc:
        raise PlacementError(f"cannot enumerate {path}: {exc}") from exc


def validate_tree(root: Path) -> None:
    """Validate a decoded tree before it can reach final output.

    Only regular files and directories are accepted.  Links are rejected even
    when they point inside the tree so a later move cannot change its meaning.
    Empty directories are valid.
    """

    root = _as_path(root, "root")
    if not _lexists(root):
        raise ValueError(f"tree root does not exist: {root}")
    root_stat = _lstat(root)
    if stat.S_ISLNK(root_stat.st_mode):
        raise ValueError(f"tree root is a symlink: {root}")
    if _is_reparse_point(root_stat):
        raise ValueError(f"tree root is a reparse point: {root}")
    if not stat.S_ISDIR(root_stat.st_mode):
        raise ValueError(f"tree root is not a directory: {root}")

    root = _absolute(root)
    stack = [root]
    while stack:
        current = stack.pop()
        if not _within(current, root):
            raise ValueError(f"tree path escaped its root: {current}")
        for child in _entries(current):
            if not _within(child, root):
                raise ValueError(f"tree path escaped its root: {child}")
            child_stat = _lstat(child)
            mode = child_stat.st_mode
            if stat.S_ISLNK(mode) or _is_reparse_point(child_stat):
                raise ValueError(f"links and reparse points are not supported in extracted trees: {child}")
            if stat.S_ISDIR(mode):
                stack.append(child)
            elif not stat.S_ISREG(mode):
                raise ValueError(f"special files are not supported in extracted trees: {child}")


def validate_policy(policy: str) -> str:
    """Validate and return an output policy name."""

    if not isinstance(policy, str) or not policy:
        raise ValueError("decompress policy must be a non-empty string")
    if policy in _STATIC_POLICIES:
        return policy
    match = _N_COLLECT.fullmatch(policy)
    if match:
        return policy
    match = _FILE_CONTENT_COLLECT.fullmatch(policy)
    if match and int(match.group(1)) >= 1:
        return policy
    match = _AUTO_FOLDER_COLLECT.fullmatch(policy)
    if match and int(match.group(1)) >= 1:
        return policy
    raise ValueError(f"invalid decompress policy: {policy}")


def _validate_conflict_mode(conflict_mode: str) -> str:
    if conflict_mode not in {"fail", "suffix"}:
        raise ValueError(f"invalid conflict mode: {conflict_mode}")
    return conflict_mode


def _component(value: str, label: str, fallback: str = "archive") -> str:
    if not isinstance(value, str) or not value or value in {".", ".."}:
        raise ValueError(f"{label} must be one path component")
    if "/" in value or "\\" in value or os.path.altsep and os.path.altsep in value:
        raise ValueError(f"{label} must be one path component")
    if os.path.splitdrive(value)[0]:
        raise ValueError(f"{label} must be one path component")
    if os.name == "nt":
        value = value.rstrip(" .") or fallback
    return value


def _suffix_path(path: Path, index: int) -> Path:
    stem, suffix = os.path.splitext(path.name)
    return path.with_name(f"{stem}_{index}{suffix}")


def _unique_path(path: Path) -> Path:
    index = 1
    candidate = path
    while _lexists(candidate):
        candidate = _suffix_path(path, index)
        index += 1
    return candidate


def _ensure_safe_output(output: Path) -> None:
    nearest = output
    while not _lexists(nearest):
        parent = nearest.parent
        if parent == nearest:
            break
        nearest = parent
    current = nearest
    while True:
        if _lexists(current):
            metadata = _lstat(current)
            if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
                raise ValueError(f"output path contains a link or reparse point: {current}")
        parent = current.parent
        if parent == current:
            break
        current = parent

    if _lexists(output):
        output_stat = _lstat(output)
        if stat.S_ISLNK(output_stat.st_mode):
            raise ValueError(f"output directory cannot be a symlink: {output}")
        if not stat.S_ISDIR(output_stat.st_mode):
            raise ValueError(f"output path is not a directory: {output}")
    else:
        try:
            output.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ValueError(f"cannot create output directory {output}: {exc}") from exc

    # Do not follow an existing link while creating a destination below it.
    current = output
    while True:
        if _lexists(current):
            metadata = _lstat(current)
            if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
                raise ValueError(f"output path contains a link or reparse point: {current}")
        parent = current.parent
        if parent == current:
            break
        current = parent


def _validate_layout_inputs(
    extracted: Path, output: Path, archive_name: str, policy: str, conflict_mode: str
) -> Tuple[Path, Path, str, str]:
    validate_policy(policy)
    _validate_conflict_mode(conflict_mode)
    archive_name = _component(archive_name, "archive_name")
    validate_tree(extracted)
    extracted = _absolute(extracted)
    output = _absolute(output)
    if _same_path(extracted, output) or _within(output, extracted):
        raise ValueError("output must not be inside the extracted tree")
    _ensure_safe_output(output)
    return extracted, output, archive_name, policy


def _content_root(extracted: Path) -> Path:
    current = extracted
    while True:
        entries = _entries(current)
        if len(entries) != 1 or not _is_dir(entries[0]):
            return current
        current = entries[0]


def _content_name(content: Path, extracted: Path, archive_name: str) -> str:
    if _same_path(content, extracted):
        return archive_name
    return _component(content.name, "content folder", fallback=archive_name)


def _count_items(root: Path, stop_at: Optional[int] = None) -> int:
    if stop_at is not None and stop_at <= 0:
        return 0
    total = 0
    stack = [root]
    while stack:
        current = stack.pop()
        for child in _entries(current):
            total += 1
            if stop_at is not None and total >= stop_at:
                return total
            if _is_dir(child):
                stack.append(child)
    return total


def _remove_empty_shells(content: Path, extracted: Path) -> None:
    current = content
    while not _same_path(current, extracted):
        try:
            current.rmdir()
        except OSError:
            break
        current = current.parent


def _preflight_item(source: Path, destination: Path, merge_dirs: bool) -> None:
    if not _lexists(destination):
        return
    source_dir = _is_dir(source)
    destination_dir = _is_dir(destination)
    if merge_dirs and source_dir and destination_dir:
        for child in _entries(source):
            _preflight_item(child, destination / child.name, merge_dirs)
        return
    raise _Conflict(f"destination conflict: {destination}")


def _preflight_items(
    items: Sequence[Path],
    destination_root: Path,
    conflict_mode: str,
    merge_dirs: bool = False,
    reject_conflicts: bool = False,
) -> None:
    if conflict_mode == "suffix" and not reject_conflicts:
        return
    for item in items:
        _preflight_item(item, destination_root / item.name, merge_dirs)


def _assert_destination_safe(destination: Path, extracted: Optional[Path], whole_tree: bool = False) -> None:
    if extracted is None:
        return
    if _same_path(destination, extracted) or _within(destination, extracted):
        raise ValueError(f"placement destination enters extracted tree: {destination}")
    if whole_tree and _within(extracted, destination):
        raise ValueError(f"placement destination contains extracted tree: {destination}")


def _move_source(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(os.fspath(source), os.fspath(destination))


def _merge_item(
    source: Path,
    destination: Path,
    conflict_mode: str,
    mark: Callable[[], None],
    set_root: Optional[Callable[[Path], None]] = None,
    top_level: bool = False,
    merge_dirs: bool = False,
) -> Path:
    if not _lexists(destination):
        _move_source(source, destination)
        mark()
        return destination

    source_dir = _is_dir(source)
    destination_dir = _is_dir(destination)
    if merge_dirs and source_dir and destination_dir:
        for child in _entries(source):
            _merge_item(child, destination / child.name, conflict_mode, mark, merge_dirs=merge_dirs)
        source.rmdir()
        return destination

    if conflict_mode == "fail":
        raise _Conflict(f"destination conflict: {destination}")
    replacement = _unique_path(destination)
    if top_level and set_root is not None:
        set_root(replacement)
    _move_source(source, replacement)
    mark()
    return replacement


def _execute_items(
    items: Sequence[Path],
    destination_root: Path,
    conflict_mode: str,
    placed: MutableSequence[Path],
    merge_dirs: bool = False,
) -> Tuple[Path, ...]:
    introduced: List[Path] = []
    for item in items:
        destination = destination_root / item.name
        state = {"destination": destination, "marked": False}

        def mark() -> None:
            if not state["marked"]:
                state["marked"] = True
                path = state["destination"]
                placed.append(path)
                introduced.append(path)

        def set_root(path: Path) -> None:
            state["destination"] = path

        try:
            actual = _merge_item(
                item,
                destination,
                conflict_mode,
                mark,
                set_root,
                top_level=True,
                merge_dirs=merge_dirs,
            )
        except _Conflict as exc:
            raise _Conflict(str(exc), placed) from exc
        except OSError as exc:
            raise PlacementError(f"could not place {item}: {exc}", placed) from exc
        if actual not in introduced and state["marked"]:
            introduced.append(actual)
    return tuple(introduced)


def _container(output: Path, name: str, conflict_mode: str) -> Path:
    target = output / _component(name, "generated folder")
    if not _lexists(target):
        return target
    return _unique_path(target)


def _place_items(
    items: Sequence[Path],
    destination_root: Path,
    conflict_mode: str,
    placed: MutableSequence[Path],
    extracted: Optional[Path] = None,
    merge_dirs: bool = False,
    reject_conflicts: bool = False,
) -> Tuple[Path, ...]:
    destination_root.mkdir(parents=True, exist_ok=True)
    for item in items:
        _assert_destination_safe(destination_root / item.name, extracted)
    _preflight_items(items, destination_root, conflict_mode, merge_dirs, reject_conflicts)
    return _execute_items(items, destination_root, conflict_mode, placed, merge_dirs)


def _place_wrapped_items(
    items: Sequence[Path],
    output: Path,
    name: str,
    conflict_mode: str,
    placed: MutableSequence[Path],
    extracted: Optional[Path] = None,
) -> Tuple[Path, ...]:
    container = _container(output, name, conflict_mode)
    _assert_destination_safe(container, extracted)
    # The container is absent by construction, so all source conflicts can be
    # checked before the first destination mutation.
    _preflight_items(items, container, "fail")
    try:
        container.mkdir(parents=False)
        placed.append(container)
        _execute_items(items, container, conflict_mode, placed, merge_dirs=False)
    except PlacementError:
        raise
    except OSError as exc:
        raise PlacementError(f"could not create placement container {container}: {exc}", placed) from exc
    return (container,)


def _place_whole_tree(
    extracted: Path,
    output: Path,
    name: str,
    conflict_mode: str,
    placed: MutableSequence[Path],
) -> Tuple[Path, ...]:
    target = _container(output, name, conflict_mode)
    _assert_destination_safe(target, extracted, whole_tree=True)
    try:
        shutil.move(os.fspath(extracted), os.fspath(target))
        placed.append(target)
    except PlacementError:
        raise
    except OSError as exc:
        if _lexists(target) and not _lexists(extracted):
            placed.append(target)
        raise PlacementError(f"could not move extracted tree to {target}: {exc}", placed) from exc
    return (target,)


def _place_direct_or_wrap(
    items: Sequence[Path],
    output: Path,
    wrapper_name: str,
    conflict_mode: str,
    placed: MutableSequence[Path],
    extracted: Optional[Path] = None,
    merge_dirs: bool = False,
    reject_conflicts: bool = True,
) -> Tuple[Path, ...]:
    try:
        return _place_items(
            items,
            output,
            conflict_mode,
            placed,
            extracted,
            merge_dirs,
            reject_conflicts,
        )
    except _Conflict:
        if not placed and (conflict_mode == "fail" or reject_conflicts):
            return _place_wrapped_items(items, output, wrapper_name, conflict_mode, placed, extracted)
        raise


def _meaningful_name(text: str) -> str:
    return "".join(
        char for char in text if (char.isalnum() and ord(char) < 128) or ord(char) >= 128
    )


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _meaningful_score(text: str) -> float:
    if not text:
        return 0.0
    score = 0.0
    digit_count = 0
    alnum_count = 0
    separators = " _-."
    for char in text:
        code = ord(char)
        if code >= 0x2E80:
            score += 1.5
            alnum_count += 1
        elif char.isalpha():
            score += 1.0
            alnum_count += 1
        elif char.isdigit():
            score += 0.5
            digit_count += 1
            alnum_count += 1
        elif char in separators:
            score += 0.1
    length = len(text)
    if digit_count / length > 0.66:
        score *= 0.6
    if (length - alnum_count) / length > 0.3:
        score *= 0.7
    if length > 4 and len(set(text)) / length < 0.3:
        score *= 0.5
    return score * (1 + 0.2 * _entropy(text))


def _auto_folder_name(strategy: str, deepest: str, archive_name: str) -> str:
    if strategy == "len":
        return deepest if len(deepest) >= len(archive_name) else archive_name
    if strategy == "meaningful":
        return deepest if len(_meaningful_name(deepest)) >= len(_meaningful_name(archive_name)) else archive_name
    return deepest if _meaningful_score(deepest) >= _meaningful_score(archive_name) else archive_name


def _only_file_content_direct(
    items: Sequence[Path],
    output: Path,
    extracted: Path,
    content: Path,
    archive_name: str,
    conflict_mode: str,
    placed: MutableSequence[Path],
) -> Tuple[Path, ...]:
    # This policy deliberately falls back for any collision, including one
    # that suffix mode could rename: its contract is a clean compatible merge.
    try:
        _preflight_items(items, output, "fail", merge_dirs=True, reject_conflicts=True)
    except _Conflict:
        return _place_wrapped_items(items, output, archive_name, conflict_mode, placed, extracted)
    result = _place_items(
        items,
        output,
        conflict_mode,
        placed,
        extracted,
        merge_dirs=True,
        reject_conflicts=True,
    )
    _remove_empty_shells(content, extracted)
    return result


def place_output(
    extracted: Path,
    output_dir: Path,
    archive_name: str,
    policy: str,
    conflict_mode: str,
) -> Tuple[Path, ...]:
    """Place a validated extraction according to one output policy.

    The return value contains destination roots introduced by this call.  If a
    move fails after some work, :class:`PlacementError.placed` names the roots
    already present in output.
    """

    extracted, output, archive_name, policy = _validate_layout_inputs(
        extracted, output_dir, archive_name, policy, conflict_mode
    )
    placed: List[Path] = []
    items = _entries(extracted)
    content = _content_root(extracted)
    content_items = _entries(content)
    deepest = _content_name(content, extracted, archive_name)

    try:
        if policy == "separate":
            return _place_whole_tree(extracted, output, archive_name, conflict_mode, placed)
        if policy == "direct":
            return _place_items(items, output, conflict_mode, placed, extracted)
        if policy == "collect":
            result = _place_direct_or_wrap(items, output, archive_name, conflict_mode, placed, extracted)
            return result

        if policy == "only-file-content":
            result = _place_wrapped_items(content_items, output, archive_name, conflict_mode, placed, extracted)
            _remove_empty_shells(content, extracted)
            return result
        if policy == "only-file-content-direct":
            return _only_file_content_direct(
                content_items,
                output,
                extracted,
                content,
                archive_name,
                conflict_mode,
                placed,
            )
        if policy == "file-content-with-folder":
            result = _place_wrapped_items(content_items, output, deepest, conflict_mode, placed, extracted)
            _remove_empty_shells(content, extracted)
            return result
        if policy == "file-content-with-folder-separate":
            container = _container(output, archive_name, conflict_mode)
            _assert_destination_safe(container, extracted)
            _preflight_items(content_items, container / deepest if deepest != archive_name else container, "fail")
            container.mkdir(parents=False)
            placed.append(container)
            target = container if deepest == archive_name else container / deepest
            if target != container:
                target.mkdir()
            _execute_items(content_items, target, conflict_mode, placed)
            _remove_empty_shells(content, extracted)
            return (container,)

        n_match = _N_COLLECT.fullmatch(policy)
        if n_match:
            threshold = int(n_match.group(1))
            if _count_items(extracted, threshold) >= threshold:
                return _place_whole_tree(extracted, output, archive_name, conflict_mode, placed)
            result = _place_direct_or_wrap(
                items,
                output,
                archive_name,
                conflict_mode,
                placed,
                extracted,
                merge_dirs=False,
                reject_conflicts=False,
            )
            return result

        file_match = _FILE_CONTENT_COLLECT.fullmatch(policy)
        if file_match:
            threshold = int(file_match.group(1))
            if _count_items(content, threshold) >= threshold:
                result = _place_wrapped_items(content_items, output, archive_name, conflict_mode, placed, extracted)
            else:
                result = _place_direct_or_wrap(
                    content_items,
                    output,
                    archive_name,
                    conflict_mode,
                    placed,
                    extracted,
                    merge_dirs=True,
                    reject_conflicts=True,
                )
            _remove_empty_shells(content, extracted)
            return result

        auto_match = _AUTO_FOLDER_COLLECT.fullmatch(policy)
        if auto_match:
            threshold = int(auto_match.group(1))
            strategy = auto_match.group(2)
            wrapper = _auto_folder_name(strategy, deepest, archive_name)
            if _count_items(content, threshold) >= threshold:
                result = _place_wrapped_items(content_items, output, wrapper, conflict_mode, placed, extracted)
            else:
                result = _place_direct_or_wrap(
                    content_items,
                    output,
                    wrapper,
                    conflict_mode,
                    placed,
                    extracted,
                    merge_dirs=True,
                    reject_conflicts=True,
                )
            _remove_empty_shells(content, extracted)
            return result
    except PlacementError as exc:
        if exc.placed:
            raise
        raise PlacementError(str(exc), placed) from exc

    raise ValueError(f"invalid decompress policy: {policy}")
