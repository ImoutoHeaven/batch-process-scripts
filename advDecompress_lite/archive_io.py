"""Archive discovery, password candidates, ZIP policy, and extraction."""

from __future__ import annotations

import ctypes
import binascii
import codecs
import os
import re
import shutil
import struct
import subprocess
import tempfile
import threading
import tarfile
import zipfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple


_SEVEN_Z_SIGNATURE = b"\x37\x7a\xbc\xaf\x27\x1c"
_TAR_SUFFIXES = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")
_WORK_DIR_NAMES = {
    ".advdecompress_work",
    ".staging_advDecompress",
    ".advdecompress_lite_tmp",
}
_WORK_DIR_NAMES_FOLDED = {value.casefold() for value in _WORK_DIR_NAMES}


@dataclass(frozen=True)
class ArchiveGroup:
    entry: Optional[Path]
    volumes: Tuple[Path, ...]
    stem: str
    kind: str
    multi: bool
    format: str
    error: Optional[str] = None

    def __post_init__(self) -> None:
        if self.entry is not None and not isinstance(self.entry, Path):
            object.__setattr__(self, "entry", Path(self.entry))
        object.__setattr__(self, "volumes", tuple(Path(p) for p in self.volumes))


class PasswordCandidates:
    """Stable, in-memory password candidates with thread-safe hit ordering."""

    def __init__(self, args) -> None:
        explicit = getattr(args, "password", None)
        values: List[str] = []
        if explicit is not None:
            values.append(str(explicit))

        password_file = getattr(args, "password_file", None)
        if password_file:
            with open(Path(password_file), "r", encoding="utf-8") as stream:
                for line in stream:
                    value = line.rstrip("\r\n")
                    if value and value not in values:
                        values.append(value)

        self._explicit = str(explicit) if explicit is not None else None
        self._values = values
        self._hits = {value: 0 for value in values}
        self._lock = threading.Lock()

    @property
    def candidates(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(self._ordered())

    @property
    def hit_counts(self) -> Mapping[str, int]:
        with self._lock:
            return dict(self._hits)

    def _ordered(self) -> List[str]:
        explicit = self._explicit
        others = [value for value in self._values if value != explicit]
        others.sort(key=lambda value: -self._hits.get(value, 0))
        return ([explicit] if explicit is not None else []) + others

    def record_success(self, password: str) -> None:
        with self._lock:
            if password not in self._hits:
                self._hits[password] = 0
                self._values.append(password)
            self._hits[password] += 1

    def __iter__(self) -> Iterator[str]:
        return iter(self.candidates)

    def __len__(self) -> int:
        return len(self._values)

    def __getitem__(self, index):
        return self.candidates[index]


def _get(args, name: str, default=None):
    return getattr(args, name, default)


def _absolute(path) -> Path:
    return Path(path).expanduser().resolve()


def _lexical_absolute(path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(path))))


def _is_reparse_point(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if callable(is_junction) and is_junction():
            return True
        if os.name == "nt":
            attributes = int(getattr(os.lstat(path), "st_file_attributes", 0) or 0)
            return bool(attributes & 0x400)
    except OSError:
        return False
    return False


def existing_path_key(path: Path) -> str:
    return os.path.normcase(os.path.normpath(str(path)))


def _depth_range(value) -> Tuple[int, Optional[int]]:
    if value in (None, ""):
        return 0, None
    if isinstance(value, (tuple, list)):
        if len(value) != 2:
            raise ValueError("depth range must contain two values")
        low, high = int(value[0]), int(value[1])
    else:
        text = str(value).strip()
        if "-" in text:
            left, right = text.split("-", 1)
            low, high = int(left), int(right)
        else:
            low = high = int(text)
    if low < 0 or (high is not None and high < 0) or (high is not None and low > high):
        raise ValueError("invalid depth range")
    return low, high


def parse_depth_range(value) -> Optional[Tuple[int, int]]:
    """Parse a CLI depth value for the runtime validation seam."""
    if value in (None, ""):
        return None
    low, high = _depth_range(value)
    return low, low if high is None else high


def _input_root(args) -> Tuple[Path, bool]:
    value = _lexical_absolute(_get(args, "path", "."))
    if _is_reparse_point(value):
        raise ValueError("reparse-point input is not supported: {}".format(value))
    return value, value.is_file()


def _path_inside(path: Path, root: Path) -> bool:
    try:
        normalized_path = existing_path_key(path)
        normalized_root = existing_path_key(root)
        return os.path.commonpath((normalized_path, normalized_root)) == normalized_root
    except ValueError:
        return False


def _excluded_roots(args, input_root: Path, input_is_file: bool) -> Tuple[Path, ...]:
    base = input_root.parent if input_is_file else input_root
    values: List[Path] = []
    for name in ("output", "success_to", "fail_to", "traditional_zip_to"):
        value = _get(args, name)
        if value:
            candidate = _lexical_absolute(value)
            if existing_path_key(candidate) != existing_path_key(base) and _path_inside(candidate, base):
                values.append(candidate)
    return tuple(values)


def _skip_dir(path: Path, input_root: Path, excluded: Sequence[Path]) -> bool:
    if path == input_root:
        return False
    if _is_reparse_point(path):
        return True
    name = path.name.casefold()
    if name in _WORK_DIR_NAMES_FOLDED or name.startswith(".advdecompress_work.retired."):
        return True
    return any(_path_inside(path, root) for root in excluded)


def _directory_files(directory: Path) -> Dict[str, Path]:
    result: Dict[str, Path] = {}
    try:
        for item in sorted(directory.iterdir(), key=lambda p: p.name.casefold()):
            try:
                if _is_reparse_point(item):
                    continue
                if item.is_file() and not item.is_symlink():
                    result[item.name] = item
            except OSError:
                continue
    except OSError:
        return {}
    return result


def _indexed_directories(root: Path, excluded: Sequence[Path], high: Optional[int]):
    pending = [(root, 0)]
    while pending:
        directory, depth = pending.pop()
        files: Dict[str, Path] = {}
        children: List[Path] = []
        try:
            entries = sorted(directory.iterdir(), key=lambda p: p.name.casefold())
        except OSError:
            continue
        for item in entries:
            try:
                if _is_reparse_point(item):
                    continue
                if item.is_file() and not item.is_symlink():
                    files[item.name] = item
                elif item.is_dir() and not item.is_symlink() and not _skip_dir(item, root, excluded):
                    children.append(item)
            except OSError:
                continue
        yield directory, files, depth
        if high is None or depth < high:
            pending.extend((child, depth + 1) for child in reversed(children))


def _find_name(files: Mapping[str, Path], name: str) -> Optional[Path]:
    exact = files.get(name)
    if exact is not None:
        return exact
    if os.name != "nt":
        stem, separator, extension = name.rpartition(".")
        if not separator or extension.casefold() not in {"exe", "rar", "zip"}:
            return None
        matches = [
            path
            for actual, path in files.items()
            if "." in actual
            and actual.rsplit(".", 1)[0] == stem
            and actual.rsplit(".", 1)[1].casefold() == extension.casefold()
        ]
        if len(matches) > 1:
            raise ValueError("ambiguous case-insensitive filename match: {}".format(name))
        return matches[0] if matches else None
    folded = name.casefold()
    matches = []
    for actual, path in files.items():
        if actual.casefold() == folded:
            matches.append(path)
    if len(matches) > 1:
        raise ValueError("ambiguous case-insensitive filename match: {}".format(name))
    if matches:
        return matches[0]
    return None


def _matches(files: Mapping[str, Path], pattern: re.Pattern) -> List[Tuple[Path, re.Match]]:
    result = []
    for name, path in files.items():
        match = pattern.fullmatch(name)
        if match:
            result.append((path, match))
    return result


_RE_7Z_VOLUME = re.compile(r"(?P<base>.+)\.7z\.(?P<number>\d+)$", re.IGNORECASE)
_RE_EXE_VOLUME = re.compile(r"(?P<base>.+)\.exe\.(?P<number>\d+)$", re.IGNORECASE)
_RE_RAR_PART = re.compile(r"(?P<base>.+)\.part(?P<number>\d+)\.rar$", re.IGNORECASE)
_RE_RAR_OLD = re.compile(r"(?P<base>.+)\.r(?P<number>\d+)$", re.IGNORECASE)
_RE_ZIP_VOLUME = re.compile(r"(?P<base>.+)\.z(?P<number>\d+)$", re.IGNORECASE)
_RE_RAR_SFX_EXE = re.compile(r"(?P<base>.+)\.part(?P<number>\d+)\.exe$", re.IGNORECASE)


def _numeric_sort(items: Iterable[Tuple[Path, re.Match]]) -> List[Path]:
    return [path for path, _ in sorted(items, key=lambda pair: (int(pair[1].group("number")), pair[0].name.casefold()))]


def _numbered_primary(items: Iterable[Tuple[Path, re.Match]]) -> Optional[Path]:
    for path, match in items:
        if int(match.group("number")) == 1:
            return path
    return None


def _valid_seven_zip_header(data: bytes, offset: int, total_size: int) -> bool:
    if len(data) < offset + 32 or data[offset : offset + 6] != _SEVEN_Z_SIGNATURE:
        return False
    try:
        start_crc = struct.unpack_from("<I", data, offset + 8)[0]
        next_offset, next_size = struct.unpack_from("<QQ", data, offset + 12)
    except struct.error:
        return False
    if binascii.crc32(data[offset + 12 : offset + 32]) & 0xFFFFFFFF != start_crc:
        return False
    return offset + 32 + next_offset + next_size <= total_size


def _seven_zip_group_state(items: Iterable[Tuple[Path, re.Match]]) -> str:
    """Classify a numbered 7z stream using its start-header bounds and CRC."""
    entries = list(items)
    primary = _numbered_primary(entries)
    if primary is None:
        return "not_7z"
    return _embedded_seven_zip_state(
        [path for path, _ in sorted(entries, key=lambda item: int(item[1].group("number")))]
    )


def _embedded_seven_zip_state(path_or_paths, total_size: Optional[int] = None) -> str:
    paths = [path_or_paths] if isinstance(path_or_paths, Path) else list(path_or_paths)
    if not paths:
        return "unknown"
    try:
        if total_size is None:
            total_size = sum(path.stat().st_size for path in paths)
        chunk_size = 1024 * 1024
        overlap = 31
        carry = b""
        stream_offset = 0
        for path in paths:
            with path.open("rb") as stream:
                while True:
                    chunk = stream.read(chunk_size)
                    if not chunk:
                        break
                    data = carry + chunk
                    data_offset = stream_offset - len(carry)
                    search_from = max(0, 512 - data_offset)
                    while True:
                        position = data.find(_SEVEN_Z_SIGNATURE, search_from)
                        if position < 0:
                            break
                        absolute = data_offset + position
                        if position + 32 <= len(data) and absolute + 32 <= total_size:
                            header = data[position : position + 32]
                            try:
                                start_crc = struct.unpack_from("<I", header, 8)[0]
                                next_offset, next_size = struct.unpack_from("<QQ", header, 12)
                            except struct.error:
                                start_crc = None
                                next_offset = next_size = 0
                            if start_crc is not None and binascii.crc32(header[12:32]) & 0xFFFFFFFF == start_crc:
                                return "complete" if absolute + 32 + next_offset + next_size <= total_size else "incomplete"
                        search_from = position + 1
                    carry = data[-overlap:]
                    stream_offset += len(chunk)
        return "unknown"
    except OSError:
        return "unknown"


def _embedded_seven_zip_complete(path: Path, total_size: Optional[int] = None) -> bool:
    return _embedded_seven_zip_state(path, total_size) == "complete"


def _archive_stem(name: str) -> str:
    lower = name.casefold()
    for suffix in _TAR_SUFFIXES:
        if lower.endswith(suffix):
            return name[: -len(suffix)] or "archive"
    for pattern in (_RE_EXE_VOLUME, _RE_7Z_VOLUME, _RE_RAR_PART, _RE_RAR_OLD, _RE_ZIP_VOLUME):
        match = pattern.fullmatch(name)
        if match:
            return match.group("base") or "archive"
    for suffix in (".exe", ".7z", ".rar", ".zip"):
        if lower.endswith(suffix):
            return name[: -len(suffix)] or "archive"
    return Path(name).stem or "archive"


def _sanitize_stem(stem: str) -> str:
    if os.name == "nt":
        stem = stem.rstrip(" .")
    return stem or "archive"


def _scan_sfx(path: Path, enabled: bool, cache: Dict[Path, Optional[str]]) -> Optional[str]:
    if path in cache:
        return cache[path]
    result = None
    is_exe_family = path.suffix.casefold() == ".exe" or _RE_EXE_VOLUME.fullmatch(path.name) is not None
    if not is_exe_family and not enabled:
        cache[path] = result
        return result
    try:
        with path.open("rb") as stream:
            header = stream.read(64)
            if is_exe_family:
                if not header.startswith(b"MZ"):
                    cache[path] = result
                    return result
            elif not header.startswith(b"\x7fELF"):
                cache[path] = result
                return result
            size = path.stat().st_size
            # ponytail: SFX signature sampling covers the first 1 MiB and last 32 MiB;
            # stream every byte only if a rare stub places its payload outside both windows.
            windows = [(0, min(size, 1024 * 1024))]
            if size > windows[0][1]:
                windows.append((max(512, size - min(size, 32 * 1024 * 1024)), min(size, 32 * 1024 * 1024)))
            for start, length in windows:
                stream.seek(start)
                data = stream.read(length)
                offset = start
                if offset == 0:
                    if is_exe_family and (b"WinRAR" in data[:8192] or b"WINRAR" in data[:8192]):
                        result = "rar"
                        break
                    offset = 512
                    data = data[512:]
                if b"Rar!" in data:
                    result = "rar"
                    break
                if _SEVEN_Z_SIGNATURE in data:
                    result = "7z"
                    break
        if result is None and is_exe_family:
            result = _pe_has_extra_data(path)
    except OSError:
        result = None
    cache[path] = result
    return result


def _pe_has_extra_data(path: Path) -> Optional[str]:
    try:
        with path.open("rb") as stream:
            dos = stream.read(64)
            if len(dos) < 64:
                return None
            pe_offset = int.from_bytes(dos[60:64], "little")
            stream.seek(pe_offset)
            header = stream.read(24)
            if len(header) < 24 or header[:4] != b"PE\0\0":
                return None
            sections = int.from_bytes(header[6:8], "little")
            optional_size = int.from_bytes(header[20:22], "little")
            stream.seek(pe_offset + 24 + optional_size)
            table = stream.read(sections * 40)
        executable_end = 0
        for offset in range(0, len(table), 40):
            section = table[offset : offset + 40]
            if len(section) < 40:
                break
            raw_size = int.from_bytes(section[16:20], "little")
            raw_offset = int.from_bytes(section[20:24], "little")
            executable_end = max(executable_end, raw_offset + raw_size)
        # ponytail: PE overlay >10 KiB is a bounded SFX fallback; parse the
        # container metadata when false positives or unusual stubs matter.
        return "7z" if path.stat().st_size - executable_end > 10 * 1024 else None
    except (OSError, IndexError, ValueError):
        return None


def _sfx_group_format(sfx_kind: Optional[str], elf: bool = False) -> Optional[str]:
    if sfx_kind == "rar":
        return "elf-sfx-rar" if elf else "sfx-rar"
    if sfx_kind == "7z":
        return "elf-sfx-7z" if elf else "sfx-7z"
    return None


def _group(
    *,
    entry: Optional[Path],
    volumes: Iterable[Path],
    stem: str,
    kind: str,
    multi: bool,
    format: str,
    error: Optional[str] = None,
) -> ArchiveGroup:
    ordered = tuple(dict.fromkeys(volumes))
    return ArchiveGroup(entry, ordered, _sanitize_stem(stem), kind, multi, format, error)


def _numbered_stream_error(
    items: Sequence[Tuple[Path, re.Match]],
    expected_start: int,
    label: str,
) -> Optional[str]:
    if not items:
        return None
    values = sorted(int(match.group("number")) for _, match in items)
    if len(set(values)) != len(values):
        return "duplicate {} volume index".format(label)
    if values[0] != expected_start:
        return "missing primary {} volume".format(label)
    for previous, current in zip(values, values[1:]):
        if current != previous + 1:
            return "missing interior {} volume".format(label)
    return None


def _combined_rar_sfx_error(items: Sequence[Tuple[Path, re.Match]]) -> Optional[str]:
    values = [int(match.group("number")) for _, match in items]
    if not values:
        return None
    stream_counts = {}
    for path, match in items:
        stream = stream_counts.setdefault(path.suffix.casefold(), {})
        index = int(match.group("number"))
        stream[index] = stream.get(index, 0) + 1
    if any(count > 1 for counts in stream_counts.values() for index, count in counts.items() if index == 1):
        return "duplicate RAR SFX volume index"
    counts = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    if any(value != 1 and count > 1 for value, count in counts.items()):
        return "duplicate RAR SFX volume index"
    ordered = sorted(counts)
    if ordered[0] != 1:
        return "missing primary RAR SFX volume"
    for previous, current in zip(ordered, ordered[1:]):
        if current != previous + 1:
            return "missing interior RAR SFX volume"
    return None


def _group_directory(files: Mapping[str, Path], args) -> List[ArchiveGroup]:
    sfx_cache: Dict[Path, Optional[str]] = {}
    detect_elf = bool(_get(args, "detect_elf_sfx", False))
    claimed: set = set()
    groups: List[ArchiveGroup] = []

    indexed = {
        "seven": _matches(files, _RE_7Z_VOLUME),
        "exe": _matches(files, _RE_EXE_VOLUME),
        "parts": _matches(files, _RE_RAR_PART),
        "old": _matches(files, _RE_RAR_OLD),
        "zip": _matches(files, _RE_ZIP_VOLUME),
        "sfx_exe": _matches(files, _RE_RAR_SFX_EXE),
    }
    by_base = {}
    for kind, collection in indexed.items():
        for path, match in collection:
            key = os.path.normcase(match.group("base"))
            current = by_base.setdefault(key, {"base": match.group("base")})
            current.setdefault(kind, []).append((path, match))

    pre_groups: List[ArchiveGroup] = []
    invalid_names: set = set()
    merged_rar_keys: set = set()
    stream_specs = {
        "seven": (1, "7z", "7z"),
        "exe": (1, "exe", "sfx-7z"),
        "parts": (1, "RAR", "rar"),
        "old": (0, "legacy RAR", "rar"),
        "zip": (1, "ZIP", "zip"),
        "sfx_exe": (1, "RAR SFX", "sfx-rar"),
    }
    stream_kinds = {
        "seven": "7z",
        "exe": "exe",
        "parts": "rar",
        "old": "rar",
        "zip": "zip",
        "sfx_exe": "exe",
    }
    for key, current in by_base.items():
        base = current["base"]
        sfx_parts = current.get("sfx_exe", [])
        sfx_primary = _numbered_primary(sfx_parts)
        sfx_kind = _scan_sfx(sfx_primary, detect_elf, sfx_cache) if sfx_primary else None
        if sfx_primary and sfx_kind == "rar":
            merged_rar_keys.add(key)
            combined = sfx_parts + current.get("parts", [])
            error = _combined_rar_sfx_error(combined)
            if error is not None:
                paths = list(dict.fromkeys(path for path, _ in combined))
                pre_groups.append(_group(
                    entry=None,
                    volumes=paths,
                    stem=base,
                    kind="exe",
                    multi=True,
                    format="ambiguous",
                    error=error,
                ))
                invalid_names.update(path.name for path in paths)
        for kind, (expected_start, label, format_name) in stream_specs.items():
            if key in merged_rar_keys and kind in ("parts", "sfx_exe"):
                continue
            items = current.get(kind, [])
            if kind == "parts" and items:
                standalone_candidate = _find_name(files, current["base"] + ".exe")
                standalone_candidate_kind = _scan_sfx(standalone_candidate, detect_elf, sfx_cache) if standalone_candidate else None
                if standalone_candidate_kind == "rar" and _numbered_primary(current.get("sfx_exe", [])) is None:
                    continue
            if kind == "parts" and sfx_primary and sfx_kind == "rar" and _numbered_primary(items) is None:
                expected_start = 2
            error = _numbered_stream_error(items, expected_start, label)
            if error is None:
                continue
            paths = [path for path, _ in items]
            if kind in ("old", "zip"):
                primary_suffix = ".rar" if kind == "old" else ".zip"
                primary_path = _find_name(files, current["base"] + primary_suffix)
                if primary_path is not None:
                    paths.append(primary_path)
            paths = list(dict.fromkeys(paths))
            pre_groups.append(_group(
                entry=None,
                volumes=paths,
                stem=base,
                kind=stream_kinds[kind],
                multi=True,
                format=format_name,
                error=error,
            ))
            invalid_names.update(path.name for path in paths)

    groups.extend(pre_groups)
    claimed.update(invalid_names)

    for key in sorted(by_base, key=str.casefold):
        current = by_base[key]
        base = current["base"]
        exe = _find_name(files, base + ".exe")
        seven = [item for item in current.get("seven", []) if item[0].name not in invalid_names]
        exe_parts = [item for item in current.get("exe", []) if item[0].name not in invalid_names]
        parts = [item for item in current.get("parts", []) if item[0].name not in invalid_names]
        old_parts = [item for item in current.get("old", []) if item[0].name not in invalid_names]
        zparts = [item for item in current.get("zip", []) if item[0].name not in invalid_names]
        sfx_exe_parts = [item for item in current.get("sfx_exe", []) if item[0].name not in invalid_names]
        sfx_primary = _numbered_primary(sfx_exe_parts)
        sfx_fallback = files.get(base) if detect_elf else None
        if detect_elf and sfx_fallback is None and os.name == "nt":
            sfx_fallback = _find_name(files, base)
        standalone_entry = exe or sfx_fallback
        standalone_kind = _scan_sfx(standalone_entry, detect_elf, sfx_cache) if standalone_entry else None
        numeric_kind = _scan_sfx(sfx_primary, detect_elf, sfx_cache) if sfx_primary else None
        exe_numeric_primary = _numbered_primary(exe_parts)
        numeric_exe_kind = _scan_sfx(exe_numeric_primary, detect_elf, sfx_cache) if exe_numeric_primary else None
        standalone_embedded_state = (
            _embedded_seven_zip_state(standalone_entry)
            if standalone_entry and standalone_kind == "7z"
            else "unknown"
        )
        standalone_embedded_complete = standalone_embedded_state == "complete"
        numeric_exe_state = (
            _embedded_seven_zip_state(
                _numeric_sort(exe_parts),
                sum(path.stat().st_size for path, _ in exe_parts),
            )
            if exe_numeric_primary and numeric_exe_kind == "7z"
            else "unknown"
        )
        numeric_group = False
        plain_rar_primary = _numbered_primary(parts)
        shared_rar_secondaries = [item for item in parts if int(item[1].group("number")) != 1]
        rar_ambiguous = bool(
            sfx_primary
            and numeric_kind == "rar"
            and plain_rar_primary is not None
            and shared_rar_secondaries
        )
        if rar_ambiguous:
            ambiguous = list(sfx_exe_parts) + list(parts)
            if standalone_entry is not None and standalone_kind == "rar":
                ambiguous = [(standalone_entry, None)] + ambiguous
            ambiguous_paths = list(dict.fromkeys(path for path, _ in ambiguous))
            groups.append(_group(
                entry=None,
                volumes=ambiguous_paths,
                stem=base,
                kind="exe",
                multi=True,
                format="ambiguous",
                error="ambiguous competing RAR SFX and RAR multipart primaries",
            ))
            claimed.update(path.name for path in ambiguous_paths)
            numeric_group = True

        numeric_exe_group = False
        numeric_exe_missing_primary = bool(exe_parts and exe_numeric_primary is None)
        companion_compatible = bool(
            standalone_entry
            and standalone_embedded_state == "incomplete"
            and standalone_kind == numeric_exe_kind
        )
        if not rar_ambiguous and numeric_exe_missing_primary and companion_compatible:
            vols = [standalone_entry] + _numeric_sort(exe_parts)
            groups.append(_group(
                entry=None,
                volumes=vols,
                stem=base,
                kind="exe",
                multi=True,
                format="sfx-7z",
                error="missing primary SFX executable volume",
            ))
            claimed.update(path.name for path in vols)
            numeric_exe_group = True

        if not numeric_exe_group and exe_numeric_primary:
            if numeric_exe_kind == "7z":
                format_name = "sfx-7z"
                error = None if numeric_exe_state in ("complete", "incomplete") else "numeric SFX primary could not be validated"
                companion_allowed = companion_compatible and numeric_exe_state in ("complete", "incomplete")
            elif numeric_exe_kind == "rar":
                format_name = "sfx-rar"
                error = None
                companion_allowed = companion_compatible
            else:
                format_name = "sfx-7z"
                error = "numeric SFX primary could not be identified"
                companion_allowed = False
            companion = [standalone_entry] if companion_allowed else []
            vols = [exe_numeric_primary] + _numeric_sort(
                [item for item in exe_parts if item[0] != exe_numeric_primary]
            ) + companion
            groups.append(_group(
                entry=exe_numeric_primary,
                volumes=vols,
                stem=base,
                kind="exe",
                multi=True,
                format=format_name,
                error=error,
            ))
            claimed.update(path.name for path in vols)
            numeric_exe_group = True
        seven_for_sfx = seven
        if standalone_entry and standalone_kind == "7z" and seven:
            if standalone_embedded_complete:
                seven_for_sfx = []
            else:
                seven_state = _seven_zip_group_state(seven)
                if seven_state == "incomplete" and _numbered_primary(seven) is not None:
                    ambiguous = [standalone_entry] + [path for path, _ in seven]
                    groups.append(_group(
                        entry=None,
                        volumes=ambiguous,
                        stem=base,
                        kind="exe",
                        multi=True,
                        format="ambiguous",
                        error="ambiguous standalone 7z SFX and numbered 7z ownership",
                    ))
                    claimed.update(path.name for path in ambiguous)
                    standalone_entry = None
                    standalone_kind = None

        # A numbered RAR SFX primary owns its numbered executable siblings and
        # RAR secondaries.  Keep a same-stem standalone SFX executable separate.
        if sfx_primary and numeric_kind == "rar" and not rar_ambiguous:
            split_source = sfx_exe_parts if plain_rar_primary is not None else sfx_exe_parts + parts
            split = [item for item in split_source if item[0] != sfx_primary]
            vols = [sfx_primary] + _numeric_sort(split)
            groups.append(_group(entry=sfx_primary, volumes=vols, stem=base, kind="exe", multi=True, format="sfx-rar"))
            claimed.update(p.name for p in vols)
            numeric_group = True
        elif sfx_primary and numeric_kind == "7z":
            split = [item for item in sfx_exe_parts if item[0] != sfx_primary]
            vols = [sfx_primary] + _numeric_sort(split)
            groups.append(_group(entry=sfx_primary, volumes=vols, stem=base, kind="exe", multi=True, format="sfx-7z"))
            claimed.update(p.name for p in vols)
            numeric_group = True

        sfx_entry = standalone_entry
        sfx_kind = standalone_kind
        elf_sfx = bool(sfx_entry and sfx_entry.suffix.casefold() != ".exe")
        sfx_format = _sfx_group_format(sfx_kind, elf_sfx)
        unclaimed_parts = [item for item in parts if item[0].name not in claimed]
        unclaimed_exe_parts = [item for item in exe_parts if item[0].name not in claimed]
        unclaimed_exe_parts_for_sfx = (
            []
            if numeric_exe_missing_primary or (exe_numeric_primary and not companion_compatible)
            else unclaimed_exe_parts
        )

        parts_error = _numbered_stream_error(parts, 1, "RAR")
        if sfx_entry and sfx_format == "sfx-rar" and unclaimed_parts and not numeric_group and (plain_rar_primary is None or parts_error is not None):
            ambiguous = [sfx_entry]
            for collection in (sfx_exe_parts, parts):
                ambiguous.extend(path for path, _ in collection)
            ambiguous = list(dict.fromkeys(ambiguous))
            groups.append(_group(
                entry=None,
                volumes=ambiguous,
                stem=base,
                kind="exe",
                multi=True,
                format="ambiguous",
                error="ambiguous standalone RAR SFX and multipart RAR ownership",
            ))
            claimed.update(path.name for path in ambiguous)
        elif sfx_entry and sfx_format:
            if sfx_kind == "7z" and (seven_for_sfx or unclaimed_exe_parts_for_sfx):
                split = seven_for_sfx + unclaimed_exe_parts_for_sfx
                vols = [sfx_entry] + _numeric_sort([item for item in split if item[0] != sfx_entry])
                groups.append(_group(entry=sfx_entry, volumes=vols, stem=base, kind="exe", multi=True, format=sfx_format))
                claimed.update(path.name for path in vols)
            elif sfx_kind == "rar" and (unclaimed_exe_parts_for_sfx or not numeric_group):
                split = unclaimed_exe_parts_for_sfx
                if split:
                    vols = [sfx_entry] + _numeric_sort([item for item in split if item[0] != sfx_entry])
                    groups.append(_group(entry=sfx_entry, volumes=vols, stem=base, kind="exe", multi=True, format=sfx_format))
                    claimed.update(path.name for path in vols)
                elif sfx_entry.name not in claimed:
                    groups.append(_group(entry=sfx_entry, volumes=[sfx_entry], stem=base, kind="exe", multi=False, format=sfx_format))
                    claimed.add(sfx_entry.name)

        if unclaimed_exe_parts and standalone_embedded_complete:
            primary = _numbered_primary(unclaimed_exe_parts)
            vols = _numeric_sort(unclaimed_exe_parts)
            format_name = "sfx-rar" if numeric_exe_kind == "rar" else "sfx-7z"
            groups.append(_group(
                entry=primary,
                volumes=vols,
                stem=base,
                kind="exe",
                multi=True,
                format=format_name,
                error=None if primary else "missing primary SFX executable volume",
            ))
            claimed.update(path.name for path in vols)

        if unclaimed_exe_parts and exe_numeric_primary is None and not numeric_exe_group:
            groups.append(_group(
                entry=None,
                volumes=_numeric_sort(unclaimed_exe_parts),
                stem=base,
                kind="exe",
                multi=True,
                format="sfx-7z",
                error="missing primary SFX executable volume",
            ))
            claimed.update(path.name for path, _ in unclaimed_exe_parts)

        unclaimed_sfx_exe_parts = [item for item in sfx_exe_parts if item[0].name not in claimed]
        if unclaimed_sfx_exe_parts and sfx_entry and not numeric_group:
            vols = _numeric_sort(unclaimed_sfx_exe_parts)
            groups.append(_group(
                entry=None,
                volumes=vols,
                stem=base,
                kind="exe",
                multi=True,
                format="sfx-rar",
                error="missing primary SFX executable volume",
            ))
            claimed.update(path.name for path in vols)

        if (exe_parts or sfx_exe_parts) and not sfx_entry and not numeric_group and not numeric_exe_group:
            vols = _numeric_sort(exe_parts + sfx_exe_parts)
            groups.append(_group(entry=None, volumes=vols, stem=base, kind="exe", multi=True, format="sfx-7z", error="missing primary SFX executable volume"))
            claimed.update(p.name for p in vols)

        if seven and not any(p.name in claimed for p, _ in seven):
            primary = _numbered_primary(seven)
            vols = _numeric_sort(seven)
            groups.append(_group(entry=primary, volumes=vols, stem=base, kind="7z", multi=True, format="7z", error=None if primary else "missing primary 7z volume"))
            claimed.update(p.name for p in vols)
        if parts and not any(p.name in claimed for p, _ in parts):
            primary = _numbered_primary(parts)
            vols = _numeric_sort(parts)
            groups.append(_group(entry=primary, volumes=vols, stem=base, kind="rar", multi=True, format="rar", error=None if primary else "missing primary RAR volume"))
            claimed.update(p.name for p in vols)
        if old_parts and not any(p.name in claimed for p, _ in old_parts):
            primary = _find_name(files, base + ".rar")
            vols = ([primary] if primary else []) + _numeric_sort(old_parts)
            groups.append(_group(entry=primary, volumes=vols, stem=base, kind="rar", multi=True, format="rar", error=None if primary else "missing primary RAR volume"))
            claimed.update(p.name for p in vols)
        if zparts and not any(p.name in claimed for p, _ in zparts):
            primary = _find_name(files, base + ".zip")
            vols = ([primary] if primary else []) + _numeric_sort(zparts)
            groups.append(_group(entry=primary, volumes=vols, stem=base, kind="zip", multi=True, format="zip", error=None if primary else "missing primary ZIP volume"))
            claimed.update(p.name for p in vols)

    for name, path in sorted(files.items(), key=lambda pair: pair[0].casefold()):
        if name in claimed:
            continue
        lower = name.casefold()
        if lower.endswith(".7z"):
            groups.append(_group(entry=path, volumes=[path], stem=_archive_stem(name), kind="7z", multi=False, format="7z"))
            claimed.add(name)
        elif lower.endswith(".rar") and not _RE_RAR_PART.fullmatch(name):
            groups.append(_group(entry=path, volumes=[path], stem=_archive_stem(name), kind="rar", multi=False, format="rar"))
            claimed.add(name)
        elif lower.endswith(".zip"):
            groups.append(_group(entry=path, volumes=[path], stem=_archive_stem(name), kind="zip", multi=False, format="zip"))
            claimed.add(name)
        elif lower.endswith(_TAR_SUFFIXES):
            groups.append(_group(entry=path, volumes=[path], stem=_archive_stem(name), kind="tar", multi=False, format="tar"))
            claimed.add(name)
        elif lower.endswith(".exe"):
            sfx_kind = _scan_sfx(path, detect_elf, sfx_cache)
            if sfx_kind:
                groups.append(_group(entry=path, volumes=[path], stem=_archive_stem(name), kind="exe", multi=False, format=_sfx_group_format(sfx_kind)))
                claimed.add(name)
        elif detect_elf:
            sfx_kind = _scan_sfx(path, True, sfx_cache)
            if sfx_kind:
                groups.append(_group(entry=path, volumes=[path], stem=_archive_stem(name), kind="exe", multi=False, format=_sfx_group_format(sfx_kind, True)))
                claimed.add(name)

    return groups


def _group_allowed(group: ArchiveGroup, args) -> bool:
    suffix = "_multi" if group.multi else ""
    return not bool(_get(args, "skip_" + group.kind + suffix, False))


def discover_archives(args) -> List[ArchiveGroup]:
    """Discover archive groups from a file or recursive directory."""
    root, single_file = _input_root(args)
    low, high = _depth_range(_get(args, "depth_range"))
    excluded = _excluded_roots(args, root, single_file)
    groups: List[ArchiveGroup] = []

    if single_file:
        directory = root.parent
        files = _directory_files(directory)
        selected = _group_directory(files, args)
        selected_path = existing_path_key(root)
        groups = [group for group in selected if any(existing_path_key(path) == selected_path for path in group.volumes)]
    elif root.is_dir():
        for current_path, files, depth in _indexed_directories(root, excluded, high):
            if depth < low or (high is not None and depth > high):
                continue
            groups.extend(_group_directory(files, args))

    groups = [_normalize_single_group(group) for group in groups]
    return [group for group in groups if _group_allowed(group, args)]


def _valid_extension(filename: str) -> bool:
    if "." not in filename:
        return False
    extension = filename.rsplit(".", 1)[1]
    return bool(extension) and len(extension) < 6 and all(ord(ch) >= 128 or ch.isalnum() for ch in extension)


def _archive_type(path: Path) -> Optional[str]:
    try:
        with path.open("rb") as stream:
            header = stream.read(8)
    except OSError:
        return None
    if header.startswith(b"Rar!\x1a\x07\x00") or header.startswith(b"Rar!\x1a\x07\x01"):
        return "rar"
    if header[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "zip"
    if header[:6] == _SEVEN_Z_SIGNATURE:
        return "7z"
    return None


def _normalize_single_group(group: ArchiveGroup) -> ArchiveGroup:
    if group.multi or group.entry is None or group.kind not in ("7z", "rar", "zip"):
        return group
    archive_type = _archive_type(group.entry)
    if archive_type is None or archive_type == group.kind:
        return group
    return replace(group, kind=archive_type, format=archive_type)


def _size_limit(value) -> int:
    if value in (None, ""):
        value = "10mb"
    if isinstance(value, int):
        return max(value, 0)
    text = str(value).strip().lower()
    if text == "0":
        return 0
    match = re.fullmatch(r"(\d+)(kb?|mb?|gb?)", text)
    if not match:
        raise ValueError("invalid extension threshold")
    return int(match.group(1)) * {"k": 1024, "kb": 1024, "m": 1024**2, "mb": 1024**2, "g": 1024**3, "gb": 1024**3}[match.group(2)]


def parse_file_size(value) -> int:
    """Parse a CLI extension-threshold value for runtime validation."""
    if value in (None, ""):
        raise ValueError("size string cannot be empty")
    return _size_limit(value)


def _extension_sibling_conflict(name: str, siblings: Sequence[str]) -> bool:
    others = [value for value in siblings if value != name]
    if not _valid_extension(name):
        return any(value.startswith(name + ".") for value in others)
    basename = name.rsplit(".", 1)[0]
    if basename.endswith(".exe"):
        return True
    if "." in basename:
        first, last = basename.rsplit(".", 1)
        return any(
            value == first
            or value == first + "." + last
            or (value.startswith(first + ".") and len(value) > len(first) + 1)
            or (value.startswith(first + "." + last + ".") and len(value) > len(first + "." + last + "."))
            for value in others
        )
    return any(value == basename or value.startswith(basename + ".") for value in others)


def fix_extensions(args) -> List[Tuple[Path, Path]]:
    """Preview and optionally repair archive extensions, returning successful renames."""
    if not (_get(args, "fix_ext", False) or _get(args, "safe_fix_ext", False)):
        return []
    root, single_file = _input_root(args)
    low, high = _depth_range(_get(args, "depth_range"))
    minimum_size = _size_limit(_get(args, "fix_extension_threshold", "10mb"))
    excluded = _excluded_roots(args, root, single_file)
    candidates: List[Path] = []

    if single_file:
        siblings = tuple(_directory_files(root.parent))
        if not _extension_sibling_conflict(root.name, siblings):
            candidates = [root]
    elif root.is_dir():
        for current_path, files, depth in _indexed_directories(root, excluded, high):
            if depth < low or (high is not None and depth > high):
                continue
            siblings = tuple(files)
            candidates.extend(path for path in files.values() if not _extension_sibling_conflict(path.name, siblings))

    planned: List[Tuple[Path, Path]] = []
    targets = set()
    for path in candidates:
        try:
            if minimum_size and path.stat().st_size < minimum_size:
                continue
        except OSError:
            continue
        if path.suffix.casefold() == ".exe":
            continue
        archive_type = _archive_type(path)
        if archive_type is None:
            continue
        name = path.name
        if name.casefold().endswith("." + archive_type):
            continue
        if _get(args, "safe_fix_ext", False) or not _valid_extension(name):
            new_name = name + "." + archive_type
        else:
            new_name = name.rsplit(".", 1)[0] + "." + archive_type
        target = path.with_name(new_name)
        if target.exists() or target in targets:
            continue
        planned.append((path, target))
        targets.add(target)

    if not planned:
        return []
    print("EXTENSION FIX PREVIEW")
    for old, new in planned:
        print(f"  {old} -> {new}")
    if _get(args, "dry_run", False):
        return []
    try:
        response = input("Continue with extension fix? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return []
    if response not in {"y", "yes"}:
        return []

    renamed: List[Tuple[Path, Path]] = []
    for old, new in planned:
        try:
            old.rename(new)
            renamed.append((old, new))
        except OSError as exc:
            print(f"Warning: extension fix failed for {old}: {exc}")
    if single_file:
        for old, new in renamed:
            if old == root:
                setattr(args, "path", str(new))
                break
    return renamed


def _extra_has_unicode_path(extra: bytes) -> bool:
    offset = 0
    while offset + 4 <= len(extra or b""):
        field, size = int.from_bytes(extra[offset : offset + 2], "little"), int.from_bytes(extra[offset + 2 : offset + 4], "little")
        if field == 0x7075:
            return True
        offset += 4 + size
    return False


def _traditional_zip(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            return bool(infos) and all(not info.flag_bits & 0x800 and not _extra_has_unicode_path(info.extra) for info in infos)
    except (OSError, zipfile.BadZipFile):
        return False


def _confidence(value) -> float:
    result = float(value or 0.0)
    return result / 100.0 if result > 1.0 else result


def _minimum_confidence(value) -> float:
    return max(0.0, min(100.0, float(value or 0.0))) / 100.0


def _encoding_codepage(encoding: Optional[str]) -> Optional[str]:
    if not encoding:
        return None
    key = encoding.strip().lower().replace("_", "-")
    aliases = {
        "ascii": "1252",
        "utf-8": "UTF-8",
        "utf8": "UTF-8",
        "gb2312": "936",
        "gb18030": "936",
        "gbk": "936",
        "cp936": "936",
        "big5": "950",
        "big5-tw": "950",
        "cp950": "950",
        "shift-jis": "932",
        "shiftjis": "932",
        "cp932": "932",
        "windows-31j": "932",
        "euc-jp": "20932",
        "euc-kr": "949",
        "cp949": "949",
        "windows-1251": "1251",
        "cp1251": "1251",
        "windows-1252": "1252",
        "cp1252": "1252",
        "windows-1250": "1250",
        "cp1250": "1250",
        "windows-1253": "1253",
        "cp1253": "1253",
        "windows-1254": "1254",
        "cp1254": "1254",
        "windows-1255": "1255",
        "cp1255": "1255",
        "windows-1256": "1256",
        "cp1256": "1256",
        "windows-1257": "1257",
        "cp1257": "1257",
        "windows-1258": "1258",
        "cp1258": "1258",
        "iso-8859-1": "28591",
        "latin-1": "28591",
        "latin1": "28591",
        "iso-8859-2": "28592",
        "latin-2": "28592",
        "iso-8859-4": "28594",
        "iso-8859-5": "28595",
        "koi8-r": "20866",
        "cp437": "437",
        "cp850": "850",
        "cp852": "852",
        "cp855": "855",
        "cp866": "866",
        "iso-8859-6": "28596",
        "iso-8859-7": "28597",
        "iso-8859-8": "28598",
        "iso-8859-9": "28599",
    }
    if key in aliases:
        return aliases[key]
    try:
        canonical = codecs.lookup(encoding).name.lower().replace("_", "-")
    except LookupError:
        return None
    if canonical in aliases:
        return aliases[canonical]
    match = re.fullmatch(r"cp(\d+)", canonical)
    if match:
        return match.group(1)
    match = re.fullmatch(r"windows-(\d+)", canonical)
    if match:
        return match.group(1)
    match = re.fullmatch(r"iso-8859-(\d+)", canonical)
    if match:
        return str(28590 + int(match.group(1)))
    return None


def _zip_detect(path: Path, args) -> Tuple[Optional[str], str]:
    try:
        with zipfile.ZipFile(path) as archive:
            raw_names = []
            for info in archive.infolist():
                if info.flag_bits & 0x800:
                    continue
                raw = getattr(info, "orig_filename", info.filename)
                if isinstance(raw, str):
                    raw = raw.encode("cp437", "surrogateescape")
                raw_names.append(raw)
    except (OSError, zipfile.BadZipFile) as exc:
        return None, f"traditional ZIP inspection failed: {exc}"
    if not raw_names:
        return None, "traditional ZIP has no legacy encoded names"
    sample = b"\n".join(raw_names)
    model = str(_get(args, "traditional_zip_decode_model", "chardet") or "chardet").lower()
    try:
        if model == "charset_normalizer":
            from charset_normalizer import detect
        elif model == "chardet":
            from chardet import detect
        else:
            return None, f"unsupported ZIP detector: {model}"
        result = detect(sample) or {}
    except ImportError:
        return None, f"ZIP detector unavailable: {model}"
    except Exception as exc:
        return None, f"ZIP detector failed: {exc}"
    encoding = result.get("encoding")
    confidence = _confidence(result.get("confidence"))
    minimum = _minimum_confidence(_get(args, "traditional_zip_decode_confidence", 90))
    codepage = _encoding_codepage(encoding)
    if codepage is None:
        return None, f"ZIP detector returned unsupported encoding: {encoding}"
    if confidence < minimum:
        return None, f"ZIP detector confidence {confidence:.3f} is below minimum {minimum:.3f}"
    return codepage, f"automatic ZIP decode selected {encoding} at confidence {confidence:.3f}"


def inspect_zip_policy(group: ArchiveGroup, args) -> Tuple[str, Optional[object], str]:
    """Return ``(extract|skip|move, codepage, reason)`` for a ZIP group."""
    if group.kind != "zip" or group.entry is None or not _traditional_zip(group.entry):
        return "extract", None, "not_traditional_zip"
    policy = str(_get(args, "traditional_zip_policy", "decode-auto") or "decode-auto").lower()
    if policy == "asis":
        return "skip", None, "traditional_zip_asis"
    if policy == "move":
        if not _get(args, "traditional_zip_to"):
            return "skip", None, "traditional_zip_move_missing_destination"
        return "move", None, "traditional_zip_move"
    if policy.startswith("decode-") and policy != "decode-auto":
        value = policy[7:]
        if not value.isdigit() or int(value) < 0:
            return "skip", None, f"traditional_zip_decode_invalid: invalid policy {policy}"
        return "extract", int(value), "traditional_zip_decode_manual"
    if policy != "decode-auto":
        return "skip", None, f"traditional_zip_decode_invalid: invalid policy {policy}"
    codepage, reason = _zip_detect(group.entry, args)
    if codepage is None:
        return "skip", None, "traditional_zip_decode_auto: " + reason
    return "extract", codepage, "traditional_zip_decode_auto: " + reason


def _windows_short_path(path: Path) -> str:
    if os.name != "nt":
        return str(path.resolve())
    try:
        kernel = ctypes.windll.kernel32
        get_short = kernel.GetShortPathNameW
        get_short.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
        get_short.restype = ctypes.c_uint32
        source = str(path.resolve())
        size = get_short(source, None, 0)
        if not size:
            return source
        buffer = ctypes.create_unicode_buffer(size + 1)
        return buffer.value if get_short(source, buffer, size + 1) else source
    except Exception:
        return str(path.resolve())


def _command_result(command: Sequence[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"required extractor is unavailable: {command[0]}") from exc
    except OSError as exc:
        raise RuntimeError(f"extractor could not start: {command[0]}: {exc}") from exc


def _seven_zip() -> str:
    command = shutil.which("7z") or shutil.which("7zz")
    if not command:
        raise RuntimeError("required extractor is unavailable: 7z")
    return command


def _password_value(password: str) -> str:
    return str(password) if password is not None else ""


def _output_text(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value or "")


def _probe_encryption(path: Path) -> str:
    result = _command_result([_seven_zip(), "l", "-slt", "-y", "-pDUMMYPASSWORD", _windows_short_path(path)])
    output = _output_text(result.stdout) + _output_text(result.stderr)
    if result.returncode == 0:
        return "encrypted_content" if re.search(r"Encrypted\s*=\s*\+", output, re.IGNORECASE) else "plain"
    if result.returncode in (7, 8, 255):
        raise RuntimeError(f"archive verification command failed for {path}: exit {result.returncode}")
    lower = output.lower()
    if any(text in lower for text in ("encrypted", "wrong password", "password", "headers error")):
        return "encrypted_header"
    raise RuntimeError(f"archive verification failed for {path}: exit {result.returncode}")


def _test_password(path: Path, password: str, status: str) -> bool:
    operation = "l" if status == "encrypted_header" else "t"
    command = [_seven_zip(), operation]
    if operation == "l":
        command.append("-slt")
    command.extend(["-y", _windows_short_path(path), f"-p{_password_value(password)}"])
    result = _command_result(command)
    if result.returncode in (7, 8, 255):
        raise RuntimeError(f"archive password test command failed for {path}: exit {result.returncode}")
    return result.returncode == 0


def _candidate_values(passwords) -> List[str]:
    if isinstance(passwords, PasswordCandidates):
        return list(passwords.candidates)
    if passwords is None:
        return []
    return [str(value) for value in passwords]


def _record_password(passwords, value: str) -> None:
    if isinstance(passwords, PasswordCandidates):
        passwords.record_success(value)


def _extract_7z(path: Path, destination: Path, password: Optional[str], zip_codepage=None) -> None:
    command = [_seven_zip(), "x", _windows_short_path(path), "-o" + _windows_short_path(destination), "-y"]
    command.append(f"-p{_password_value(password)}" if password is not None else "-pDUMMYPASSWORD")
    if zip_codepage is not None:
        command.append("-tzip")
        if zip_codepage not in ("", "UTF-8", "utf-8", 65001, "65001"):
            command.append(f"-mcp={zip_codepage}")
    result = _command_result(command)
    if result.returncode != 0:
        detail = (_output_text(result.stderr) or _output_text(result.stdout)).strip()
        raise RuntimeError(f"archive extraction failed for {path}: exit {result.returncode}: {detail[:300]}")


def _extract_rar(path: Path, destination: Path, password: Optional[str]) -> None:
    rar = shutil.which("rar")
    if not rar:
        _extract_7z(path, destination, password)
        return
    command = [rar, "x", _windows_short_path(path), _windows_short_path(destination), "-y"]
    command.append(f"-p{_password_value(password)}" if password is not None else "-pDUMMYPASSWORD")
    result = _command_result(command)
    if result.returncode != 0:
        detail = (_output_text(result.stderr) or _output_text(result.stdout)).strip()
        raise RuntimeError(f"RAR extraction failed for {path}: exit {result.returncode}: {detail[:300]}")


def _looks_like_tar(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            header = stream.read(512)
        if len(header) >= 512 and header[257:263] in (b"ustar\x00", b"ustar "):
            return True
        return tarfile.is_tarfile(str(path))
    except (OSError, tarfile.TarError):
        return False


def _extract_tar(path: Path, destination: Path, password: Optional[str], zip_codepage=None) -> None:
    if path.name.casefold().endswith(".tar"):
        _extract_7z(path, destination, password)
        return
    stage = Path(tempfile.mkdtemp(prefix="advdecompress-tar-", dir=str(destination.parent)))
    try:
        _extract_7z(path, stage, password)
        entries = list(stage.rglob("*"))
        candidates = [item for item in entries if item.is_file() and _looks_like_tar(item)]
        if len(entries) != 1 or len(candidates) != 1:
            raise RuntimeError(f"compressed TAR outer stage did not produce one TAR payload: {path}")
        _extract_7z(candidates[0], destination, password)
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def _ensure_nonempty(root: Path) -> None:
    try:
        next(root.iterdir())
    except StopIteration as exc:
        raise RuntimeError("extractor reported success but produced an empty tree") from exc
    except OSError as exc:
        raise RuntimeError(f"cannot inspect extracted tree: {root}: {exc}") from exc


def extract_archive(
    group: ArchiveGroup,
    destination,
    args,
    passwords,
    zip_codepage=None,
) -> None:
    """Extract a complete archive group into ``destination`` or raise."""
    if group.error:
        raise RuntimeError(group.error)
    if group.entry is None:
        raise RuntimeError("archive group has no primary entry")
    destination = _absolute(destination)
    destination.mkdir(parents=True, exist_ok=True)
    password_values = _candidate_values(passwords)
    explicit = _get(args, "password", None)
    password = str(explicit) if explicit is not None else None

    if group.kind != "tar" and password_values and _get(args, "password_file"):
        status = _probe_encryption(group.entry)
        if status != "plain":
            password = None
            for candidate in password_values:
                if _test_password(group.entry, candidate, status):
                    password = candidate
                    _record_password(passwords, candidate)
                    break
            else:
                raise RuntimeError(f"no supplied password opens {group.entry}")

    if group.kind == "tar":
        _extract_tar(group.entry, destination, password, zip_codepage)
    elif bool(_get(args, "enable_rar", False)) and (
        group.kind == "rar" or group.format in ("sfx-rar", "elf-sfx-rar")
    ):
        _extract_rar(group.entry, destination, password)
    else:
        _extract_7z(group.entry, destination, password, zip_codepage if group.kind == "zip" else None)
    _ensure_nonempty(destination)
