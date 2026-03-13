#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import importlib
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote


@dataclass(frozen=True)
class TorrentMetadata:
    dn: str
    has_v1: bool
    has_v2: bool
    btih: str | None
    btmh: str | None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Extract magnet links from torrent files")
    parser.add_argument("input_dir", help="Directory to scan recursively for .torrent files")
    parser.add_argument(
        "-o",
        "--out",
        help="Output file path (flat mode) or output root directory (--keep-dirs)",
    )
    parser.add_argument("--keep-dirs", action="store_true", help="Write one files.magnet.txt per directory")
    return parser


@lru_cache(maxsize=1)
def _load_native_parser():
    try:
        return importlib.import_module("magnet_extractor_native")
    except Exception:
        return None


def _extract_torrent_metadata_from_bytes_py(payload: bytes) -> TorrentMetadata:
    info_bytes = _extract_info_slice(payload)
    info = _bdecode(info_bytes)
    if not isinstance(info, dict):
        raise ValueError("torrent info must be a dictionary")

    dn = _decode_text(info.get(b"name.utf-8") or info.get(b"name"))
    if not dn:
        raise ValueError("torrent missing display name")

    has_v1 = b"pieces" in info
    has_v2 = info.get(b"meta version") == 2 and b"file tree" in info
    if not has_v1 and not has_v2:
        raise ValueError("torrent has neither v1 nor v2 metadata")

    btih = hashlib.sha1(info_bytes).hexdigest() if has_v1 else None
    btmh = f"1220{hashlib.sha256(info_bytes).hexdigest()}" if has_v2 else None
    return TorrentMetadata(dn=dn, has_v1=has_v1, has_v2=has_v2, btih=btih, btmh=btmh)


def _extract_torrent_metadata_from_bytes_native(payload: bytes, native_parser=None) -> TorrentMetadata:
    parser = native_parser if native_parser is not None else _load_native_parser()
    if parser is None:
        raise RuntimeError("native parser is unavailable")

    dn, has_v1, has_v2, btih, btmh = parser.extract_torrent_metadata(payload)
    return TorrentMetadata(dn=dn, has_v1=has_v1, has_v2=has_v2, btih=btih, btmh=btmh)


def extract_torrent_metadata_from_bytes(payload: bytes) -> TorrentMetadata:
    native_parser = _load_native_parser()
    if native_parser is None:
        return _extract_torrent_metadata_from_bytes_py(payload)
    try:
        return _extract_torrent_metadata_from_bytes_native(payload, native_parser)
    except Exception:
        # Native parse failures must not break pure-Python mode; retry with the reference parser.
        return _extract_torrent_metadata_from_bytes_py(payload)


def build_magnet(meta: TorrentMetadata) -> str:
    parts: list[str] = []
    if meta.btih is not None:
        parts.append(f"xt=urn:btih:{meta.btih}")
    if meta.btmh is not None:
        parts.append(f"xt=urn:btmh:{meta.btmh}")
    parts.append(f"dn={quote(meta.dn, safe='')}")
    return "magnet:?" + "&".join(parts)


def extract_torrent_metadata(torrent_path: Path) -> TorrentMetadata:
    return extract_torrent_metadata_from_bytes(torrent_path.read_bytes())


def iter_torrent_files(input_dir: Path):
    for root, dir_names, file_names in os.walk(input_dir):
        dir_names.sort(key=lambda name: (name.casefold(), name))
        for file_name in sorted(file_names, key=lambda name: (name.casefold(), name)):
            if file_name.lower().endswith(".torrent"):
                yield Path(root) / file_name


def write_outputs(input_dir: Path, out_path: Path | None, keep_dirs: bool) -> int:
    targets: dict[Path, list[str]] = {}
    base_dir = out_path if out_path is not None else input_dir
    flat_file = out_path if out_path is not None else input_dir / "files.magnet.txt"

    for torrent_path in iter_torrent_files(input_dir):
        magnet = build_magnet(extract_torrent_metadata(torrent_path))
        if keep_dirs:
            relative_parent = torrent_path.parent.relative_to(input_dir)
            target = base_dir / relative_parent / "files.magnet.txt"
        else:
            target = flat_file
        targets.setdefault(target, []).append(magnet)

    for target, lines in sorted(targets.items(), key=lambda item: item[0].as_posix()):
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return 0


def find_non_directory_ancestor(path: Path) -> tuple[Path, str] | None:
    current = path
    while True:
        if current.exists():
            return None if current.is_dir() else (current, "file")
        if current.is_symlink():
            return current, "broken symlink"
        parent = current.parent
        if parent == current:
            return None
        current = parent


def validate_out_path_contract(
    parser: argparse.ArgumentParser, out_path: Path | None, keep_dirs: bool
) -> None:
    if out_path is None:
        return
    if keep_dirs and out_path.is_file():
        parser.error(f"--keep-dirs output path must be a directory, not a file: {out_path}")
    if not keep_dirs and out_path.is_dir():
        parser.error(f"flat mode output path must be a file, not a directory: {out_path}")

    ancestor_to_check = out_path if keep_dirs else out_path.parent
    invalid_ancestor = find_non_directory_ancestor(ancestor_to_check)
    if invalid_ancestor is None:
        return
    ancestor_path, ancestor_kind = invalid_ancestor
    if keep_dirs:
        parser.error(
            f"--keep-dirs output path must be under directories, not under a {ancestor_kind}: {ancestor_path}"
        )
    parser.error(f"flat mode output path must be under directories, not under a {ancestor_kind}: {ancestor_path}")


def _extract_info_slice(payload: bytes) -> bytes:
    if payload[:1] != b"d":
        raise ValueError("torrent payload must be a dictionary")

    (_, info_slice), end = _parse_dict(payload, 0, capture_info=True)
    if end != len(payload):
        raise ValueError("trailing bytes after torrent payload")
    if info_slice is None:
        raise ValueError("torrent missing info dictionary")
    return info_slice


def _bdecode(payload: bytes) -> object:
    value, end = _parse_any(payload, 0)
    if end != len(payload):
        raise ValueError("trailing bytes after bencoded value")
    return value


def _parse_any(payload: bytes, index: int, capture_info: bool = False):
    if index >= len(payload):
        raise ValueError("unexpected end of bencoded data")

    token = payload[index : index + 1]
    if token == b"i":
        return _parse_int(payload, index)
    if token == b"l":
        return _parse_list(payload, index)
    if token == b"d":
        return _parse_dict(payload, index, capture_info)
    if token.isdigit():
        return _parse_bytes(payload, index)
    raise ValueError("invalid bencode token")


def _parse_int(payload: bytes, index: int) -> tuple[int, int]:
    end = payload.find(b"e", index + 1)
    if end == -1:
        raise ValueError("unterminated integer")

    token = payload[index + 1 : end]
    if not token:
        raise ValueError("empty integer")
    negative = token[:1] == b"-"
    digits = token[1:] if negative else token
    if not digits or not digits.isdigit():
        raise ValueError("invalid integer digits")
    if digits.startswith(b"0") and len(digits) > 1:
        raise ValueError("invalid integer leading zero")
    if negative and digits == b"0":
        raise ValueError("invalid negative zero")

    return int(token), end + 1


def _parse_bytes(payload: bytes, index: int) -> tuple[bytes, int]:
    colon = payload.find(b":", index)
    if colon == -1:
        raise ValueError("unterminated byte string length")

    length_token = payload[index:colon]
    if not length_token or not length_token.isdigit():
        raise ValueError("invalid byte string length")
    if length_token.startswith(b"0") and len(length_token) > 1:
        raise ValueError("invalid byte string leading zero")

    length = int(length_token)
    start = colon + 1
    end = start + length
    if end > len(payload):
        raise ValueError("byte string overruns payload")
    return payload[start:end], end


def _parse_list(payload: bytes, index: int) -> tuple[list[object], int]:
    items: list[object] = []
    index += 1
    while True:
        if index >= len(payload):
            raise ValueError("unterminated list")
        if payload[index : index + 1] == b"e":
            return items, index + 1
        item, index = _parse_any(payload, index)
        items.append(item)


def _parse_dict(payload: bytes, index: int, capture_info: bool = False):
    items: dict[bytes, object] = {}
    info_slice: bytes | None = None
    previous_key: bytes | None = None
    index += 1

    while True:
        if index >= len(payload):
            raise ValueError("unterminated dictionary")
        if payload[index : index + 1] == b"e":
            if capture_info:
                return (items, info_slice), index + 1
            return items, index + 1

        key, index = _parse_bytes(payload, index)
        if previous_key is not None and key <= previous_key:
            raise ValueError("dictionary keys must be strictly sorted")
        previous_key = key

        value_start = index
        value, index = _parse_any(payload, index)
        items[key] = value

        if capture_info and key == b"info":
            if not isinstance(value, dict):
                raise ValueError("torrent info must be a dictionary")
            info_slice = payload[value_start:index]


def _decode_text(value: object) -> str:
    if not isinstance(value, bytes):
        raise ValueError("torrent name must be a byte string")
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("torrent name must be valid UTF-8") from None


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    input_dir = Path(args.input_dir)
    if not input_dir.is_dir():
        parser.error(f"input directory does not exist: {input_dir}")
    out_path = Path(args.out) if args.out else None
    validate_out_path_contract(parser, out_path, args.keep_dirs)
    return write_outputs(input_dir, out_path, args.keep_dirs)


if __name__ == "__main__":
    raise SystemExit(main())
