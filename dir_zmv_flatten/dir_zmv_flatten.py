import argparse
import errno
import os
import shutil
import sys
from typing import Optional


def _safe_is_dir(path: str) -> bool:
    return os.path.isdir(path) and (not os.path.islink(path))


def _iter_immediate_subdirs(root_path: str) -> list[str]:
    names = sorted(os.listdir(root_path))
    result: list[str] = []
    for name in names:
        path = os.path.join(root_path, name)
        if _safe_is_dir(path):
            result.append(path)
    return result


def _resolve_conflict(dst_path: str) -> str:
    if not os.path.exists(dst_path):
        return dst_path
    base = os.path.basename(dst_path)
    root = os.path.dirname(dst_path)
    stem, ext = os.path.splitext(base)
    idx = 1
    while True:
        if ext:
            candidate = f"{stem} ({idx}){ext}"
        else:
            candidate = f"{stem} ({idx})"
        candidate_path = os.path.join(root, candidate)
        if not os.path.exists(candidate_path):
            return candidate_path
        idx += 1


def _move(src: str, dst: str) -> None:
    try:
        shutil.move(src, dst)
    except OSError as e:
        if e.errno == errno.EXDEV:
            if os.path.isdir(src):
                shutil.copytree(src, dst)
                shutil.rmtree(src)
            else:
                shutil.copy2(src, dst)
                os.unlink(src)
        else:
            raise


def _ensure_dir(path: str, dry_run: bool) -> None:
    if os.path.isdir(path):
        return
    if not dry_run:
        os.makedirs(path, exist_ok=True)


def _delete_if_empty(path: str, dry_run: bool) -> None:
    if not os.path.isdir(path):
        return
    if os.listdir(path):
        return
    if not dry_run:
        os.rmdir(path)


def flatten_root(
    root_path: str,
    out_dir: Optional[str] = None,
    delete_empty_src_dirs: bool = False,
    dry_run: bool = False,
) -> None:
    root_path = os.path.abspath(root_path)
    out_dir = os.path.abspath(out_dir or root_path)
    _ensure_dir(out_dir, dry_run)

    for subdir in _iter_immediate_subdirs(root_path):
        for name in sorted(os.listdir(subdir)):
            src = os.path.join(subdir, name)
            dst = _resolve_conflict(os.path.join(out_dir, name))
            if not dry_run:
                _move(src, dst)
        if delete_empty_src_dirs:
            _delete_if_empty(subdir, dry_run)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Flatten one level of subdirs")
    parser.add_argument("root_path", help="Root directory to process")
    parser.add_argument("--delete-empty-src-dirs", "-d", action="store_true")
    parser.add_argument("--dry-run", "-n", action="store_true")
    parser.add_argument("--out", "-o", default=None)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(args=argv)
    if not os.path.isdir(args.root_path):
        print("Error: invalid directory", file=sys.stderr)
        return 1
    flatten_root(
        args.root_path,
        out_dir=args.out,
        delete_empty_src_dirs=args.delete_empty_src_dirs,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
