import os
import platform
import shutil
import threading
import time
import uuid
from dataclasses import dataclass


@dataclass(frozen=True)
class InputPathInfo:
    path: str
    is_file: bool
    is_dir: bool


def get_short_path_name(long_path):
    if platform.system() != "Windows":
        return long_path

    try:
        import ctypes
        from ctypes import wintypes

        windll = getattr(ctypes, "windll", None)
        if windll is None:
            return long_path

        get_short_path = windll.kernel32.GetShortPathNameW
        get_short_path.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPWSTR,
            wintypes.DWORD,
        ]
        get_short_path.restype = wintypes.DWORD

        buffer_size = get_short_path(long_path, None, 0)
        if buffer_size == 0:
            return long_path

        buffer = ctypes.create_unicode_buffer(buffer_size)
        result = get_short_path(long_path, buffer, buffer_size)
        if result == 0:
            return long_path

        return buffer.value
    except Exception:
        return long_path


def safe_path_for_operation(path, debug=False):
    del debug
    if not path:
        return path

    if platform.system() == "Windows":
        short_path = get_short_path_name(path)
        if short_path:
            return short_path

    return path


def safe_abspath(path, debug=False):
    del debug
    try:
        return os.path.abspath(path)
    except Exception:
        return path


def safe_exists(path, debug=False):
    del debug
    try:
        return os.path.exists(safe_path_for_operation(path))
    except Exception:
        return False


def safe_isdir(path, debug=False):
    del debug
    try:
        return os.path.isdir(safe_path_for_operation(path))
    except Exception:
        return False


def safe_isfile(path, debug=False):
    del debug
    try:
        return os.path.isfile(safe_path_for_operation(path))
    except Exception:
        return False


def safe_makedirs(path, exist_ok=True, debug=False):
    del debug
    try:
        os.makedirs(safe_path_for_operation(path), exist_ok=exist_ok)
        return True
    except Exception:
        return False


def safe_remove(path, debug=False):
    del debug
    try:
        os.remove(safe_path_for_operation(path))
        return True
    except Exception:
        return False


def safe_rmdir(path, debug=False):
    del debug
    try:
        os.rmdir(safe_path_for_operation(path))
        return True
    except Exception:
        return False


def safe_rmtree(path, debug=False):
    del debug
    try:
        shutil.rmtree(safe_path_for_operation(path))
        return True
    except Exception:
        return False


def safe_move(src, dst, debug=False):
    del debug
    try:
        safe_src = safe_path_for_operation(src)
        safe_dst = safe_path_for_operation(dst)

        if safe_exists(dst):
            if safe_isfile(dst):
                safe_remove(dst)
            else:
                safe_rmtree(dst)

        shutil.move(safe_src, safe_dst)
        return True
    except Exception:
        return False


def safe_walk(top, debug=False):
    del debug
    try:
        safe_top = safe_path_for_operation(top)
        for root, dirs, files in os.walk(safe_top):
            if safe_top != top:
                rel_root = os.path.relpath(root, safe_top)
                if rel_root == ".":
                    converted_root = top
                else:
                    converted_root = os.path.join(top, rel_root)
            else:
                converted_root = root

            yield converted_root, dirs, files
    except Exception:
        return


def validate_input_path(path, debug=False):
    normalized_path = safe_abspath(path, debug=debug)
    if not safe_exists(normalized_path, debug=debug):
        raise ValueError(f"input path does not exist: {path}")

    is_file = safe_isfile(normalized_path, debug=debug)
    is_dir = safe_isdir(normalized_path, debug=debug)
    if not (is_file or is_dir):
        raise ValueError(f"input path is neither a file nor a directory: {path}")

    return InputPathInfo(path=normalized_path, is_file=is_file, is_dir=is_dir)


def get_relative_path(item_path, base_path):
    item_abs = safe_abspath(item_path)
    base_abs = safe_abspath(base_path)
    rel_path = os.path.relpath(item_abs, base_abs)
    if rel_path == ".":
        return os.path.basename(base_abs)
    return rel_path


def compute_final_output_dir(item_path, base_path, out_dir):
    item_abs = safe_abspath(item_path)
    if not out_dir:
        return os.path.dirname(item_abs)

    output_dir = safe_abspath(out_dir)
    rel_path = get_relative_path(item_abs, base_path)
    rel_dir = os.path.dirname(rel_path)
    if rel_dir and rel_dir != ".":
        return safe_abspath(os.path.join(output_dir, rel_dir))
    return output_dir


def create_unique_tmp_dir(base_dir, debug=False):
    del debug
    try:
        timestamp = str(int(time.time() * 1000))
        thread_id = threading.get_ident()
        unique_id = uuid.uuid4().hex[:8]
        tmp_dir_name = f"tmp_{timestamp}_{thread_id}_{unique_id}"
        tmp_dir_path = safe_abspath(os.path.join(base_dir, tmp_dir_name))
        if safe_makedirs(tmp_dir_path, exist_ok=False):
            return tmp_dir_path
    except Exception:
        return None

    return None


def cleanup_tmp_dir(tmp_dir_path, debug=False):
    del debug
    if not safe_exists(tmp_dir_path):
        return True
    return safe_rmtree(tmp_dir_path)


def move_files_to_final_destination(
    source_files, final_output_dir, rel_path=None, debug=False
):
    """Move artifact files into an already-resolved final output directory.

    `final_output_dir` is the sole source of output nesting. `rel_path` is kept only
    for interface compatibility with callers that still pass it during Task 2/3
    transition work.
    """
    del debug, rel_path
    moved_files = []
    try:
        missing_sources = [
            source_file for source_file in source_files if not safe_exists(source_file)
        ]
        if missing_sources:
            return False, []

        final_target_dir = safe_abspath(final_output_dir)
        if not safe_makedirs(final_target_dir, exist_ok=True):
            return False, []

        for source_file in source_files:
            filename = os.path.basename(source_file)
            target_file = safe_abspath(os.path.join(final_target_dir, filename))
            if not safe_move(source_file, target_file):
                return False, moved_files
            moved_files.append(target_file)

        return True, moved_files
    except Exception:
        return False, moved_files


def is_folder_empty(folder_path):
    try:
        for root, dirs, files in safe_walk(folder_path):
            if files:
                return False
            for dir_name in dirs:
                sub_path = os.path.join(root, dir_name)
                if not is_folder_empty(sub_path):
                    return False
        return True
    except Exception:
        return False


def safe_delete_file(file_path, dry_run=False):
    if dry_run:
        return True
    return safe_remove(file_path)


def safe_delete_folder(folder_path, dry_run=False):
    if dry_run:
        return True

    try:
        if is_folder_empty(folder_path):
            return safe_rmdir(folder_path)
        return False
    except Exception:
        return False
