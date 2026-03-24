import os

from . import fs


def should_skip_file(file_path, skip_extensions):
    if not skip_extensions:
        return False

    _, ext = os.path.splitext(file_path)
    ext = ext[1:].lower() if ext.startswith(".") else ext.lower()
    normalized_extensions = {
        extension.lower().lstrip(".") for extension in skip_extensions
    }
    return ext in normalized_extensions


def folder_contains_skip_extensions(folder_path, skip_extensions, debug=False):
    if not skip_extensions:
        return False

    try:
        for root, _, files in fs.safe_walk(folder_path, debug=debug):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                if should_skip_file(file_path, skip_extensions):
                    return True
        return False
    except Exception:
        return True


def get_items_at_depth(
    base_folder,
    target_depth,
    *,
    skip_files=False,
    skip_folders=False,
    skip_extensions=None,
    ext_skip_folder_tree=False,
    debug=False,
):
    skip_extensions = list(skip_extensions or [])
    base_folder = fs.safe_abspath(base_folder)
    items = {"files": [], "folders": []}

    if target_depth == 0:
        if not skip_folders:
            folder_path = fs.safe_abspath(base_folder)
            if not fs.is_folder_empty(folder_path):
                if ext_skip_folder_tree and skip_extensions:
                    if folder_contains_skip_extensions(
                        folder_path, skip_extensions, debug=debug
                    ):
                        return items
                items["folders"].append(folder_path)
        return items

    for root, dirs, files in fs.safe_walk(base_folder, debug=debug):
        rel_path = os.path.relpath(root, base_folder)
        current_depth = 0 if rel_path == "." else len(rel_path.split(os.sep))

        if current_depth != target_depth - 1:
            continue

        if not skip_files:
            for file_name in files:
                abs_path = fs.safe_abspath(os.path.join(root, file_name))
                if should_skip_file(abs_path, skip_extensions):
                    continue
                items["files"].append(abs_path)

        if not skip_folders:
            for dir_name in dirs:
                abs_path = fs.safe_abspath(os.path.join(root, dir_name))
                if fs.is_folder_empty(abs_path):
                    continue
                if ext_skip_folder_tree and skip_extensions:
                    if folder_contains_skip_extensions(
                        abs_path, skip_extensions, debug=debug
                    ):
                        continue
                items["folders"].append(abs_path)

    return items
