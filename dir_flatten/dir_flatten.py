import os
import shutil
import argparse
import uuid
import time
import errno
import sys
from typing import List, Dict, Any


# ----------------- Util helpers -----------------

def safe_isdir(path: str, debug: bool = False) -> bool:
    """Safely determine whether *path* is a real directory (skip symlinks)."""
    try:
        return os.path.isdir(path) and (not os.path.islink(path))
    except Exception as e:
        if debug:
            print(f"  DEBUG: safe_isdir failed for {path}: {e}")
        return False


def safe_walk(root: str, debug: bool = False):
    """Yield from os.walk while skipping symlink dirs and swallowing errors."""
    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        dirnames[:] = [d for d in dirnames if safe_isdir(os.path.join(dirpath, d), debug)]
        yield dirpath, dirnames, filenames


# ----------------- Core algorithm -----------------

def find_file_content(tmp_dir: str, debug: bool = False) -> Dict[str, Any]:
    """Locate the *file_content* inside *tmp_dir* as defined in the spec."""
    result = {
        'found': False,
        'path': tmp_dir,
        'depth': 0,
        'items': [],
        'parent_folder_path': tmp_dir,
        'parent_folder_name': ''
    }

    if debug:
        print(f"  DEBUG: 开始查找 file_content: {tmp_dir}")

    def get_items_at_depth(path: str, current_depth: int = 1):
        items: List[Dict[str, Any]] = []
        try:
            if current_depth == 1:
                for item in os.listdir(path):
                    item_path = os.path.join(path, item)
                    items.append({
                        'name': item,
                        'path': item_path,
                        'is_dir': safe_isdir(item_path, debug)
                    })
            else:
                for root, dirs, files in safe_walk(path, debug):
                    rel = os.path.relpath(root, path)
                    depth = len([p for p in rel.split(os.sep) if p and p != '.'])
                    if depth == current_depth - 1:
                        for d in dirs:
                            items.append({'name': d, 'path': os.path.join(root, d), 'is_dir': True})
                        for f in files:
                            items.append({'name': f, 'path': os.path.join(root, f), 'is_dir': False})
        except Exception as e:
            if debug:
                print(f"  DEBUG: 获取深度{current_depth}项目失败: {e}")
        return items

    # Search depth by depth
    for depth in range(1, 11):
        items = get_items_at_depth(tmp_dir, depth)
        if debug:
            print(f"  DEBUG: 深度{depth}: {len(items)} items")
        if len(items) >= 2:
            result.update({
                'found': True,
                'depth': depth,
                'items': items
            })
            # locate parent folder path
            if depth == 1:
                result.update({
                    'parent_folder_path': tmp_dir,
                    'parent_folder_name': os.path.basename(tmp_dir)
                })
            else:
                for root, _, _ in safe_walk(tmp_dir, debug):
                    rel = os.path.relpath(root, tmp_dir)
                    d = 0 if rel == '.' else len(rel.split(os.sep))
                    if d == depth - 1:
                        result.update({
                            'parent_folder_path': root,
                            'parent_folder_name': os.path.basename(root)
                        })
                        break
            break
        if not items:
            break

    # Fallback to deepest single item if still not found
    if not result['found']:
        deepest_items: List[Dict[str, Any]] = []
        max_depth = 0
        deepest_parent = tmp_dir
        for root, dirs, files in safe_walk(tmp_dir, debug):
            rel = os.path.relpath(root, tmp_dir)
            depth = 0 if rel == '.' else len(rel.split(os.sep))
            if depth > max_depth:
                max_depth = depth
                deepest_parent = root
                deepest_items = []
            if depth == max_depth:
                deepest_items.extend([
                    {'name': f, 'path': os.path.join(root, f), 'is_dir': False} for f in files
                ])
        if deepest_items:
            result.update({
                'found': True,
                'depth': max_depth + 1,
                'items': deepest_items,
                'parent_folder_path': deepest_parent,
                'parent_folder_name': os.path.basename(deepest_parent)
            })
    return result


def cleanup_empty_dirs(root: str, keep_root: bool = True, debug: bool = False):
    for dirpath, dirnames, filenames in os.walk(root, topdown=False):
        if os.path.islink(dirpath):
            continue

        try:
            # Use fresh listdir to avoid stale dirnames after earlier deletions
            is_empty = len(os.listdir(dirpath)) == 0
        except FileNotFoundError:
            # Directory already gone
            continue
        except Exception as e:
            if debug:
                print(f"  DEBUG: 检查 {dirpath} 失败: {e}")
            continue

        if is_empty:
            if keep_root and os.path.abspath(dirpath) == os.path.abspath(root):
                continue
            try:
                os.rmdir(dirpath)
                if debug:
                    print(f"  DEBUG: 删除空目录 {dirpath}")
            except Exception as e:
                if debug:
                    print(f"  DEBUG: 删除 {dirpath} 失败: {e}")


# ----------------- Main flatten logic -----------------

def _all_entries_under(paths: List[str]) -> List[str]:
    all_set: List[str] = []
    for p in paths:
        if os.path.isdir(p):
            for r, ds, fs in os.walk(p):
                for d in ds:
                    all_set.append(os.path.join(r, d))
                for f in fs:
                    all_set.append(os.path.join(r, f))
            all_set.append(p)
        else:
            all_set.append(p)
    return all_set


def _move(src: str, dst: str):
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


def flatten_subfolder(subfolder: str, *, verbose: bool = False, dry_run: bool = False):
    if verbose:
        print(f"[INFO] 处理子目录: {subfolder}")

    info = find_file_content(subfolder, debug=verbose)
    if not info['found'] or info['depth'] <= 1:
        if verbose:
            print("[INFO] 跳过, depth<=1 或未检测到 file_content\n")
        return

    parent = info['parent_folder_path']
    items = info['items']
    # Conflict detection
    moving_roots = [i['path'] for i in items]
    conflict = False
    for p in _all_entries_under(moving_roots):
        rel = os.path.relpath(p, parent)
        dest = os.path.join(subfolder, rel)
        if os.path.exists(dest):
            conflict = True
            if verbose:
                print(f"[WARN] 冲突: {dest} 已存在")
    if conflict:
        if verbose:
            print("[WARN] 本子目录存在冲突, 放弃处理\n")
        return

    tmp_dir = os.path.join(os.getcwd(), f"tmp_{int(time.time())}_{uuid.uuid4().hex[:8]}")
    if verbose:
        print(f"[INFO] 创建临时目录 {tmp_dir}")
    if not dry_run:
        os.makedirs(tmp_dir, exist_ok=True)

    for item in items:
        dst = os.path.join(tmp_dir, item['name'])
        if verbose:
            print(f"[MOVE] {item['path']} -> {dst}")
        if not dry_run:
            _move(item['path'], dst)

    if verbose:
        print(f"[INFO] 清理空目录 {subfolder}")
    if not dry_run:
        cleanup_empty_dirs(subfolder, keep_root=True, debug=verbose)

    for name in os.listdir(tmp_dir):
        src = os.path.join(tmp_dir, name)
        dst = os.path.join(subfolder, name)
        if verbose:
            print(f"[MOVE] {src} -> {dst}")
        if not dry_run:
            _move(src, dst)
    if verbose:
        print(f"[INFO] 删除临时目录 {tmp_dir}\n")
    if not dry_run:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ----------------- Driver code -----------------

def collect_subfolders(root: str, scan_depth: int, debug: bool = False) -> List[str]:
    result: List[str] = []
    root = os.path.abspath(root)
    for dirpath, dirnames, _ in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        depth = 0 if rel == '.' else len(rel.split(os.sep))
        # 当当前目录相对于 root 的深度等于 scan_depth 时，直接把当前目录加入结果
        if depth == scan_depth:
            if safe_isdir(dirpath, debug):
                result.append(dirpath)
            # 不再深入该目录的子目录，避免收集更深层
            dirnames.clear()
        # 若已超过指定深度，则无需继续向下遍历
        elif depth > scan_depth:
            dirnames.clear()  # prune deeper traversal for efficiency
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="目录扁平化工具")
    parser.add_argument('root_path', help='根目录路径')
    parser.add_argument('--scan-depth', type=int, required=True, help='从 root=0 开始的相对深度 (直接子目录=1, 依此类推)')
    parser.add_argument('--verbose', action='store_true', help='输出详细信息')
    parser.add_argument('--dry-run', action='store_true', help='仅模拟执行, 不做改动')
    args = parser.parse_args(args=argv)

    if not os.path.isdir(args.root_path):
        print("错误: 无效目录", file=sys.stderr)
        sys.exit(1)

    root = os.path.abspath(args.root_path)
    if args.verbose:
        print(f"[INFO] root: {root}, scan_depth: {args.scan_depth}\n")

    subs = collect_subfolders(root, args.scan_depth, debug=args.verbose)
    if args.verbose:
        print(f"[INFO] 共 {len(subs)} 个 subfolder:")
        for s in subs:
            print(f"  - {s}")
        print()

    for sub in subs:
        try:
            flatten_subfolder(sub, verbose=args.verbose, dry_run=args.dry_run)
        except Exception as e:
            print(f"[ERROR] 处理 {sub} 失败: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()


if __name__ == '__main__':
    main() 