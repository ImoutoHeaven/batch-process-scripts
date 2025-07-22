import os
import shutil
import argparse
import uuid
import time
import errno
import sys
import logging
from datetime import datetime
from typing import List, Dict, Any


# ----------------- Logging setup -----------------

def setup_logging(verbose: bool = False, debug: bool = False):
    """Setup logging configuration with formatted output."""
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    
    # Create custom formatter with colors for different levels
    class ColoredFormatter(logging.Formatter):
        COLORS = {
            'DEBUG': '\033[36m',    # Cyan
            'INFO': '\033[32m',     # Green
            'WARNING': '\033[33m',  # Yellow
            'ERROR': '\033[31m',    # Red
            'CRITICAL': '\033[35m', # Magenta
        }
        RESET = '\033[0m'
        
        def format(self, record):
            # Add timestamp
            record.timestamp = datetime.now().strftime('%H:%M:%S')
            
            # Format the message
            log_message = super().format(record)
            
            # Add color if terminal supports it
            if hasattr(sys.stderr, 'isatty') and sys.stderr.isatty():
                color = self.COLORS.get(record.levelname, '')
                return f"{color}[{record.timestamp}] {record.levelname:8s} | {log_message}{self.RESET}"
            else:
                return f"[{record.timestamp}] {record.levelname:8s} | {log_message}"
    
    # Configure root logger
    logging.basicConfig(
        level=level,
        format='%(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Set custom formatter
    for handler in logging.root.handlers:
        handler.setFormatter(ColoredFormatter())
    
    return logging.getLogger('dir_flatten')

# Global logger instance
logger = None

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

    if debug and logger:
        logger.debug(f"开始查找 file_content: {tmp_dir}")

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
            if debug and logger:
                logger.debug(f"获取深度{current_depth}项目失败: {e}")
        return items

    # Search depth by depth
    for depth in range(1, 11):
        items = get_items_at_depth(tmp_dir, depth)
        if debug and logger:
            logger.debug(f"深度{depth}: {len(items)} items")
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
            if debug and logger:
                logger.debug(f"检查目录 {dirpath} 失败: {e}")
            continue

        if is_empty:
            if keep_root and os.path.abspath(dirpath) == os.path.abspath(root):
                continue
            try:
                os.rmdir(dirpath)
                if debug and logger:
                    logger.debug(f"删除空目录: {dirpath}")
            except Exception as e:
                if debug and logger:
                    logger.debug(f"删除目录 {dirpath} 失败: {e}")


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
    """Move file/directory with cross-device support and logging."""
    try:
        if logger:
            logger.debug(f"Moving: {src} -> {dst}")
        shutil.move(src, dst)
    except OSError as e:
        if e.errno == errno.EXDEV:
            if logger:
                logger.debug(f"Cross-device move detected, using copy+delete: {src} -> {dst}")
            if os.path.isdir(src):
                shutil.copytree(src, dst)
                shutil.rmtree(src)
            else:
                shutil.copy2(src, dst)
                os.unlink(src)
        else:
            if logger:
                logger.error(f"Move failed: {src} -> {dst}, error: {e}")
            raise


def flatten_subfolder(subfolder: str, *, verbose: bool = False, dry_run: bool = False):
    if verbose and logger:
        logger.info(f"处理子目录: {subfolder}")

    info = find_file_content(subfolder, debug=verbose)
    if not info['found'] or info['depth'] <= 1:
        if verbose and logger:
            logger.info("跳过, depth<=1 或未检测到 file_content")
        return
    
    # Log analysis result
    if verbose and logger:
        logger.info(f"分析结果: depth={info['depth']}, items={len(info['items'])}, parent={info['parent_folder_name']}")

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
            if verbose and logger:
                logger.warning(f"冲突: {dest} 已存在")
    if conflict:
        if verbose and logger:
            logger.warning("本子目录存在冲突, 放弃处理")
        return

    tmp_dir = os.path.join(os.getcwd(), f"tmp_{int(time.time())}_{uuid.uuid4().hex[:8]}")
    if verbose and logger:
        logger.info(f"创建临时目录: {tmp_dir}")
    if not dry_run:
        os.makedirs(tmp_dir, exist_ok=True)

    for item in items:
        dst = os.path.join(tmp_dir, item['name'])
        if verbose and logger:
            logger.info(f"MOVE: {item['path']} -> {dst}")
        if not dry_run:
            _move(item['path'], dst)

    if verbose and logger:
        logger.info(f"清理空目录: {subfolder}")
    if not dry_run:
        cleanup_empty_dirs(subfolder, keep_root=True, debug=verbose)

    for name in os.listdir(tmp_dir):
        src = os.path.join(tmp_dir, name)
        dst = os.path.join(subfolder, name)
        if verbose and logger:
            logger.info(f"MOVE: {src} -> {dst}")
        if not dry_run:
            _move(src, dst)
    if verbose and logger:
        logger.info(f"删除临时目录: {tmp_dir}")
    if not dry_run:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ----------------- Driver code -----------------

def collect_subfolders(root: str, scan_depth: int, debug: bool = False) -> List[str]:
    """Collect subfolders at specified depth with logging."""
    result: List[str] = []
    root = os.path.abspath(root)
    
    if debug and logger:
        logger.debug(f"Collecting subfolders at depth {scan_depth} from: {root}")
    for dirpath, dirnames, _ in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        depth = 0 if rel == '.' else len(rel.split(os.sep))
        # 当当前目录相对于 root 的深度等于 scan_depth 时，直接把当前目录加入结果
        if depth == scan_depth:
            if safe_isdir(dirpath, debug):
                result.append(dirpath)
                if debug and logger:
                    logger.debug(f"Found subfolder at depth {depth}: {dirpath}")
            # 不再深入该目录的子目录，避免收集更深层
            dirnames.clear()
        # 若已超过指定深度，则无需继续向下遍历
        elif depth > scan_depth:
            dirnames.clear()  # prune deeper traversal for efficiency
    return result


def main(argv=None):
    global logger
    
    parser = argparse.ArgumentParser(description="目录扁平化工具")
    parser.add_argument('root_path', help='根目录路径')
    parser.add_argument('--scan-depth', type=int, required=True, help='从 root=0 开始的相对深度 (直接子目录=1, 依此类推)')
    parser.add_argument('--verbose', action='store_true', help='输出详细信息')
    parser.add_argument('--dry-run', action='store_true', help='仅模拟执行, 不做改动')
    parser.add_argument('--debug', action='store_true', help='输出调试信息')
    args = parser.parse_args(args=argv)
    
    # Setup logging based on arguments
    logger = setup_logging(verbose=args.verbose, debug=args.debug)

    if not os.path.isdir(args.root_path):
        logger.error("错误: 无效目录")
        sys.exit(1)

    root = os.path.abspath(args.root_path)
    logger.info(f"=== 开始目录扁平化操作 ===")
    logger.info(f"root: {root}")
    logger.info(f"scan_depth: {args.scan_depth}")
    if args.dry_run:
        logger.info("DRY RUN 模式 - 不会实际修改文件")

    subs = collect_subfolders(root, args.scan_depth, debug=args.debug)
    logger.info(f"共找到 {len(subs)} 个子目录待处理")
    if args.debug:
        for s in subs:
            logger.debug(f"- {s}")

    success_count = 0
    error_count = 0
    
    for i, sub in enumerate(subs, 1):
        try:
            logger.info(f"[{i}/{len(subs)}] 处理: {os.path.basename(sub)}")
            flatten_subfolder(sub, verbose=args.verbose, dry_run=args.dry_run)
            success_count += 1
        except Exception as e:
            error_count += 1
            logger.error(f"处理 {sub} 失败: {e}")
            if args.debug:
                import traceback
                logger.debug(traceback.format_exc())
    
    logger.info(f"=== 完成 ===")
    logger.info(f"成功处理: {success_count} 个目录")
    if error_count > 0:
        logger.warning(f"失败: {error_count} 个目录")


if __name__ == '__main__':
    main() 