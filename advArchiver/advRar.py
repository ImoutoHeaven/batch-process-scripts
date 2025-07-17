#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import argparse
import subprocess
import shutil
import platform
import time
import random
import atexit
import socket
import tempfile
import re
import glob
import signal
import shlex
import threading
import uuid
from datetime import datetime
from collections import defaultdict


# 全局统计信息
class CompressionStats:
    def __init__(self):
        self.success_files = 0
        self.success_folders = 0
        self.failed_files = 0
        self.failed_folders = 0
        self.failed_items = []  # 存储失败的详细信息
        self.start_time = time.time()

    def add_success(self, item_type, item_path):
        if item_type == 'file':
            self.success_files += 1
        else:
            self.success_folders += 1
        self.log(f"✓ 成功压缩{item_type}: {item_path}")

    def add_failure(self, item_type, item_path, error_code, error_msg, cmd_str):
        if item_type == 'file':
            self.failed_files += 1
        else:
            self.failed_folders += 1

        failure_info = {
            'type': item_type,
            'path': item_path,
            'error_code': error_code,
            'error_msg': error_msg,
            'command': cmd_str,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        self.failed_items.append(failure_info)

        self.log(f"✗ 压缩失败{item_type}: {item_path}")
        self.log(f"  错误码: {error_code}")
        self.log(f"  错误信息: {error_msg}")
        self.log(f"  执行命令: {cmd_str}")

    def log(self, message):
        """输出到控制台"""
        print(message)

    def print_final_stats(self):
        """打印最终统计信息"""
        total_time = time.time() - self.start_time
        total_success = self.success_files + self.success_folders
        total_failed = self.failed_files + self.failed_folders
        total_items = total_success + total_failed

        stats_message = f"""
{'=' * 60}
压缩任务完成统计
{'=' * 60}
总耗时: {total_time:.2f} 秒
总项目数: {total_items}
成功数量: {total_success} (文件: {self.success_files}, 文件夹: {self.success_folders})
失败数量: {total_failed} (文件: {self.failed_files}, 文件夹: {self.failed_folders})
成功率: {(total_success / total_items * 100) if total_items > 0 else 0:.1f}%

"""

        if self.failed_items:
            stats_message += "失败项目详情:\n"
            stats_message += "-" * 40 + "\n"
            for i, item in enumerate(self.failed_items, 1):
                stats_message += f"{i}. {item['type']}: {item['path']}\n"
                stats_message += f"   时间: {item['timestamp']}\n"
                stats_message += f"   错误码: {item['error_code']}\n"
                stats_message += f"   错误信息: {item['error_msg']}\n"
                stats_message += f"   执行命令: {item['command']}\n\n"

        stats_message += "=" * 60

        print(stats_message)


# 全局统计对象
stats = CompressionStats()


# 全局锁文件路径 - 确保路径一致性
def get_lock_file_path():
    """获取一致的锁文件路径"""
    if platform.system() == 'Windows':
        # Windows: 硬编码使用系统临时目录，确保路径一致性
        temp_dir = 'C:\\Windows\\Temp'
    else:
        # Unix/Linux: 使用标准临时目录
        temp_dir = '/tmp'

    return os.path.join(temp_dir, 'rar_comp_lock')


LOCK_FILE = get_lock_file_path()

# 全局变量保存锁文件句柄
lock_handle = None

# 新增：标记当前实例是否拥有锁的全局变量
lock_owner = False


def run_tasks_concurrently(items, args, base_path):
    """
    使用 ThreadPoolExecutor 并发执行文件/文件夹压缩任务。
    捕获 Ctrl+C / SIGTERM 等中断，确保线程池被正确关闭。
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _dispatch(path, item_type):
        if item_type == 'file':
            process_file(path, args, base_path)
        else:
            process_folder(path, args, base_path)

    futures = []
    total = len(items['files']) + len(items['folders'])
    print(f"并发模式: 启动 {args.threads} 个工作线程，任务总数 {total}")

    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            # 提交任务
            for p in items['files']:
                futures.append(executor.submit(_dispatch, p, 'file'))
            for p in items['folders']:
                futures.append(executor.submit(_dispatch, p, 'folder'))

            for fut in as_completed(futures):
                # 如果子线程抛异常，主线程立即感知并重抛
                fut.result()
    except KeyboardInterrupt:
        print("\n检测到用户中断，正在取消剩余任务 ...")
        executor.shutdown(wait=False, cancel_futures=True)
        raise



# 临时目录辅助
def create_unique_temp_dir(base_dir, debug=False):
    """
    在指定基础目录下创建唯一的临时目录

    Args:
        base_dir: 基础目录路径
        debug: 是否输出调试信息

    Returns:
        str: 创建的临时目录的绝对路径，如果失败返回None
    """
    try:
        timestamp = str(int(time.time() * 1000))
        thread_id = threading.get_ident()
        unique_id = str(uuid.uuid4().hex[:8])  # 8-char random hex for extra safety
        unique_suffix = f"{timestamp}_{thread_id}_{unique_id}"
        tmp_dir_name = f"tmp_{unique_suffix}"

        tmp_dir_path = os.path.join(base_dir, tmp_dir_name)
        tmp_dir_abs = safe_abspath(tmp_dir_path)

        if safe_makedirs(tmp_dir_abs, exist_ok=False, debug=debug):
            if debug:
                print(f"成功创建临时目录: {tmp_dir_abs}")
            return tmp_dir_abs
        else:
            if debug:
                print(f"创建临时目录失败: {tmp_dir_abs}")
            return None

    except Exception as e:
        if debug:
            print(f"创建临时目录时出错: {e}")
        return None


def cleanup_temp_dir(tmp_dir_path, debug=False):
    """
    清理并删除临时目录

    Args:
        tmp_dir_path: 临时目录的绝对路径
        debug: 是否输出调试信息

    Returns:
        bool: 是否成功清理
    """
    try:
        if not safe_exists(tmp_dir_path, debug):
            if debug:
                print(f"临时目录不存在，无需清理: {tmp_dir_path}")
            return True

        # 递归删除临时目录及其所有内容
        if safe_rmtree(tmp_dir_path, debug):
            if debug:
                print(f"成功清理临时目录: {tmp_dir_path}")
            return True
        else:
            if debug:
                print(f"清理临时目录失败: {tmp_dir_path}")
            return False

    except Exception as e:
        if debug:
            print(f"清理临时目录时出错 {tmp_dir_path}: {e}")
        return False


def move_files_to_final_destination(temp_dir, final_output_dir, moved_files, debug=False):
    """
    将文件从临时目录移动到最终目的地

    Args:
        temp_dir: 临时目录路径
        final_output_dir: 最终输出目录路径
        moved_files: 在临时目录中重命名后的文件列表
        debug: 是否输出调试信息

    Returns:
        tuple: (success, final_files) - 是否成功，最终文件列表
    """
    final_files = []

    try:
        # 确保最终输出目录存在
        if not safe_makedirs(final_output_dir, exist_ok=True, debug=debug):
            if debug:
                print(f"无法创建最终输出目录: {final_output_dir}")
            return False, []

        for temp_file in moved_files:
            # 获取文件名
            file_name = os.path.basename(temp_file)
            final_file_path = os.path.join(final_output_dir, file_name)

            if debug:
                print(f"移动文件: {temp_file} -> {final_file_path}")

            # 移动文件到最终位置
            if safe_move(temp_file, final_file_path, debug):
                final_files.append(final_file_path)
                if debug:
                    print(f"成功移动文件: {file_name}")
            else:
                if debug:
                    print(f"移动文件失败: {temp_file} -> {final_file_path}")
                return False, final_files

        return True, final_files

    except Exception as e:
        if debug:
            print(f"移动文件到最终目的地时出错: {e}")
        return False, final_files


# 临时目录辅助结束

# ==================== 短路径API改造 ====================

def get_short_path_name(long_path):
    """获取Windows短路径名（8.3格式），用于处理特殊字符"""
    if not is_windows():
        return long_path

    try:
        import ctypes
        from ctypes import wintypes

        # 获取短路径名
        GetShortPathNameW = ctypes.windll.kernel32.GetShortPathNameW
        GetShortPathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
        GetShortPathNameW.restype = wintypes.DWORD

        # 首先获取需要的缓冲区大小
        buffer_size = GetShortPathNameW(long_path, None, 0)
        if buffer_size == 0:
            return long_path

        # 创建缓冲区并获取短路径
        buffer = ctypes.create_unicode_buffer(buffer_size)
        result = GetShortPathNameW(long_path, buffer, buffer_size)
        if result == 0:
            return long_path

        return buffer.value
    except Exception:
        return long_path


def safe_path_for_operation(path, debug=False):
    """
    为文件系统操作获取安全的路径（优先使用短路径）

    Args:
        path: 原始路径
        debug: 是否输出调试信息

    Returns:
        str: 安全的路径（短路径或原路径）
    """
    if not path:
        return path

    if is_windows():
        short_path = get_short_path_name(path)
        if short_path != path and short_path:
            if debug:
                print(f"使用短路径: {path} -> {short_path}")
            return short_path
        elif debug:
            print(f"使用原路径: {path}")

    return path


def safe_exists(path, debug=False):
    """安全的路径存在性检查"""
    try:
        safe_path = safe_path_for_operation(path, debug)
        return os.path.exists(safe_path)
    except Exception as e:
        if debug:
            print(f"检查路径存在性失败 {path}: {e}")
        return False


def safe_isdir(path, debug=False):
    """安全的目录检查"""
    try:
        safe_path = safe_path_for_operation(path, debug)
        return os.path.isdir(safe_path)
    except Exception as e:
        if debug:
            print(f"检查路径是否为目录失败 {path}: {e}")
        return False


def safe_isfile(path, debug=False):
    """安全的文件检查"""
    try:
        safe_path = safe_path_for_operation(path, debug)
        return os.path.isfile(safe_path)
    except Exception as e:
        if debug:
            print(f"检查路径是否为文件失败 {path}: {e}")
        return False


def safe_makedirs(path, exist_ok=True, debug=False):
    """安全的目录创建"""
    try:
        safe_path = safe_path_for_operation(path, debug)
        os.makedirs(safe_path, exist_ok=exist_ok)
        if debug:
            print(f"成功创建目录: {path}")
        return True
    except Exception as e:
        if debug:
            print(f"创建目录失败 {path}: {e}")
        return False


def safe_remove(path, debug=False):
    """安全的文件删除"""
    try:
        safe_path = safe_path_for_operation(path, debug)
        os.remove(safe_path)
        if debug:
            print(f"成功删除文件: {path}")
        return True
    except Exception as e:
        if debug:
            print(f"删除文件失败 {path}: {e}")
        return False


def safe_rmdir(path, debug=False):
    """安全的空目录删除"""
    try:
        safe_path = safe_path_for_operation(path, debug)
        os.rmdir(safe_path)
        if debug:
            print(f"成功删除目录: {path}")
        return True
    except Exception as e:
        if debug:
            print(f"删除目录失败 {path}: {e}")
        return False


def safe_rmtree(path, debug=False):
    """安全的递归目录删除"""
    try:
        safe_path = safe_path_for_operation(path, debug)
        shutil.rmtree(safe_path)
        if debug:
            print(f"成功递归删除目录: {path}")
        return True
    except Exception as e:
        if debug:
            print(f"递归删除目录失败 {path}: {e}")
        return False


def safe_move(src, dst, debug=False):
    """安全的文件/目录移动/重命名"""
    try:
        safe_src = safe_path_for_operation(src, debug)
        safe_dst = safe_path_for_operation(dst, debug)

        # 如果目标已存在，先删除
        if safe_exists(dst, debug):
            if safe_isfile(dst, debug):
                safe_remove(dst, debug)
            else:
                safe_rmtree(dst, debug)

        shutil.move(safe_src, safe_dst)
        if debug:
            print(f"成功移动: {src} -> {dst}")
        return True
    except Exception as e:
        if debug:
            print(f"移动失败 {src} -> {dst}: {e}")
        return False


def safe_glob(pattern, debug=False):
    """安全的文件匹配（glob）"""
    try:
        # 对于glob，我们需要在模式的目录部分使用短路径
        pattern_dir = os.path.dirname(pattern)
        pattern_name = os.path.basename(pattern)

        if pattern_dir:
            safe_pattern_dir = safe_path_for_operation(pattern_dir, debug)
            safe_pattern = os.path.join(safe_pattern_dir, pattern_name)
        else:
            safe_pattern = pattern

        if debug:
            print(f"Glob模式: {pattern} -> {safe_pattern}")

        results = glob.glob(safe_pattern)

        # 将结果转换回原始路径格式
        if debug and results:
            print(f"Glob找到 {len(results)} 个文件")

        return results
    except Exception as e:
        if debug:
            print(f"Glob匹配失败 {pattern}: {e}")
        return []


def safe_walk(top, debug=False):
    """安全的目录遍历"""
    try:
        safe_top = safe_path_for_operation(top, debug)
        for root, dirs, files in os.walk(safe_top):
            # 将短路径结果转换回相对于原始top的路径
            if safe_top != top:
                # 需要将root从短路径转换回长路径格式
                rel_root = os.path.relpath(root, safe_top)
                if rel_root == '.':
                    converted_root = top
                else:
                    converted_root = os.path.join(top, rel_root)
            else:
                converted_root = root

            yield converted_root, dirs, files
    except Exception as e:
        if debug:
            print(f"目录遍历失败 {top}: {e}")
        return


def safe_chdir(path, debug=False):
    """安全的工作目录切换"""
    try:
        safe_path = safe_path_for_operation(path, debug)
        os.chdir(safe_path)
        if debug:
            print(f"成功切换到目录: {path}")
        return True
    except Exception as e:
        if debug:
            print(f"切换目录失败 {path}: {e}")
        return False


def safe_abspath(path, debug=False):
    """安全的绝对路径获取"""
    try:
        # 先获取绝对路径，然后尝试获取短路径
        abs_path = os.path.abspath(path)
        return abs_path  # 返回长路径作为标准引用
    except Exception as e:
        if debug:
            print(f"获取绝对路径失败 {path}: {e}")
        return path


# ==================== 结束短路径API改造 ====================

def check_shell_environment():
    """检查当前shell环境，如果是cmd则提示切换到PowerShell"""
    if platform.system() == 'Windows':
        try:
            # 更可靠的CMD检测方法
            # 1. 检查PSModulePath（PowerShell特有）
            # 2. 检查PROMPT格式
            # 3. 尝试执行PowerShell特有命令

            is_cmd = False

            # 方法1：检查PSModulePath环境变量
            if 'PSModulePath' not in os.environ:
                is_cmd = True

            # 方法2：检查PROMPT格式，CMD通常包含$P$G
            prompt = os.environ.get('PROMPT', '')
            if '$P$G' in prompt.upper():
                is_cmd = True

            # 方法3：检查COMSPEC
            comspec = os.environ.get('COMSPEC', '').lower()
            if 'cmd.exe' in comspec and 'PSModulePath' not in os.environ:
                is_cmd = True

            if is_cmd:
                print("=" * 60)
                print("警告: 检测到您正在使用CMD命令提示符")
                print("建议切换到PowerShell以获得更好的特殊字符支持")
                print("请按以下步骤操作:")
                print("1. 按Win+R，输入'powershell'，按Enter")
                print("2. 或者在开始菜单搜索'PowerShell'")
                print("3. 在PowerShell中重新运行此脚本")
                print("=" * 60)

                response = input("是否继续使用CMD运行？(y/N): ").lower().strip()
                if response not in ['y', 'yes']:
                    print("程序已退出，请在PowerShell中重新运行")
                    sys.exit(0)
                print()
        except:
            pass  # 如果检测失败，继续运行


def quote_path_for_rar(path):
    """为RAR命令正确引用路径，处理特殊字符和以-开头的文件名"""
    if platform.system() == 'Windows':
        # 对于Windows，优先尝试使用短路径名
        short_path = get_short_path_name(path)
        if short_path != path and short_path:
            # 如果成功获取短路径名，使用短路径（通常是ASCII安全的）
            path = short_path

        # 检查最终路径的文件名是否以 '-' 开头
        filename = os.path.basename(path)
        if filename.startswith('-'):
            # 对于以 '-' 开头的文件名，添加 './' 前缀避免被识别为选项
            dirname = os.path.dirname(path)
            if dirname:
                path = os.path.join(dirname, '.' + os.sep + filename)
            else:
                path = '.' + os.sep + filename

        # Windows下使用双引号，并转义内部的双引号
        if '"' in path:
            path = path.replace('"', '\\"')
        return f'"{path}"'
    else:
        # Unix/Linux系统
        # 检查文件名是否以 '-' 开头
        if os.path.basename(path).startswith('-'):
            # 添加 './' 前缀
            dirname = os.path.dirname(path)
            filename = os.path.basename(path)
            if dirname:
                path = os.path.join(dirname, '.', filename)
            else:
                path = os.path.join('.', filename)

        return shlex.quote(path)


def execute_rar_command(rar_cmd, debug=False):
    """执行RAR命令，处理编码问题"""
    cmd_str = ' '.join(rar_cmd)

    try:
        # 设置环境变量以确保正确的编码处理
        env = os.environ.copy()
        if is_windows():
            # Windows特定设置
            env['PYTHONIOENCODING'] = 'utf-8'

            # 尝试设置控制台代码页为UTF-8
            try:
                import ctypes
                # 设置控制台输入输出编码为UTF-8
                if hasattr(ctypes.windll.kernel32, 'SetConsoleCP'):
                    ctypes.windll.kernel32.SetConsoleCP(65001)
                    ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            except:
                pass

            # 使用shell=True，让Windows命令解释器处理
            result = subprocess.run(
                cmd_str,
                shell=True,
                check=False,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                env=env
            )
        else:
            # Unix/Linux系统
            env['LC_ALL'] = 'C.UTF-8'
            env['LANG'] = 'C.UTF-8'

            # 对于非Windows系统，移除命令中的引号并使用列表形式
            cleaned_cmd = [arg.strip('"\'') for arg in rar_cmd]
            result = subprocess.run(
                cleaned_cmd,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                env=env
            )

        return result

    except Exception as e:
        # 如果出现异常，创建一个模拟的result对象
        class MockResult:
            def __init__(self, returncode, stdout, stderr):
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = stderr

        return MockResult(-1, "", str(e))


def acquire_lock(max_attempts=30, min_wait=2, max_wait=10):
    """
    尝试获取全局锁，如果锁被占用则重试。
    使用文件存在性作为锁机制：文件存在=有锁，文件不存在=无锁。

    Args:
        max_attempts: 最大尝试次数
        min_wait: 重试最小等待时间（秒）
        max_wait: 重试最大等待时间（秒）

    Returns:
        bool: 是否成功获取锁
    """
    global lock_handle
    global LOCK_FILE
    global lock_owner  # 新增：锁所有者标记

    attempt = 0

    while attempt < max_attempts:
        try:
            # 检查锁文件是否存在
            if safe_exists(LOCK_FILE):
                # 锁文件存在，说明有其他进程正在使用
                pass
            else:
                # 锁文件不存在，尝试创建锁文件
                try:
                    # 使用短路径获取安全的锁文件路径
                    safe_lock_file = safe_path_for_operation(LOCK_FILE)

                    # 使用 'x' 模式：只有当文件不存在时才创建，如果文件已存在会抛出异常
                    lock_handle = open(safe_lock_file, 'x')

                    # 成功创建锁文件，写入进程信息
                    hostname = socket.gethostname()
                    pid = os.getpid()
                    lock_info = f"{hostname}:{pid}:{time.time()}"
                    lock_handle.write(lock_info)
                    lock_handle.flush()
                    lock_handle.close()  # 关闭文件句柄，但保留锁文件
                    lock_handle = None

                    # 设置锁所有者标记
                    lock_owner = True

                    # 注册退出时的清理函数
                    atexit.register(release_lock)
                    return True

                except FileExistsError:
                    # 文件已存在，其他进程在我们检查后创建了锁文件
                    if lock_handle:
                        try:
                            lock_handle.close()
                        except:
                            pass
                        lock_handle = None

        except Exception as e:
            print(f"获取锁时出错: {e}")
            # 出现异常情况，清理并重试
            if lock_handle:
                try:
                    lock_handle.close()
                except:
                    pass
                lock_handle = None

        # 随机等待时间后重试
        wait_time = random.uniform(min_wait, max_wait)
        print(f"锁被占用，将在 {wait_time:.2f} 秒后重试 (尝试 {attempt + 1}/{max_attempts})")
        time.sleep(wait_time)
        attempt += 1

    print(f"无法获取锁，已达到最大重试次数 ({max_attempts})")
    return False


def release_lock():
    """释放全局锁，只有锁的拥有者才能释放锁"""
    global lock_handle
    global lock_owner

    # 只有锁的拥有者才能释放锁
    if not lock_owner:
        return

    # 关闭文件句柄（如果还打开着）
    if lock_handle:
        try:
            lock_handle.close()
        except:
            pass
        lock_handle = None

    # 尝试删除锁文件，最多重试5次
    max_retries = 5
    retry_delay = 5  # 每次重试间隔5秒

    for attempt in range(max_retries):
        try:
            if safe_exists(LOCK_FILE):
                if safe_remove(LOCK_FILE):
                    print(f"成功删除锁文件: {LOCK_FILE}")
                    lock_owner = False  # 重置锁所有者标记
                    return
            else:
                # 文件不存在，说明已经被删除了
                lock_owner = False  # 重置锁所有者标记
                return

        except Exception as e:
            print(f"删除锁文件失败 (尝试 {attempt + 1}/{max_retries}): {e}")
            if attempt < max_retries - 1:  # 不是最后一次尝试
                print(f"将在 {retry_delay} 秒后重试...")
                time.sleep(retry_delay)
            else:
                print(f"删除锁文件失败，已达到最大重试次数 ({max_retries})")
                print(f"请手动删除锁文件: {LOCK_FILE}")


def profile_type(value):
    """用于argparse的自定义类型，以验证profile参数"""
    if value in ['store', 'best', 'fastest']:
        return value

    # 支持多种分卷单位格式：g/gb/m/mb/k/kb（不区分大小写）
    match = re.match(r'^parted-(\d+)(g|gb|m|mb|k|kb)$', value, re.IGNORECASE)
    if match:
        size = int(match.group(1))
        unit = match.group(2).lower()
        if size > 0:
            return value

    raise argparse.ArgumentTypeError(
        f"'{value}' 不是一个有效的配置。请选择 'store', 'best', 'fastest', 或者 'parted-XXunit' (例如: 'parted-10g', 'parted-100mb', 'parted-500k')。"
    )


def parse_arguments():
    """解析命令行参数，并新增 --threads 并发选项"""
    parser = argparse.ArgumentParser(description='RAR压缩工具')
    parser.add_argument('folder_path', help='要处理的文件夹路径')
    parser.add_argument('--dry-run', action='store_true', help='仅预览操作，不执行实际命令')
    parser.add_argument('--depth', type=int, default=0, help='压缩处理的深度级别 (0, 1, 2, ...)')
    parser.add_argument('-p', '--password', help='设置压缩包密码')
    parser.add_argument('-d', '--delete', action='store_true', help='压缩成功后删除原文件/文件夹')
    parser.add_argument(
        '--profile',
        type=profile_type,
        default='best',
        help="压缩配置文件: 'store', 'best', 'fastest', 或 'parted-XXunit' (例如: 'parted-10g', 'parted-100mb', 'parted-500k')"
    )
    parser.add_argument('--debug', action='store_true', help='显示调试信息')
    parser.add_argument('--no-lock', action='store_true', help='不使用全局锁（谨慎使用）')
    parser.add_argument('--lock-timeout', type=int, default=30, help='锁定超时时间（最大重试次数）')
    parser.add_argument('--out', help='指定压缩后文件的输出目录路径')

    # 并发线程数（新增）
    parser.add_argument('-t', '--threads', type=int, default=1,
                        help='同时进行压缩的任务数 (>=1)')

    # 跳过规则
    parser.add_argument('--skip-files', action='store_true', help='跳过文件，仅处理文件夹')
    parser.add_argument('--skip-folders', action='store_true', help='跳过文件夹，仅处理文件')
    parser.add_argument('--ext-skip-folder-tree', action='store_true',
                        help='当指定 --skip-${ext} 参数时，跳过包含指定扩展名文件的整个文件夹树')

    args, unknown = parser.parse_known_args()

    # 处理 --skip-ext
    skip_extensions = []
    for arg in unknown:
        if arg.startswith('--skip-'):
            ext = arg[7:]
            if ext:
                skip_extensions.append(ext.lower())
            else:
                print(f"警告: 忽略无效的跳过参数: {arg}")
        else:
            print(f"错误: 未知参数: {arg}")
            sys.exit(1)
    args.skip_extensions = skip_extensions

    # 线程数校验
    if args.threads < 1:
        parser.error("--threads 必须 >= 1")

    return args



def is_windows():
    """检查当前操作系统是否为Windows"""
    return platform.system() == 'Windows'


def get_rar_command():
    """根据操作系统获取RAR命令"""
    # 尝试运行rar命令检查是否可用
    try:
        result = subprocess.run(['rar', '-?' if is_windows() else '--help'],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                shell=is_windows(),
                                encoding='utf-8',
                                errors='replace')
        if result.returncode in [0, 1, 7]:  # RAR命令可能返回这些代码
            return 'rar'
    except Exception:
        pass

    # 如果rar不可用，尝试使用winrar命令（仅限Windows）
    if is_windows():
        try:
            result = subprocess.run(['winrar', '-?'],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    shell=True,
                                    encoding='utf-8',
                                    errors='replace')
            if result.returncode in [0, 1, 7]:
                return 'winrar'
        except Exception:
            pass

    # 如果都不可用，使用默认的rar命令，如果不存在会在执行时报错
    return 'rar'


def is_folder_empty(folder_path):
    """检查文件夹是否为空（递归检查）"""
    try:
        for root, dirs, files in safe_walk(folder_path):
            # 如果找到任何文件，则不为空
            if files:
                return False
            # 如果找到任何非空子目录，则不为空
            for dir_name in dirs:
                sub_path = os.path.join(root, dir_name)
                if not is_folder_empty(sub_path):
                    return False
        return True
    except Exception:
        # 如果无法访问文件夹，假设不为空（安全起见）
        return False


def should_skip_file(file_path, skip_extensions):
    """检查文件是否应该被跳过"""
    if not skip_extensions:
        return False

    # 获取文件扩展名（去掉点号，转为小写）
    _, ext = os.path.splitext(file_path)
    if ext.startswith('.'):
        ext = ext[1:]  # 移除点号
    ext = ext.lower()

    return ext in skip_extensions


def folder_contains_skip_extensions(folder_path, skip_extensions, debug=False):
    """递归检查文件夹是否包含指定扩展名的文件"""
    if not skip_extensions:
        return False

    try:
        for root, dirs, files in safe_walk(folder_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                if should_skip_file(file_path, skip_extensions):
                    if debug:
                        print(f"文件夹 {folder_path} 包含跳过的扩展名文件: {file_path}")
                    return True
        return False
    except Exception as e:
        if debug:
            print(f"检查文件夹 {folder_path} 时出错: {e}")
        # 如果无法访问文件夹，为安全起见返回True（跳过）
        return True


def remove_directory(path, dry_run=False):
    """递归删除目录及其内容"""
    if dry_run:
        print(f"[DRY-RUN] 将删除目录: {path}")
        return True

    return safe_rmtree(path)


def get_items_at_depth(base_folder, target_depth, args):
    """获取指定深度的文件和文件夹列表，应用过滤规则"""
    items = {'files': [], 'folders': []}

    if target_depth == 0:
        # 深度0特殊处理：直接返回基础文件夹
        if not args.skip_folders:
            folder_path = safe_abspath(base_folder)
            # 检查文件夹是否为空
            if not is_folder_empty(folder_path):
                # 新增：检查 --ext-skip-folder-tree 参数
                if args.ext_skip_folder_tree and args.skip_extensions:
                    if folder_contains_skip_extensions(folder_path, args.skip_extensions, args.debug):
                        if args.debug:
                            print(f"跳过包含指定扩展名文件的文件夹: {folder_path}")
                        return items

                items['folders'].append(folder_path)
            elif args.debug:
                print(f"跳过空文件夹: {folder_path}")
        return items

    # 对深度>0的情况，遍历文件系统
    for root, dirs, files in safe_walk(base_folder):
        # 计算当前相对于基础文件夹的深度
        rel_path = os.path.relpath(root, base_folder)
        current_depth = 0 if rel_path == '.' else len(rel_path.split(os.sep))

        # 如果当前深度正好是目标深度-1，则其子项（文件和文件夹）就是目标深度的项
        if current_depth == target_depth - 1:
            # 收集当前层级的所有文件（如果不跳过文件）
            if not args.skip_files:
                for file_name in files:
                    full_path = os.path.join(root, file_name)
                    abs_path = safe_abspath(full_path)

                    # 检查是否应该跳过此文件（基于扩展名）
                    if should_skip_file(abs_path, args.skip_extensions):
                        if args.debug:
                            print(f"跳过文件（扩展名过滤）: {abs_path}")
                        continue

                    items['files'].append(abs_path)

            # 收集当前层级的所有文件夹（如果不跳过文件夹）
            if not args.skip_folders:
                for dir_name in dirs:
                    full_path = os.path.join(root, dir_name)
                    abs_path = safe_abspath(full_path)

                    # 检查文件夹是否为空
                    if is_folder_empty(abs_path):
                        if args.debug:
                            print(f"跳过空文件夹: {abs_path}")
                        continue

                    # 新增：检查 --ext-skip-folder-tree 参数
                    if args.ext_skip_folder_tree and args.skip_extensions:
                        if folder_contains_skip_extensions(abs_path, args.skip_extensions, args.debug):
                            if args.debug:
                                print(f"跳过包含指定扩展名文件的文件夹: {abs_path}")
                            continue

                    items['folders'].append(abs_path)

    return items


def normalize_volume_size(size_str, unit_str):
    """
    将用户输入的分卷大小标准化为RAR可识别的格式

    Args:
        size_str: 大小数字字符串
        unit_str: 单位字符串（g/gb/m/mb/k/kb，不区分大小写）

    Returns:
        str: RAR格式的分卷大小参数（如 "10g", "100m", "500k"）
    """
    unit = unit_str.lower()

    # 将所有单位标准化为RAR的简短格式
    if unit in ['g', 'gb']:
        return f"{size_str}g"
    elif unit in ['m', 'mb']:
        return f"{size_str}m"
    elif unit in ['k', 'kb']:
        return f"{size_str}k"
    else:
        # 默认使用原始输入（不应该到达这里，因为profile_type已经验证过）
        return f"{size_str}{unit}"

def prepare_folder_path_for_rar(folder_path, debug=False):
    """
    返回满足 RAR CLI 要求的 **绝对目录路径**，并确保：
    • Windows: 以反斜杠 '\\' 结尾，且已转换为 8.3 短路径（若可）。
    • 其他平台: 以正斜杠 '/' 结尾。
    """
    abs_path = safe_abspath(folder_path).rstrip('/\\')  # 先去掉现有结尾
    safe_path = safe_path_for_operation(abs_path, debug)

    if is_windows():
        if not safe_path.endswith('\\'):
            safe_path += '\\'
    else:  # Linux / macOS 等
        if not safe_path.endswith('/'):
            safe_path += '/'

    if debug:
        print(f"文件夹输入路径已规范化: {folder_path} -> {safe_path}")
    return safe_path


def build_rar_switches(profile, password, delete_files=False):
    """
    构建 RAR 命令开关参数。
    变更点：
    1. 无论何种 profile，统一追加 -ep1 以去除输入路径中高层目录。
    2. 其余逻辑保持不变。
    """
    switches = []

    # 压缩后删除源文件
    if delete_files:
        switches.append('-df')

    # profile 逻辑（与旧实现一致）
    if profile.startswith('parted-') or profile == 'store':
        switches.extend([
            '-m0', '-md32m', '-s-', '-htb', '-qo+', '-oi:1', '-rr5p', '-ma5'
        ])
        if profile.startswith('parted-'):
            match = re.match(r'^parted-(\d+)(g|gb|m|mb|k|kb)$', profile, re.IGNORECASE)
            if match:
                size, unit = match.groups()
                switches.append(f'-v{normalize_volume_size(size, unit)}')
    elif profile == 'fastest':
        switches.extend([
            '-m1', '-md256m', '-s-', '-htb', '-qo+', '-oi:1', '-rr5p', '-ma5'
        ])
    else:  # best
        switches.extend([
            '-m5', '-md256m', '-s', '-htb', '-qo+', '-oi:1', '-rr5p', '-ma5'
        ])

    # 统一追加 -ep1
    switches.append('-ep1')

    # 密码
    if password:
        switches.extend([f'-p{password}', '-hp'])

    return switches



def find_and_rename_rar_files(temp_name_prefix, target_name_prefix, search_dir, debug=False):
    """
    查找并重命名RAR文件（支持分卷）

    Args:
        temp_name_prefix: 临时文件名前缀（如 "temp_archive"）
        target_name_prefix: 目标文件名前缀（如 "folder_name"）
        search_dir: 搜索目录
        debug: 是否输出调试信息

    Returns:
        tuple: (success, moved_files) - 是否成功，移动的文件列表
    """
    moved_files = []

    # 首先查找单个RAR文件
    single_rar = os.path.join(search_dir, f"{temp_name_prefix}.rar")

    if safe_exists(single_rar, debug):
        # 找到单个RAR文件
        target_file = os.path.join(search_dir, f"{target_name_prefix}.rar")

        if debug:
            print(f"找到单个RAR文件: {single_rar}")
            print(f"目标文件: {target_file}")

        try:
            # 使用安全的移动函数
            if safe_move(single_rar, target_file, debug):
                moved_files.append(target_file)
                if debug:
                    print(f"成功移动文件: {single_rar} -> {target_file}")
                return True, moved_files
            else:
                print(f"移动单个RAR文件时出错")
                return False, []

        except Exception as e:
            print(f"移动单个RAR文件时出错: {e}")
            return False, []

    # 如果没有找到单个RAR文件，查找分卷文件
    # 支持多种分卷命名格式：
    # temp_archive.part1.rar, temp_archive.part01.rar, temp_archive.part001.rar
    part_patterns = [
        f"{temp_name_prefix}.part*.rar",
        f"{temp_name_prefix}.part*.RAR"  # 也支持大写扩展名
    ]

    part_files = []
    for pattern in part_patterns:
        search_pattern = os.path.join(search_dir, pattern)
        found_files = safe_glob(search_pattern, debug)
        part_files.extend(found_files)

    # 去重并排序
    part_files = sorted(list(set(part_files)))

    if debug:
        print(f"搜索分卷文件模式: {part_patterns}")
        print(f"找到的分卷文件: {part_files}")

    if not part_files:
        print(f"错误: 没有找到RAR文件 {temp_name_prefix}.rar 或分卷文件 {temp_name_prefix}.part*.rar")
        return False, []

    # 处理分卷文件
    print(f"找到 {len(part_files)} 个分卷文件，开始重命名...")

    try:
        for part_file in part_files:
            # 从文件名中提取part信息
            filename = os.path.basename(part_file)

            # 使用正则表达式提取part部分
            # 支持格式：temp_archive.part1.rar, temp_archive.part01.rar等
            pattern = rf'^{re.escape(temp_name_prefix)}\.(.+)\.rar$'
            match = re.match(pattern, filename, re.IGNORECASE)

            if match:
                part_suffix = match.group(1)  # 例如 "part1", "part01", "part001"
                target_filename = f"{target_name_prefix}.{part_suffix}.rar"
                target_file = os.path.join(search_dir, target_filename)

                if debug:
                    print(f"重命名分卷: {part_file} -> {target_file}")

                # 使用安全的移动函数
                if safe_move(part_file, target_file, debug):
                    moved_files.append(target_file)
                else:
                    print(f"警告: 移动分卷文件失败: {part_file}")

            else:
                print(f"警告: 无法解析分卷文件名格式: {filename}")

        print(f"成功处理 {len(moved_files)} 个分卷文件")
        return True, moved_files

    except Exception as e:
        print(f"处理分卷文件时出错: {e}")
        if debug:
            import traceback
            traceback.print_exc()
        return False, moved_files


def get_relative_path(item_path, base_path):
    """计算项目相对于基础路径的相对路径"""
    # 获取绝对路径
    item_abs = safe_abspath(item_path)
    base_abs = safe_abspath(base_path)

    # 计算相对路径
    rel_path = os.path.relpath(item_abs, base_abs)

    # 如果是当前目录，返回基础路径的名称
    if rel_path == '.':
        return os.path.basename(base_abs)

    return rel_path


def safe_delete_file(file_path, dry_run=False):
    """安全删除文件"""
    if dry_run:
        print(f"[DRY-RUN] 将删除文件: {file_path}")
        return True

    return safe_remove(file_path, debug=True)


def safe_delete_folder(folder_path, dry_run=False):
    """安全删除文件夹（只删除空文件夹）"""
    if dry_run:
        print(f"[DRY-RUN] 将删除文件夹: {folder_path}")
        return True

    try:
        # 检查文件夹是否为空
        if is_folder_empty(folder_path):
            if safe_rmdir(folder_path, debug=True):
                print(f"已删除原始空文件夹: {folder_path}")
                return True
            else:
                print(f"删除文件夹失败: {folder_path}")
                return False
        else:
            print(f"文件夹不为空，跳过删除: {folder_path}")
            return False
    except Exception as e:
        print(f"删除文件夹失败 {folder_path}: {e}")
        return False


def process_file(file_path, args, base_path):
    """处理单个文件的压缩操作（已移除 cd 逻辑，全部使用绝对路径）"""
    global stats

    # 绝对路径 & 相对信息
    abs_file_path = safe_abspath(file_path)
    rel_path = get_relative_path(abs_file_path, base_path)
    file_name_no_ext = os.path.splitext(os.path.basename(abs_file_path))[0]

    # 计算输出目录
    if args.out:
        output_dir = safe_abspath(args.out)
        safe_makedirs(output_dir, exist_ok=True, debug=args.debug)
        rel_dir = os.path.dirname(rel_path)
        final_output_dir = os.path.join(output_dir, rel_dir) if rel_dir and rel_dir != '.' else output_dir
    else:
        final_output_dir = os.path.dirname(abs_file_path)

    # 创建唯一临时目录
    temp_dir = create_unique_temp_dir(os.getcwd(), args.debug)
    if not temp_dir:
        stats.add_failure('文件', abs_file_path, -1, "无法创建临时目录", "")
        return

    try:
        # 构建 RAR 命令
        rar_switches = build_rar_switches(args.profile, args.password, args.delete)
        rar_cmd = [get_rar_command(), 'a', *rar_switches]

        temp_rar_path = os.path.join(temp_dir, "temp_archive.rar")
        rar_cmd.append(quote_path_for_rar(temp_rar_path))          # 输出
        rar_cmd.append(quote_path_for_rar(abs_file_path))          # 输入(绝对)

        cmd_str = ' '.join(rar_cmd)
        if args.debug:
            print(f"[DEBUG] 文件压缩命令: {cmd_str}")

        if args.dry_run:
            stats.log(f"[DRY-RUN] 将执行: {cmd_str}")
            return

        result = execute_rar_command(rar_cmd, args.debug)

        if result.returncode == 0:
            # 重命名并移动 RAR
            final_name = os.path.splitext(os.path.basename(rel_path))[0]
            ok_rename, moved = find_and_rename_rar_files("temp_archive", final_name, temp_dir, args.debug)
            if ok_rename:
                ok_move, finals = move_files_to_final_destination(temp_dir, final_output_dir, moved, args.debug)
                if ok_move:
                    stats.add_success('文件', abs_file_path)
                else:
                    stats.add_failure('文件', abs_file_path, 0, "移动RAR到最终目录失败", cmd_str)
            else:
                stats.add_failure('文件', abs_file_path, 0, "重命名RAR失败", cmd_str)
        else:
            stats.add_failure('文件', abs_file_path, result.returncode,
                              result.stderr or "未知错误", cmd_str)
    finally:
        cleanup_temp_dir(temp_dir, args.debug)


def process_folder(folder_path, args, base_path):
    """处理文件夹压缩（已移除 cd 逻辑，使用绝对路径 + -r）"""
    global stats

    # 跳过规则保持不变
    if args.ext_skip_folder_tree and args.skip_extensions and not args.skip_folders:
        if folder_contains_skip_extensions(folder_path, args.skip_extensions, args.debug):
            stats.log(f"跳过包含指定扩展名文件的文件夹: {folder_path}")
            return

    rel_path = get_relative_path(folder_path, base_path)

    # 输出目录
    if args.out:
        output_dir = safe_abspath(args.out)
        safe_makedirs(output_dir, exist_ok=True, debug=args.debug)
        rel_dir = os.path.dirname(rel_path)
        final_output_dir = os.path.join(output_dir, rel_dir) if rel_dir and rel_dir != '.' else output_dir
    else:
        final_output_dir = os.path.dirname(folder_path)

    temp_dir = create_unique_temp_dir(os.getcwd(), args.debug)
    if not temp_dir:
        stats.add_failure('文件夹', folder_path, -1, "无法创建临时目录", "")
        return

    try:
        rar_switches = build_rar_switches(args.profile, args.password, args.delete)
        rar_switches.insert(0, '-r')  # 文件夹需递归

        rar_cmd = [get_rar_command(), 'a', *rar_switches]

        temp_rar_path = os.path.join(temp_dir, "temp_archive.rar")
        rar_cmd.append(quote_path_for_rar(temp_rar_path))                   # 输出
        folder_input = prepare_folder_path_for_rar(folder_path, args.debug)
        rar_cmd.append(quote_path_for_rar(folder_input))                    # 输入(绝对 + 尾部分隔)

        cmd_str = ' '.join(rar_cmd)
        if args.debug:
            print(f"[DEBUG] 文件夹压缩命令: {cmd_str}")

        if args.dry_run:
            stats.log(f"[DRY-RUN] 将执行: {cmd_str}")
            return

        result = execute_rar_command(rar_cmd, args.debug)

        if result.returncode == 0:
            final_name = os.path.basename(rel_path)
            ok_rename, moved = find_and_rename_rar_files("temp_archive", final_name, temp_dir, args.debug)
            if ok_rename:
                ok_move, finals = move_files_to_final_destination(temp_dir, final_output_dir, moved, args.debug)
                if ok_move:
                    if args.delete:
                        safe_delete_folder(folder_path, args.dry_run)
                    stats.add_success('文件夹', folder_path)
                else:
                    stats.add_failure('文件夹', folder_path, 0, "移动RAR到最终目录失败", cmd_str)
            else:
                stats.add_failure('文件夹', folder_path, 0, "重命名RAR失败", cmd_str)
        else:
            stats.add_failure('文件夹', folder_path, result.returncode,
                              result.stderr or "未知错误", cmd_str)
    finally:
        cleanup_temp_dir(temp_dir, args.debug)



def signal_handler(signum, frame):
    """信号处理器，用于在程序被中断时清理锁文件"""
    print(f"\n收到信号 {signum}，正在清理...")
    stats.print_final_stats()
    release_lock()  # 只有锁的拥有者才会释放锁
    sys.exit(1)


def main():
    """主函数"""
    global stats
    global lock_owner

    # 检查shell环境
    check_shell_environment()

    # 初始化统计信息
    stats.log("程序开始执行")

    args = parse_arguments()

    # 验证参数组合
    if args.skip_files and args.skip_folders:
        error_msg = "错误: 不能同时指定 --skip-files 和 --skip-folders，这样不会有任何需要处理的项目"
        stats.log(error_msg)
        print(error_msg)
        sys.exit(1)

    # 新增：验证 --ext-skip-folder-tree 参数
    if args.ext_skip_folder_tree and not args.skip_extensions:
        warning_msg = "警告: 指定了 --ext-skip-folder-tree 但没有指定任何 --skip-${ext} 参数，该选项将被忽略"
        stats.log(warning_msg)
        print(warning_msg)

    if args.ext_skip_folder_tree and args.skip_folders:
        info_msg = "信息: --ext-skip-folder-tree 与 --skip-folders 组合使用时逻辑保持不变（不处理文件夹）"
        stats.log(info_msg)
        if args.debug:
            print(info_msg)

    # 验证目标路径
    if not safe_exists(args.folder_path, args.debug):
        error_msg = f"错误: 路径不存在 - {args.folder_path}"
        stats.log(error_msg)
        print(error_msg)
        sys.exit(1)

    if not safe_isdir(args.folder_path, args.debug):
        error_msg = f"错误: 不是一个目录 - {args.folder_path}"
        stats.log(error_msg)
        print(error_msg)
        sys.exit(1)

    # 验证输出路径（如果指定了）
    if args.out:
        # 如果输出路径不存在，尝试创建
        try:
            if safe_makedirs(args.out, exist_ok=True, debug=args.debug):
                output_msg = f"输出目录: {safe_abspath(args.out)}"
                stats.log(output_msg)
                print(output_msg)
            else:
                error_msg = f"错误: 无法创建输出目录 {args.out}"
                stats.log(error_msg)
                print(error_msg)
                sys.exit(1)
        except Exception as e:
            error_msg = f"错误: 无法创建输出目录 {args.out}: {e}"
            stats.log(error_msg)
            print(error_msg)
            sys.exit(1)

    # 尝试获取全局锁（除非指定了--no-lock选项）
    lock_acquired = False
    if not args.no_lock:
        if acquire_lock(max_attempts=args.lock_timeout):
            lock_acquired = True
            lock_msg = f"成功获取全局锁: {LOCK_FILE}"
            stats.log(lock_msg)
            print(lock_msg)

            # 设置信号处理器，确保异常退出时能清理锁文件
            signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C
            signal.signal(signal.SIGTERM, signal_handler)  # 终止信号
            if hasattr(signal, 'SIGBREAK'):  # Windows
                signal.signal(signal.SIGBREAK, signal_handler)
        else:
            error_msg = "无法获取全局锁，退出程序"
            stats.log(error_msg)
            print(error_msg)
            # 注意：这里不调用release_lock()，因为当前实例没有获取到锁
            sys.exit(2)

    try:
        # 在Windows系统上设置控制台编码为UTF-8
        if is_windows():
            try:
                import ctypes
                # 设置控制台输入输出编码为UTF-8
                if hasattr(ctypes.windll.kernel32, 'SetConsoleCP'):
                    ctypes.windll.kernel32.SetConsoleCP(65001)
                    ctypes.windll.kernel32.SetConsoleOutputCP(65001)
                if args.debug:
                    stats.log("已设置Windows控制台编码为UTF-8")
            except Exception as e:
                if args.debug:
                    stats.log(f"设置Windows控制台编码时出错: {e}")

        # 显示过滤信息（如果开启了调试模式）
        if args.debug:
            stats.log("过滤设置:")
            stats.log(f"- 跳过文件: {args.skip_files}")
            stats.log(f"- 跳过文件夹: {args.skip_folders}")
            stats.log(f"- 跳过扩展名: {args.skip_extensions}")
            stats.log(f"- 扩展名文件夹树跳过: {args.ext_skip_folder_tree}")

        # 获取指定深度的文件和文件夹列表（应用过滤规则）
        items = get_items_at_depth(args.folder_path, args.depth, args)

        if args.debug:
            debug_msg = f"找到以下符合深度 {args.depth} 的项目（应用过滤后）:"
            stats.log(debug_msg)
            stats.log(f"文件数量: {len(items['files'])}")
            stats.log(f"文件夹数量: {len(items['folders'])}")
            if len(items['files']) > 0:
                stats.log("文件列表（前10个）:")
                for path in items['files'][:10]:
                    stats.log(f"- {path}")
                if len(items['files']) > 10:
                    stats.log(f"... 还有 {len(items['files']) - 10} 个文件")
            if len(items['folders']) > 0:
                stats.log("文件夹列表（前10个）:")
                for path in items['folders'][:10]:
                    stats.log(f"- {path}")
                if len(items['folders']) > 10:
                    stats.log(f"... 还有 {len(items['folders']) - 10} 个文件夹")

        total_items = len(items['files']) + len(items['folders'])
        if total_items == 0:
            warning_msg = f"警告: 在深度 {args.depth} 没有找到任何符合条件的文件或文件夹"
            stats.log(warning_msg)
            print(warning_msg)
            sys.exit(0)

        start_msg = f"准备处理 {total_items} 个项目（{len(items['files'])} 个文件，{len(items['folders'])} 个文件夹）"
        stats.log(start_msg)
        print(start_msg)

        # 获取基础路径（用于计算相对路径）
        base_path = safe_abspath(args.folder_path)

        # 根据线程数选择执行模式
        if args.threads > 1:
            run_tasks_concurrently(items, args, base_path)
        else:
            # 顺序执行
            for i, file_path in enumerate(items['files'], 1):
                print(f"\n[{i}/{len(items['files'])}] 处理文件: {file_path}")
                process_file(file_path, args, base_path)

            for i, folder_path in enumerate(items['folders'], 1):
                print(f"\n[{i}/{len(items['folders'])}] 处理文件夹: {folder_path}")
                process_folder(folder_path, args, base_path)

    finally:
        # 打印最终统计信息
        stats.print_final_stats()

        # 确保释放锁（如果已获取）
        if lock_acquired:
            release_lock()
            stats.log("已释放全局锁")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n程序被用户中断")
        stats.print_final_stats()
        # 只有获取了锁的实例才释放锁
        if lock_owner:
            release_lock()
        sys.exit(1)
    except Exception as e:
        print(f"\n程序异常退出: {e}")
        stats.print_final_stats()
        # 只有获取了锁的实例才释放锁
        if lock_owner:
            release_lock()
        sys.exit(1)
