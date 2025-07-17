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
        self.par2_failed_items = []  # 存储恢复记录生成失败的项目
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

    def add_par2_failure(self, item_type, item_path, archive_files):
        """记录恢复记录生成失败的项目"""
        par2_failure_info = {
            'type': item_type,
            'path': item_path,
            'archive_files': archive_files,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        self.par2_failed_items.append(par2_failure_info)

        self.log(f"⚠ 恢复记录生成失败{item_type}: {item_path}")
        self.log(f"  压缩文件已成功创建，但无法生成恢复记录")

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

        if self.par2_failed_items:
            stats_message += "恢复记录生成失败项目:\n"
            stats_message += "-" * 40 + "\n"
            for i, item in enumerate(self.par2_failed_items, 1):
                stats_message += f"{i}. {item['type']}: {item['path']}\n"
                stats_message += f"   时间: {item['timestamp']}\n"
                stats_message += f"   压缩文件: {', '.join(item['archive_files'])}\n"
                stats_message += f"   说明: 压缩成功但无恢复记录，建议手动生成PAR2文件\n\n"

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

    return os.path.join(temp_dir, '7z_comp_lock')


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

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        # 提交任务
        for p in items['files']:
            futures.append(executor.submit(_dispatch, p, 'file'))
        for p in items['folders']:
            futures.append(executor.submit(_dispatch, p, 'folder'))

        try:
            for fut in as_completed(futures):
                # 触发异常重抛，便于主线程感知
                fut.result()
        except KeyboardInterrupt:
            print("\n检测到用户中断，正在取消剩余任务 ...")
            executor.shutdown(wait=False, cancel_futures=True)
            raise



def create_unique_tmp_dir(base_dir, debug=False):
    """
    在指定基础目录中创建唯一的临时目录

    Args:
        base_dir: 基础目录路径
        debug: 是否输出调试信息

    Returns:
        str: 创建的临时目录的绝对路径，如果创建失败返回None
    """
    try:
        timestamp = str(int(time.time() * 1000))
        thread_id = threading.get_ident()
        unique_id = str(uuid.uuid4().hex[:8])  # 8-char random hex for extra safety
        unique_suffix = f"{timestamp}_{thread_id}_{unique_id}"
        tmp_dir_name = f"tmp_{unique_suffix}"

        tmp_dir_path = os.path.join(base_dir, tmp_dir_name)
        tmp_dir_abs_path = safe_abspath(tmp_dir_path)

        if safe_makedirs(tmp_dir_abs_path, exist_ok=False, debug=debug):
            if debug:
                print(f"成功创建临时目录: {tmp_dir_abs_path}")
            return tmp_dir_abs_path
        else:
            if debug:
                print(f"创建临时目录失败: {tmp_dir_abs_path}")
            return None

    except Exception as e:
        if debug:
            print(f"创建临时目录时出现异常: {e}")
        return None


def cleanup_tmp_dir(tmp_dir_path, debug=False):
    """
    清理并删除临时目录

    Args:
        tmp_dir_path: 临时目录路径
        debug: 是否输出调试信息

    Returns:
        bool: 是否成功清理
    """
    try:
        if not safe_exists(tmp_dir_path, debug):
            if debug:
                print(f"临时目录不存在，无需清理: {tmp_dir_path}")
            return True

        # 递归删除临时目录及其内容
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
            print(f"清理临时目录时出现异常: {e}")
        return False


def move_files_to_final_destination(source_files, target_dir, rel_path, debug=False):
    """
    将文件移动到最终目标位置，保持相对路径结构

    Args:
        source_files: 源文件列表
        target_dir: 目标基础目录
        rel_path: 相对路径（用于保持目录结构）
        debug: 是否输出调试信息

    Returns:
        tuple: (success, moved_files) - 是否成功，移动后的文件列表
    """
    moved_files = []

    try:
        # 计算最终目标目录
        rel_dir = os.path.dirname(rel_path) if rel_path != '.' else ''
        if rel_dir and rel_dir != '.':
            final_target_dir = os.path.join(target_dir, rel_dir)
            safe_makedirs(final_target_dir, exist_ok=True, debug=debug)
        else:
            final_target_dir = target_dir

        # 移动每个文件
        for source_file in source_files:
            if not safe_exists(source_file, debug):
                if debug:
                    print(f"源文件不存在，跳过移动: {source_file}")
                continue

            filename = os.path.basename(source_file)
            target_file = os.path.join(final_target_dir, filename)

            if safe_move(source_file, target_file, debug):
                moved_files.append(target_file)
                if debug:
                    print(f"成功移动文件: {source_file} -> {target_file}")
            else:
                if debug:
                    print(f"移动文件失败: {source_file} -> {target_file}")
                # 移动失败时，清理已移动的文件
                for cleanup_file in moved_files:
                    safe_remove(cleanup_file, debug)
                return False, []

        return True, moved_files

    except Exception as e:
        if debug:
            print(f"移动文件到最终目标位置时出现异常: {e}")
        # 清理已移动的文件
        for cleanup_file in moved_files:
            safe_remove(cleanup_file, debug)
        return False, []


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


def check_required_tools(no_par2=False):
    """检查7z和parpar是否在PATH中可用"""
    missing_tools = []

    # 检查7z
    try:
        result = subprocess.run(['7z'],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                shell=is_windows(),
                                encoding='utf-8',
                                errors='replace')
        # 7z命令存在时通常会输出版本信息到stdout或stderr
        if result.returncode != 0 and not result.stdout and not result.stderr:
            missing_tools.append('7z')
    except Exception:
        missing_tools.append('7z')

    # 只有在不跳过PAR2恢复记录时才检查parpar
    if not no_par2:
        try:
            result = subprocess.run(['parpar', '--version'],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    shell=is_windows(),
                                    encoding='utf-8',
                                    errors='replace')
            # parpar --version应该正常退出并输出版本信息
            if result.returncode != 0:
                missing_tools.append('parpar')
        except Exception:
            missing_tools.append('parpar')

    if missing_tools:
        error_msg = f"错误: 以下必需工具未在PATH中找到: {', '.join(missing_tools)}\n"
        error_msg += "请确保以下工具已安装并在PATH环境变量中:\n"
        if '7z' in missing_tools:
            error_msg += "- 7z: 7-Zip命令行工具 (https://www.7-zip.org/)\n"
        if 'parpar' in missing_tools:
            error_msg += "- parpar: PAR2恢复记录生成工具 (https://github.com/animetosho/ParPar)\n"
            error_msg += "  提示: 如果不需要PAR2恢复记录，可以使用 --no-rec 参数跳过此检查\n"

        print(error_msg)
        sys.exit(1)


def quote_path_for_7z(path):
    """为 7‑Zip CLI 安全引用路径（支持包含 * 通配符的绝对路径）。"""
    import os, platform, shlex

    wildcard_part = ""
    if path.endswith(os.sep + "*"):
        wildcard_part = os.sep + "*"; dir_part = path[:-2]
    elif path.endswith("/*"):
        wildcard_part = "/*"; dir_part = path[:-2]
    else:
        dir_part = path

    if platform.system() == "Windows":
        short_dir = get_short_path_name(dir_part) or dir_part
        if os.path.basename(short_dir).startswith("-") and not wildcard_part:
            short_dir = os.path.join(os.path.dirname(short_dir), "." + os.sep + os.path.basename(short_dir))
        safe_path = short_dir + wildcard_part
        safe_path = safe_path.replace('"', '\\"') if '"' in safe_path else safe_path
        return f'"{safe_path}"'
    else:
        unix_path = dir_part + wildcard_part
        if os.path.basename(dir_part).startswith("-") and not wildcard_part:
            unix_path = os.path.join(os.path.dirname(dir_part), "./" + os.path.basename(dir_part)) + wildcard_part
        return shlex.quote(unix_path)



def execute_7z_command(z7_cmd, debug=False):
    """执行7z命令，处理编码问题"""
    cmd_str = ' '.join(z7_cmd)

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
            cleaned_cmd = [arg.strip('"\'') for arg in z7_cmd]
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


def execute_parpar_command(parpar_cmd, debug=False):
    """执行parpar命令"""
    cmd_str = ' '.join(parpar_cmd)

    try:
        # 设置环境变量以确保正确的编码处理
        env = os.environ.copy()
        if is_windows():
            env['PYTHONIOENCODING'] = 'utf-8'
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
            env['LC_ALL'] = 'C.UTF-8'
            env['LANG'] = 'C.UTF-8'
            cleaned_cmd = [arg.strip('"\'') for arg in parpar_cmd]
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
        class MockResult:
            def __init__(self, returncode, stdout, stderr):
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = stderr

        return MockResult(-1, "", str(e))


def quote_path_for_parpar(path):
    """为parpar命令正确引用路径，但保持完整文件名不使用短路径"""
    if platform.system() == 'Windows':
        # 对于Windows，不使用短路径，保持原始长路径
        # 只处理以 '-' 开头的文件名
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


def generate_par2_for_file(file_path, debug=False):
    """为单个文件生成PAR2文件"""
    try:
        # 获取文件所在目录
        file_dir = os.path.dirname(file_path)
        file_name = os.path.basename(file_path)

        # PAR2文件将在同一目录下生成
        par2_output = os.path.join(file_dir, f"{file_name}.par2")

        # 构建 parpar 命令
        parpar_cmd = [
            'parpar',
            '-s', '0.6w',
            '--noindex',
            '-r', '5%',
            '--unicode',
            '--recovery-files', '1',
            '-R',
            '-o', quote_path_for_parpar(par2_output),
            quote_path_for_parpar(file_path)  # 使用完整长路径，不使用短路径
        ]

        cmd_str = ' '.join(parpar_cmd)

        if debug:
            print(f"生成PAR2文件: {file_path}")
            print(f"执行命令: {cmd_str}")

        # 执行 parpar 命令
        result = execute_parpar_command(parpar_cmd, debug)

        if debug:
            print(f"PAR2生成结果 - 返回码: {result.returncode}")
            if result.stdout:
                print(f"标准输出: {result.stdout}")
            if result.stderr:
                print(f"错误输出: {result.stderr}")

        if result.returncode == 0:
            # 检查PAR2文件是否真的生成了
            if safe_exists(par2_output, debug):
                if debug:
                    print(f"PAR2文件生成成功: {par2_output}")
                return True, par2_output
            else:
                if debug:
                    print(f"PAR2命令成功但文件不存在: {par2_output}")
                return False, None
        else:
            if debug:
                print(f"PAR2生成失败，返回码: {result.returncode}")
            return False, None

    except Exception as e:
        if debug:
            print(f"生成PAR2时出现异常: {e}")
        return False, None


def append_par2_to_file(archive_file, par2_file, debug=False):
    """将PAR2文件内容追加到压缩文件末尾"""
    try:
        # 读取PAR2文件的二进制内容
        with open(safe_path_for_operation(par2_file, debug), 'rb') as par2_f:
            par2_content = par2_f.read()

        # 将PAR2内容追加到压缩文件末尾
        with open(safe_path_for_operation(archive_file, debug), 'ab') as archive_f:
            archive_f.write(par2_content)

        if debug:
            print(f"PAR2内容已追加到: {archive_file}")

        return True

    except Exception as e:
        if debug:
            print(f"追加PAR2内容失败: {e}")
        return False


def process_par2_for_archives(archive_files, embed_par2=True, debug=False):
    """为压缩文件列表生成PAR2恢复记录，可选择是否嵌入到7z文件中"""
    if not archive_files:
        return False, []

    try:
        generated_par2_files = []

        # 第一阶段：为所有文件生成PAR2
        for archive_file in archive_files:
            success, par2_file = generate_par2_for_file(archive_file, debug)
            if success and par2_file:
                generated_par2_files.append((archive_file, par2_file))
            else:
                # 如果任何一个PAR2生成失败，清理已生成的PAR2文件
                if debug:
                    print(f"PAR2生成失败，清理已生成的PAR2文件")
                for _, cleanup_par2 in generated_par2_files:
                    safe_remove(cleanup_par2, debug)
                return False, []

        if embed_par2:
            # 第二阶段：将所有PAR2内容追加到对应的压缩文件
            for archive_file, par2_file in generated_par2_files:
                if not append_par2_to_file(archive_file, par2_file, debug):
                    # 如果追加失败，不清理压缩文件，只清理PAR2文件
                    if debug:
                        print(f"PAR2追加失败，清理PAR2文件")
                    for _, cleanup_par2 in generated_par2_files:
                        safe_remove(cleanup_par2, debug)
                    return False, []

            # 第三阶段：清理临时PAR2文件
            for _, par2_file in generated_par2_files:
                safe_remove(par2_file, debug)

            if debug:
                print(f"成功为 {len(archive_files)} 个文件生成并嵌入PAR2恢复记录")

            return True, []
        else:
            # 不嵌入模式：保留PAR2文件，返回文件列表用于后续移动
            par2_files = [par2_file for _, par2_file in generated_par2_files]

            if debug:
                print(f"成功为 {len(archive_files)} 个文件生成独立PAR2恢复记录")
                for par2_file in par2_files:
                    print(f"  - PAR2文件: {par2_file}")

            return True, par2_files

    except Exception as e:
        if debug:
            print(f"处理PAR2时出现异常: {e}")
        return False, []


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


def is_parted_profile(profile):
    """检查profile是否为分卷模式"""
    return profile.startswith('parted-')


def parse_arguments():
    """解析命令行参数（新增 --threads 选项）"""
    parser = argparse.ArgumentParser(description='7z压缩工具（含PAR2恢复记录，多线程支持）')
    parser.add_argument('folder_path', help='要处理的文件夹路径')

    # 并发线程数（新增）
    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=1,
        help='同时进行压缩的任务数 (默认: 1)'
    )

    parser.add_argument('--dry-run', action='store_true', help='仅预览操作，不执行实际命令')
    parser.add_argument('--depth', type=int, default=0, help='压缩处理的深度级别 (0, 1, 2, ...)')
    parser.add_argument('-p', '--password', help='设置压缩包密码')
    parser.add_argument('-d', '--delete', action='store_true', help='压缩成功后删除原文件/文件夹')
    parser.add_argument(
        '--profile',
        type=profile_type,
        default='best',
        help="压缩配置文件: 'store', 'best', 'fastest', 或 'parted-XXunit' (例如: 'parted-10g')"
    )
    parser.add_argument('--debug', action='store_true', help='显示调试信息')
    parser.add_argument('--no-lock', action='store_true', help='不使用全局锁（谨慎使用）')
    parser.add_argument('--lock-timeout', type=int, default=30, help='锁定超时时间（最大重试次数）')
    parser.add_argument('--out', help='指定压缩后文件的输出目录路径')
    parser.add_argument('--no-emb', action='store_true', help='生成独立的PAR2文件，不嵌入到7z文件中')
    parser.add_argument('--no-rec', action='store_true', help='不生成PAR2恢复记录（跳过parpar工具检查）')

    # 过滤相关
    parser.add_argument('--skip-files', action='store_true', help='跳过文件，仅处理文件夹')
    parser.add_argument('--skip-folders', action='store_true', help='跳过文件夹，仅处理文件')
    parser.add_argument('--ext-skip-folder-tree', action='store_true',
                        help='当指定--skip-${ext}参数时，跳过包含对应扩展名文件的整个文件夹')

    args, unknown = parser.parse_known_args()

    # 处理 --skip-<ext>
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
    return args



def is_windows():
    """检查当前操作系统是否为Windows"""
    return platform.system() == 'Windows'


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
                # 新增：检查文件夹是否包含要跳过的扩展名文件（如果启用了ext-skip-folder-tree）
                if args.ext_skip_folder_tree and args.skip_extensions:
                    if folder_contains_skip_extensions(folder_path, args.skip_extensions, args.debug):
                        if args.debug:
                            print(f"跳过包含排除扩展名文件的文件夹: {folder_path}")
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

                    # 新增：检查文件夹是否包含要跳过的扩展名文件（如果启用了ext-skip-folder-tree）
                    if args.ext_skip_folder_tree and args.skip_extensions:
                        if folder_contains_skip_extensions(abs_path, args.skip_extensions, args.debug):
                            if args.debug:
                                print(f"跳过包含排除扩展名文件的文件夹: {abs_path}")
                            continue

                    items['folders'].append(abs_path)

    return items


def normalize_volume_size(size_str, unit_str):
    """
    将用户输入的分卷大小标准化为7z可识别的格式

    Args:
        size_str: 大小数字字符串
        unit_str: 单位字符串（g/gb/m/mb/k/kb，不区分大小写）

    Returns:
        str: 7z格式的分卷大小参数（如 "10g", "100m", "500k"）
    """
    unit = unit_str.lower()

    # 将所有单位标准化为7z的简短格式
    if unit in ['g', 'gb']:
        return f"{size_str}g"
    elif unit in ['m', 'mb']:
        return f"{size_str}m"
    elif unit in ['k', 'kb']:
        return f"{size_str}k"
    else:
        # 默认使用原始输入（不应该到达这里，因为profile_type已经验证过）
        return f"{size_str}{unit}"


def build_7z_switches(profile, password, delete_files=False):
    """构建7z命令开关参数"""
    switches = []

    # 如果需要删除源文件，添加-sdel参数
    # 7z只有在压缩成功时才会执行删除操作，所以这是安全的
    if delete_files:
        switches.append('-sdel')

    # 处理 'store' 和 'parted-XXunit' 配置
    if profile.startswith('parted-') or profile == 'store':
        switches.extend([
            '-m0=Copy',  # 仅存储，不压缩
            '-ms=off',  # 不使用固实压缩
        ])
        # 如果是分卷模式，添加分卷大小参数
        if profile.startswith('parted-'):
            # 支持多种单位格式：g/gb/m/mb/k/kb
            match = re.match(r'^parted-(\d+)(g|gb|m|mb|k|kb)$', profile, re.IGNORECASE)
            if match:
                size = match.group(1)
                unit = match.group(2)
                volume_size = normalize_volume_size(size, unit)
                switches.append(f'-v{volume_size}')

    # 处理 'fastest' 配置
    elif profile == 'fastest':
        switches.extend([
            '-mx=1',  # 最快压缩级别
            '-ms=off',  # 不使用固实压缩
            '-md=256m',  # 大字典：256MB
        ])

    # 处理 'best' 配置
    else:  # best
        switches.extend([
            '-mx=9',  # 最佳压缩级别
            '-ms=on',  # 使用固实压缩
            '-md=256m',  # 大字典：256MB
        ])

    # 添加密码参数（如果提供了密码）
    if password:
        switches.extend([f'-p{password}', '-mhe=on'])  # -mhe=on选项加密文件头

    return switches


def find_and_rename_7z_files(temp_name_prefix, target_name_prefix, search_dir, debug=False):
    """
    查找并重命名7z文件（支持分卷）

    Args:
        temp_name_prefix: 临时文件名前缀（如 "temp_archive"）
        target_name_prefix: 目标文件名前缀（如 "folder_name"）
        search_dir: 搜索目录
        debug: 是否输出调试信息

    Returns:
        tuple: (success, moved_files) - 是否成功，移动的文件列表
    """
    moved_files = []

    # 首先查找单个7z文件
    single_7z = os.path.join(search_dir, f"{temp_name_prefix}.7z")

    if safe_exists(single_7z, debug):
        # 找到单个7z文件
        target_file = os.path.join(search_dir, f"{target_name_prefix}.7z")

        if debug:
            print(f"找到单个7z文件: {single_7z}")
            print(f"目标文件: {target_file}")

        try:
            # 使用安全的移动函数
            if safe_move(single_7z, target_file, debug):
                moved_files.append(target_file)
                if debug:
                    print(f"成功移动文件: {single_7z} -> {target_file}")
                return True, moved_files
            else:
                print(f"移动单个7z文件时出错")
                return False, []

        except Exception as e:
            print(f"移动单个7z文件时出错: {e}")
            return False, []

    # 如果没有找到单个7z文件，查找分卷文件
    # 7z分卷格式：temp_archive.7z.001, temp_archive.7z.002, ...
    part_patterns = [
        f"{temp_name_prefix}.7z.*",
    ]

    part_files = []
    for pattern in part_patterns:
        search_pattern = os.path.join(search_dir, pattern)
        found_files = safe_glob(search_pattern, debug)
        part_files.extend(found_files)

    # 过滤出真正的分卷文件（以数字结尾）
    valid_part_files = []
    for part_file in part_files:
        filename = os.path.basename(part_file)
        # 检查是否符合 temp_archive.7z.001 格式
        pattern = rf'^{re.escape(temp_name_prefix)}\.7z\.(\d+)$'
        if re.match(pattern, filename, re.IGNORECASE):
            valid_part_files.append(part_file)

    # 去重并排序
    valid_part_files = sorted(list(set(valid_part_files)))

    if debug:
        print(f"搜索分卷文件模式: {part_patterns}")
        print(f"找到的分卷文件: {valid_part_files}")

    if not valid_part_files:
        print(f"错误: 没有找到7z文件 {temp_name_prefix}.7z 或分卷文件 {temp_name_prefix}.7z.xxx")
        return False, []

    # 处理分卷文件
    print(f"找到 {len(valid_part_files)} 个分卷文件，开始重命名...")

    try:
        for part_file in valid_part_files:
            # 从文件名中提取分卷编号
            filename = os.path.basename(part_file)

            # 使用正则表达式提取分卷编号
            pattern = rf'^{re.escape(temp_name_prefix)}\.7z\.(\d+)$'
            match = re.match(pattern, filename, re.IGNORECASE)

            if match:
                volume_number = match.group(1)  # 例如 "001", "002"
                target_filename = f"{target_name_prefix}.7z.{volume_number}"
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
    global stats
    file_path = safe_abspath(file_path)
    file_dir = os.path.dirname(file_path)
    file_name = os.path.basename(file_path)
    rel_path = get_relative_path(file_path, base_path)

    final_target_dir = safe_abspath(args.out) if args.out else file_dir
    safe_makedirs(final_target_dir, exist_ok=True, debug=args.debug)

    tmp_dir = create_unique_tmp_dir(os.getcwd(), args.debug)
    if not tmp_dir:
        stats.add_failure('文件', file_path, -1, '创建临时目录失败', '')
        return

    try:
        z7_switches = build_7z_switches(args.profile, args.password, args.delete)
        temp_archive_path = os.path.join(tmp_dir, 'temp_archive.7z')

        z7_cmd = ['7z', 'a', *z7_switches,
                  quote_path_for_7z(temp_archive_path),
                  quote_path_for_7z(file_path)]
        cmd_str = ' '.join(z7_cmd)
        if args.debug:
            print(f"执行命令: {cmd_str}")
        if args.dry_run:
            stats.log(f"[DRY-RUN] {cmd_str}")
            return

        result = execute_7z_command(z7_cmd, args.debug)
        if result.returncode != 0:
            stats.add_failure('文件', file_path, result.returncode,
                              result.stderr or '未知错误', cmd_str)
            return

        final_name = os.path.splitext(os.path.basename(rel_path))[0]
        success, renamed_files = find_and_rename_7z_files(
            'temp_archive', final_name, tmp_dir, args.debug)
        if not (success and renamed_files):
            stats.add_failure('文件', file_path, 0, '重命名7z文件失败', cmd_str)
            return

        all_files_to_move = renamed_files[:]
        if not args.no_rec:
            embed_par2 = not (is_parted_profile(args.profile) or args.no_emb)
            par2_success, par2_files = process_par2_for_archives(
                renamed_files, embed_par2, args.debug)
            if not par2_success:
                stats.add_par2_failure('文件', file_path, renamed_files)
            else:
                all_files_to_move.extend(par2_files)

        moved, _ = move_files_to_final_destination(
            all_files_to_move, final_target_dir, rel_path, args.debug)
        if moved:
            stats.add_success('文件', file_path)
        else:
            stats.add_failure('文件', file_path, 0, '移动文件失败', cmd_str)
    finally:
        cleanup_tmp_dir(tmp_dir, args.debug)



def process_folder(folder_path, args, base_path):
    global stats
    folder_path = safe_abspath(folder_path)
    rel_path = get_relative_path(folder_path, base_path)
    final_target_dir = safe_abspath(args.out) if args.out else os.path.dirname(folder_path)
    safe_makedirs(final_target_dir, exist_ok=True, debug=args.debug)

    tmp_dir = create_unique_tmp_dir(os.getcwd(), args.debug)
    if not tmp_dir:
        stats.add_failure('文件夹', folder_path, -1, '创建临时目录失败', '')
        return

    try:
        z7_switches = build_7z_switches(args.profile, args.password, args.delete)
        temp_archive_path = os.path.join(tmp_dir, 'temp_archive.7z')
        wildcard_input = os.path.join(folder_path, '*')
        z7_cmd = ['7z', 'a', *z7_switches,
                  quote_path_for_7z(temp_archive_path),
                  quote_path_for_7z(wildcard_input)]
        cmd_str = ' '.join(z7_cmd)
        if args.debug:
            print(f"执行命令: {cmd_str}")
        if args.dry_run:
            stats.log(f"[DRY-RUN] {cmd_str}")
            return

        result = execute_7z_command(z7_cmd, args.debug)
        if result.returncode != 0:
            stats.add_failure('文件夹', folder_path, result.returncode,
                              result.stderr or '未知错误', cmd_str)
            return

        final_name = os.path.basename(rel_path)
        success, renamed_files = find_and_rename_7z_files(
            'temp_archive', final_name, tmp_dir, args.debug)
        if not (success and renamed_files):
            stats.add_failure('文件夹', folder_path, 0, '重命名7z文件失败', cmd_str)
            return

        all_files_to_move = renamed_files[:]
        if not args.no_rec:
            embed_par2 = not (is_parted_profile(args.profile) or args.no_emb)
            par2_success, par2_files = process_par2_for_archives(
                renamed_files, embed_par2, args.debug)
            if not par2_success:
                stats.add_par2_failure('文件夹', folder_path, renamed_files)
            else:
                all_files_to_move.extend(par2_files)

        moved, _ = move_files_to_final_destination(
            all_files_to_move, final_target_dir, rel_path, args.debug)
        if moved:
            if args.delete:
                safe_delete_folder(folder_path, args.dry_run)
            stats.add_success('文件夹', folder_path)
        else:
            stats.add_failure('文件夹', folder_path, 0, '移动文件失败', cmd_str)
    finally:
        cleanup_tmp_dir(tmp_dir, args.debug)


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

    # 解析参数（需要先解析参数才能知道是否使用--no-rec）
    args = parse_arguments()

    # 新增：分卷模式下PAR2处理逻辑调整
    if is_parted_profile(args.profile):
        if not args.no_rec:
            # 分卷模式且未禁用PAR2：强制使用独立PAR2（不嵌入）
            if not args.no_emb:
                args.no_emb = True  # 自动设置为独立模式
                print("注意: 分卷模式自动使用独立PAR2文件（不嵌入），以确保分卷文件格式兼容性")
        # 如果指定了--no-rec，则不生成PAR2文件（保持原有逻辑）

    # 检查必需工具（根据--no-rec参数决定是否检查parpar）
    check_required_tools(no_par2=args.no_rec)

    # 初始化统计信息
    stats.log("程序开始执行")

    # 验证参数组合
    if args.skip_files and args.skip_folders:
        error_msg = "错误: 不能同时指定 --skip-files 和 --skip-folders，这样不会有任何需要处理的项目"
        stats.log(error_msg)
        print(error_msg)
        sys.exit(1)

    # 验证ext-skip-folder-tree参数的使用条件
    if args.ext_skip_folder_tree:
        if not args.skip_extensions:
            error_msg = "错误: --ext-skip-folder-tree 参数只有在指定 --skip-${ext} 参数时才有效"
            stats.log(error_msg)
            print(error_msg)
            sys.exit(1)

        if args.skip_folders:
            warning_msg = "警告: --ext-skip-folder-tree 与 --skip-folders 组合时，逻辑与原先一致（不处理文件夹）"
            stats.log(warning_msg)
            print(warning_msg)

    # 验证--no-rec与--no-emb的组合
    if args.no_rec and args.no_emb:
        warning_msg = "警告: --no-rec 与 --no-emb 同时使用时，--no-emb 参数无效（因为不会生成PAR2文件）"
        stats.log(warning_msg)
        print(warning_msg)

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

    # 显示PAR2恢复记录设置
    if args.no_rec:
        rec_msg = "PAR2恢复记录: 已禁用（--no-rec参数）"
    elif is_parted_profile(args.profile):
        rec_msg = "PAR2恢复记录: 生成独立文件（分卷模式自动设置）"
    elif args.no_emb:
        rec_msg = "PAR2恢复记录: 生成独立文件（--no-emb参数）"
    else:
        rec_msg = "PAR2恢复记录: 嵌入到7z文件中"
    stats.log(rec_msg)
    print(rec_msg)

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
            stats.log(f"- 扩展名文件夹树过滤: {args.ext_skip_folder_tree}")
            stats.log(f"- 跳过PAR2恢复记录: {args.no_rec}")
            stats.log(f"- 分卷模式: {is_parted_profile(args.profile)}")

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
            # 顺序执行（与旧版保持一致）
            for i, file_path in enumerate(items['files'], 1):
                print(f"\n[{i}/{len(items['files'])}] 处理文件: {file_path}")
                process_file(file_path, args, base_path)

            for i, folder_path in enumerate(items['folders'], 1):
                print(f"\n[{i}/{len(items['folders'])}] 处理文件夹: {folder_path}")
                process_folder(folder_path, args, base_path)

    finally:
        stats.print_final_stats()
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
