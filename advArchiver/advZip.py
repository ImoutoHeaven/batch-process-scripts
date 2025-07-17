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
import uuid
import threading
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

    return os.path.join(temp_dir, 'zip_comp_lock')


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

    total = len(items['files']) + len(items['folders'])
    print(f"并发模式: 启动 {args.threads} 个工作线程，任务总数 {total}")

    # 线程池执行
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for p in items['files']:
            futures.append(executor.submit(_dispatch, p, 'file'))
        for p in items['folders']:
            futures.append(executor.submit(_dispatch, p, 'folder'))

        try:
            for fut in as_completed(futures):
                fut.result()          # 触发异常回溯到主线程
        except KeyboardInterrupt:
            print("\n检测到用户中断，正在取消剩余任务 ...")
            executor.shutdown(wait=False, cancel_futures=True)
            raise



def build_folder_input_path(folder_path: str, debug: bool = False) -> str:
    """
    构造 7-Zip 用的文件夹输入参数：
        • Windows  : “C:\\Path\\To\\Folder\\*”
        • 非 Windows: “/path/to/folder/*”
    - Windows 下先转短路径再追加通配符，最后整体加引号；
    - *nix 下直接返回绝对路径+通配符，不加引号（subprocess shell=False）。
    """
    # 取得绝对路径并保证末尾分隔符
    abs_path = safe_abspath(folder_path, debug)
    if not abs_path.endswith(os.sep):
        abs_path += os.sep

    if is_windows():
        # 先转短路径（去掉末尾分隔符再转）
        short_base = get_short_path_name(abs_path.rstrip(os.sep)) or abs_path.rstrip(os.sep)
        wildcard_path = f'{short_base}{os.sep}*'
        # Windows 走 shell=True，因此需要整体加引号并转义内部引号
        if '"' in wildcard_path:
            wildcard_path = wildcard_path.replace('"', '\\"')
        return f'"{wildcard_path}"'
    else:
        # 非 Windows 直接返回，无需额外引号
        return f"{abs_path}*"


def create_unique_tmp_dir(debug=False):
    """
    在脚本当前工作目录创建唯一的临时目录

    Returns:
        str: 创建的临时目录的绝对路径，失败时返回None
    """
    try:
        # 获取脚本当前工作目录
        script_cwd = os.getcwd()

        # 生成唯一后缀
        timestamp = str(int(time.time() * 1000))
        thread_id = threading.get_ident()
        unique_id = str(uuid.uuid4().hex[:8])  # 8-char random hex for extra safety
        unique_suffix = f"{timestamp}_{thread_id}_{unique_id}"
        tmp_dir_name = f"tmp_{unique_suffix}"

        # 创建临时目录的绝对路径
        tmp_dir_path = os.path.join(script_cwd, tmp_dir_name)

        # 创建目录
        if safe_makedirs(tmp_dir_path, exist_ok=False, debug=debug):
            if debug:
                print(f"成功创建临时目录: {tmp_dir_path}")
            return tmp_dir_path
        else:
            if debug:
                print(f"创建临时目录失败: {tmp_dir_path}")
            return None

    except Exception as e:
        if debug:
            print(f"创建临时目录时出错: {e}")
        return None


def cleanup_tmp_dir(tmp_dir_path, debug=False):
    """
    清理并删除临时目录

    Args:
        tmp_dir_path: 临时目录的绝对路径
        debug: 是否输出调试信息

    Returns:
        bool: 是否成功清理
    """
    try:
        if not tmp_dir_path or not safe_exists(tmp_dir_path, debug):
            if debug:
                print(f"临时目录不存在，无需清理: {tmp_dir_path}")
            return True

        # 检查目录是否为空
        try:
            dir_contents = os.listdir(safe_path_for_operation(tmp_dir_path, debug))
            if dir_contents:
                if debug:
                    print(f"临时目录不为空，包含: {dir_contents}")
                # 强制删除目录及其内容
                if safe_rmtree(tmp_dir_path, debug):
                    if debug:
                        print(f"成功强制删除非空临时目录: {tmp_dir_path}")
                    return True
                else:
                    if debug:
                        print(f"强制删除临时目录失败: {tmp_dir_path}")
                    return False
            else:
                # 目录为空，直接删除
                if safe_rmdir(tmp_dir_path, debug):
                    if debug:
                        print(f"成功删除空临时目录: {tmp_dir_path}")
                    return True
                else:
                    if debug:
                        print(f"删除空临时目录失败: {tmp_dir_path}")
                    return False

        except Exception as e:
            if debug:
                print(f"检查临时目录内容时出错: {e}")
            # 尝试强制删除
            if safe_rmtree(tmp_dir_path, debug):
                if debug:
                    print(f"成功强制删除临时目录: {tmp_dir_path}")
                return True
            else:
                if debug:
                    print(f"强制删除临时目录失败: {tmp_dir_path}")
                return False

    except Exception as e:
        if debug:
            print(f"清理临时目录时出错: {e}")
        return False


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


def check_required_tools(skip_parpar=False):
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

    # 检查parpar（如果需要）
    if not skip_parpar:
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

        print(error_msg)
        sys.exit(1)


def quote_path_for_7z(path):
    """为7z命令正确引用路径，处理特殊字符和以-开头的文件名"""
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


def process_par2_for_archives(archive_files, debug=False):
    """为压缩文件列表生成独立的PAR2恢复记录"""
    if not archive_files:
        return False, []

    try:
        generated_par2_files = []

        # 为所有文件生成PAR2
        for archive_file in archive_files:
            success, par2_file = generate_par2_for_file(archive_file, debug)
            if success and par2_file:
                generated_par2_files.append(par2_file)
            else:
                # 如果任何一个PAR2生成失败，清理已生成的PAR2文件
                if debug:
                    print(f"PAR2生成失败，清理已生成的PAR2文件")
                for cleanup_par2 in generated_par2_files:
                    safe_remove(cleanup_par2, debug)
                return False, []

        if debug:
            print(f"成功为 {len(archive_files)} 个文件生成独立PAR2恢复记录")
            for par2_file in generated_par2_files:
                print(f"  - PAR2文件: {par2_file}")

        return True, generated_par2_files

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

    raise argparse.ArgumentTypeError(
        f"'{value}' 不是一个有效的配置。请选择 'store', 'best', 或 'fastest'。"
    )


def code_page_type(value):
    """用于argparse的自定义类型，以验证code-page参数"""
    if value == 'mcu':
        return value

    # 检查是否为数字代码页
    try:
        code_page = int(value)
        if code_page > 0:
            return str(code_page)
    except ValueError:
        pass

    raise argparse.ArgumentTypeError(
        f"'{value}' 不是一个有效的代码页。请使用 'mcu' 或正整数代码页编号（如 936, 932, 65001）。"
    )


def parse_arguments():
    """解析命令行参数（新增 -t / --threads 并默认 1）"""
    parser = argparse.ArgumentParser(description='ZIP压缩工具（含PAR2恢复记录）')
    parser.add_argument('folder_path', help='要处理的文件夹路径')
    parser.add_argument('--dry-run', action='store_true', help='仅预览操作，不执行实际命令')
    parser.add_argument('--depth', type=int, default=0, help='压缩处理的深度级别 (0, 1, 2, ...)')
    parser.add_argument('-p', '--password', help='设置压缩包密码')
    parser.add_argument('-d', '--delete', action='store_true', help='压缩成功后删除原文件/文件夹')
    parser.add_argument(
        '--profile',
        type=profile_type,
        default='best',
        help="压缩配置文件: 'store' (仅存储), 'best' (最佳压缩), 'fastest' (最快压缩)"
    )
    parser.add_argument(
        '--code-page',
        type=code_page_type,
        default='mcu',
        help="ZIP文件名编码: 'mcu' (UTF-8), 或数字代码页 (936=GBK, 932=Shift-JIS, 65001=UTF-8)"
    )
    parser.add_argument('--debug', action='store_true', help='显示调试信息')
    parser.add_argument('--no-lock', action='store_true', help='不使用全局锁（谨慎使用）')
    parser.add_argument('--lock-timeout', type=int, default=30, help='锁定超时时间（最大重试次数）')
    parser.add_argument('--out', help='指定压缩后文件的输出目录路径')
    parser.add_argument('--no-rec', action='store_true', help='不生成PAR2恢复记录文件')

    # 线程数（新增）
    parser.add_argument('-t', '--threads', type=int, default=1,
                        help='同时进行的压缩任务数，默认为 1')

    # 过滤参数
    parser.add_argument('--skip-files', action='store_true', help='跳过文件，仅处理文件夹')
    parser.add_argument('--skip-folders', action='store_true', help='跳过文件夹，仅处理文件')
    parser.add_argument('--ext-skip-folder-tree', action='store_true',
                        help='与 --skip-扩展名 配合使用，跳过包含指定扩展名文件的整个文件夹树')

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

    # 合法性检查：线程数必须 ≥1
    if args.threads < 1:
        print("错误: --threads 必须为正整数")
        sys.exit(1)

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
                # 检查是否需要应用扩展名文件夹树过滤
                if (args.ext_skip_folder_tree and
                        args.skip_extensions and
                        not args.skip_folders):

                    if folder_contains_skip_extensions(folder_path, args.skip_extensions, args.debug):
                        if args.debug:
                            print(f"跳过包含指定扩展名文件的文件夹: {folder_path}")
                    else:
                        items['folders'].append(folder_path)
                else:
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

                    # 检查是否需要应用扩展名文件夹树过滤
                    if (args.ext_skip_folder_tree and
                            args.skip_extensions and
                            not args.skip_folders):

                        if folder_contains_skip_extensions(abs_path, args.skip_extensions, args.debug):
                            if args.debug:
                                print(f"跳过包含指定扩展名文件的文件夹: {abs_path}")
                            continue

                    items['folders'].append(abs_path)

    return items


def build_7z_switches(profile, password, code_page, delete_files=False):
    """构建7z命令开关参数"""
    switches = []

    # 指定ZIP格式
    switches.append('-tzip')

    # 如果需要删除源文件，添加-sdel参数
    # 7z只有在压缩成功时才会执行删除操作，所以这是安全的
    if delete_files:
        switches.append('-sdel')

    # 处理编码参数
    if code_page == 'mcu':
        switches.append('-mcu=on')
    else:
        switches.append(f'-mcp={code_page}')

    # 处理不同的压缩配置 - ZIP格式使用-mx参数
    if profile == 'store':
        switches.append('-mx=0')  # 仅存储，不压缩
    elif profile == 'fastest':
        switches.extend([
            '-mx=1',  # 最快压缩级别
            '-mfb=32',  # 字典大小：32
        ])
    else:  # best
        switches.extend([
            '-mx=9',  # 最佳压缩级别
            '-mfb=256',  # 字典大小：256
        ])

    # 添加密码参数（如果提供了密码）
    # ZIP格式不支持加密文件头，使用引号包围密码以处理特殊字符
    if password:
        switches.append(f'-p"{password}"')

    return switches


def find_and_rename_zip_file(temp_name_prefix, target_name_prefix, search_dir, debug=False):
    """
    查找并重命名ZIP文件

    Args:
        temp_name_prefix: 临时文件名前缀（如 "temp_archive"）
        target_name_prefix: 目标文件名前缀（如 "folder_name"）
        search_dir: 搜索目录
        debug: 是否输出调试信息

    Returns:
        tuple: (success, moved_files) - 是否成功，移动的文件列表
    """
    moved_files = []

    # 查找ZIP文件
    zip_file = os.path.join(search_dir, f"{temp_name_prefix}.zip")

    if safe_exists(zip_file, debug):
        # 找到ZIP文件
        target_file = os.path.join(search_dir, f"{target_name_prefix}.zip")

        if debug:
            print(f"找到ZIP文件: {zip_file}")
            print(f"目标文件: {target_file}")

        try:
            # 使用安全的移动函数
            if safe_move(zip_file, target_file, debug):
                moved_files.append(target_file)
                if debug:
                    print(f"成功移动文件: {zip_file} -> {target_file}")
                return True, moved_files
            else:
                print(f"移动ZIP文件时出错")
                return False, []

        except Exception as e:
            print(f"移动ZIP文件时出错: {e}")
            return False, []

    print(f"错误: 没有找到ZIP文件 {temp_name_prefix}.zip")
    return False, []


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
    """处理单个文件的压缩操作（完全使用绝对路径，无 cd 操作）"""
    global stats

    abs_file_path = safe_abspath(file_path)
    file_name = os.path.basename(abs_file_path)
    name_without_ext = os.path.splitext(file_name)[0]

    # 计算相对路径，用于输出结构
    rel_path = get_relative_path(abs_file_path, base_path)

    # 生成最终输出目录（保持原有逻辑）
    if args.out:
        output_dir = safe_abspath(args.out)
        safe_makedirs(output_dir, exist_ok=True, debug=args.debug)
        rel_dir = os.path.dirname(rel_path)
        final_output_dir = os.path.join(output_dir, rel_dir) if rel_dir and rel_dir != '.' else output_dir
        safe_makedirs(final_output_dir, exist_ok=True, debug=args.debug)
    else:
        final_output_dir = os.path.dirname(abs_file_path)

    tmp_dir_path = None
    try:
        tmp_dir_path = create_unique_tmp_dir(args.debug)
        if not tmp_dir_path:
            raise Exception("无法创建临时目录")

        # 组装 7z 命令
        z7_switches = build_7z_switches(args.profile, args.password, args.code_page, args.delete)
        temp_zip_path = os.path.join(tmp_dir_path, "temp_archive.zip")

        z7_cmd = ['7z', 'a', *z7_switches, quote_path_for_7z(temp_zip_path),
                  quote_path_for_7z(abs_file_path)]

        cmd_str = ' '.join(z7_cmd)
        if args.debug:
            print(f"[DEBUG] 7z CMD: {cmd_str}")

        if args.dry_run:
            stats.log(f"[DRY-RUN] 将执行: {cmd_str}")
            return

        stats.log(f"执行: {cmd_str}")
        result = execute_7z_command(z7_cmd, args.debug)

        if result.returncode != 0:
            stats.add_failure('文件', abs_file_path, result.returncode,
                              result.stderr or "未知错误", cmd_str)
            return

        # 重命名、生成 PAR2、移动——保持原有逻辑
        final_name = os.path.splitext(os.path.basename(rel_path))[0]
        temp_zip_file = temp_zip_path
        final_zip_file = os.path.join(tmp_dir_path, f"{final_name}.zip")
        if not safe_move(temp_zip_file, final_zip_file, args.debug):
            stats.add_failure('文件', abs_file_path, 0, "重命名ZIP失败", cmd_str)
            return

        par2_files = []
        if not args.no_rec:
            ok, par2_files = process_par2_for_archives([final_zip_file], args.debug)
            if not ok:
                stats.add_par2_failure('文件', abs_file_path, [final_zip_file])

        target_zip = os.path.join(final_output_dir, f"{final_name}.zip")
        if not safe_move(final_zip_file, target_zip, args.debug):
            stats.add_failure('文件', abs_file_path, 0, "移动ZIP失败", cmd_str)
            return

        for p in par2_files:
            safe_move(p, os.path.join(final_output_dir, os.path.basename(p)), args.debug)

        stats.add_success('文件', abs_file_path)

    except Exception as e:
        stats.add_failure('文件', abs_file_path, -1, str(e),
                          cmd_str if 'cmd_str' in locals() else "未知命令")
        if args.debug:
            import traceback
            traceback.print_exc()
    finally:
        if tmp_dir_path:
            cleanup_tmp_dir(tmp_dir_path, args.debug)



def process_folder(folder_path, args, base_path):
    """处理单个文件夹的压缩操作（完全使用绝对路径，无 cd 操作）"""
    global stats

    abs_folder_path = safe_abspath(folder_path)
    folder_name = os.path.basename(abs_folder_path)
    rel_path = get_relative_path(abs_folder_path, base_path)

    # 输出目录同旧逻辑
    if args.out:
        output_dir = safe_abspath(args.out)
        safe_makedirs(output_dir, exist_ok=True, debug=args.debug)
        rel_dir = os.path.dirname(rel_path)
        final_output_dir = os.path.join(output_dir, rel_dir) if rel_dir and rel_dir != '.' else output_dir
        safe_makedirs(final_output_dir, exist_ok=True, debug=args.debug)
    else:
        final_output_dir = os.path.dirname(abs_folder_path)

    tmp_dir_path = None
    try:
        tmp_dir_path = create_unique_tmp_dir(args.debug)
        if not tmp_dir_path:
            raise Exception("无法创建临时目录")

        z7_switches = build_7z_switches(args.profile, args.password, args.code_page, args.delete)
        temp_zip_path = os.path.join(tmp_dir_path, "temp_archive.zip")
        folder_input = build_folder_input_path(abs_folder_path, args.debug)

        z7_cmd = ['7z', 'a', *z7_switches,
                  quote_path_for_7z(temp_zip_path), folder_input]

        cmd_str = ' '.join(z7_cmd)
        if args.debug:
            print(f"[DEBUG] 7z CMD: {cmd_str}")

        if args.dry_run:
            stats.log(f"[DRY-RUN] 将执行: {cmd_str}")
            return

        stats.log(f"执行: {cmd_str}")
        result = execute_7z_command(z7_cmd, args.debug)

        if result.returncode != 0:
            stats.add_failure('文件夹', abs_folder_path, result.returncode,
                              result.stderr or "未知错误", cmd_str)
            return

        final_name = os.path.basename(rel_path)
        final_zip_file = os.path.join(tmp_dir_path, f"{final_name}.zip")
        if not safe_move(temp_zip_path, final_zip_file, args.debug):
            stats.add_failure('文件夹', abs_folder_path, 0, "重命名ZIP失败", cmd_str)
            return

        par2_files = []
        if not args.no_rec:
            ok, par2_files = process_par2_for_archives([final_zip_file], args.debug)
            if not ok:
                stats.add_par2_failure('文件夹', abs_folder_path, [final_zip_file])

        target_zip = os.path.join(final_output_dir, f"{final_name}.zip")
        if not safe_move(final_zip_file, target_zip, args.debug):
            stats.add_failure('文件夹', abs_folder_path, 0, "移动ZIP失败", cmd_str)
            return

        for p in par2_files:
            safe_move(p, os.path.join(final_output_dir, os.path.basename(p)), args.debug)

        # 若 -sdel 删除后目录为空则清理
        if args.delete and is_folder_empty(abs_folder_path):
            safe_delete_folder(abs_folder_path, args.dry_run)

        stats.add_success('文件夹', abs_folder_path)

    except Exception as e:
        stats.add_failure('文件夹', abs_folder_path, -1, str(e),
                          cmd_str if 'cmd_str' in locals() else "未知命令")
        if args.debug:
            import traceback
            traceback.print_exc()
    finally:
        if tmp_dir_path:
            cleanup_tmp_dir(tmp_dir_path, args.debug)


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

    # 解析参数（需要先解析以确定是否需要检查parpar）
    args = parse_arguments()

    # 检查必需工具（根据--no-rec参数决定是否检查parpar）
    check_required_tools(skip_parpar=args.no_rec)

    # 初始化统计信息
    stats.log("程序开始执行")

    # 验证参数组合
    if args.skip_files and args.skip_folders:
        error_msg = "错误: 不能同时指定 --skip-files 和 --skip-folders，这样不会有任何需要处理的项目"
        stats.log(error_msg)
        print(error_msg)
        sys.exit(1)

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
            stats.log(f"- 扩展名文件夹树过滤: {args.ext_skip_folder_tree}")
            stats.log(f"- 压缩配置: {args.profile}")
            stats.log(f"- 代码页: {args.code_page}")
            stats.log(f"- 生成PAR2: {not args.no_rec}")

            # 检查参数组合的有效性
            if args.ext_skip_folder_tree:
                if not args.skip_extensions:
                    stats.log("警告: --ext-skip-folder-tree 参数只有在指定 --skip-扩展名 参数时才生效")
                elif args.skip_folders:
                    stats.log("提示: --ext-skip-folder-tree 与 --skip-folders 组合时逻辑与原先一致")

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
            # 顺序执行（保持旧行为）
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
