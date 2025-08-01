#!/usr/bin/env python3
"""
Advanced Decompressor Script - Enhanced Version
Supports Windows 10/Debian 12 platforms
Recursively scans and extracts various archive formats including SFX files
Fixed Unicode handling for all subprocess operations
Added Windows short path API support, script locking, and new decompress policies
"""

import os
import sys
import re
import struct
import subprocess
import argparse
import shutil
import time
import threading
import uuid
import glob
import socket
import platform
import random
import signal
import atexit
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Union, Tuple
import stat

# Global verbose flag
VERBOSE = False


# Global interrupt flag for multi-threaded execution
_interrupt_flag = threading.Event()

def set_interrupt_flag():
    """Set the global interrupt flag to signal all threads to stop"""
    global _interrupt_flag
    _interrupt_flag.set()
    if VERBOSE:
        print("  DEBUG: Global interrupt flag set")

def check_interrupt():
    """Check if interrupt has been requested and raise KeyboardInterrupt if so"""
    global _interrupt_flag
    if _interrupt_flag.is_set():
        raise KeyboardInterrupt("Interrupt requested")

def reset_interrupt_flag():
    """Reset the interrupt flag (used at start of main execution)"""
    global _interrupt_flag
    _interrupt_flag.clear()

# --- NEW: unified archive filename parser ---

def parse_archive_filename(filename: str):
    """统一解析归档文件名，返回 base_filename、file_ext、file_ext_extend。

    - file_ext: 最末尾扩展（如 'zip' / 'rar' / '7z' / 'exe' / '001' 等数字）
    - file_ext_extend: 可选扩展，仅可能为 '7z' 或 'part<digits>'，否则空字符串
    """
    parts = filename.split('.')
    if len(parts) < 2:
        # 无扩展名
        return {
            'base_filename': filename,
            'file_ext': '',
            'file_ext_extend': ''
        }

    file_ext = parts[-1].lower()
    file_ext_extend = ''

    if len(parts) >= 3:
        cand = parts[-2].lower()
        if re.fullmatch(r'part\d+', cand) or cand == '7z':
            file_ext_extend = cand
            base_filename = '.'.join(parts[:-2])
        else:
            base_filename = '.'.join(parts[:-1])
    else:
        base_filename = '.'.join(parts[:-1])

    return {
        'base_filename': base_filename,
        'file_ext': file_ext,
        'file_ext_extend': file_ext_extend,
    }

# === Helper: 判断文件是否拥有合法扩展名 ===
def has_valid_extension(filename: str) -> bool:
    """根据自定义规则判断 filename 是否具有“合法扩展名”。

    规则：
    1. 必须包含 '.' 且末段非空；
    2. 若末段中的字符是 ASCII，则只能是大小写字母或数字；
       一旦出现任何 ASCII 非字母数字字符（包括空格、标点、括号等），即判定为非法；
    3. 对于非 ASCII 字符（如中文、日文、Emoji 等）不做限制。
    """
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1]
    if not ext:
        return False
    # 长度限制：常见归档扩展名一般 <6（zip/rar/7z/exe/001/00001 等）
    if len(ext) >= 6:
        return False
    # 仅当包含特定标点符号时才视为无效扩展名
    invalid_chars = '()[]{}（）【】""\'\'<>《》'
    for ch in ext:
        if ch in invalid_chars:
            return False
    return True

class SFXDetector:
    """Detects if an EXE file is a self-extracting archive by analyzing file headers"""

    # Common archive format signatures
    SIGNATURES = {
        'RAR': [b'Rar!'],
        '7Z': [b'\x37\x7A\xBC\xAF\x27\x1C'],
        # 'ZIP': [b'PK\x03\x04'],  # 没人会用ZIP打包为EXE，但程序却可能会用
        # 'CAB': [b'MSCF'],       # 没人会用CAB打包为EXE，但程序却可能会用
        # 'ARJ': [b'\x60\xEA'],   # 没人会用ARJ打包为EXE，但程序却可能会用
    }

    def __init__(self, verbose=False):
        """
        Initialize the SFX detector

        Args:
            verbose: Whether to output detailed information
        """
        self.verbose = verbose

    def is_exe(self, file_path):
        """
        Check if a file is a valid EXE file (only reads the first two bytes)

        Returns:
            bool: True if it's a valid EXE file, False otherwise
        """
        try:
            with safe_open(file_path, 'rb') as f:
                result = f.read(2) == b'MZ'
                if self.verbose:
                    print(f"  DEBUG: EXE检查 {file_path}: {result}")
                return result
        except Exception as e:
            if self.verbose:
                print(f"  DEBUG: EXE检查失败 {file_path}: {e}")
            return False

    def get_pe_structure(self, file_path):
        """
        Analyze PE file structure to find the end of the executable part
        Only reads necessary header and section table information

        Returns:
            Dict: Analysis results containing:
                - valid: Whether it's a valid PE file
                - file_size: Total file size
                - executable_end: End position of the executable part
                - error: Error message (if any)
        """
        result = {
            'valid': False,
            'file_size': 0,
            'executable_end': 0,
            'error': None
        }

        try:
            if self.verbose:
                print(f"  DEBUG: 分析PE结构: {file_path}")

            with safe_open(file_path, 'rb') as f:
                # Get total file size
                f.seek(0, 2)
                result['file_size'] = f.tell()
                f.seek(0)

                if self.verbose:
                    print(f"  DEBUG: 文件大小: {result['file_size']} bytes")

                # Read DOS header (only need the first 64 bytes)
                dos_header = f.read(64)
                if dos_header[:2] != b'MZ':
                    result['error'] = 'Not a valid PE file (MZ header)'
                    return result

                # Get PE header offset
                pe_offset = struct.unpack('<I', dos_header[60:64])[0]

                if self.verbose:
                    print(f"  DEBUG: PE头偏移: 0x{pe_offset:x}")

                # Check if PE offset is reasonable
                if pe_offset <= 0 or pe_offset >= result['file_size']:
                    result['error'] = 'Invalid PE header offset'
                    return result

                # Move to PE header
                f.seek(pe_offset)
                pe_signature = f.read(4)
                if pe_signature != b'PE\x00\x00':
                    result['error'] = 'Not a valid PE file (PE signature)'
                    return result

                # Read File Header (20 bytes)
                file_header = f.read(20)
                num_sections = struct.unpack('<H', file_header[2:4])[0]
                size_of_optional_header = struct.unpack('<H', file_header[16:18])[0]

                if self.verbose:
                    print(f"  DEBUG: 节数量: {num_sections}")

                # Skip Optional Header
                f.seek(pe_offset + 24 + size_of_optional_header)

                # Analyze section table to find the maximum file offset
                max_end_offset = 0

                for i in range(num_sections):
                    section = f.read(40)  # Each section table entry is 40 bytes
                    if len(section) < 40:
                        break

                    pointer_to_raw_data = struct.unpack('<I', section[20:24])[0]
                    size_of_raw_data = struct.unpack('<I', section[16:20])[0]

                    if pointer_to_raw_data > 0:
                        section_end = pointer_to_raw_data + size_of_raw_data
                        max_end_offset = max(max_end_offset, section_end)

                        if self.verbose:
                            section_name = section[:8].rstrip(b'\x00').decode('ascii', errors='ignore')
                            print(
                                f"  DEBUG: 节 {i + 1} ({section_name}): 偏移=0x{pointer_to_raw_data:x}, 大小={size_of_raw_data}, 结束=0x{section_end:x}")

                result['executable_end'] = max_end_offset
                result['valid'] = True

                if self.verbose:
                    print(f"  DEBUG: 可执行部分结束位置: 0x{max_end_offset:x}")

                return result

        except Exception as e:
            result['error'] = str(e)
            if self.verbose:
                print(f"  DEBUG: PE结构分析失败: {e}")
            return result

    def find_signature_after_exe(self, file_path, start_offset):
        """
        Find archive signatures from the specified offset by reading the file in chunks

        Returns:
            Dict: Results containing:
                - found: Whether a signature was found
                - format: Archive format found
                - offset: Position of the signature in the file
        """
        result = {
            'found': False,
            'format': None,
            'offset': 0
        }

        if self.verbose:
            print(f"  DEBUG: 从偏移0x{start_offset:x}开始查找归档签名")

        # Based on NSIS and other SFX implementations, archives are usually located at 512 or 4096 byte aligned positions
        aligned_offsets = []

        # Calculate nearest 512-byte aligned position
        if start_offset % 512 != 0:
            aligned_offsets.append(start_offset + (512 - start_offset % 512))
        else:
            aligned_offsets.append(start_offset)

        # Add next few aligned positions
        for i in range(1, 10):
            aligned_offsets.append(aligned_offsets[0] + i * 512)

        # Also check 4096-byte aligned positions
        if start_offset % 4096 != 0:
            aligned_offsets.append(start_offset + (4096 - start_offset % 4096))

        # Add extra potential positions
        aligned_offsets.append(start_offset)  # Start directly from executable end
        aligned_offsets.append(0x800)  # Some SFX use fixed offsets
        aligned_offsets.append(0x1000)

        # Remove duplicates and sort
        aligned_offsets = sorted(set(aligned_offsets))

        try:
            with safe_open(file_path, 'rb') as f:
                # Check file size to ensure offset is valid
                f.seek(0, 2)
                file_size = f.tell()

                # Read block size
                block_size = 4096  # Read 4KB at a time

                # Check each aligned position
                for offset in aligned_offsets:
                    if offset >= file_size:
                        continue

                    if self.verbose:
                        print(f"  DEBUG: 检查对齐偏移: 0x{offset:x}")

                    f.seek(offset)
                    block = f.read(block_size)

                    # Check if this block contains any known archive signatures
                    for fmt, signatures in self.SIGNATURES.items():
                        for sig in signatures:
                            pos = block.find(sig)
                            if pos >= 0:
                                result['found'] = True
                                result['format'] = fmt
                                result['offset'] = offset + pos

                                if self.verbose:
                                    print(f"  DEBUG: 找到{fmt}签名，偏移: 0x{result['offset']:x}")

                                return result

                # If aligned positions didn't find anything, try sequential scanning
                # But limit scan range to avoid reading the entire file
                max_scan_size = min(10 * 1024 * 1024, file_size - start_offset)  # Scan max 10MB

                if max_scan_size > 0:
                    if self.verbose:
                        print(f"  DEBUG: 开始顺序扫描，最大扫描大小: {max_scan_size} bytes")

                    # Use larger block size for scanning
                    scan_block_size = 1024 * 1024  # 1MB blocks

                    for offset in range(start_offset, start_offset + max_scan_size, scan_block_size):
                        f.seek(offset)
                        block = f.read(scan_block_size)

                        for fmt, signatures in self.SIGNATURES.items():
                            for sig in signatures:
                                pos = block.find(sig)
                                if pos >= 0:
                                    result['found'] = True
                                    result['format'] = fmt
                                    result['offset'] = offset + pos

                                    if self.verbose:
                                        print(f"  DEBUG: 顺序扫描找到{fmt}签名，偏移: 0x{result['offset']:x}")

                                    return result

                return result

        except Exception as e:
            if self.verbose:
                print(f"  DEBUG: Error finding signature: {str(e)}")
            return result

    def check_7z_signature_variant(self, file_path):
        """
        Specially check for 7z SFX variant signatures
        Some 7z SFX may use different signatures or offsets

        Returns:
            Dict: Results
        """
        result = {
            'found': False,
            'offset': 0
        }

        if self.verbose:
            print(f"  DEBUG: 检查7z SFX变体签名")

        # Some known 7z SFX variant offsets and signatures
        known_offsets = [0x80000, 0x88000, 0x8A000, 0x8C000, 0x90000]

        try:
            with safe_open(file_path, 'rb') as f:
                f.seek(0, 2)
                file_size = f.tell()

                for offset in known_offsets:
                    if offset >= file_size:
                        continue

                    if self.verbose:
                        print(f"  DEBUG: 检查7z变体偏移: 0x{offset:x}")

                    f.seek(offset)
                    # Check 7z signature
                    signature = f.read(6)
                    if signature == b'\x37\x7A\xBC\xAF\x27\x1C':
                        result['found'] = True
                        result['offset'] = offset

                        if self.verbose:
                            print(f"  DEBUG: 找到7z变体签名，偏移: 0x{offset:x}")

                        return result
        except Exception as e:
            if self.verbose:
                print(f"  DEBUG: 检查7z变体失败: {e}")
            pass

        return result

    def check_rar_special_marker(self, file_path):
        """
        Check for RAR SFX special markers
        Some WinRAR SFX files contain special markers at specific positions

        Returns:
            bool: Whether it contains RAR SFX markers
        """
        if self.verbose:
            print(f"  DEBUG: 检查RAR SFX特殊标记")

        try:
            with safe_open(file_path, 'rb') as f:
                # Check file size
                f.seek(0, 2)
                file_size = f.tell()

                # Check several known RAR marker positions
                markers = [
                    (0x100, b'WinRAR SFX'),
                    (0x400, b'WINRAR'),
                    (0x400, b'WinRAR')
                ]

                for offset, marker in markers:
                    if offset + len(marker) <= file_size:
                        f.seek(offset)
                        if f.read(len(marker)) == marker:
                            if self.verbose:
                                print(f"  DEBUG: 找到RAR标记: {marker} 在偏移 0x{offset:x}")
                            return True

                # Try to find "WINRAR" or "WinRAR" strings in the first 8KB
                f.seek(0)
                header = f.read(8192)
                if b'WINRAR' in header or b'WinRAR' in header:
                    if self.verbose:
                        print(f"  DEBUG: 在文件头部找到WinRAR字符串")
                    return True

        except Exception as e:
            if self.verbose:
                print(f"  DEBUG: 检查RAR标记失败: {e}")
            pass

        return False

    def is_sfx(self, file_path, detailed=False):
        """
        Determine if a file is a self-extracting (SFX) archive by analyzing file headers

        Args:
            file_path: File path
            detailed: Whether to return detailed analysis results

        Returns:
            Union[bool, Dict]:
                If detailed=False, returns a boolean indicating whether it's an SFX file
                If detailed=True, returns a dictionary with detailed analysis results
        """
        if self.verbose:
            print(f"  DEBUG: SFX检测开始: {file_path}")

        if not safe_exists(file_path, self.verbose):
            if detailed:
                return {'is_sfx': False, 'error': 'File does not exist'}
            return False

        if not self.is_exe(file_path):
            if detailed:
                return {'is_sfx': False, 'error': 'Not a valid EXE file'}
            return False

        results = {}

        # 1. Analyze PE structure
        pe_analysis = self.get_pe_structure(file_path)
        results['pe_analysis'] = pe_analysis

        # 2. Check RAR special markers
        rar_marker_found = self.check_rar_special_marker(file_path)
        results['rar_marker'] = rar_marker_found

        # 3. Find archive signatures from executable end position
        signature_result = {'found': False}
        if pe_analysis['valid']:
            signature_result = self.find_signature_after_exe(
                file_path,
                pe_analysis['executable_end']
            )
        results['signature'] = signature_result

        # 4. Check 7z special variants
        if not signature_result['found']:
            sevenzip_variant = self.check_7z_signature_variant(file_path)
            results['7z_variant'] = sevenzip_variant
            signature_result['found'] = sevenzip_variant['found']

        # 5. Analyze extra data size (if PE analysis is valid)
        extra_data_size = 0
        if pe_analysis['valid']:
            extra_data_size = pe_analysis['file_size'] - pe_analysis['executable_end']
        results['extra_data_size'] = extra_data_size

        # Final determination
        is_sfx = (
                signature_result['found'] or
                rar_marker_found or
                (pe_analysis['valid'] and extra_data_size > 1024 * 10)  # 10KB threshold
        )
        results['is_sfx'] = is_sfx

        if self.verbose:
            print(f"  DEBUG: SFX检测结果: {is_sfx}")
            if is_sfx:
                print(f"  DEBUG: 签名发现: {signature_result['found']}")
                print(f"  DEBUG: RAR标记: {rar_marker_found}")
                print(f"  DEBUG: 额外数据大小: {extra_data_size}")

        if detailed:
            return results
        return is_sfx

class ArchiveProcessor:
    """Handles archive processing with various policies."""

    def __init__(self, args):
        """【修正】初始化时添加参数验证"""
        self.args = args
        self.sfx_detector = SFXDetector(verbose=args.verbose)
        self.failed_archives = []
        self.successful_archives = []
        self.skipped_archives = []
        self.skipped_rename_archives = []  # 扩展名修复时跳过的文件
        self.fixed_rename_archives = []    # 扩展名修复时成功重命名的文件 (原路径, 新路径)
        
        # 【新增】全局密码管理
        self.password_candidates = []      # 全局密码候选列表
        self.password_hit_counts = {}      # 密码命中统计字典
        
        # 【新增】验证和修正参数
        self.validate_args()
        
        # 【新增】构建全局密码候选列表
        self.build_password_candidates()

    def find_archives(self, search_path):
        """重构后的查找归档文件函数（修正单文件volume处理）"""
        archives = []

        # 一开始就绝对化路径
        search_path = os.path.abspath(search_path)

        # Check for interrupt at start
        check_interrupt()

        if VERBOSE:
            print(f"  DEBUG: 查找归档文件: {search_path}")

        # 解析深度范围参数
        depth_range = None
        if hasattr(self.args, 'depth_range') and self.args.depth_range:
            try:
                depth_range = parse_depth_range(self.args.depth_range)
                if VERBOSE:
                    print(f"  DEBUG: 使用深度范围: {depth_range[0]}-{depth_range[1]}")
            except ValueError as e:
                print(f"Error: Invalid depth range: {e}")
                return []

        # 处理单个文件的情况（修正volume处理逻辑）
        if safe_isfile(search_path, VERBOSE):
            if VERBOSE:
                print(f"  DEBUG: 处理单个文件: {search_path}")
            
            # 单个文件忽略深度参数
            archive_type = self.is_archive_single_or_volume(search_path)
            
            if archive_type == 'notarchive':
                if VERBOSE:
                    print(f"  DEBUG: 跳过非归档文件: {search_path}")
                self.skipped_archives.append(search_path)
            elif archive_type == 'volume':
                # 【修正】检查是否为主卷，主卷可以处理
                if self.is_main_volume(search_path):
                    # 是主卷，检查是否应该跳过
                    should_skip, skip_reason = self._should_skip_multi_archive(search_path)
                    if should_skip:
                        if VERBOSE:
                            print(f"  DEBUG: 跳过单个分卷主文件: {search_path} - {skip_reason}")
                        self.skipped_archives.append(search_path)
                    else:
                        archives.append(search_path)
                        if VERBOSE:
                            print(f"  DEBUG: 添加单个分卷主文件: {search_path}")
                else:
                    if VERBOSE:
                        print(f"  DEBUG: 跳过单个非主卷文件: {search_path}")
                    self.skipped_archives.append(search_path)
            elif archive_type == 'single':
                # 检查是否应该跳过
                should_skip, skip_reason = self._should_skip_single_archive(search_path)
                if should_skip:
                    if VERBOSE:
                        print(f"  DEBUG: 跳过文件: {search_path} - {skip_reason}")
                    self.skipped_archives.append(search_path)
                else:
                    archives.append(search_path)
                    if VERBOSE:
                        print(f"  DEBUG: 添加单文件归档: {search_path}")
            
            return archives

        # 处理目录的情况（逻辑保持不变）
        if not safe_isdir(search_path, VERBOSE):
            if VERBOSE:
                print(f"  DEBUG: 路径不是文件也不是目录: {search_path}")
            return archives

        try:
            for root, dirs, files in safe_walk(search_path, VERBOSE):
                # Check for interrupt during directory traversal
                check_interrupt()
                
                # 计算当前目录相对于搜索路径的深度
                try:
                    rel_path = os.path.relpath(root, search_path)
                    if rel_path == '.':
                        current_depth = 0
                    else:
                        path_parts = [p for p in rel_path.split(os.sep) if p and p != '.']
                        current_depth = len(path_parts)
                except ValueError:
                    if VERBOSE:
                        print(f"  DEBUG: 无法计算相对路径，跳过: {root}")
                    continue

                # 检查当前深度是否在指定范围内
                if depth_range is not None:
                    if not (depth_range[0] <= current_depth <= depth_range[1]):
                        if VERBOSE:
                            print(f"  DEBUG: 跳过深度{current_depth}的目录（超出范围）: {root}")
                        continue

                if VERBOSE:
                    print(f"  DEBUG: 处理深度{current_depth}的目录: {root}")

                for file in files:
                    # Check for interrupt for each file
                    check_interrupt()
                    
                    filepath = os.path.join(root, file)
                    
                    # 判断文件类型
                    archive_type = self.is_archive_single_or_volume(filepath)
                    
                    if archive_type == 'notarchive':
                        if VERBOSE:
                            print(f"  DEBUG: 跳过非归档文件: {filepath}")
                        continue
                    
                    elif archive_type == 'single':
                        # 单文件处理
                        should_skip, skip_reason = self._should_skip_single_archive(filepath)
                        if should_skip:
                            if VERBOSE:
                                print(f"  DEBUG: 跳过单文件归档: {filepath} - {skip_reason}")
                            self.skipped_archives.append(filepath)
                        else:
                            archives.append(filepath)
                            if VERBOSE:
                                print(f"  DEBUG: 找到单文件归档（深度{current_depth}）: {filepath}")
                    
                    elif archive_type == 'volume':
                        # 分卷文件处理
                        if self.is_secondary_volume(filepath):
                            if VERBOSE:
                                print(f"  DEBUG: 跳过从卷: {filepath}")
                            continue
                        
                        if not self.is_main_volume(filepath):
                            if VERBOSE:
                                print(f"  DEBUG: 跳过非主卷分卷文件: {filepath}")
                            continue
                        
                        # 这是主卷，检查是否应该跳过
                        should_skip, skip_reason = self._should_skip_multi_archive(filepath)
                        if should_skip:
                            if VERBOSE:
                                print(f"  DEBUG: 跳过分卷归档: {filepath} - {skip_reason}")
                            self.skipped_archives.append(filepath)
                        else:
                            archives.append(filepath)
                            if VERBOSE:
                                print(f"  DEBUG: 找到分卷归档主卷（深度{current_depth}）: {filepath}")

        except KeyboardInterrupt:
            print(f"\nInterrupted while scanning for archives")
            raise
        except Exception as e:
            if VERBOSE:
                print(f"  DEBUG: 遍历目录失败: {e}")

        if VERBOSE:
            print(f"  DEBUG: 总共找到 {len(archives)} 个归档文件")
            print(f"  DEBUG: 跳过 {len(self.skipped_archives)} 个文件")

        return archives

    def find_correct_password(self, archive_path, password_candidates=None, encryption_status='encrypted_content'):
        """
        Find correct password from candidates using is_password_correct.
        
        Args:
            archive_path: Path to the archive
            password_candidates: List of password candidates to test (deprecated, uses self.password_candidates)
            encryption_status: Type of encryption ('encrypted_header', 'encrypted_content', or 'plain')
        
        Returns:
            str or None: Correct password if found, None if no correct password found
        """
        # 使用全局密码候选列表
        candidates_to_test = self.password_candidates if self.password_candidates else []
        
        if not candidates_to_test:
            return ""

        if VERBOSE:
            print(f"  DEBUG: Testing {len(candidates_to_test)} password candidates")
            print(f"  DEBUG: Encryption type: {encryption_status}")

        for i, password in enumerate(candidates_to_test):
            # Check for interrupt before testing each password
            check_interrupt()
            
            if VERBOSE:
                print(f"  DEBUG: Testing password {i + 1}/{len(candidates_to_test)}")

            if is_password_correct(archive_path, password, encryption_status):
                if VERBOSE:
                    print(f"  DEBUG: Found correct password (candidate {i + 1})")
                
                # 更新密码命中统计
                if password in self.password_hit_counts:
                    self.password_hit_counts[password] += 1
                    if VERBOSE:
                        print(f"  DEBUG: Password hit count updated to {self.password_hit_counts[password]}")
                    
                    # 重新排序密码候选列表
                    self.reorder_password_candidates()
                
                return password

        return None

    def get_relative_path(self, file_path, base_path):
        """Get relative path from base path."""
        try:
            return os.path.relpath(os.path.dirname(file_path), base_path)
        except ValueError:
            return ""

    def move_volumes_with_structure(self, volumes, target_base):
        """Move volumes preserving directory structure."""
        # Check for interrupt at start
        check_interrupt()
        
        safe_makedirs(target_base, debug=VERBOSE)

        base_path = self.args.path if safe_isdir(self.args.path, VERBOSE) else os.path.dirname(self.args.path)

        if VERBOSE:
            print(f"  DEBUG: Moving {len(volumes)} volumes to {target_base}")
            for vol in volumes:
                print(f"  DEBUG: Volume to move: {vol}")

        for volume in volumes:
            # Check for interrupt before each file move
            check_interrupt()
            
            try:
                rel_path = self.get_relative_path(volume, base_path)
                target_dir = os.path.join(target_base, rel_path) if rel_path else target_base
                safe_makedirs(target_dir, debug=VERBOSE)

                target_file = os.path.join(target_dir, os.path.basename(volume))
                safe_move(volume, target_file, VERBOSE)
                print(f"  Moved: {volume} -> {target_file}")
            except KeyboardInterrupt:
                # Re-raise interrupt
                raise
            except Exception as e:
                print(f"  Warning: Could not move {volume}: {e}")


    def process_archive(self, archive_path):
        """Process a single archive following the exact specification."""
        # Check for interrupt at the start
        check_interrupt()
        
        archive_path = os.path.abspath(archive_path)
        print(f"Processing: {archive_path}")

        # 处理传统ZIP策略
        traditional_zip_result = self.handle_traditional_zip_policy(archive_path)
        if not traditional_zip_result['should_continue']:
            if VERBOSE:
                print(f"  DEBUG: 传统ZIP策略处理完成: {traditional_zip_result['reason']}")
            
            # 根据策略结果决定是否算作成功或跳过
            if traditional_zip_result['reason'].startswith('传统ZIP已移动'):
                self.successful_archives.append(archive_path)
                return True
            else:
                self.skipped_archives.append(archive_path)
                return False
        
        # 获取ZIP解码参数（如果有）
        zip_decode_from_policy = traditional_zip_result.get('zip_decode')

        if self.args.dry_run:
            print(f"  [DRY RUN] Would process: {archive_path}")
            return True

        # Check for interrupt before starting extraction
        check_interrupt()

        # Step 1: Determine if we need to test passwords
        need_password_testing = bool(self.args.password_file)

        if VERBOSE:
            print(f"  DEBUG: 需要密码测试: {need_password_testing}")

        # Step 2: Check encryption status
        encryption_status = 'plain'
        if need_password_testing:
            check_interrupt()  # Check before potentially long operation
            encryption_status = check_encryption(archive_path)
            if encryption_status is None:
                print(f"  Warning: Cannot determine if {archive_path} is an archive")
                self.skipped_archives.append(archive_path)
                return False
            elif encryption_status in ['encrypted_header', 'encrypted_content']:
                if VERBOSE:
                    print(f"  DEBUG: Archive is encrypted (type: {encryption_status})")
            elif VERBOSE:
                print(f"  DEBUG: Archive is not encrypted")

        # Step 3: Find correct password using global password candidates
        correct_password = ""

        if need_password_testing and encryption_status in ['encrypted_header', 'encrypted_content']:
            # Test passwords using global password candidates
            check_interrupt()  # Check before potentially long password testing
            correct_password = self.find_correct_password(archive_path, encryption_status=encryption_status)
            if correct_password is None:
                print(f"  Error: No correct password found for {archive_path}")
                # Apply fail policy before returning - 使用新的get_all_volumes方法
                all_volumes = self.get_all_volumes(archive_path)
                if self.args.fail_policy == 'move' and self.args.fail_to:
                    fail_to_abs = os.path.abspath(self.args.fail_to)
                    self.move_volumes_with_structure(all_volumes, fail_to_abs)
                self.failed_archives.append(archive_path)
                return False
        else:
            # Not testing passwords - use provided password directly or empty
            correct_password = self.args.password if self.args.password else ""
            if VERBOSE:
                print(f"  DEBUG: Using provided password (or empty password)")

        # Step 4: Create temporary directory with thread-safe unique name
        timestamp = str(int(time.time() * 1000))
        thread_id = threading.get_ident()
        unique_id = str(uuid.uuid4().hex[:8])
        unique_suffix = f"{timestamp}_{thread_id}_{unique_id}"
        tmp_dir = f"tmp_{unique_suffix}"

        if VERBOSE:
            print(f"  DEBUG: 创建临时目录: {tmp_dir}")

        try:
            # Check for interrupt before extraction
            check_interrupt()

            # Step 5: Extract using try_extract function
            final_zip_decode = zip_decode_from_policy if zip_decode_from_policy is not None else getattr(self.args, 'zip_decode', None)
            enable_rar = getattr(self.args, 'enable_rar', False)

            # Check RAR availability if needed
            if enable_rar and not check_rar_available():
                print(f"  Warning: RAR command not available, falling back to 7z")
                enable_rar = False

            success = try_extract(archive_path, correct_password, tmp_dir, final_zip_decode, enable_rar, self.sfx_detector)

            # Check for interrupt after extraction
            check_interrupt()

            # Step 6: Find all volumes for this archive - 使用新的get_all_volumes方法
            all_volumes = self.get_all_volumes(archive_path)

            if success:
                print(f"  Successfully extracted to temporary directory")

                # Step 7: Apply success policy BEFORE decompress policy
                if self.args.success_policy == 'delete':
                    if VERBOSE:
                        print(f"  DEBUG: 应用删除成功策略")
                    for volume in all_volumes:
                        try:
                            safe_remove(volume, VERBOSE)
                            print(f"  Deleted: {volume}")
                        except Exception as e:
                            print(f"  Warning: Could not delete {volume}: {e}")

                elif self.args.success_policy == 'move' and self.args.success_to:
                    if VERBOSE:
                        print(f"  DEBUG: 应用移动成功策略")
                    self.move_volumes_with_structure(all_volumes, os.path.abspath(self.args.success_to))

                # Check for interrupt before decompress policy
                check_interrupt()

                # Step 8: Apply decompress policy
                self.apply_decompress_policy(archive_path, tmp_dir, unique_suffix)

                self.successful_archives.append(archive_path)
                return True

            else:
                print(f"  Failed to extract: {archive_path}")

                # Step 7: Apply fail policy BEFORE decompress policy cleanup
                if self.args.fail_policy == 'move' and self.args.fail_to:
                    if VERBOSE:
                        print(f"  DEBUG: 应用失败策略")
                    self.move_volumes_with_structure(all_volumes, os.path.abspath(self.args.fail_to))

                self.failed_archives.append(archive_path)
                return False

        except KeyboardInterrupt:
            # Re-raise KeyboardInterrupt to propagate to main thread
            print(f"\n  Interrupted while processing: {archive_path}")
            raise
        finally:
            # Step 9: Clean up temporary directory
            clean_temp_dir(tmp_dir)

    def apply_decompress_policy(self, archive_path, tmp_dir, unique_suffix):
        """Apply the specified decompress policy following exact specification."""
        # Check for interrupt at start
        check_interrupt()
        
        base_path = self.args.path if safe_isdir(self.args.path, VERBOSE) else os.path.dirname(self.args.path)
        rel_path = self.get_relative_path(archive_path, base_path)

        # Determine output directory
        if self.args.output:
            output_base = self.args.output
        else:
            output_base = base_path

        final_output_dir = os.path.join(output_base, rel_path) if rel_path else output_base
        safe_makedirs(final_output_dir, debug=VERBOSE)

        archive_base_name = get_archive_base_name(archive_path)

        if VERBOSE:
            print(f"  DEBUG: 应用解压策略: {self.args.decompress_policy}")
            print(f"  DEBUG: 归档基础名称: {archive_base_name}")
            print(f"  DEBUG: 输出目录: {final_output_dir}")

        # Check interrupt before applying policy
        check_interrupt()

        if self.args.decompress_policy == 'separate':
            self.apply_separate_policy(tmp_dir, final_output_dir, archive_base_name, unique_suffix)

        elif self.args.decompress_policy == 'direct':
            self.apply_direct_policy(tmp_dir, final_output_dir, archive_base_name, unique_suffix)

        elif self.args.decompress_policy == 'only-file-content':
            apply_only_file_content_policy(tmp_dir, final_output_dir, archive_base_name, unique_suffix)

        elif self.args.decompress_policy == 'only-file-content-direct':
            apply_only_file_content_direct_policy(tmp_dir, final_output_dir, archive_base_name, unique_suffix)

        elif self.args.decompress_policy == 'file-content-with-folder':
            apply_file_content_with_folder_policy(tmp_dir, final_output_dir, archive_base_name, unique_suffix)

        elif self.args.decompress_policy == 'file-content-with-folder-separate':
            apply_file_content_with_folder_separate_policy(tmp_dir, final_output_dir, archive_base_name, unique_suffix)

        elif re.match(r'^file-content-auto-folder-\d+-collect-(len|meaningful)$', self.args.decompress_policy):
            # file-content-auto-folder-N-collect-len/meaningful policy
            parts = self.args.decompress_policy.split('-')
            threshold = int(parts[4])  # N值
            strategy_type = parts[6]   # len 或 meaningful

            if strategy_type == 'len':
                apply_file_content_auto_folder_collect_len_policy(tmp_dir, final_output_dir, archive_base_name, threshold, unique_suffix)
            elif strategy_type == 'meaningful':
                apply_file_content_auto_folder_collect_meaningful_policy(tmp_dir, final_output_dir, archive_base_name, threshold, unique_suffix)

        elif self.args.decompress_policy.startswith('file-content-') and self.args.decompress_policy.endswith('-collect'):
            # file-content-N-collect policy
            threshold = int(self.args.decompress_policy.split('-')[2])
            apply_file_content_collect_policy(tmp_dir, final_output_dir, archive_base_name, threshold, unique_suffix)

        else:
            # N-collect policy
            threshold = int(self.args.decompress_policy.split('-')[0])
            self.apply_collect_policy(tmp_dir, final_output_dir, archive_base_name, threshold, unique_suffix)


    def apply_separate_policy(self, tmp_dir, output_dir, archive_name, unique_suffix):
        """Apply separate decompress policy following exact specification."""
        if VERBOSE:
            print(f"  DEBUG: 应用separate策略")

        apply_separate_policy_internal(tmp_dir, output_dir, archive_name, unique_suffix)

    def apply_direct_policy(self, tmp_dir, output_dir, archive_name, unique_suffix):
        """Apply direct decompress policy following exact specification."""
        if VERBOSE:
            print(f"  DEBUG: 应用direct策略")

        # Check for conflicts
        try:
            tmp_items = os.listdir(tmp_dir)
            conflicts = [item for item in tmp_items if safe_exists(os.path.join(output_dir, item), VERBOSE)]

            if VERBOSE:
                print(f"  DEBUG: 检查冲突 - tmp项目: {len(tmp_items)}, 冲突: {len(conflicts)}")

            if conflicts:
                # Create archive folder for conflicts
                archive_folder = os.path.join(output_dir, archive_name)
                archive_folder = ensure_unique_name(archive_folder, unique_suffix)
                safe_makedirs(archive_folder, debug=VERBOSE)

                # Move all items to archive folder
                for item in tmp_items:
                    src_item = os.path.join(tmp_dir, item)
                    dest_item = os.path.join(archive_folder, item)
                    safe_move(src_item, dest_item, VERBOSE)

                print(f"  Extracted to: {archive_folder} (conflicts detected)")
            else:
                # Move directly to output directory
                for item in tmp_items:
                    src_item = os.path.join(tmp_dir, item)
                    dest_item = os.path.join(output_dir, item)
                    safe_move(src_item, dest_item, VERBOSE)

                print(f"  Extracted to: {output_dir}")
        except Exception as e:
            if VERBOSE:
                print(f"  DEBUG: direct策略执行失败: {e}")
            # 回退到separate策略
            self.apply_separate_policy(tmp_dir, output_dir, archive_name, unique_suffix)

    def apply_collect_policy(self, tmp_dir, output_dir, archive_name, threshold, unique_suffix):
        """Apply N-collect decompress policy following exact specification."""
        if VERBOSE:
            print(f"  DEBUG: 应用{threshold}-collect策略")

        files, dirs = count_items_in_dir(tmp_dir)
        total_items = files + dirs

        if VERBOSE:
            print(f"  DEBUG: 统计项目 - 文件: {files}, 目录: {dirs}, 总计: {total_items}, 阈值: {threshold}")

        if total_items >= threshold:
            # Create archive folder
            archive_folder = os.path.join(output_dir, archive_name)
            archive_folder = ensure_unique_name(archive_folder, unique_suffix)
            safe_makedirs(archive_folder, debug=VERBOSE)

            # Move all items to archive folder
            try:
                for item in os.listdir(tmp_dir):
                    src_item = os.path.join(tmp_dir, item)
                    dest_item = os.path.join(archive_folder, item)
                    safe_move(src_item, dest_item, VERBOSE)
            except Exception as e:
                if VERBOSE:
                    print(f"  DEBUG: collect策略移动失败: {e}")

            print(f"  Extracted to: {archive_folder} ({total_items} items >= {threshold})")
        else:
            # Extract directly, handling conflicts like direct policy
            self.apply_direct_policy(tmp_dir, output_dir, archive_name, unique_suffix)
            print(f"  Extracted directly ({total_items} items < {threshold})")

    def handle_traditional_zip_policy(self, archive_path):
        """
        处理传统ZIP策略（添加错误检查）
        
        Args:
            archive_path: 归档文件路径
            
        Returns:
            dict: {
                'should_continue': bool,  # 是否继续后续处理
                'zip_decode': int or None,  # ZIP解码参数
                'reason': str  # 处理原因
            }
        """
        result = {
            'should_continue': True,
            'zip_decode': None,
            'reason': ''
        }
        
        # 【优先级3】添加参数检查
        if not hasattr(self.args, 'traditional_zip_policy'):
            if VERBOSE:
                print(f"  DEBUG: 未找到traditional_zip_policy，使用默认值decode-auto")
            self.args.traditional_zip_policy = 'decode-auto'
        
        # 检查是否是ZIP文件
        if not is_zip_format(archive_path):
            return result
            
        # 检查是否是传统ZIP
        if not is_traditional_zip(archive_path):
            if VERBOSE:
                print(f"  DEBUG: 非传统ZIP，无需应用传统ZIP策略")
            return result
            
        if VERBOSE:
            print(f"  DEBUG: 检测到传统ZIP，应用策略: {self.args.traditional_zip_policy}")
        
        policy = self.args.traditional_zip_policy.lower()
        
        # 处理move策略
        if policy == 'move':
            if not hasattr(self.args, 'traditional_zip_to') or not self.args.traditional_zip_to:
                print(f"  Error: --traditional-zip-to is required with --traditional-zip-policy move")
                result['should_continue'] = False
                result['reason'] = '缺少--traditional-zip-to参数'
                return result
                
            try:
                # 使用新的get_all_volumes方法查找所有相关卷
                all_volumes = self.get_all_volumes(archive_path)
                
                if VERBOSE:
                    print(f"  DEBUG: 移动传统ZIP文件到: {self.args.traditional_zip_to}")
                
                # 移动文件保持目录结构
                traditional_zip_to_abs = os.path.abspath(self.args.traditional_zip_to)
                self.move_volumes_with_structure(all_volumes, traditional_zip_to_abs)
                
                print(f"  Traditional ZIP moved to: {traditional_zip_to_abs}")
                result['should_continue'] = False
                result['reason'] = '传统ZIP已移动'
                return result
                
            except Exception as e:
                print(f"  Error moving traditional ZIP: {e}")
                result['should_continue'] = False
                result['reason'] = f'移动传统ZIP失败: {e}'
                return result
        
        # 处理decode-${int}策略  
        elif policy.startswith('decode-') and policy != 'decode-auto':
            try:
                # 提取编码数字
                encoding_str = policy[7:]  # 去掉'decode-'前缀
                zip_decode = int(encoding_str)
                
                if VERBOSE:
                    print(f"  DEBUG: 使用手动指定编码: {zip_decode}")
                
                result['zip_decode'] = zip_decode
                result['reason'] = f'使用手动编码{zip_decode}'
                return result
                
            except ValueError:
                print(f"  Error: Invalid encoding in --traditional-zip-policy: {policy}")
                result['should_continue'] = False
                result['reason'] = '无效的编码参数'
                return result
        
        # 处理decode-auto策略
        elif policy == 'decode-auto':
            try:
                # 首先检查依赖库是否可用
                enable_llm = getattr(self.args, 'enable_llm', False)
                try:
                    import zipfile
                    decode_model = getattr(self.args, 'traditional_zip_decode_model', 'chardet')
                    if decode_model == 'charset_normalizer':
                        from charset_normalizer import detect
                    else:
                        import chardet
                    if enable_llm:
                        from transformers import pipeline
                except ImportError as e:
                    if VERBOSE:
                        print(f"  DEBUG: decode-auto所需库不可用，跳过传统ZIP策略: {e}")
                        if enable_llm and ('transformers' in str(e) or 'torch' in str(e)):
                            print(f"  DEBUG: 请安装transformers库: pip install transformers torch")
                    result['should_continue'] = False
                    result['reason'] = f'decode-auto依赖库不可用，跳过处理'
                    return result
                
                # 混合编码检测
                chardet_confidence_threshold = getattr(self.args, 'traditional_zip_decode_confidence', 90) / 100.0
                llm_confidence_threshold = getattr(self.args, 'llm_confidence', 95) / 100.0
                
                encoding_result = guess_zip_encoding(
                    archive_path, 
                    enable_llm=enable_llm,
                    chardet_confidence_threshold=chardet_confidence_threshold,
                    llm_confidence_threshold=llm_confidence_threshold,
                    decode_model=decode_model
                )
                
                if not encoding_result['success']:
                    if VERBOSE:
                        print(f"  DEBUG: 混合编码检测失败，跳过处理")
                    result['should_continue'] = False  
                    result['reason'] = '混合编码检测失败'
                    return result
                
                # 显示检测结果信息
                detected_confidence = encoding_result['confidence']
                
                if VERBOSE:
                    if enable_llm and 'llm_confidence' in encoding_result:
                        print(f"  DEBUG: 混合检测成功 - chardet置信度: {encoding_result.get('detection_confidence', 0):.2%}, "
                              f"LLM置信度: {encoding_result.get('llm_confidence', 0):.2%}, "
                              f"综合置信度: {detected_confidence:.2%}")
                    else:
                        print(f"  DEBUG: chardet检测成功 - 置信度: {detected_confidence:.2%}")
                
                # 注意：置信度检查已在guess_zip_encoding内部完成，这里不需要再检查
                
                # 转换编码为7z参数
                detected_encoding = encoding_result['encoding']
                zip_decode_param = get_7z_encoding_param(detected_encoding)
                
                if not zip_decode_param:
                    if VERBOSE:
                        print(f"  DEBUG: 无法映射检测到的编码到7z参数: {detected_encoding}")
                    result['should_continue'] = False
                    result['reason'] = f'无法映射编码{detected_encoding}到7z参数'
                    return result
                
                if VERBOSE:
                    print(f"  DEBUG: 自动检测编码: {detected_encoding} -> {zip_decode_param}")
                
                # 对于UTF-8编码参数，使用特殊处理
                if zip_decode_param == 'UTF-8':
                    result['zip_decode'] = None  # 让7z使用默认UTF-8处理
                else:
                    try:
                        result['zip_decode'] = int(zip_decode_param)
                    except ValueError:
                        result['zip_decode'] = None
                
                result['reason'] = f'自动检测编码{detected_encoding}(置信度{detected_confidence:.1%})'
                return result
                
            except Exception as e:
                if VERBOSE:
                    print(f"  DEBUG: decode-auto处理异常: {e}")
                result['should_continue'] = False
                result['reason'] = f'自动编码检测异常，跳过处理: {e}'
                return result
        
        # 处理asis策略
        elif policy == 'asis':
            if VERBOSE:
                print(f"  DEBUG: asis策略，跳过处理")
            result['should_continue'] = False
            result['reason'] = '传统ZIP按asis策略跳过'
            return result
        
        # 未知策略
        else:
            print(f"  Error: Unknown traditional-zip-policy: {policy}")
            result['should_continue'] = False  
            result['reason'] = f'未知策略: {policy}'
            return result


    def is_archive_single_or_volume(self, file_path):
        """
        判断文件是单包、分卷还是非压缩包（统一逻辑）
        Returns: 'single' | 'volume' | 'notarchive'
        """
        if not safe_isfile(file_path, VERBOSE):
            return 'notarchive'

        info = parse_archive_filename(os.path.basename(file_path))
        bf, ext, ext2 = info['base_filename'], info['file_ext'], info['file_ext_extend']
        folder = os.path.dirname(file_path)

        # --- 7z ---
        if ext == '7z':
            return 'single'
        if ext.isdigit() and ext2 == '7z' and not safe_exists(os.path.join(folder, bf + '.exe')):
            return 'volume'

        # --- RAR5 (.partN.rar) ---
        if ext == 'rar' and re.fullmatch(r'part\d+', ext2):
            if not safe_glob(os.path.join(folder, bf + '.part*.exe')):
                return 'volume'

        # --- RAR4 ---
        if ext == 'rar' and self._has_volume_files(bf, folder, 'rar4'):
            return 'volume'
        if re.fullmatch(r'r\d+', ext):
            return 'volume'

        # --- ZIP ---
        if ext == 'zip' and self._has_volume_files(bf, folder, 'zip'):
            return 'volume'
        if re.fullmatch(r'z\d+', ext):
            return 'volume'

        # --- EXE ---
        if ext == 'exe':
            if not self.sfx_detector.is_sfx(file_path):
                return 'notarchive'

            sfx = self.sfx_detector.is_sfx(file_path, detailed=True)
            is_rar_sfx = (sfx.get('signature', {}).get('format') == 'RAR') or sfx.get('rar_marker', False)

            if is_rar_sfx:
                if safe_glob(os.path.join(folder, bf + '.part*.rar')):
                    return 'volume'
                return 'single'
            else:
                if self._has_volume_files(bf, folder, '7z'):
                    return 'volume'
                return 'single'

        return 'notarchive'

    def is_archive_single_or_volume_innerLogic(self, file_path):
        """
        判断文件是单包还是分卷（内部逻辑，返回详细类型）
        返回值格式: {"is_multi": bool, "type": str}
        """
        if not safe_isfile(file_path, VERBOSE):
            return {"is_multi": False, "type": "unknown"}

        info = parse_archive_filename(os.path.basename(file_path))
        bf, ext, ext2 = info['base_filename'], info['file_ext'], info['file_ext_extend']
        folder = os.path.dirname(file_path)

        # --- 7z ---
        if ext == '7z':
            return {"is_multi": False, "type": "7z-single"}
        if ext.isdigit() and ext2 == '7z':
            if safe_exists(os.path.join(folder, bf + '.exe')):
                # SFX 7z 从卷
                return {"is_multi": True, "type": "exe-7z-multi"}
            return {"is_multi": True, "type": "7z-multi"}

        # --- RAR5 (.partN.rar) ---
        if ext == 'rar' and re.fullmatch(r'part\d+', ext2):
            if safe_glob(os.path.join(folder, bf + '.part*.exe')):
                return {"is_multi": True, "type": "exe-rar-multi"}
            return {"is_multi": True, "type": "rar5-multi"}

        # --- RAR4 ---
        if ext == 'rar':
            if self._has_volume_files(bf, folder, 'rar4'):
                return {"is_multi": True, "type": "rar4-multi"}
            return {"is_multi": False, "type": "rar4/rar5-single"}
        if re.fullmatch(r'r\d+', ext):
            return {"is_multi": True, "type": "rar4-multi"}

        # --- ZIP ---
        if ext == 'zip':
            if self._has_volume_files(bf, folder, 'zip'):
                return {"is_multi": True, "type": "zip-multi"}
            return {"is_multi": False, "type": "zip-single"}
        if re.fullmatch(r'z\d+', ext):
            return {"is_multi": True, "type": "zip-multi"}

        # --- EXE ---
        if ext == 'exe':
            if not self.sfx_detector.is_sfx(file_path):
                return {"is_multi": False, "type": "exe-notarchive"}

            sfx = self.sfx_detector.is_sfx(file_path, detailed=True)
            is_rar_sfx = (sfx.get('signature', {}).get('format') == 'RAR') or sfx.get('rar_marker', False)

            if is_rar_sfx:
                if safe_glob(os.path.join(folder, bf + '.part*.rar')):
                    return {"is_multi": True, "type": "exe-rar-multi"}
                return {"is_multi": False, "type": "exe-rar-single"}
            else:
                if self._has_volume_files(bf, folder, '7z'):
                    return {"is_multi": True, "type": "exe-7z-multi"}
                return {"is_multi": False, "type": "exe-7z-single"}

        return {"is_multi": False, "type": "unknown"}

    def is_main_volume(self, file_path):
        """判断归档文件是否为主卷（统一逻辑）"""
        if not safe_isfile(file_path, VERBOSE):
            return False

        info = parse_archive_filename(os.path.basename(file_path))
        bf, ext, ext2 = info['base_filename'], info['file_ext'], info['file_ext_extend']
        folder = os.path.dirname(file_path)
        name_lower = os.path.basename(file_path).lower()

        # 7z 主卷
        if ext.isdigit() and ext2 == '7z' and int(re.sub(r'^0+', '', ext) or '0') == 1 \
           and not safe_exists(os.path.join(folder, bf + '.exe')):
            return True

        # RAR5 主卷
        m_ext2 = re.fullmatch(r'part(\d+)', ext2)
        if ext == 'rar' and m_ext2:
            if int(re.sub(r'^0+', '', m_ext2.group(1)) or '0') == 1 and \
               not safe_glob(os.path.join(folder, bf + '.part*.exe')):
                return True

        # RAR4 主卷
        if ext == 'rar' and self._has_volume_files(bf, folder, 'rar4'):
            return True

        # ZIP 主卷
        if ext == 'zip' and self._has_volume_files(bf, folder, 'zip'):
            return True

        # EXE SFX 主卷
        if ext == 'exe' and self.sfx_detector.is_sfx(file_path):
            sfx = self.sfx_detector.is_sfx(file_path, detailed=True)
            is_rar_sfx = (sfx.get('signature', {}).get('format') == 'RAR') or sfx.get('rar_marker', False)

            # EXE-RAR-SFX
            if is_rar_sfx and safe_glob(os.path.join(folder, bf + '.part*.rar')):
                m = re.search(r'\.part(\d+)\.exe$', name_lower)
                if m is None or int(re.sub(r'^0+', '', m.group(1)) or '0') == 1:
                    return True

            # EXE-7z-SFX
            if (not is_rar_sfx) and self._has_volume_files(bf, folder, '7z'):
                return True

        return False

    def is_secondary_volume(self, file_path):
        """判断归档文件是否为从卷（统一逻辑）"""
        # 若是主卷直接返回 False
        if self.is_main_volume(file_path):
            return False
        if not safe_isfile(file_path, VERBOSE):
            return False

        info = parse_archive_filename(os.path.basename(file_path))
        bf, ext, ext2 = info['base_filename'], info['file_ext'], info['file_ext_extend']
        folder = os.path.dirname(file_path)

        # 7z 纯分卷
        if ext.isdigit() and ext2 == '7z' and not safe_exists(os.path.join(folder, bf + '.exe')):
            return True

        # RAR5 纯分卷
        if ext == 'rar' and re.fullmatch(r'part\d+', ext2):
            if not safe_glob(os.path.join(folder, bf + '.part*.exe')):
                return True

        # RAR4 从卷
        if re.fullmatch(r'r\d+', ext):
            return True

        # ZIP 从卷
        if re.fullmatch(r'z\d+', ext):
            return True

        # EXE-RAR SFX 从卷 (.rar 形式)
        if ext == 'rar' and re.fullmatch(r'part\d+', ext2) and \
           safe_glob(os.path.join(folder, bf + '.part*.exe')):
            return True

        # EXE-7z SFX 从卷 (.7z.N)
        if ext.isdigit() and ext2 == '7z' and safe_exists(os.path.join(folder, bf + '.exe')) and \
           self.sfx_detector.is_sfx(os.path.join(folder, bf + '.exe')):
            sfx = self.sfx_detector.is_sfx(os.path.join(folder, bf + '.exe'), detailed=True)
            is_rar_sfx = (sfx.get('signature', {}).get('format') == 'RAR') or sfx.get('rar_marker', False)
            if not is_rar_sfx:
                return True

        return False

    def _get_volume_files(self, base_filename, folder, volume_type):
        """
        获取指定类型的分卷文件列表
        volume_type: '7z', 'rar4', 'zip'
        返回匹配的分卷文件列表
        """
        patterns = {
            '7z': f"{base_filename}.7z.[^.]+",
            'rar4': f"{base_filename}.r[^.]+", 
            'zip': f"{base_filename}.z[^.]+"
        }
        if volume_type not in patterns:
            return []
        return safe_glob(os.path.join(folder, patterns[volume_type]), preserve_char_classes=True)

    def _has_volume_files(self, base_filename, folder, volume_type):
        """检查是否存在指定类型的分卷文件"""
        return bool(self._get_volume_files(base_filename, folder, volume_type))

    def get_all_volumes(self, file_path):
        """给定归档或分卷文件，返回同组内所有分卷（包含主卷）"""
        if not safe_isfile(file_path, VERBOSE):
            return [file_path]

        info = parse_archive_filename(os.path.basename(file_path))
        bf, ext, ext2 = info['base_filename'], info['file_ext'], info['file_ext_extend']
        folder = os.path.dirname(file_path)
        volumes = set()

        # 7z 纯
        if ext.isdigit() and ext2 == '7z' and not safe_exists(os.path.join(folder, bf + '.exe')):
            volumes |= set(self._get_volume_files(bf, folder, '7z'))

        # EXE SFX 统一处理（从 .exe 文件开始的所有 SFX 情况）
        elif ext == 'exe' and self.sfx_detector.is_sfx(file_path):
            sfx = self.sfx_detector.is_sfx(file_path, detailed=True)
            is_rar_sfx = (sfx.get('signature', {}).get('format') == 'RAR') or sfx.get('rar_marker', False)
            
            if is_rar_sfx:
                # EXE-RAR SFX 分卷处理
                if safe_glob(os.path.join(folder, bf + '.part*.rar')):
                    volumes.add(file_path)  # 添加 .exe 主卷
                    volumes |= set(safe_glob(os.path.join(folder, bf + '.part*.rar')))
            else:
                # EXE-7z SFX 分卷处理  
                if self._has_volume_files(bf, folder, '7z'):
                    volumes.add(file_path)  # 添加 .exe 主卷
                    volumes |= set(self._get_volume_files(bf, folder, '7z'))

        # RAR5 纯
        elif ext == 'rar' and re.fullmatch(r'part\d+', ext2) \
             and not safe_glob(os.path.join(folder, bf + '.part*.exe')):
            volumes |= set(safe_glob(os.path.join(folder, bf + '.part*.rar')))

        # RAR5 SFX 从卷（从 .rar 文件开始查找的情况）
        elif ext == 'rar' and re.fullmatch(r'part\d+', ext2) and \
             safe_glob(os.path.join(folder, bf + '.part*.exe')):
            volumes.add(os.path.join(folder, bf + '.exe'))
            volumes |= set(safe_glob(os.path.join(folder, bf + '.part*.rar')))

        # RAR4
        elif (ext == 'rar' and self._has_volume_files(bf, folder, 'rar4')) or re.fullmatch(r'r\d+', ext):
            volumes.add(os.path.join(folder, bf + '.rar'))
            volumes |= set(self._get_volume_files(bf, folder, 'rar4'))

        # ZIP
        elif (ext == 'zip' and self._has_volume_files(bf, folder, 'zip')) or re.fullmatch(r'z\d+', ext):
            volumes.add(os.path.join(folder, bf + '.zip'))
            volumes |= set(self._get_volume_files(bf, folder, 'zip'))

        if not volumes:
            volumes.add(file_path)

        return sorted(volumes)

    def _should_skip_single_archive(self, file_path):
        """
        检查是否应该跳过单文件归档
        
        Args:
            file_path: 文件路径
            
        Returns:
            tuple: (should_skip: bool, reason: str)
        """
        filename_lower = os.path.basename(file_path).lower()
        
        if VERBOSE:
            print(f"  DEBUG: 检查是否跳过单文件归档: {file_path}")
        
        # 7z单文件
        if filename_lower.endswith('.7z'):
            if self.args.skip_7z:
                return True, "单个7z文件被跳过 (--skip-7z)"
        
        # RAR单文件
        elif filename_lower.endswith('.rar'):
            if self.args.skip_rar:
                return True, "单个RAR文件被跳过 (--skip-rar)"
        
        # ZIP单文件
        elif filename_lower.endswith('.zip'):
            if self.args.skip_zip:
                return True, "单个ZIP文件被跳过 (--skip-zip)"
            
            # 检查传统ZIP策略
            if hasattr(self.args, 'traditional_zip_policy') and self.args.traditional_zip_policy:
                if is_traditional_zip(file_path):
                    if self.args.traditional_zip_policy.lower() == 'asis':
                        return True, "传统编码ZIP文件被跳过 (--traditional-zip-policy asis)"
        
        # EXE SFX单文件
        elif filename_lower.endswith('.exe'):
            if self.args.skip_exe:
                return True, "单个EXE文件被跳过 (--skip-exe)"
        
        return False, ""
    

    def _should_skip_multi_archive(self, file_path):
        """
        检查是否应该跳过分卷归档（优化版本）
        
        Args:
            file_path: 主卷文件路径
            
        Returns:
            tuple: (should_skip: bool, reason: str)
        """
        filename = os.path.basename(file_path)
        filename_lower = filename.lower()
        
        if VERBOSE:
            print(f"  DEBUG: 检查是否跳过分卷归档: {file_path}")
        
        # 7z分卷
        if re.search(r'\.7z\.\d+$', filename_lower):
            if self.args.skip_7z_multi:
                return True, "7z分卷文件被跳过 (--skip-7z-multi)"
        
        # RAR分卷  
        elif filename_lower.endswith('.rar'):
            if self.args.skip_rar_multi:
                return True, "RAR分卷文件被跳过 (--skip-rar-multi)"
        
        # ZIP分卷 - 【优化】直接使用现有的检测函数
        elif filename_lower.endswith('.zip'):
            if is_zip_multi_volume(file_path) and self.args.skip_zip_multi:
                return True, "ZIP分卷文件被跳过 (--skip-zip-multi)"
        
        # EXE SFX分卷
        elif filename_lower.endswith('.exe'):
            if self.args.skip_exe_multi:
                return True, "EXE分卷文件被跳过 (--skip-exe-multi)"
        
        return False, ""

    def check_should_skip(self, archive_path):
        """
        【新增】便捷的跳过检查方法（优先级2）
        
        Args:
            archive_path: 归档文件路径
            
        Returns:
            tuple: (should_skip: bool, reason: str)
        """
        return should_skip_archive(archive_path, self.args, processor=self)

    def validate_args(self):
        """
        【新增】验证和修正args参数（优先级3）
        """
        # 确保所有必要的skip参数都存在
        skip_attrs = ['skip_7z', 'skip_rar', 'skip_zip', 'skip_exe',
                     'skip_7z_multi', 'skip_rar_multi', 'skip_zip_multi', 'skip_exe_multi']
        
        for attr in skip_attrs:
            if not hasattr(self.args, attr):
                setattr(self.args, attr, False)
                if VERBOSE:
                    print(f"  DEBUG: 设置默认值 {attr} = False")
        
        # 确保传统ZIP策略参数存在
        if not hasattr(self.args, 'traditional_zip_policy'):
            self.args.traditional_zip_policy = 'decode-auto'
            if VERBOSE:
                print(f"  DEBUG: 设置默认值 traditional_zip_policy = decode-auto")
        
        if not hasattr(self.args, 'traditional_zip_decode_confidence'):
            self.args.traditional_zip_decode_confidence = 90
            if VERBOSE:
                print(f"  DEBUG: 设置默认值 traditional_zip_decode_confidence = 90")
        
        if not hasattr(self.args, 'enable_llm'):
            self.args.enable_llm = False
            if VERBOSE:
                print(f"  DEBUG: 设置默认值 enable_llm = False")
        
        if not hasattr(self.args, 'llm_confidence'):
            self.args.llm_confidence = 95
            if VERBOSE:
                print(f"  DEBUG: 设置默认值 llm_confidence = 95")

    def build_password_candidates(self):
        """
        构建全局密码候选列表，包含-p参数和-pf文件中的密码
        """
        self.password_candidates = []
        self.password_hit_counts = {}
        
        # 优先添加-p参数指定的密码
        if self.args.password:
            self.password_candidates.append(self.args.password)
            self.password_hit_counts[self.args.password] = 0
            if VERBOSE:
                print(f"  DEBUG: 添加命令行密码到候选列表")
        
        # 处理密码文件(-pf参数)
        if self.args.password_file:
            try:
                password_file_abs = os.path.abspath(self.args.password_file)
                with safe_open(password_file_abs, 'r', encoding='utf-8') as f:
                    file_passwords = []
                    for line in f:
                        # 只去除换行符，保留首尾空格
                        password = line.rstrip('\r\n')
                        if password:  # 跳过空行
                            file_passwords.append(password)
                    
                    # 对密码文件中的密码进行去重
                    unique_passwords = []
                    seen = set()
                    for pwd in file_passwords:
                        if pwd not in seen and pwd not in self.password_candidates:
                            unique_passwords.append(pwd)
                            seen.add(pwd)
                    
                    # 添加到候选列表并初始化命中统计
                    self.password_candidates.extend(unique_passwords)
                    for pwd in unique_passwords:
                        self.password_hit_counts[pwd] = 0
                    
                    if VERBOSE:
                        print(f"  DEBUG: 从密码文件读取 {len(unique_passwords)} 个唯一密码")
                        print(f"  DEBUG: 总共构建 {len(self.password_candidates)} 个密码候选")
                        
            except Exception as e:
                print(f"  Warning: 无法读取密码文件: {e}")
    
    def reorder_password_candidates(self):
        """
        根据命中次数重新排序密码候选列表，保持-p参数密码的优先级
        """
        if len(self.password_candidates) <= 1:
            return
        
        # -p参数密码（如果存在）
        p_password = self.args.password if self.args.password else None
        
        # 分离-p密码和其他密码
        other_passwords = []
        for pwd in self.password_candidates:
            if pwd != p_password:
                other_passwords.append(pwd)
        
        # 根据命中次数对其他密码排序（降序）
        other_passwords.sort(key=lambda x: self.password_hit_counts.get(x, 0), reverse=True)
        
        # 重构密码候选列表：-p密码在前，其他按命中次数排序
        self.password_candidates = []
        if p_password:
            self.password_candidates.append(p_password)
        self.password_candidates.extend(other_passwords)
        
        if VERBOSE:
            print(f"  DEBUG: 重新排序密码候选列表，总数: {len(self.password_candidates)}")


# ==================== 编码检测和验证函数 ====================

def verify_encoding_with_llm(zip_path, encoding, confidence_threshold):
    """
    用指定编码解码ZIP文件名，通过LLM进行语言验证
    
    Args:
        zip_path: ZIP文件路径
        encoding: chardet检测到的编码
        confidence_threshold: LLM置信度阈值 (0.0-1.0)
        
    Returns:
        dict: 包含 language, confidence, success 的字典
    """
    import zipfile
    
    result = {'language': None,
              'confidence': 0.0,
              'success': False}
    
    try:
        # 1. 用指定编码解码所有文件名
        decoded_texts = []
        safe_zip_path = safe_path_for_operation(zip_path, VERBOSE)
        
        with zipfile.ZipFile(safe_zip_path, 'r') as zf:
            for info in zf.infolist():
                if info.flag_bits & 0x800:  # 跳过UTF-8条目
                    continue
                    
                raw_name = getattr(info, 'orig_filename', None) or info.filename
                
                # 统一转 bytes
                if isinstance(raw_name, str):
                    raw_name = raw_name.encode('cp437', 'surrogateescape')
                
                # 用指定编码解码
                try:
                    decoded_text = raw_name.decode(encoding)
                    decoded_texts.append(decoded_text)
                except UnicodeDecodeError:
                    if VERBOSE:
                        print(f"  DEBUG: 无法用 {encoding} 解码文件名: {raw_name}")
                    continue
        
        if not decoded_texts:
            if VERBOSE:
                print(f"  DEBUG: 无法用编码 {encoding} 解码任何文件名")
            return result
        
        # 2. 发送给LLM进行语言检测
        llm_result = detect_language_with_llm(decoded_texts)
        
        if llm_result['success']:
            result.update({
                'language': llm_result['language'],
                'confidence': llm_result['confidence'],
                'success': True
            })
            
            if VERBOSE:
                print(f"  DEBUG: LLM语言验证结果 - 语言: {llm_result['language']}, 置信度: {llm_result['confidence']:.3f}")
        
    except Exception as e:
        if VERBOSE:
            print(f"  DEBUG: LLM编码验证异常: {e}")
    
    return result


def detect_language_with_llm(text_samples):
    """
    使用 LLM 模型检测文本语言（纯语言检测，不推断编码）
    
    Args:
        text_samples: list of str, 文本样本列表
    
    Returns:
        dict: 包含 language, confidence, success 的字典
    """
    result = {'language': None,
              'confidence': 0.0,
              'success': False}
    
    try:
        from transformers import pipeline
        
        # 如果模型不存在会自动下载
        model_ckpt = "papluca/xlm-roberta-base-language-detection"
        if VERBOSE:
            print(f"  DEBUG: 正在加载LLM模型 {model_ckpt}...")
        
        try:
            pipe = pipeline("text-classification", model=model_ckpt)
            if VERBOSE:
                print(f"  DEBUG: LLM模型加载成功")
        except Exception as download_error:
            if VERBOSE:
                print(f"  DEBUG: LLM模型下载/加载失败: {download_error}")
                print(f"  DEBUG: 可能的原因: 网络连接问题、磁盘空间不足、或模型仓库不可用")
            result['success'] = False
            return result
        
        # 合并样本文本
        combined_text = '\n'.join(text_samples[:10])  # 限制样本数量避免过长
        if len(combined_text) > 1000:  # 限制文本长度
            combined_text = combined_text[:1000]
        
        # 执行语言检测
        detection_result = pipe(combined_text, top_k=1, truncation=True)
        
        if detection_result and len(detection_result) > 0:
            detected_lang = detection_result[0]['label']
            confidence = detection_result[0]['score']
            
            result.update({
                'language': detected_lang,
                'confidence': confidence,
                'success': True
            })
            
            if VERBOSE:
                print(f"  DEBUG: LLM语言检测结果 - 语言: {detected_lang}, 置信度: {confidence:.3f}")
                
    except ImportError as e:
        if VERBOSE:
            print(f"  DEBUG: transformers库不可用，请安装: pip install transformers torch")
        result['success'] = False
    except Exception as e:
        if VERBOSE:
            print(f"  DEBUG: LLM语言检测异常: {e}")
        result['success'] = False
    
    return result




def guess_zip_encoding(zip_path, enable_llm=False, chardet_confidence_threshold=0.9, llm_confidence_threshold=0.95, decode_model='chardet'):
    """
    混合编码检测：chardet + LLM验证
    
    改进要点
    --------
    1. 统一通过 `safe_path_for_operation()` 处理超长 / Unicode 路径。  
    2. **保证** 参与 `b'\\n'.join()` 的全部元素都是 `bytes`，  
       - `ZipInfo.orig_filename` 可能是 *str*，需转 CP437。  
       - 若属性不存在则退回 `info.filename`（同样转 bytes）。  
    3. 当所有条目均已设置 UTF‑8 标志时直接返回 `success=False`，避免误报。
    4. 混合检测模式：先用chardet检测，再用LLM验证语言一致性。
    
    Args:
        zip_path: ZIP 文件路径
        enable_llm: 是否启用LLM二次验证
        chardet_confidence_threshold: chardet置信度阈值 (0.0-1.0)
        llm_confidence_threshold: LLM置信度阈值 (0.0-1.0)
        decode_model: 编码检测库 ('chardet' 或 'charset_normalizer')
    """
    import zipfile
    if decode_model == 'charset_normalizer':
        from charset_normalizer import detect
    else:
        import chardet

    result = {'encoding': None,
              'language': None,
              'confidence': 0.0,
              'success':   False}

    if VERBOSE:
        print(f"  DEBUG: 开始混合编码检测: {zip_path}")

    safe_zip_path   = safe_path_for_operation(zip_path, VERBOSE)
    filename_bytes  = []

    try:
        with zipfile.ZipFile(safe_zip_path, 'r') as zf:
            for info in zf.infolist():
                if info.flag_bits & 0x800:          # 已是 UTF‑8 条目
                    continue

                raw_name = getattr(info, 'orig_filename', None) or info.filename

                # 统一转 bytes（若本身已是 bytes 则按原值）
                if isinstance(raw_name, str):
                    raw_name = raw_name.encode('cp437', 'surrogateescape')

                filename_bytes.append(raw_name)

        if not filename_bytes:                      # 无传统编码条目
            if VERBOSE:
                print("  DEBUG: 全部条目已采用 UTF‑8 – 非传统ZIP")
            return result

        # 步骤1: 使用指定库检测编码
        sample = b'\n'.join(filename_bytes)
        
        # 统一使用 detect() 方法（两个库都兼容）
        if decode_model == 'charset_normalizer':
            detection_result = detect(sample)
            library_name = "charset_normalizer"
        else:
            detection_result = chardet.detect(sample)
            library_name = "chardet"
            
        if not detection_result or not detection_result.get('encoding'):
            if VERBOSE:
                print(f"  DEBUG: {library_name}检测失败")
            return result
            
        detected_confidence = detection_result.get('confidence', 0.0)
        detected_encoding = detection_result['encoding']
        
        if VERBOSE:
            print(f"  DEBUG: {library_name}检测结果 - 编码: {detected_encoding}, 置信度: {detected_confidence:.3f}")
        
        # 步骤2: 置信度检查
        if detected_confidence < chardet_confidence_threshold:
            if VERBOSE:
                print(f"  DEBUG: 检测置信度过低 ({detected_confidence:.3f} < {chardet_confidence_threshold:.3f})，跳过")
            return result
        
        # 步骤3: 如果不启用LLM，直接返回检测结果
        if not enable_llm:
            result.update({
                'encoding': detected_encoding,
                'language': detection_result.get('language'),  # 兼容的方式获取语言信息
                'confidence': detected_confidence,
                'success': True
            })
            if VERBOSE:
                print(f"  DEBUG: 使用{library_name}结果，无LLM验证")
            return result
        
        # 步骤4: 用检测到的编码解码文本，发送给LLM验证
        llm_result = verify_encoding_with_llm(zip_path, detected_encoding, llm_confidence_threshold)
        
        if llm_result['success'] and llm_result['confidence'] >= llm_confidence_threshold:
            # LLM验证通过，返回混合结果
            result.update({
                'encoding': detected_encoding,
                'language': llm_result['language'],
                'detection_confidence': detected_confidence,
                'llm_confidence': llm_result['confidence'],
                'confidence': min(detected_confidence, llm_result['confidence']),  # 取较小值作为总体置信度
                'success': True
            })
            if VERBOSE:
                print(f"  DEBUG: LLM验证通过 - 语言: {llm_result['language']}, 置信度: {llm_result['confidence']:.3f}")
        else:
            # LLM验证失败，认为整体检测失败
            if VERBOSE:
                if not llm_result['success']:
                    print("  DEBUG: LLM验证失败")
                else:
                    print(f"  DEBUG: LLM置信度过低 ({llm_result['confidence']:.3f} < {llm_confidence_threshold:.3f})")
            result = {'success': False}
            
    except Exception as exc:
        if VERBOSE:
            print(f"  DEBUG: ZIP编码检测异常: {exc}")

    return result




def get_7z_encoding_param(encoding):
    """
    将检测到的编码转换为7z命令的-mcp参数值
    基于chardet的稳定输出进行精确映射
    
    Args:
        encoding: chardet检测到的编码名称
        
    Returns:
        str or None: 7z支持的编码参数，如果不支持则返回None
    """
    if not encoding:
        return None
    
    # chardet和charset_normalizer稳定输出的完整映射表
    encoding_map = {
        # ASCII和基础编码
        'ascii': '1252',  # ASCII可以安全地使用Windows-1252
        
        # Unicode编码系列
        'utf-8': 'UTF-8',
        'utf-8-sig': 'UTF-8',  # charset_normalizer带BOM的UTF-8
        'utf8': 'UTF-8',       # 简写形式
        'utf-16': 'UTF-16',
        'utf-16-be': 'UTF-16BE',
        'utf-16-le': 'UTF-16LE',
        'utf16': 'UTF-16',     # 简写形式
        'utf-32': 'UTF-32',
        'utf-32-be': 'UTF-32BE',
        'utf-32-le': 'UTF-32LE',
        'utf32': 'UTF-32',     # 简写形式
        
        # 中文编码 (两个库的可能输出)
        'big5': '950',
        'big5-tw': '950',      # charset_normalizer别名
        'big5hkscs': '950',    # 香港增补字符集
        'gb2312': '936',
        'gb18030': '936',
        'gb18030-2000': '936', # charset_normalizer可能输出
        'gbk': '936',          # charset_normalizer常用输出
        'cp936': '936',        # Windows代码页
        'ms936': '936',        # 微软别名
        'euc-tw': '950',
        'hz-gb-2312': '936',
        'hz': '936',           # 简写
        'iso-2022-cn': '936',
        
        # 日文编码 - 关键差异区域
        # chardet的传统输出
        'shift_jis': '932',
        'shift-jis': '932',    # 连字符变体
        'sjis': '932',         # 简写形式
        's_jis': '932',        # 下划线变体
        'shiftjis': '932',     # 无分隔符
        # charset_normalizer的标准输出
        'cp932': '932',        # Windows代码页932 (最常见输出)
        'windows-31j': '932',  # IANA标准名称
        'ms932': '932',        # 微软内部名称
        'ms_kanji': '932',     # 微软别名
        'mskanji': '932',      # 无下划线变体
        'x_mac_japanese': '932', # Mac日语编码
        # 其他日语编码
        'euc-jp': '20932',
        'eucjp': '20932',      # 简写
        'ujis': '20932',       # Unix JIS
        'iso-2022-jp': '50222',
        'iso2022jp': '50222',  # 无连字符
        'euc_jis_2004': '20932',     # JIS X 0213
        'shift_jis_2004': '932',     # JIS X 0213
        'shift_jisx0213': '932',     # JIS X 0213变体
        
        # 韩文编码
        'euc-kr': '949',
        'euckr': '949',        # 简写
        'cp949': '949',        # Windows代码页949 (charset_normalizer常用)
        'ms949': '949',        # 微软别名
        'uhc': '949',          # Unified Hangul Code
        'ks_c_5601': '949',    # 韩国标准
        'ks_c_5601_1987': '949', # charset_normalizer可能输出
        'ksc5601': '949',      # chardet可能输出
        'iso-2022-kr': '50225',
        'iso2022kr': '50225',  # 无连字符
        'johab': '1361',       # 朝鲜语Johab编码
        'cp1361': '1361',      # Johab的代码页
        'ms1361': '1361',      # 微软别名
        
        # 俄语/西里尔编码
        'koi8-r': '20866',
        'koi8_r': '20866',     # 下划线变体
        'maccyrillic': '10007',
        'mac_cyrillic': '10007', # 下划线变体
        'ibm855': '855',
        'cp855': '855',        # charset_normalizer格式
        'ibm866': '866',
        'cp866': '866',        # charset_normalizer格式
        'iso-8859-5': '28595',
        'iso8859_5': '28595',  # charset_normalizer格式
        'windows-1251': '1251',
        'cp1251': '1251',      # charset_normalizer常用
        'cyrillic': '28595',   # 通用西里尔
        
        # 西欧语言编码
        'iso-8859-1': '28591',
        'iso8859_1': '28591',  # charset_normalizer格式
        'latin-1': '28591',
        'latin_1': '28591',    # charset_normalizer别名
        'latin1': '28591',     # 简写
        'windows-1252': '1252',
        'cp1252': '1252',      # charset_normalizer常用
        
        # 中欧语言编码（匈牙利语等）
        'iso-8859-2': '28592',
        'iso8859_2': '28592',  # charset_normalizer格式
        'latin-2': '28592',
        'latin_2': '28592',    # charset_normalizer别名
        'windows-1250': '1250',
        'cp1250': '1250',      # charset_normalizer常用
        
        # 希腊语编码
        'iso-8859-7': '28597',
        'iso8859_7': '28597',  # charset_normalizer格式
        'greek': '28597',      # chardet可能输出
        'windows-1253': '1253',
        'cp1253': '1253',      # charset_normalizer常用
        
        # 希伯来语编码
        'iso-8859-8': '28598',
        'iso8859_8': '28598',  # charset_normalizer格式
        'hebrew': '28598',     # chardet可能输出
        'windows-1255': '1255',
        'cp1255': '1255',      # charset_normalizer常用
        
        # 土耳其语编码
        'iso-8859-9': '28599',
        'iso8859_9': '28599',  # charset_normalizer格式
        'latin-5': '28599',
        'windows-1254': '1254',
        'cp1254': '1254',      # charset_normalizer常用
        
        # 阿拉伯语编码
        'iso-8859-6': '28596',
        'iso8859_6': '28596',  # charset_normalizer格式
        'arabic': '28596',     # chardet可能输出
        'windows-1256': '1256',
        'cp1256': '1256',      # charset_normalizer常用
        
        # 波罗的海语言编码
        'iso-8859-4': '28594',
        'iso8859_4': '28594',  # charset_normalizer格式
        'windows-1257': '1257',
        'cp1257': '1257',      # charset_normalizer常用
        
        # 越南语编码
        'windows-1258': '1258',
        'cp1258': '1258',      # charset_normalizer常用
        
        # 泰语编码
        'tis-620': '874',
        'tis620': '874',       # 简写
        'cp874': '874',        # charset_normalizer常用
        'thai': '874',         # chardet可能输出
        
        # 其他常见编码
        'cp437': '437',        # DOS美国
        'cp850': '850',        # DOS西欧
        'cp852': '852',        # DOS中欧
        'cp775': '775',        # DOS波罗的海
        'hp_roman8': '1051',   # HP Roman8
        'mac_roman': '10000',  # Mac Roman
        'macintosh': '10000',  # Mac Roman别名
    }
    
    # 标准化输入编码名称（只处理大小写）
    encoding_lower = encoding.lower().strip()
    
    # 精确匹配
    if encoding_lower in encoding_map:
        code_page = encoding_map[encoding_lower]
        if VERBOSE:
            print(f"  DEBUG: 编码映射 {encoding} -> {code_page}")
        return code_page
    
    # 处理编码名称的常见变体
    # 因为不同库和版本间可能有细微的命名差异
    normalized_variants = [
        encoding_lower.replace('-', '_'),  # ISO-8859-1 -> iso_8859_1
        encoding_lower.replace('_', '-'),  # shift_jis -> shift-jis  
        encoding_lower.replace('-', ''),   # ISO-8859-1 -> iso88591
        encoding_lower.replace('_', ''),   # shift_jis -> shiftjis
        encoding_lower.replace(' ', '-'),  # "shift jis" -> shift-jis
        encoding_lower.replace(' ', '_'),  # "shift jis" -> shift_jis
        encoding_lower.replace(' ', ''),   # "shift jis" -> shiftjis
    ]
    
    for variant in normalized_variants:
        if variant in encoding_map:
            code_page = encoding_map[variant]
            if VERBOSE:
                print(f"  DEBUG: 编码变体映射 {encoding} ({variant}) -> {code_page}")
            return code_page
    
    # 特殊处理：如果是未知的CP开头的编码，尝试直接提取数字
    if encoding_lower.startswith('cp') and len(encoding_lower) > 2:
        try:
            cp_number = encoding_lower[2:]
            # 验证是否为纯数字且在合理范围内
            cp_int = int(cp_number)
            if 1 <= cp_int <= 65535:  # 合理的代码页范围
                if VERBOSE:
                    print(f"  DEBUG: 直接使用代码页号 {encoding} -> {cp_number}")
                return cp_number
        except ValueError:
            pass
    
    # 特殊处理：Windows-开头的编码
    if encoding_lower.startswith('windows-') and len(encoding_lower) > 8:
        try:
            win_number = encoding_lower[8:]  # 去掉 "windows-"
            win_int = int(win_number)
            if 1250 <= win_int <= 1258:  # Windows代码页范围
                if VERBOSE:
                    print(f"  DEBUG: Windows编码映射 {encoding} -> {win_number}")
                return win_number
        except ValueError:
            pass
    
    # 如果完全没有匹配，记录并返回None
    if VERBOSE:
        print(f"  DEBUG: 未知编码，无法映射到7z参数: {encoding}")
        print(f"  DEBUG: 建议检查chardet或charset_normalizer版本和文档，确认 '{encoding}' 是否为有效输出")
    
    return None
    

# === 传统zip编码检测实现 ===
def is_traditional_zip(archive_path):
    """
    经过修正的函数，用于检测传统ZIP编码。
    如果任何条目使用了现代UTF-8扩展字段(0x7075)，则返回False。
    """
    try:
        # 确保文件是.zip文件
        if not archive_path.lower().endswith('.zip'):
            return False
            
        with safe_open(archive_path, 'rb') as f:
            # 记录是否至少有一个非UTF-8标志的条目，这是成为传统ZIP的前提
            has_non_utf8_entry = False
            
            while True:
                sig = f.read(4)
                # 到达中央目录或文件末尾，结束循环
                if sig != b'PK\x03\x04':
                    break
                    
                hdr = f.read(26)  # 读取本地文件头的固定部分
                if len(hdr) < 26:
                    return False # 文件头不完整
                    
                gpbf = int.from_bytes(hdr[2:4], 'little')
                name_len = int.from_bytes(hdr[22:24], 'little')
                extra_len = int.from_bytes(hdr[24:26], 'little')
                
                # 检查通用位标志的bit 11
                is_utf8_flag_set = gpbf & (1 << 11)
                
                # 如果UTF-8标志位被设置，这绝对是现代ZIP，直接返回False
                if is_utf8_flag_set:
                    return False
                    
                # 如果文件名长度为0，视为不规范，但继续检查
                if name_len == 0:
                    # 在某些情况下，这可能是目录条目，但缺少文件名是不寻常的
                    pass

                # 跳过文件名
                f.seek(name_len, 1)

                # --- 主要修改部分开始 ---
                # 检查扩展字段是否存在并解析它
                if extra_len > 0:
                    extra_data = f.read(extra_len)
                    offset = 0
                    # 遍历扩展字段中的所有块
                    while offset < extra_len:
                        # 确保有足够的空间读取块头（ID和大小）
                        if offset + 4 > extra_len:
                            break # 扩展字段格式错误
                        
                        header_id = int.from_bytes(extra_data[offset:offset+2], 'little')
                        data_size = int.from_bytes(extra_data[offset+2:offset+4], 'little')
                        
                        # 0x7075 是 Info-ZIP Unicode Path Extra Field 的ID
                        # 它的存在明确表示这是一个现代的、支持Unicode的ZIP
                        if header_id == 0x7075:
                            return False
                            
                        # 移动到下一个扩展块
                        offset += 4 + data_size
                # --- 主要修改部分结束 ---

                # 标记我们至少找到了一个没有设置UTF-8标志的条目
                has_non_utf8_entry = True

                # 处理数据描述符（Data Descriptor）
                has_dd = gpbf & (1 << 3)
                if not has_dd:
                    # 如果没有数据描述符，则从文件头读取压缩后的大小并跳过
                    comp_size = int.from_bytes(hdr[14:18], 'little') # 注意：偏移量应为14-18
                    f.seek(comp_size, 1)
                else:
                    # 如果存在数据描述符，情况变得复杂。
                    # 原函数的逻辑是"遇到Data-Descriptor直接判定为True"，这可能不准确。
                    # 一个更稳妥的方法是正确地跳过数据，但这需要流式解压的知识。
                    # 为了保持简单，我们假设如果到这里还没被判定为False，就继续循环。
                    # 这里我们遵循原函数的逻辑：只要存在一个非UTF8条目，就可能是传统ZIP。
                    # 我们让循环自然结束，最后根据has_non_utf8_entry判断。
                    # 注意：在实际情况中，我们需要找到下一个 'PK' 签名来恢复流，这里简化处理。
                    # 为了安全起见，这里我们直接中断，并依赖于循环外的最终判断。
                    # 现代ZIP很少在没有流式传输的情况下使用数据描述符。
                    # 我们可以认为，如果到这里还没返回False，它就是"传统的"。
                    # 但更准确的逻辑在下面循环结束后的return语句中处理。
                    pass # 这里的处理逻辑依赖于循环后的最终判断
            
            # 如果循环正常结束，判断是否满足"传统ZIP"的条件：
            # 至少存在一个条目，且所有遇到的条目都没有UTF-8标志或UTF-8扩展字段。
            return has_non_utf8_entry

    except Exception as exc:
        if VERBOSE:
            print(f"  DEBUG: 传统ZIP检测异常: {exc}")
        return False



# === Extension Fix Logic ====

def detect_archive_type(file_path):
    """
    通过文件头检测归档文件类型
    
    Args:
        file_path: 文件路径
        
    Returns:
        str: 检测到的归档类型（"RAR 4.x", "RAR 5.x", "ZIP", "ZIP (empty)", "ZIP (spanned)", "7Z", "Unknown"）
    """
    try:
        with open(file_path, 'rb') as f:
            header = f.read(8)
        
        # RAR检测
        if header[:7] == b'\x52\x61\x72\x21\x1A\x07\x00':
            return "RAR 4.x"
        elif header[:8] == b'\x52\x61\x72\x21\x1A\x07\x01\x00':
            return "RAR 5.x"
        
        # ZIP检测
        elif header[:4] == b'\x50\x4B\x03\x04':
            return "ZIP"
        elif header[:4] == b'\x50\x4B\x05\x06':
            return "ZIP (empty)"
        elif header[:4] == b'\x50\x4B\x07\x08':
            return "ZIP (spanned)"
        
        # 7Z检测
        elif header[:6] == b'\x37\x7A\xBC\xAF\x27\x1C':
            return "7Z"
        
        return "Unknown"
    except Exception as e:
        if VERBOSE:
            print(f"  DEBUG: 文件头检测异常 {file_path}: {e}")
        return "Unknown"


def fix_archive_ext(processor, abs_path, args):
    """
    扩展名修复主函数
    
    Args:
        processor: ArchiveProcessor实例
        abs_path: 绝对路径
        args: 命令行参数
    """
    if not args.fix_ext and not args.safe_fix_ext:
        return
    
    if VERBOSE:
        print("  DEBUG: 开始扩展名修复预处理...")
    
    # 解析深度范围参数
    depth_range = None
    if hasattr(args, 'depth_range') and args.depth_range:
        try:
            depth_range = parse_depth_range(args.depth_range)
            if VERBOSE:
                print(f"  DEBUG: 扩展名修复使用深度范围: {depth_range[0]}-{depth_range[1]}")
        except ValueError as e:
            print(f"Error: Invalid depth range for extension fix: {e}")
            return
    
    # 1. 收集所有候选文件
    candidate_files = []
    
    if safe_isfile(abs_path, VERBOSE):
        # 单个文件情况
        candidate_files.append(abs_path)
    elif safe_isdir(abs_path, VERBOSE):
        # 目录情况，根据深度范围收集文件
        try:
            for root, dirs, files in os.walk(abs_path):
                check_interrupt()
                
                if depth_range:
                    current_depth = root.replace(abs_path, '').count(os.sep)
                    if current_depth < depth_range[0] or current_depth > depth_range[1]:
                        continue
                
                for filename in files:
                    filepath = os.path.join(root, filename)
                    if safe_isfile(filepath, VERBOSE):
                        candidate_files.append(filepath)
        except Exception as e:
            if VERBOSE:
                print(f"  DEBUG: 收集文件时出错: {e}")
            return
    else:
        if VERBOSE:
            print(f"  DEBUG: 路径不存在或无法访问: {abs_path}")
        return
    
    if VERBOSE:
        print(f"  DEBUG: 收集到 {len(candidate_files)} 个候选文件")
    
    # 2. 对每个文件进行冲突检查和处理
    files_to_process = []
    
    for filepath in candidate_files:
        check_interrupt()
        
        try:
            filename = os.path.basename(filepath)
            parent_dir = os.path.dirname(filepath)
            
            # 获取目录下所有文件
            try:
                dir_files = [f for f in os.listdir(parent_dir) if safe_isfile(os.path.join(parent_dir, f), False)]
            except:
                if VERBOSE:
                    print(f"  DEBUG: 无法列出目录文件: {parent_dir}")
                continue
            
            should_skip = False
            
            # 解析文件名和扩展名
            if not has_valid_extension(filename):
                # (1.1) 文件没有扩展名
                # 检查是否存在 {filename}.{anyExt} 的文件
                for other_file in dir_files:
                    if other_file != filename and other_file.startswith(filename + '.'):
                        should_skip = True
                        if VERBOSE:
                            print(f"  DEBUG: skip-rename-archives: 跳过 {filepath} - 存在同名扩展文件 {other_file}")
                        break
            else:
                # 文件有扩展名
                name_parts = filename.rsplit('.', 1)
                basename = name_parts[0]
                file_ext = name_parts[1].lower()
                
                # (1.2) 如果扩展名是 exe，跳过
                if file_ext == 'exe':
                    should_skip = True
                    if VERBOSE:
                        print(f"  DEBUG: skip-rename-archives: 跳过 {filepath} - exe文件")
                elif '.' in basename:
                    # (1.3) basename 包含 '.'，从右往左分割
                    basename_parts = basename.rsplit('.', 1)
                    first_part = basename_parts[0]
                    last_part = basename_parts[1]
                    
                    # 检查冲突文件
                    conflict_patterns = [
                        first_part,  # 无扩展名
                        first_part + '.',  # 前缀匹配任意扩展名
                        first_part + '.' + last_part,  # 无扩展名
                        first_part + '.' + last_part + '.'  # 前缀匹配任意扩展名
                    ]
                    
                    for other_file in dir_files:
                        if other_file == filename:
                            continue
                        
                        # 检查是否匹配冲突模式
                        if (other_file == conflict_patterns[0] or  # {firstPart}
                            other_file == conflict_patterns[2] or  # {firstPart}.{lastPart}
                            (other_file.startswith(conflict_patterns[1]) and len(other_file) > len(conflict_patterns[1])) or  # {firstPart}.{anyExt}
                            (other_file.startswith(conflict_patterns[3]) and len(other_file) > len(conflict_patterns[3]))):  # {firstPart}.{lastPart}.{anyExt}
                            should_skip = True
                            if VERBOSE:
                                print(f"  DEBUG: skip-rename-archives: 跳过 {filepath} - 存在冲突文件 {other_file}")
                            break
                else:
                    # (1.4) basename 不包含 '.'
                    # 检查是否存在冲突文件
                    for other_file in dir_files:
                        if other_file == filename:
                            continue
                        
                        if (other_file == basename or  # {filename} 无扩展名
                            (other_file.startswith(basename + '.') and other_file != filename)):  # {filename}.{anyExt}
                            should_skip = True
                            if VERBOSE:
                                print(f"  DEBUG: skip-rename-archives: 跳过 {filepath} - 存在冲突文件 {other_file}")
                            break
            
            if should_skip:
                processor.skipped_rename_archives.append(filepath)
            else:
                files_to_process.append(filepath)
                
        except Exception as e:
            if VERBOSE:
                print(f"  DEBUG: 处理文件时出错 {filepath}: {e}")
            continue
    
    if VERBOSE:
        print(f"  DEBUG: 筛选出 {len(files_to_process)} 个文件需要检测和重命名")
    
    # 3. 对筛选出的文件进行文件头检测，收集重命名计划
    planned_renames = []
    final_skipped = []
    
    for filepath in files_to_process:
        check_interrupt()
        
        try:
            archive_type = detect_archive_type(filepath)
            
            if archive_type == "Unknown":
                if VERBOSE:
                    print(f"  DEBUG: skip-rename-archives: 跳过 {filepath} - 未知文件类型")
                final_skipped.append((filepath, "未知文件类型"))
                continue
            
            # 确定目标扩展名
            if archive_type.startswith("RAR"):
                target_ext = "rar"
            elif archive_type.startswith("ZIP"):
                target_ext = "zip"
            elif archive_type == "7Z":
                target_ext = "7z"
            else:
                if VERBOSE:
                    print(f"  DEBUG: skip-rename-archives: 跳过 {filepath} - 不支持的归档类型 {archive_type}")
                final_skipped.append((filepath, f"不支持的归档类型 {archive_type}"))
                continue
            
            # 计划重命名
            filename = os.path.basename(filepath)
            
            # 如果扩展名已正确（忽略大小写），直接跳过，不记录日志
            if filename.lower().endswith('.' + target_ext):
                continue

            parent_dir = os.path.dirname(filepath)
            
            # 根据模式确定新文件名
            if args.safe_fix_ext:
                # 安全模式：始终追加扩展名
                new_filename = filename + '.' + target_ext
            else:
                # 普通模式：根据是否有有效扩展名决定
                if not has_valid_extension(filename):
                    # 无扩展名，添加扩展名
                    new_filename = filename + '.' + target_ext
                else:
                    # 有扩展名，替换扩展名
                    name_parts = filename.rsplit('.', 1)
                    new_filename = name_parts[0] + '.' + target_ext
            
            new_filepath = os.path.join(parent_dir, new_filename)
            
            # 检查目标文件是否已存在
            if safe_isfile(new_filepath, False):
                if VERBOSE:
                    print(f"  DEBUG: skip-rename-archives: 跳过 {filepath} - 目标文件已存在 {new_filename}")
                final_skipped.append((filepath, f"目标文件已存在 {new_filename}"))
                continue
            
            # 添加到重命名计划
            planned_renames.append((filepath, new_filepath, archive_type))
        
        except Exception as e:
            if VERBOSE:
                print(f"  DEBUG: 检测文件头时出错 {filepath}: {e}")
            final_skipped.append((filepath, f"检测文件头时出错: {e}"))
    
    # 4. 显示交互式确认界面（仅当有文件需要重命名时）
    if not planned_renames:
        if VERBOSE:
            print(f"  DEBUG: 没有文件需要重命名，跳过 {len(final_skipped)} 个文件")
        return
    
    print("\n" + "=" * 60)
    print("EXTENSION FIX PREVIEW")
    print("=" * 60)
    
    print(f"Files to rename ({len(planned_renames)} files):")
    for old_path, new_path, archive_type in planned_renames:
        print(f"  {old_path} -> {new_path} (detected as {archive_type})")
    
    # 交互确认
    print(f"\nContinue with extension fix? [y/N]: ", end="", flush=True)
    try:
        response = input().strip().lower()
        if response not in ['y', 'yes']:
            print("Extension fix cancelled by user.")
            return
    except (KeyboardInterrupt, EOFError):
        print("\nExtension fix cancelled by user.")
        return
    
    # 5. 执行重命名
    print(f"\nExecuting extension fix...")
    for old_path, new_path, archive_type in planned_renames:
        try:
            os.rename(old_path, new_path)
            processor.fixed_rename_archives.append((old_path, new_path))
            print(f"fix-rename-archives: {old_path} -> {new_path} (detected as {archive_type})")
            if VERBOSE:
                print(f"  DEBUG: fix-rename-archives: 重命名成功 {old_path} -> {new_path}")
        except Exception as e:
            if VERBOSE:
                print(f"  DEBUG: skip-rename-archives: 重命名失败 {old_path} -> {new_path}: {e}")
            processor.skipped_rename_archives.append(old_path)
            final_skipped.append((old_path, f"重命名失败: {e}"))
    
    # 将最终跳过的文件添加到processor
    for filepath, reason in final_skipped:
        if filepath not in processor.skipped_rename_archives:
            processor.skipped_rename_archives.append(filepath)
    
    # 打印汇总
    print(f"\nExtension fix completed: renamed {len(processor.fixed_rename_archives)} files, skipped {len(processor.skipped_rename_archives)} files")


# === depth 限制 实现 ====

def parse_depth_range(depth_range_str):
    """
    解析深度范围字符串
    
    Args:
        depth_range_str: 深度范围字符串，格式为 "int1-int2" 或 "int"
        
    Returns:
        tuple: (min_depth, max_depth) 或 None（如果解析失败）
        
    Raises:
        ValueError: 如果格式无效或深度值无效
    """
    if not depth_range_str:
        return None
        
    depth_range_str = depth_range_str.strip()
    
    if VERBOSE:
        print(f"  DEBUG: 解析深度范围: {depth_range_str}")
    
    try:
        if '-' in depth_range_str:
            # 格式: "int1-int2"
            parts = depth_range_str.split('-')
            if len(parts) != 2:
                raise ValueError(f"Invalid depth range format: {depth_range_str}")
                
            min_depth = int(parts[0].strip())
            max_depth = int(parts[1].strip())
            
            if min_depth < 0 or max_depth < 0:
                raise ValueError(f"Depth values must be non-negative: {depth_range_str}")
                
            if min_depth > max_depth:
                raise ValueError(f"Min depth must be <= max depth: {depth_range_str}")
                
            if VERBOSE:
                print(f"  DEBUG: 解析范围 {min_depth}-{max_depth}")
                
            return (min_depth, max_depth)
        else:
            # 格式: "int"
            depth = int(depth_range_str)
            if depth < 0:
                raise ValueError(f"Depth value must be non-negative: {depth_range_str}")
                
            if VERBOSE:
                print(f"  DEBUG: 解析单一深度 {depth}")
                
            return (depth, depth)
            
    except ValueError as e:
        if VERBOSE:
            print(f"  DEBUG: 深度范围解析失败: {e}")
        raise
        


# ==== 解压filter实现 ====
def is_zip_multi_volume(zip_path, processor=None):
    """判断ZIP文件是否为分卷（统一逻辑 helper）"""
    if not zip_path.lower().endswith('.zip'):
        return False

    # 使用现有的 processor 如果有
    if processor:
        return processor.is_archive_single_or_volume(zip_path) == 'volume'

    # 创建临时处理器
    class _TmpArgs:
        def __init__(self):
            self.verbose = VERBOSE
            # 添加密码相关属性以避免AttributeError
            self.password = None
            self.password_file = None
    temp_proc = ArchiveProcessor(_TmpArgs())
    return temp_proc.is_archive_single_or_volume(zip_path) == 'volume'



def is_exe_multi_volume(exe_path, processor=None):
    """DEPRECATED: 已弃用，逻辑整合到 ArchiveProcessor.is_archive_single_or_volume"""
    return ArchiveProcessor(type('A', (object,), {'verbose': VERBOSE})()).is_archive_single_or_volume(exe_path) == 'volume'

def should_skip_archive(archive_path, args, processor=None):
    """
    根据跳过参数判断是否应该跳过指定的归档文件（优化版本）
    
    Args:
        archive_path: 归档文件路径
        args: 命令行参数对象
        processor: ArchiveProcessor实例（推荐传入以避免重复创建）

    Returns:
        tuple: (should_skip: bool, reason: str) 是否跳过和跳过原因
    """
    if VERBOSE:
        print(f"  DEBUG: 检查是否跳过归档: {archive_path}")

    # 如果提供了processor，直接使用（最优路径）
    if processor:
        archive_type = processor.is_archive_single_or_volume(archive_path)
        
        if archive_type == 'notarchive':
            return True, "非归档文件被跳过"
        
        elif archive_type == 'single':
            return processor._should_skip_single_archive(archive_path)
        
        elif archive_type == 'volume':
            if not processor.is_main_volume(archive_path):
                return True, "非主卷分卷文件被跳过"
            return processor._should_skip_multi_archive(archive_path)
    
    # 兼容性：如果没有提供processor，创建临时的
    if VERBOSE:
        print(f"  DEBUG: 创建临时processor检查跳过状态")
    
    temp_sfx_detector = SFXDetector(verbose=VERBOSE)
    
    class TempArgs:
        def __init__(self):
            self.verbose = VERBOSE
            # 复制必要的skip参数
            skip_attrs = ['skip_7z', 'skip_rar', 'skip_zip', 'skip_exe',
                         'skip_7z_multi', 'skip_rar_multi', 'skip_zip_multi', 'skip_exe_multi',
                         'traditional_zip_policy']
            for attr in skip_attrs:
                if hasattr(args, attr):
                    setattr(self, attr, getattr(args, attr))
                else:
                    # 设置默认值
                    if attr == 'traditional_zip_policy':
                        setattr(self, attr, 'decode-auto')
                    else:
                        setattr(self, attr, False)
    
    temp_args = TempArgs()
    temp_processor = ArchiveProcessor(temp_args)
    temp_processor.sfx_detector = temp_sfx_detector
    
    # 递归调用，这次会使用processor分支
    return should_skip_archive(archive_path, args, processor=temp_processor)
    
def is_multi_volume_archive(archive_path, processor=None):
    """DEPRECATED: 已弃用，直接调用 ArchiveProcessor 统一接口"""
    if processor:
        return processor.is_archive_single_or_volume(archive_path) == 'volume'
    class _Tmp:
        def __init__(self):
            self.verbose = VERBOSE
    return ArchiveProcessor(_Tmp()).is_archive_single_or_volume(archive_path) == 'volume'

# ==================== 短路径API改造 ====================

def is_windows():
    """检查是否为Windows系统"""
    return platform.system() == 'Windows'


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

def safe_path_for_operation(path: str, debug: bool = False) -> str:
    """
    Windows路径安全处理：优先使用短路径避免兼容性问题
    - 自动处理长路径问题（>260字符）
    - 处理包含特殊字符的路径
    - 确保与os.path模块良好配合
    - 对非Windows系统直接返回原始路径
    """
    if not is_windows() or not path:
        return path
    
    try:
        # 先标准化路径
        abs_path = os.path.abspath(os.path.expandvars(path))
        
        # 优先尝试获取短路径（8.3格式）
        short_path = get_short_path_name(abs_path)
        
        # 如果成功获取到短路径且与原路径不同，则使用短路径
        if short_path != abs_path:
            if debug:
                print(f"  DEBUG: 使用短路径: {path} -> {short_path}")
            return short_path
        
        # 如果无法获取短路径或短路径与原路径相同，则使用原路径
        if debug:
            print(f"  DEBUG: 使用原路径: {abs_path}")
        return abs_path
        
    except Exception as e:
        if debug:
            print(f"  DEBUG: 路径处理失败 {path}: {e}")
        return path

def safe_open(file_path, mode='r', *args, **kwargs):
    """
    替代内建 open，自动处理 Windows 超长/Unicode 路径。
    额外接受 keyword 参数 debug=True 开启调试输出。
    """
    debug = kwargs.pop('debug', False)
    safe_path = safe_path_for_operation(file_path, debug)
    if debug:
        print(f"  DEBUG: safe_open -> {safe_path}")
    return open(safe_path, mode, *args, **kwargs)

def safe_glob(pattern: str, debug: bool = False, preserve_char_classes: bool = False):
    """
    简单的glob替代，使用正则表达式避免fnmatch的特殊字符问题
    支持大小写不敏感匹配
    """
    import re
    
    if debug:
        print(f"  DEBUG: 原始pattern: {pattern}")
    
    # 分离目录和文件名模式
    dir_path = os.path.dirname(pattern)
    file_pattern = os.path.basename(pattern)
    
    if debug:
        print(f"  DEBUG: 目录路径: {dir_path}")
        print(f"  DEBUG: 文件模式: {file_pattern}")
    
    # 如果没有目录路径，使用当前目录
    if not dir_path:
        dir_path = '.'
    
    # 先对目录路径进行安全处理
    safe_dir_path = safe_path_for_operation(dir_path, debug)
    
    try:
        # 确保目录存在
        if not os.path.exists(safe_dir_path):
            if debug:
                print(f"  DEBUG: 目录不存在: {safe_dir_path}")
            return []
        
        # 获取目录中的所有文件
        try:
            files = os.listdir(safe_dir_path)
        except (OSError, UnicodeDecodeError) as e:
            if debug:
                print(f"  DEBUG: 列出目录失败: {e}")
            return []
        
        if debug:
            print(f"  DEBUG: 目录中的文件数量: {len(files)}")
        
        # 将glob模式转换为正则表达式
        import re
        
        if preserve_char_classes:
            # 需要保护特定的字符类模式（仅用于分卷文件匹配）
            char_classes = []
            temp_pattern = file_pattern
            
            # 只保护特定的字符类模式，如 [^.]+ 等
            def replace_specific_char_class(match):
                char_classes.append(match.group(0))
                return f"__CHAR_CLASS_{len(char_classes)-1}__"
            
            # 在转义之前提取我们需要的字符类模式（原始字符串中的模式）
            specific_patterns = [
                r'\[\^\.\]\+',  # [^.]+
                r'\[\^\.\]\*',  # [^.]*
                r'\[\^\.\]\?',  # [^.]?
            ]
            
            for pattern in specific_patterns:
                temp_pattern = re.sub(pattern, replace_specific_char_class, temp_pattern)
            
            # 转义剩余的特殊字符  
            regex_pattern = re.escape(temp_pattern)
            
            # 恢复通配符
            regex_pattern = regex_pattern.replace(r'\*', '.*')
            regex_pattern = regex_pattern.replace(r'\?', '.')
            
            # 恢复被保护的字符类
            for i, char_class in enumerate(char_classes):
                placeholder = re.escape(f"__CHAR_CLASS_{i}__")
                regex_pattern = regex_pattern.replace(placeholder, char_class)
        else:
            # 传统模式：只处理*和?通配符
            regex_pattern = re.escape(file_pattern)
            regex_pattern = regex_pattern.replace(r'\*', '.*')
            regex_pattern = regex_pattern.replace(r'\?', '.')
        
        regex_pattern = '^' + regex_pattern + '$'  # 精确匹配
        
        if debug:
            print(f"  DEBUG: 原始文件模式: {file_pattern}")
            print(f"  DEBUG: 正则表达式: {regex_pattern}")
        
        # 编译正则表达式，使用大小写不敏感标志
        try:
            regex = re.compile(regex_pattern, re.IGNORECASE)
        except re.error as e:
            if debug:
                print(f"  DEBUG: 正则表达式编译失败: {e}")
            return []
        
        matched_files = []
        for file in files:
            try:
                if regex.match(file):
                    full_path = os.path.join(dir_path, file)
                    matched_files.append(full_path)
                    if debug:
                        print(f"  DEBUG: 匹配到文件: {file}")
            except (UnicodeDecodeError, UnicodeEncodeError) as e:
                if debug:
                    print(f"  DEBUG: 文件名编码问题: {file}, 错误: {e}")
                continue
        
        if debug:
            print(f"  DEBUG: 总共匹配到 {len(matched_files)} 个文件")
        
        return sorted(matched_files)
        
    except Exception as e:
        if debug:
            print(f"  DEBUG: safe_glob异常: {e}")
        return []

def _patch_cmd_paths(cmd):
    """
    接受 list / tuple / str，返回替换了路径元素后的同类型对象。
    规则：凡是现存的文件或目录，都调用 safe_path_for_operation 处理。
    """
    if isinstance(cmd, (list, tuple)):
        patched = []
        for token in cmd:
            try:
                if os.path.isabs(token) and safe_exists(token):
                    patched.append(safe_path_for_operation(token))
                else:
                    patched.append(token)
            except Exception:
                patched.append(token)
        return type(cmd)(patched)
    return cmd  # 字符串情况交由 shell 处理


def safe_exists(path, debug=False):
    """安全的路径存在性检查"""
    try:
        safe_path = safe_path_for_operation(path, debug)
        return os.path.exists(safe_path)
    except Exception as e:
        if debug:
            print(f"  DEBUG: 检查路径存在性失败 {path}: {e}")
        return False


def safe_isdir(path, debug=False):
    """安全的目录检查"""
    try:
        safe_path = safe_path_for_operation(path, debug)
        return os.path.isdir(safe_path)
    except Exception as e:
        if debug:
            print(f"  DEBUG: 检查路径是否为目录失败 {path}: {e}")
        return False


def safe_isfile(path, debug=False):
    """安全的文件检查"""
    try:
        safe_path = safe_path_for_operation(path, debug)
        return os.path.isfile(safe_path)
    except Exception as e:
        if debug:
            print(f"  DEBUG: 检查路径是否为文件失败 {path}: {e}")
        return False


def safe_makedirs(path, exist_ok=True, debug=False):
    """安全的目录创建"""
    try:
        safe_path = safe_path_for_operation(path, debug)
        os.makedirs(safe_path, exist_ok=exist_ok)
        if debug:
            print(f"  DEBUG: 成功创建目录: {path}")
        return True
    except Exception as e:
        if debug:
            print(f"  DEBUG: 创建目录失败 {path}: {e}")
        return False


def safe_remove(path, debug=False):
    """安全的文件删除"""
    try:
        safe_path = safe_path_for_operation(path, debug)
        os.remove(safe_path)
        if debug:
            print(f"  DEBUG: 成功删除文件: {path}")
        return True
    except Exception as e:
        if debug:
            print(f"  DEBUG: 删除文件失败 {path}: {e}")
        return False


def safe_rmdir(path, debug=False):
    """安全的空目录删除"""
    try:
        safe_path = safe_path_for_operation(path, debug)
        os.rmdir(safe_path)
        if debug:
            print(f"  DEBUG: 成功删除目录: {path}")
        return True
    except Exception as e:
        if debug:
            print(f"  DEBUG: 删除目录失败 {path}: {e}")
        return False


def safe_rmtree(path, debug=False):
    """安全的递归目录删除，自动处理只读属性"""
    def _onerror(func, path_, exc_info):
        """当无法删除只读文件时，修改权限后重试"""
        try:
            os.chmod(path_, stat.S_IWRITE)
            func(path_)
            if debug:
                print(f"  DEBUG: 强制删除只读项: {path_}")
        except Exception as e_inner:
            if debug:
                print(f"  DEBUG: 强制删除失败 {path_}: {e_inner}")

    try:
        safe_path = safe_path_for_operation(path, debug)
        shutil.rmtree(safe_path, onerror=_onerror)
        if debug:
            print(f"  DEBUG: 成功递归删除目录: {path}")
        return True
    except Exception as e:
        if debug:
            print(f"  DEBUG: 递归删除目录失败 {path}: {e}")
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
            print(f"  DEBUG: 成功移动: {src} -> {dst}")
        return True
    except Exception as e:
        if debug:
            print(f"  DEBUG: 移动失败 {src} -> {dst}: {e}")
        return False


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
            print(f"  DEBUG: 目录遍历失败 {top}: {e}")
        return


# ==================== 结束短路径API改造 ====================

# ==================== 锁机制 ====================

# 全局锁文件路径 - 确保路径一致性
def get_lock_file_path():
    """获取一致的锁文件路径"""
    if platform.system() == 'Windows':
        # Windows: 硬编码使用系统临时目录，确保路径一致性
        temp_dir = 'C:\\Windows\\Temp'
    else:
        # Unix/Linux: 使用标准临时目录
        temp_dir = '/tmp'

    return os.path.join(temp_dir, 'decomp_lock')


LOCK_FILE = get_lock_file_path()

# 全局变量保存锁文件句柄
lock_handle = None

# 新增：标记当前实例是否拥有锁的全局变量
lock_owner = False


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
            if safe_exists(LOCK_FILE, VERBOSE):
                # 锁文件存在，说明有其他进程正在使用
                pass
            else:
                # 锁文件不存在，尝试创建锁文件
                try:
                    # 使用短路径获取安全的锁文件路径
                    safe_lock_file = safe_path_for_operation(LOCK_FILE)

                    # 使用 'x' 模式：只有当文件不存在时才创建，如果文件已存在会抛出异常
                    lock_handle = safe_open(safe_lock_file, 'x')

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

                    if VERBOSE:
                        print(f"  DEBUG: 成功获取全局锁: {LOCK_FILE}")

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
            if VERBOSE:
                print(f"  DEBUG: 获取锁时出错: {e}")
            # 出现异常情况，清理并重试
            if lock_handle:
                try:
                    lock_handle.close()
                except:
                    pass
                lock_handle = None

        # 随机等待时间后重试
        wait_time = random.uniform(min_wait, max_wait)
        print(f"  锁被占用，将在 {wait_time:.2f} 秒后重试 (尝试 {attempt + 1}/{max_attempts})")
        time.sleep(wait_time)
        attempt += 1

    print(f"  无法获取锁，已达到最大重试次数 ({max_attempts})")
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
            if safe_exists(LOCK_FILE, VERBOSE):
                if safe_remove(LOCK_FILE, VERBOSE):
                    if VERBOSE:
                        print(f"  DEBUG: 成功删除锁文件: {LOCK_FILE}")
                    lock_owner = False  # 重置锁所有者标记
                    return
            else:
                # 文件不存在，说明已经被删除了
                lock_owner = False  # 重置锁所有者标记
                return

        except Exception as e:
            print(f"  删除锁文件失败 (尝试 {attempt + 1}/{max_retries}): {e}")
            if attempt < max_retries - 1:  # 不是最后一次尝试
                print(f"  将在 {retry_delay} 秒后重试...")
                time.sleep(retry_delay)
            else:
                print(f"  删除锁文件失败，已达到最大重试次数 ({max_retries})")
                print(f"  请手动删除锁文件: {LOCK_FILE}")


def signal_handler(signum, frame):
    """信号处理器，用于在程序被中断时设置全局中断标志"""
    print(f"\n  收到信号 {signum}，正在请求停止所有任务...")
    # Set the global interrupt flag for multi-threaded execution
    set_interrupt_flag()
    # The main thread will catch the KeyboardInterrupt that follows
    # and handle cleanup and exiting gracefully.
    # We do not need to call sys.exit() here.


# ==================== 结束锁机制 ====================

def setup_windows_utf8():
    """Setup UTF-8 encoding for Windows console operations"""
    if not sys.platform.startswith('win'):
        return

    success_count = 0
    total_attempts = 0

    try:
        # Set environment variables for UTF-8 encoding
        os.environ['PYTHONIOENCODING'] = 'utf-8'
        os.environ['LC_ALL'] = 'C.UTF-8'
        os.environ['LANG'] = 'C.UTF-8'

        if VERBOSE:
            print("  DEBUG: 设置环境变量: PYTHONIOENCODING=utf-8, LC_ALL=C.UTF-8, LANG=C.UTF-8")

        # 检测当前shell环境
        is_powershell = False

        # 检测PowerShell环境
        if 'PSModulePath' in os.environ:
            is_powershell = True
        # 检测CMD环境或默认情况
        else:
            # 默认假设是CMD环境
            is_powershell = False

        shell_type = "PowerShell" if is_powershell else "CMD"
        if VERBOSE:
            print(f"  DEBUG: 检测到shell环境: {shell_type}")

        # 方法1: 使用Windows API设置控制台编码 (最可靠的方法)
        total_attempts += 1
        try:
            import ctypes
            if hasattr(ctypes.windll.kernel32, 'SetConsoleCP') and \
               hasattr(ctypes.windll.kernel32, 'SetConsoleOutputCP'):
                # 设置控制台输入输出编码为UTF-8 (65001)
                input_result = ctypes.windll.kernel32.SetConsoleCP(65001)
                output_result = ctypes.windll.kernel32.SetConsoleOutputCP(65001)

                if input_result and output_result:
                    success_count += 1
                    if VERBOSE:
                        print("  DEBUG: ✓ Windows API设置控制台编码成功 (SetConsoleCP/SetConsoleOutputCP)")
                else:
                    if VERBOSE:
                        print(f"  DEBUG: ✗ Windows API设置控制台编码失败 (输入:{input_result}, 输出:{output_result})")
            else:
                if VERBOSE:
                    print("  DEBUG: ✗ Windows API方法不可用 (SetConsoleCP/SetConsoleOutputCP)")
        except Exception as e:
            if VERBOSE:
                print(f"  DEBUG: ✗ Windows API设置控制台编码异常: {e}")

        # 方法2: 根据shell环境使用对应的命令
        total_attempts += 1
        if is_powershell:
            # PowerShell环境: 使用PowerShell命令设置编码
            try:
                ps_cmd = '[Console]::OutputEncoding = [Console]::InputEncoding = [System.Text.Encoding]::UTF8'
                result = subprocess.run(['powershell', '-Command', ps_cmd],
                                      stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL,
                                      check=False,
                                      timeout=5)
                if result.returncode == 0:
                    success_count += 1
                    if VERBOSE:
                        print("  DEBUG: ✓ PowerShell控制台编码设置成功")
                else:
                    if VERBOSE:
                        print(f"  DEBUG: ✗ PowerShell控制台编码设置失败 (返回码: {result.returncode})")
            except Exception as e:
                if VERBOSE:
                    print(f"  DEBUG: ✗ PowerShell控制台编码设置异常: {e}")
        else:
            # CMD环境: 使用chcp命令设置代码页
            try:
                result = subprocess.run(['chcp', '65001'],
                                      stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL,
                                      check=False,
                                      timeout=5)
                if result.returncode == 0:
                    success_count += 1
                    if VERBOSE:
                        print("  DEBUG: ✓ CMD代码页设置成功 (chcp 65001)")
                else:
                    if VERBOSE:
                        print(f"  DEBUG: ✗ CMD代码页设置失败 (返回码: {result.returncode})")
            except Exception as e:
                if VERBOSE:
                    print(f"  DEBUG: ✗ CMD代码页设置异常: {e}")

        # 总结设置结果
        if success_count > 0:
            if VERBOSE:
                print(f"  DEBUG: Windows UTF-8环境设置完成 ({success_count}/{total_attempts} 方法成功)")
        else:
            print(f"  警告: Windows UTF-8环境设置失败 (0/{total_attempts} 方法成功)，可能影响特殊字符显示")

    except Exception as e:
        print(f"  警告: Windows UTF-8环境设置过程中发生异常: {e}")


def safe_decode(byte_data, encoding='utf-8', fallback_encodings=None):
    """
    Safely decode byte data to string with multiple encoding fallbacks

    Args:
        byte_data: Bytes to decode
        encoding: Primary encoding to try (default: utf-8)
        fallback_encodings: List of fallback encodings to try

    Returns:
        str: Decoded string
    """
    if fallback_encodings is None:
        fallback_encodings = ['cp1252', 'iso-8859-1', 'gbk', 'shift-jis']

    if isinstance(byte_data, str):
        return byte_data

    # Try primary encoding with error handling
    try:
        return byte_data.decode(encoding, errors='replace')
    except (UnicodeDecodeError, LookupError):
        pass

    # Try fallback encodings
    for fallback in fallback_encodings:
        try:
            return byte_data.decode(fallback, errors='replace')
        except (UnicodeDecodeError, LookupError):
            continue

    # Last resort: decode with ignore errors
    try:
        return byte_data.decode('utf-8', errors='ignore')
    except:
        return str(byte_data, errors='ignore')


def safe_subprocess_run(cmd, **kwargs):
    """
    Wrapper around subprocess.run with encoding‑safe decoding.
    """
    kwargs = kwargs.copy()
    for flag in ('text', 'encoding', 'universal_newlines'):
        kwargs.pop(flag, None)

    # 调用方如果没有要求捕获输出，则不做解码工作
    capture_out = ('stdout' in kwargs and kwargs['stdout'] == subprocess.PIPE) \
                  or ('capture_output' in kwargs and kwargs['capture_output'])
    capture_err = ('stderr' in kwargs and kwargs['stderr'] == subprocess.PIPE) \
                  or ('capture_output' in kwargs and kwargs['capture_output'])

    try:
        patched_cmd = _patch_cmd_paths(cmd)
        res = subprocess.run(patched_cmd, **kwargs)
        if capture_out and isinstance(res.stdout, bytes):
            res.stdout = safe_decode(res.stdout)
        if capture_err and isinstance(res.stderr, bytes):
            res.stderr = safe_decode(res.stderr)
        return res
    except Exception as exc:
        if VERBOSE:
            print(f"  DEBUG: subprocess error: {exc}")
        # 构造兼容对象
        class Dummy:
            def __init__(self, err):
                self.returncode, self.stdout, self.stderr = 1, '', str(err)
        return Dummy(exc)



def safe_popen_communicate(cmd, **kwargs):
    """
    Wrapper around subprocess.Popen + communicate
    ‑‑ 增强日志打印，避免因 command 元素非 str 而触发 TypeError。
    """
    kwargs_copy = kwargs.copy()
    for flag in ('text', 'encoding', 'universal_newlines'):
        kwargs_copy.pop(flag, None)

    def _cmd_to_str(c):
        return ' '.join(map(str, c)) if isinstance(c, (list, tuple)) else str(c)

    try:
        if VERBOSE:
            print(f"  DEBUG: 执行Popen命令: {_cmd_to_str(cmd)}")

        proc = subprocess.Popen(cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                **kwargs_copy)

        stdout_b, stderr_b = proc.communicate()
        stdout_s = safe_decode(stdout_b) if stdout_b else ""
        stderr_s = safe_decode(stderr_b) if stderr_b else ""

        if VERBOSE:
            print(f"  DEBUG: Popen返回码: {proc.returncode}")
            if stdout_s:
                print(f"  DEBUG: stdout摘要: {stdout_s[:200]}")
            if stderr_s:
                print(f"  DEBUG: stderr摘要: {stderr_s[:200]}")

        return stdout_s, stderr_s, proc.returncode

    except Exception as exc:
        if VERBOSE:
            print(f"  DEBUG: Popen error: {exc}")
        return "", str(exc), 1



def check_encryption(filepath):
    """
    Check if an archive is encrypted and determine the encryption type.
    Uses return codes as primary indicator for more accurate detection.
    Always provides a password to avoid interactive prompts.
    
    Returns:
        str: One of the following encryption status:
            - 'encrypted_header': Header+content encrypted, or header corrupted
            - 'encrypted_content': Header readable, content encrypted (Encrypted = +)
            - 'plain': Not encrypted
            - None: Not an archive
    """
    try:
        if VERBOSE:
            print(f"  DEBUG: Testing archive encryption: {filepath}")

        # Strategy: Always use a dummy password to avoid interactive prompts
        # This prevents 7z from waiting for user input on header-encrypted archives
        
        # Step 1: Test with dummy password
        if VERBOSE:
            print(f"  DEBUG: Testing with dummy password to avoid interactive prompts")

        stdout_output, stderr_output, returncode = safe_popen_communicate(
            ['7z', 'l', '-slt', '-pDUMMYPASSWORD', filepath]
        )

        output_combined = stdout_output + stderr_output

        if VERBOSE:
            print(f"  DEBUG: Dummy password test - Return code: {returncode}")
            print(f"  DEBUG: Output excerpt: {output_combined[:200]}")

        # Analyze based on return code first
        if returncode == 0:
            # Return code 0: Archive opened successfully with dummy password
            if VERBOSE:
                print(f"  DEBUG: Archive opened successfully with dummy password (code 0)")
            
            # This means either:
            # 1. Archive is not encrypted (dummy password ignored)
            # 2. Archive has content encryption only (header readable)
            # 3. By incredible coincidence, dummy password is correct (extremely unlikely)
            
            # Check for content encryption indicators
            if "Encrypted = +" in output_combined:
                if VERBOSE:
                    print(f"  DEBUG: Content encryption detected (Encrypted = +)")
                return 'encrypted_content'
            else:
                # Verify it's really not encrypted by testing with different dummy password
                if VERBOSE:
                    print(f"  DEBUG: Verifying no encryption by testing with different dummy password")
                
                stdout_output2, stderr_output2, returncode2 = safe_popen_communicate(
                    ['7z', 'l', '-slt', '-pDUMMYPASSWORD2', filepath]  # Different dummy password
                )
                
                if returncode2 == 0:
                    if VERBOSE:
                        print(f"  DEBUG: Confirmed - no encryption detected (works with any dummy password)")
                    return 'plain'
                else:
                    # Unexpected: failed with second dummy password but succeeded with first
                    # This suggests the first dummy password somehow worked (extremely unlikely)
                    # More likely there's some inconsistency - assume content encryption to be safe
                    if VERBOSE:
                        print(f"  DEBUG: Inconsistent results with different dummy passwords - assuming content encryption")
                    return 'encrypted_content'

        elif returncode == 2:
            # Return code 2: Fatal error with dummy password
            if VERBOSE:
                print(f"  DEBUG: Fatal error with dummy password (code 2)")
            
            # Check if it's not an archive at all
            if any(phrase in output_combined for phrase in [
                "Cannot open the file as archive",
                "is not archive", 
                "Can not open the file as archive",
                "Unsupported archive type"
            ]):
                if VERBOSE:
                    print(f"  DEBUG: Not an archive (fatal error + not archive message)")
                return None
            
            # Check for encryption-related fatal errors
            if any(phrase in output_combined for phrase in [
                "Cannot open encrypted archive",
                "Wrong password",
                "encrypted archive",
                "Can not open encrypted archive"
            ]):
                if VERBOSE:
                    print(f"  DEBUG: Header encryption detected (fatal error + encryption message)")
                return 'encrypted_header'
            
            # Check for specific error patterns that indicate encryption
            if any(phrase in output_combined for phrase in [
                "password",
                "Password",
                "PASSWORD"
            ]):
                if VERBOSE:
                    print(f"  DEBUG: Header encryption detected (password-related error)")
                return 'encrypted_header'
            
            # Other fatal errors - test with different dummy password to differentiate
            if VERBOSE:
                print(f"  DEBUG: Testing with different dummy password to differentiate error cause")
            
            stdout_output3, stderr_output3, returncode3 = safe_popen_communicate(
                ['7z', 'l', '-slt', '-pDUMMYPASSWORD2', filepath]  # Different dummy password
            )
            
            if returncode3 == 2:
                # Same error with different dummy password - likely corruption or not an archive
                if any(phrase in (stdout_output3 + stderr_output3) for phrase in [
                    "Cannot open the file as archive",
                    "is not archive",
                    "Can not open the file as archive"
                ]):
                    if VERBOSE:
                        print(f"  DEBUG: Confirmed not an archive")
                    return None
                else:
                    if VERBOSE:
                        print(f"  DEBUG: Assuming header encryption (consistent fatal error with different passwords)")
                    return 'encrypted_header'
            else:
                # Different result with different dummy password - likely header encryption
                if VERBOSE:
                    print(f"  DEBUG: Header encryption detected (different results with different dummy passwords)")
                return 'encrypted_header'

        elif returncode == 1:
            # Return code 1: Warning with dummy password
            if VERBOSE:
                print(f"  DEBUG: Warning with dummy password (code 1)")
            
            # Even with warnings, check for encryption indicators
            if "Encrypted = +" in output_combined:
                if VERBOSE:
                    print(f"  DEBUG: Content encryption detected despite warnings")
                return 'encrypted_content'
            
            # Check for encryption-related warnings
            if any(phrase in output_combined for phrase in [
                "Cannot open encrypted archive", 
                "Wrong password",
                "encrypted archive"
            ]):
                if VERBOSE:
                    print(f"  DEBUG: Header encryption detected (warning + encryption message)")
                return 'encrypted_header'
            
            if VERBOSE:
                print(f"  DEBUG: No encryption detected (warnings present)")
            return 'plain'

        elif returncode == 7:
            # Return code 7: Command line error
            if VERBOSE:
                print(f"  DEBUG: Command line error (code 7)")
            print(f"  Error: Command line error when testing {filepath}")
            return None

        elif returncode == 8:
            # Return code 8: Not enough memory
            if VERBOSE:
                print(f"  DEBUG: Memory error (code 8)")
            print(f"  Error: Not enough memory when testing {filepath}")
            return None

        elif returncode == 255:
            # Return code 255: User stopped the process
            if VERBOSE:
                print(f"  DEBUG: Process stopped by user (code 255)")
            print(f"  Error: Process stopped when testing {filepath}")
            return None

        else:
            # Unknown return code
            if VERBOSE:
                print(f"  DEBUG: Unknown return code {returncode}")
            
            # Check for obvious not-archive indicators
            if any(phrase in output_combined for phrase in [
                "Cannot open the file as archive",
                "is not archive",
                "Can not open the file as archive"
            ]):
                if VERBOSE:
                    print(f"  DEBUG: Not an archive (unknown code + not archive message)")
                return None
            
            # Assume header encryption for unknown error codes
            if VERBOSE:
                print(f"  DEBUG: Assuming header encryption due to unknown error code")
            return 'encrypted_header'

    except Exception as e:
        if VERBOSE:
            print(f"  DEBUG: Exception occurred: {str(e)}")
        print(f"  Error checking encryption: {str(e)}")
        return None

def is_password_correct(archive_path, password, encryption_status='encrypted_content'):
    """
    Test if a password is correct for an archive.
    
    Args:
        archive_path: Path to the archive
        password: Password to test
        encryption_status: Type of encryption ('encrypted_header', 'encrypted_content', or 'plain')
    
    Returns:
        bool: True if password is correct, False otherwise
    """
    try:
        if VERBOSE:
            print(f"  DEBUG: Testing password for {archive_path} with encryption type: {encryption_status}")
            print(f"  DEBUG: Password: {'<empty>' if not password else '<provided>'}")

        if encryption_status == 'encrypted_header':
            # For header encryption, use list command with lower IO overhead
            cmd = ['7z', 'l', '-slt', str(archive_path), f'-p{password}', '-y']
            if VERBOSE:
                print(f"  DEBUG: Using list command for header encryption test")
        else:
            # For content-only encryption or plain archives, use test command (current logic)
            cmd = ['7z', 't', str(archive_path), f'-p{password}', '-y']
            if VERBOSE:
                print(f"  DEBUG: Using test command for content encryption test")
        cmd = _patch_cmd_paths(cmd)
        result = safe_subprocess_run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        success = result.returncode == 0

        if VERBOSE:
            print(f"  DEBUG: Password test result: {'Success' if success else 'Failed'}")
            if not success and result.stderr:
                print(f"  DEBUG: Error details: {result.stderr[:200]}")

        return success
    except Exception as e:
        if VERBOSE:
            print(f"  DEBUG: Error testing password: {e}")
        return False


def try_extract(archive_path, password, tmp_dir, zip_decode=None, enable_rar=False, sfx_detector=None):
    """
    Extract archive to temporary directory.

    Args:
        archive_path: 归档文件路径
        password: 解压密码
        tmp_dir: 临时目录
        zip_decode: ZIP文件代码页（例如932表示shift-jis）
        enable_rar: 是否启用RAR解压器
        sfx_detector: SFXDetector实例，用于检测SFX文件格式
    """
    try:
        # Check for interrupt before starting
        check_interrupt()
        
        if VERBOSE:
            print(f"  DEBUG: 开始解压: {archive_path} -> {tmp_dir}")

        # 创建临时目录（重要！RAR和7z都需要目标目录存在）
        if not safe_makedirs(tmp_dir, debug=VERBOSE):
            if VERBOSE:
                print(f"  DEBUG: 创建临时目录失败: {tmp_dir}")
            return False

        # 判断是否应该使用RAR解压
        use_rar = should_use_rar_extractor(archive_path, enable_rar, sfx_detector)

        if use_rar:
            # 使用RAR命令解压
            if VERBOSE:
                print(f"  DEBUG: 使用RAR命令解压")

            # 获取安全的路径（短路径）
            safe_archive_path = safe_path_for_operation(archive_path, VERBOSE)
            safe_tmp_dir = safe_path_for_operation(tmp_dir, VERBOSE)

            cmd = ['rar', 'x', safe_archive_path, safe_tmp_dir]

            # 添加密码参数（如果有密码则使用，否则使用虚拟密码避免hang住）
            if password:
                cmd.extend([f'-p{password}'])
            else:
                cmd.extend([f'-pDUMMYPASSWORD'])

            # 添加其他RAR参数
            cmd.extend(['-y'])  # 自动回答yes

            if VERBOSE:
                print(f"  DEBUG: RAR命令: {' '.join(cmd)}")
                print(f"  DEBUG: 原始路径: {archive_path}")
                print(f"  DEBUG: 安全路径: {safe_archive_path}")
            
            # Check interrupt before running command
            check_interrupt()
            
            cmd = _patch_cmd_paths(cmd)
            result = safe_subprocess_run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        else:
            # 使用7z命令解压
            if VERBOSE:
                print(f"  DEBUG: 使用7z命令解压")

            # 7z命令也使用安全路径
            safe_archive_path = safe_path_for_operation(archive_path, VERBOSE)
            safe_tmp_dir = safe_path_for_operation(tmp_dir, VERBOSE)

            cmd = ['7z', 'x', safe_archive_path, f'-o{safe_tmp_dir}', '-y']
            if password:
                cmd.extend([f'-p{password}'])
            else:
                cmd.extend([f'-pDUMMYPASSWORD'])

            # 如果指定了zip_decode参数且当前文件是ZIP格式，则添加-mcp参数
            if zip_decode is not None and is_zip_format(archive_path):
                try:
                    # 确保zip_decode是有效的整数或字符串
                    if isinstance(zip_decode, int):
                        mcp_param = f'-mcp={zip_decode}'
                    elif isinstance(zip_decode, str) and zip_decode.isdigit():
                        mcp_param = f'-mcp={zip_decode}'
                    elif isinstance(zip_decode, str):
                        # 处理非数字字符串编码（如'UTF-8'）
                        if zip_decode.upper() == 'UTF-8':
                            # 对于UTF-8，7z默认就是UTF-8，无需添加参数
                            mcp_param = None
                            if VERBOSE:
                                print(f"  DEBUG: UTF-8编码，使用7z默认处理")
                        else:
                            mcp_param = f'-mcp={zip_decode}'
                    else:
                        # 无效的编码参数，跳过
                        if VERBOSE:
                            print(f"  DEBUG: 无效的ZIP编码参数，跳过: {zip_decode}")
                        mcp_param = None
                    
                    if mcp_param:
                        cmd.append(mcp_param)
                        if VERBOSE:
                            print(f"  DEBUG: 添加ZIP代码页参数: {mcp_param}")
                            
                except Exception as e:
                    if VERBOSE:
                        print(f"  DEBUG: 处理ZIP编码参数时出错，跳过: {e}")

            if VERBOSE:
                print(f"  DEBUG: 7z命令: {' '.join(cmd)}")
                print(f"  DEBUG: 原始路径: {archive_path}")
                print(f"  DEBUG: 安全路径: {safe_archive_path}")
            
            # Check interrupt before running command
            check_interrupt()
            
            cmd = _patch_cmd_paths(cmd)
            result = safe_subprocess_run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Check interrupt after extraction completes
        check_interrupt()

        success = result.returncode == 0

        if VERBOSE:
            extractor = 'RAR' if use_rar else '7z'
            print(f"  DEBUG: {extractor}解压结果: {'成功' if success else '失败'}")
            if not success and result.stderr:
                print(f"  DEBUG: 解压错误: {result.stderr[:300]}")

        return success

    except KeyboardInterrupt:
        # Clean up tmp_dir if it was created before interrupt
        if safe_exists(tmp_dir, VERBOSE):
            try:
                safe_rmtree(tmp_dir, VERBOSE)
            except:
                pass
        raise
    except Exception as e:
        if VERBOSE:
            print(f"  DEBUG: Error extracting: {e}")
        return False

def get_archive_base_name(filepath):
    """Get base name for archive (updated to work with new logic)."""
    filename = os.path.basename(filepath)
    filename_lower = filename.lower()

    if VERBOSE:
        print(f"  DEBUG: 获取归档基础名称: {filename}")

    # Handle different archive types correctly
    if filename_lower.endswith('.exe'):
        # For SFX files, remove .exe and part indicators
        base = re.sub(r'\.exe$', '', filename, flags=re.IGNORECASE)
        base = re.sub(r'\.part\d+$', '', base, flags=re.IGNORECASE)
        return base

    elif filename_lower.endswith('.rar'):
        if re.search(r'\.part\d+\.rar$', filename_lower):
            # Multi-part RAR: remove .partN.rar
            return re.sub(r'\.part\d+\.rar$', '', filename, flags=re.IGNORECASE)
        else:
            # Single RAR: remove .rar
            return re.sub(r'\.rar$', '', filename, flags=re.IGNORECASE)

    elif filename_lower.endswith('.7z'):
        # Single 7z: remove .7z
        return re.sub(r'\.7z$', '', filename, flags=re.IGNORECASE)

    elif re.search(r'\.7z\.\d+$', filename_lower):
        # Multi-part 7z: remove .7z.NNN
        return re.sub(r'\.7z\.\d+$', '', filename, flags=re.IGNORECASE)

    elif filename_lower.endswith('.zip'):
        # ZIP: remove .zip
        return re.sub(r'\.zip$', '', filename, flags=re.IGNORECASE)

    elif re.search(r'\.z\d+$', filename_lower):
        # ZIP volumes: remove .zNN
        return re.sub(r'\.z\d+$', '', filename, flags=re.IGNORECASE)

    elif re.search(r'\.r\d+$', filename_lower):
        # RAR4 volumes: remove .rNN
        return re.sub(r'\.r\d+$', '', filename, flags=re.IGNORECASE)

    # Fallback
    return os.path.splitext(filename)[0]



def count_items_in_dir(directory):
    """Count files and directories in a directory recursively."""
    files = 0
    dirs = 0

    try:
        for root, dirnames, filenames in safe_walk(directory, VERBOSE):
            files += len(filenames)
            dirs += len(dirnames)
    except Exception as e:
        if VERBOSE:
            print(f"  DEBUG: 统计目录项目失败: {e}")

    if VERBOSE:
        print(f"  DEBUG: 目录 {directory} 包含 {files} 个文件, {dirs} 个目录")

    return files, dirs


def ensure_unique_name(target_path, unique_suffix):
    """Ensure target path is unique by adding unique_suffix if needed."""
    if not safe_exists(target_path, VERBOSE):
        return target_path

    base, ext = os.path.splitext(target_path)
    result = f"{base}_{unique_suffix}{ext}"

    if VERBOSE:
        print(f"  DEBUG: 路径冲突，使用唯一名称: {target_path} -> {result}")

    return result


def get_deepest_folder_name(file_content_info, tmp_dir, archive_base_name):
    """
    确定deepest_folder_name

    Args:
        file_content_info: find_file_content返回的信息
        tmp_dir: 临时目录路径
        archive_base_name: 归档基础名称

    Returns:
        str: deepest_folder_name
    """
    parent_folder_path = file_content_info['parent_folder_path']

    # 规范化路径进行比较
    tmp_dir_normalized = os.path.normpath(os.path.abspath(tmp_dir))
    parent_normalized = os.path.normpath(os.path.abspath(parent_folder_path))

    if parent_normalized == tmp_dir_normalized:
        # 父文件夹就是tmp文件夹，使用archive_base_name
        return archive_base_name
    else:
        # 使用父文件夹名称
        return os.path.basename(parent_folder_path)


def remove_ascii_non_meaningful_chars(text):
    """
    去除ASCII非表意字符，保留ASCII字母数字和所有非ASCII字符

    Args:
        text: 输入字符串

    Returns:
        str: 过滤后的字符串
    """
    result = []
    for char in text:
        # 保留ASCII字母数字
        if char.isalnum() and ord(char) < 128:
            result.append(char)
        # 保留所有非ASCII字符
        elif ord(char) >= 128:
            result.append(char)
        # 跳过ASCII标点符号和空白字符

    return ''.join(result)


def clean_temp_dir(temp_dir):
    """Safely remove temporary directory and confirm it's empty first."""
    try:
        if safe_exists(temp_dir, VERBOSE):
            # Check if directory is empty
            try:
                if not os.listdir(temp_dir):
                    safe_rmdir(temp_dir, VERBOSE)
                    if VERBOSE:
                        print(f"  DEBUG: 删除空临时目录: {temp_dir}")
                else:
                    # If not empty, force remove (this shouldn't happen in normal flow)
                    safe_rmtree(temp_dir, VERBOSE)
                    if VERBOSE:
                        print(f"  WARNING: 临时目录非空，强制删除: {temp_dir}")
            except Exception as e:
                if VERBOSE:
                    print(f"  DEBUG: 删除临时目录失败: {temp_dir}, {e}")
    except Exception as e:
        print(f"Warning: Could not remove temporary directory {temp_dir}: {e}")


def is_zip_format(archive_path):
    """
    判断文件是否为ZIP格式或ZIP分卷

    Args:
        archive_path: 归档文件路径

    Returns:
        bool: 如果是ZIP格式或ZIP分卷返回True，否则返回False
    """
    filename_lower = os.path.basename(archive_path).lower()

    if VERBOSE:
        print(f"  DEBUG: 检查是否为ZIP格式: {archive_path}")

    # 检查文件扩展名
    if filename_lower.endswith('.zip'):
        if VERBOSE:
            print(f"  DEBUG: 检测到ZIP文件")
        return True

    # 检查ZIP分卷格式 (.z01, .z02, etc.)
    if re.search(r'\.z\d+$', filename_lower):
        if VERBOSE:
            print(f"  DEBUG: 检测到ZIP分卷文件")
        return True

    # 检查文件魔术字节 (PK header)
    try:
        with safe_open(archive_path, 'rb') as f:
            header = f.read(4)
            if header.startswith(b'PK'):
                if VERBOSE:
                    print(f"  DEBUG: 通过魔术字节检测到ZIP格式")
                return True
    except Exception as e:
        if VERBOSE:
            print(f"  DEBUG: 读取文件头失败: {e}")

    if VERBOSE:
        print(f"  DEBUG: 非ZIP格式")
    return False


# ==================== 新增解压策略 ====================

def find_file_content(tmp_dir, debug=False):
    """
    递归查找$file_content - 定义为同一深度有2个或以上文件夹/文件的层级

    Args:
        tmp_dir: 临时目录路径
        debug: 是否输出调试信息

    Returns:
        dict: {
            'found': bool,  # 是否找到
            'path': str,    # file_content所在路径
            'depth': int,   # 相对深度
            'items': list,  # file_content项目列表
            'parent_folder_path': str,  # file_content的父文件夹路径
            'parent_folder_name': str   # file_content的父文件夹名称
        }
    """
    result = {
        'found': False,
        'path': tmp_dir,
        'depth': 0,
        'items': [],
        'parent_folder_path': tmp_dir,
        'parent_folder_name': ''
    }

    if debug:
        print(f"  DEBUG: 开始查找file_content: {tmp_dir}")

    def get_items_at_depth(path, current_depth=1):
        """获取指定深度的所有项目"""
        try:
            items = []
            if current_depth == 1:
                # 直接列出当前目录内容
                for item in os.listdir(path):
                    item_path = os.path.join(path, item)
                    items.append({
                        'name': item,
                        'path': item_path,
                        'is_dir': safe_isdir(item_path, debug)
                    })
            else:
                # 递归查找指定深度的项目
                for root, dirs, files in safe_walk(path, debug):
                    rel_path = os.path.relpath(root, path)
                    depth = len([p for p in rel_path.split(os.sep) if p and p != '.'])

                    if depth == current_depth - 1:
                        # 这一层的目录，添加其子项目
                        for dir_name in dirs:
                            dir_path = os.path.join(root, dir_name)
                            items.append({
                                'name': dir_name,
                                'path': dir_path,
                                'is_dir': True
                            })
                        for file_name in files:
                            file_path = os.path.join(root, file_name)
                            items.append({
                                'name': file_name,
                                'path': file_path,
                                'is_dir': False
                            })
            return items
        except Exception as e:
            if debug:
                print(f"  DEBUG: 获取深度{current_depth}项目失败: {e}")
            return []

    # 从深度1开始递归查找
    max_search_depth = 10  # 避免无限递归

    for depth in range(1, max_search_depth + 1):
        items = get_items_at_depth(tmp_dir, depth)

        if debug:
            print(f"  DEBUG: 深度{depth}: 找到{len(items)}个项目")
            for item in items[:5]:  # 只显示前5个
                print(f"    {item['name']} ({'文件夹' if item['is_dir'] else '文件'})")

        if len(items) >= 2:
            # 找到file_content
            result['found'] = True
            result['depth'] = depth
            result['items'] = items

            # 计算file_content所在的父目录路径和名称
            if depth == 1:
                result['path'] = tmp_dir
                result['parent_folder_path'] = tmp_dir
                result['parent_folder_name'] = os.path.basename(tmp_dir)
            else:
                # 需要找到深度为depth-1的目录
                for root, dirs, files in safe_walk(tmp_dir, debug):
                    rel_path = os.path.relpath(root, tmp_dir)
                    if rel_path == '.':
                        current_depth = 0
                    else:
                        current_depth = len([p for p in rel_path.split(os.sep) if p])

                    if current_depth == depth - 1:
                        result['path'] = root
                        result['parent_folder_path'] = root
                        result['parent_folder_name'] = os.path.basename(root)
                        break

            if debug:
                print(f"  DEBUG: 找到file_content在深度{depth}")
                print(f"  DEBUG: file_content路径: {result['path']}")
                print(f"  DEBUG: 父文件夹路径: {result['parent_folder_path']}")
                print(f"  DEBUG: 父文件夹名称: {result['parent_folder_name']}")
            break

        if not items:
            # 没有更深的项目了
            break

    if not result['found']:
        # 特殊情况：没有找到满足条件的file_content
        # 找最深层的单个项目作为file_content
        if debug:
            print(f"  DEBUG: 没有找到标准file_content，查找最深层项目")

        deepest_items = []
        max_depth = 0
        deepest_parent_path = tmp_dir

        for root, dirs, files in safe_walk(tmp_dir, debug):
            rel_path = os.path.relpath(root, tmp_dir)
            if rel_path == '.':
                depth = 0
            else:
                depth = len([p for p in rel_path.split(os.sep) if p])

            if depth > max_depth:
                max_depth = depth
                deepest_items = []
                deepest_parent_path = root

                # 添加当前层的文件
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    deepest_items.append({
                        'name': file_name,
                        'path': file_path,
                        'is_dir': False
                    })

                # 添加当前层的空目录
                for dir_name in dirs:
                    dir_path = os.path.join(root, dir_name)
                    # 检查这个目录是否有子内容
                    has_content = False
                    try:
                        for sub_root, sub_dirs, sub_files in safe_walk(dir_path, debug):
                            if sub_dirs or sub_files:
                                has_content = True
                                break
                    except:
                        pass

                    if not has_content:
                        deepest_items.append({
                            'name': dir_name,
                            'path': dir_path,
                            'is_dir': True
                        })
            elif depth == max_depth:
                # 添加到当前最深层
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    deepest_items.append({
                        'name': file_name,
                        'path': file_path,
                        'is_dir': False
                    })

        if deepest_items:
            result['found'] = True
            result['depth'] = max_depth + 1
            result['items'] = deepest_items
            result['path'] = deepest_parent_path
            result['parent_folder_path'] = deepest_parent_path
            result['parent_folder_name'] = os.path.basename(deepest_parent_path)

            if debug:
                print(f"  DEBUG: 使用最深层项目作为file_content，深度{result['depth']}")
                print(f"  DEBUG: 父文件夹路径: {result['parent_folder_path']}")
                print(f"  DEBUG: 父文件夹名称: {result['parent_folder_name']}")

    return result





def apply_only_file_content_policy(tmp_dir, output_dir, archive_name, unique_suffix):
    """
    应用only-file-content策略

    Args:
        tmp_dir: 临时目录
        output_dir: 输出目录
        archive_name: 归档名称
        unique_suffix: 唯一后缀
    """
    if VERBOSE:
        print(f"  DEBUG: 应用only-file-content策略")

    # 1. 查找file_content
    file_content = find_file_content(tmp_dir, VERBOSE)

    if not file_content['found']:
        if VERBOSE:
            print(f"  DEBUG: 未找到file_content，回退到separate策略")
        # 回退到separate策略
        apply_separate_policy_internal(tmp_dir, output_dir, archive_name, unique_suffix)
        return

    # 2. 创建content临时目录
    content_dir = f"content_{unique_suffix}"

    try:
        safe_makedirs(content_dir, debug=VERBOSE)

        if VERBOSE:
            print(f"  DEBUG: 创建content目录: {content_dir}")

        # 3. 移动file_content到content目录
        for item in file_content['items']:
            src_path = item['path']
            dst_path = os.path.join(content_dir, item['name'])

            if VERBOSE:
                print(f"  DEBUG: 移动file_content项目: {src_path} -> {dst_path}")

            safe_move(src_path, dst_path, VERBOSE)

        # 4. 确认tmp目录只剩空文件夹
        has_files = False
        try:
            for root, dirs, files in safe_walk(tmp_dir, VERBOSE):
                if files:
                    has_files = True
                    if VERBOSE:
                        print(f"  DEBUG: 警告：tmp目录仍有文件: {files}")
                    break
        except Exception as e:
            if VERBOSE:
                print(f"  DEBUG: 检查tmp目录失败: {e}")

        # 5. 创建最终输出目录
        final_archive_dir = os.path.join(output_dir, archive_name)
        final_archive_dir = ensure_unique_name(final_archive_dir, unique_suffix)
        safe_makedirs(final_archive_dir, debug=VERBOSE)

        # 6. 移动content到最终目录
        for item in os.listdir(content_dir):
            src_path = os.path.join(content_dir, item)
            dst_path = os.path.join(final_archive_dir, item)

            if VERBOSE:
                print(f"  DEBUG: 移动到最终目录: {src_path} -> {dst_path}")

            safe_move(src_path, dst_path, VERBOSE)

        print(f"  Extracted using only-file-content policy to: {final_archive_dir}")

    finally:
        # 7. 清理content目录
        if safe_exists(content_dir, VERBOSE):
            safe_rmtree(content_dir, VERBOSE)


def apply_file_content_with_folder_policy(tmp_dir, output_dir, archive_name, unique_suffix):
    """
    应用file-content-with-folder策略

    Args:
        tmp_dir: 临时目录
        output_dir: 输出目录
        archive_name: 归档名称（压缩文件名称或分卷压缩包主名称）
        unique_suffix: 唯一后缀
    """
    if VERBOSE:
        print(f"  DEBUG: 应用file-content-with-folder策略")

    # 1. 查找file_content
    file_content = find_file_content(tmp_dir, VERBOSE)

    if not file_content['found']:
        if VERBOSE:
            print(f"  DEBUG: 未找到file_content，回退到separate策略")
        # 回退到separate策略
        apply_separate_policy_internal(tmp_dir, output_dir, archive_name, unique_suffix)
        return

    # 2. 创建content临时目录
    content_dir = f"content_{unique_suffix}"

    try:
        safe_makedirs(content_dir, debug=VERBOSE)

        if VERBOSE:
            print(f"  DEBUG: 创建content目录: {content_dir}")

        # 3. 移动file_content到content目录
        for item in file_content['items']:
            src_path = item['path']
            dst_path = os.path.join(content_dir, item['name'])

            if VERBOSE:
                print(f"  DEBUG: 移动file_content项目: {src_path} -> {dst_path}")

            safe_move(src_path, dst_path, VERBOSE)

        # 4. 确定deepest_folder_name
        # 如果父文件夹就是tmp文件夹，则认为父文件夹名称是archive_name
        # 如果父文件夹不是tmp文件夹，则使用file_content的父文件夹名称
        if file_content['parent_folder_path'] == tmp_dir:
            deepest_folder_name = archive_name
            if VERBOSE:
                print(f"  DEBUG: file_content的父文件夹是tmp目录，使用归档名称: {deepest_folder_name}")
        else:
            deepest_folder_name = file_content['parent_folder_name']
            if VERBOSE:
                print(f"  DEBUG: 使用file_content的父文件夹名称: {deepest_folder_name}")

        # 5. 创建最终输出目录（使用deepest_folder_name）
        final_archive_dir = os.path.join(output_dir, deepest_folder_name)
        final_archive_dir = ensure_unique_name(final_archive_dir, unique_suffix)
        safe_makedirs(final_archive_dir, debug=VERBOSE)

        # 6. 移动content到最终目录
        for item in os.listdir(content_dir):
            src_path = os.path.join(content_dir, item)
            dst_path = os.path.join(final_archive_dir, item)

            if VERBOSE:
                print(f"  DEBUG: 移动到最终目录: {src_path} -> {dst_path}")

            safe_move(src_path, dst_path, VERBOSE)

        print(f"  Extracted using file-content-with-folder policy to: {final_archive_dir}")

    finally:
        # 7. 清理content目录
        if safe_exists(content_dir, VERBOSE):
            safe_rmtree(content_dir, VERBOSE)


def apply_separate_policy_internal(tmp_dir, output_dir, archive_name, unique_suffix):
    """内部separate策略实现，供其他策略回退使用"""
    # Check for interrupt at start
    check_interrupt()
    
    separate_dir = f"separate_{unique_suffix}"

    try:
        safe_makedirs(separate_dir, debug=VERBOSE)

        # Create archive folder in separate directory
        archive_folder = os.path.join(separate_dir, archive_name)
        archive_folder = ensure_unique_name(archive_folder, unique_suffix)
        safe_makedirs(archive_folder, debug=VERBOSE)

        # Move contents from tmp to archive folder
        try:
            for item in os.listdir(tmp_dir):
                # Check for interrupt before each item move
                check_interrupt()
                
                src_item = os.path.join(tmp_dir, item)
                dest_item = os.path.join(archive_folder, item)
                safe_move(src_item, dest_item, VERBOSE)
        except KeyboardInterrupt:
            # Re-raise interrupt
            raise
        except Exception as e:
            if VERBOSE:
                print(f"  DEBUG: 移动内容失败: {e}")

        # Check for interrupt before final move
        check_interrupt()

        # Move archive folder to final destination
        final_archive_path = os.path.join(output_dir, archive_name)
        final_archive_path = ensure_unique_name(final_archive_path, unique_suffix)
        safe_move(archive_folder, final_archive_path, VERBOSE)

        print(f"  Extracted to: {final_archive_path}")

    except KeyboardInterrupt:
        # Clean up temporary directory on interrupt
        if safe_exists(separate_dir, VERBOSE):
            try:
                safe_rmtree(separate_dir, VERBOSE)
            except:
                pass
        raise
    finally:
        if safe_exists(separate_dir, VERBOSE):
            safe_rmtree(separate_dir, VERBOSE)

def apply_file_content_with_folder_separate_policy(tmp_dir, output_dir, archive_name, unique_suffix):
    """
    应用file-content-with-folder-separate策略

    Args:
        tmp_dir: 临时目录
        output_dir: 输出目录
        archive_name: 归档名称（压缩文件名称或分卷压缩包主名称）
        unique_suffix: 唯一后缀
    """
    if VERBOSE:
        print(f"  DEBUG: 应用file-content-with-folder-separate策略")

    # 1. 查找file_content
    file_content = find_file_content(tmp_dir, VERBOSE)

    if not file_content['found']:
        if VERBOSE:
            print(f"  DEBUG: 未找到file_content，回退到separate策略")
        # 回退到separate策略
        apply_separate_policy_internal(tmp_dir, output_dir, archive_name, unique_suffix)
        return

    # 2. 创建content临时目录
    content_dir = f"content_{unique_suffix}"

    try:
        safe_makedirs(content_dir, debug=VERBOSE)

        if VERBOSE:
            print(f"  DEBUG: 创建content目录: {content_dir}")

        # 3. 移动file_content到content目录
        for item in file_content['items']:
            src_path = item['path']
            dst_path = os.path.join(content_dir, item['name'])

            if VERBOSE:
                print(f"  DEBUG: 移动file_content项目: {src_path} -> {dst_path}")

            safe_move(src_path, dst_path, VERBOSE)

        # 4. 确定deepest_folder_name
        deepest_folder_name = get_deepest_folder_name(file_content, tmp_dir, archive_name)
        if VERBOSE:
            print(f"  DEBUG: 确定的deepest_folder_name: {deepest_folder_name}")

        # 5. 创建最终输出目录
        archive_container_dir = os.path.join(output_dir, archive_name)
        archive_container_dir = ensure_unique_name(archive_container_dir, unique_suffix)
        safe_makedirs(archive_container_dir, debug=VERBOSE)
        
        # 根据archive_name和deepest_folder_name是否相同决定目录结构
        if archive_name == deepest_folder_name:
            # 使用archive_name/{file_content}结构
            final_archive_dir = archive_container_dir
            if VERBOSE:
                print(f"  DEBUG: archive_name与deepest_folder_name相同，使用archive_name/{{file_content}}结构")
                print(f"  DEBUG: 创建archive容器目录: {archive_container_dir}")
                print(f"  DEBUG: 最终目录即为容器目录: {final_archive_dir}")
        else:
            # 使用archive_name/{deepest_folder_name}/{file_content}结构
            final_archive_dir = os.path.join(archive_container_dir, deepest_folder_name)
            final_archive_dir = ensure_unique_name(final_archive_dir, unique_suffix)
            safe_makedirs(final_archive_dir, debug=VERBOSE)
            if VERBOSE:
                print(f"  DEBUG: archive_name与deepest_folder_name不同，使用archive_name/{{deepest_folder_name}}/{{file_content}}结构")
                print(f"  DEBUG: 创建archive容器目录: {archive_container_dir}")
                print(f"  DEBUG: 创建最终目录: {final_archive_dir}")

        # 6. 移动content到最终目录
        for item in os.listdir(content_dir):
            src_path = os.path.join(content_dir, item)
            dst_path = os.path.join(final_archive_dir, item)

            if VERBOSE:
                print(f"  DEBUG: 移动到最终目录: {src_path} -> {dst_path}")

            safe_move(src_path, dst_path, VERBOSE)

        print(f"  Extracted using file-content-with-folder-separate policy to: {final_archive_dir}")

    finally:
        # 7. 清理content目录
        if safe_exists(content_dir, VERBOSE):
            safe_rmtree(content_dir, VERBOSE)
            

def apply_only_file_content_direct_policy(tmp_dir, output_dir, archive_name, unique_suffix):
    """
    "only-file-content-direct" 策略：
    1. 抽取 file_content（与 only-file-content 相同逻辑）
    2. 若将 file_content 直接合并进 output_dir 时 **任意文件** 会冲突，则回退到 only-file-content 策略
       （文件冲突判定：content_dir 中的文件与 output_dir 中同相对路径已有文件重名）
       目录同名但内部文件不冲突视为可合并
    3. 无冲突时，递归移动/合并所有内容到 output_dir
    """
    if VERBOSE:
        print(f"  DEBUG: 应用only-file-content-direct策略")

    # 1. 识别 file_content
    file_content = find_file_content(tmp_dir, VERBOSE)
    if not file_content['found']:
        if VERBOSE:
            print(f"  DEBUG: 未找到file_content，回退only-file-content策略")
        apply_only_file_content_policy(tmp_dir, output_dir, archive_name, unique_suffix)
        return

    # 2. 临时 content 目录
    content_dir = f"content_{unique_suffix}"
    safe_makedirs(content_dir, debug=VERBOSE)

    try:
        # 移动 file_content 项目到 content_dir
        for item in file_content['items']:
            src = item['path']
            dst = os.path.join(content_dir, item['name'])
            if VERBOSE:
                print(f"  DEBUG: 移动file_content项目: {src} -> {dst}")
            safe_move(src, dst, VERBOSE)

        # 3. 冲突检测（仅文件）
        conflict_found = False
        for root, dirs, files in safe_walk(content_dir, VERBOSE):
            rel_root = os.path.relpath(root, content_dir)
            rel_root = '' if rel_root == '.' else rel_root
            # 只检查文件
            for f in files:
                rel_path = os.path.join(rel_root, f) if rel_root else f
                dest_path = os.path.join(output_dir, rel_path)
                if safe_isfile(dest_path, VERBOSE):
                    if VERBOSE:
                        print(f"  DEBUG: 冲突文件检测到: {dest_path}")
                    conflict_found = True
                    break
            if conflict_found:
                break

        if conflict_found:
            if VERBOSE:
                print(f"  DEBUG: 检测到文件冲突，回退only-file-content策略")
            apply_only_file_content_policy(tmp_dir, output_dir, archive_name, unique_suffix)
            return

        # 4. 无冲突 -> 合并/移动到 output_dir
        for root, dirs, files in safe_walk(content_dir, VERBOSE):
            rel_root = os.path.relpath(root, content_dir)
            target_root = output_dir if rel_root == '.' else os.path.join(output_dir, rel_root)
            safe_makedirs(target_root, debug=VERBOSE)

            for d in dirs:
                dest_dir = os.path.join(target_root, d)
                safe_makedirs(dest_dir, debug=VERBOSE)

            for f in files:
                src_f = os.path.join(root, f)
                dest_f = os.path.join(target_root, f)
                safe_move(src_f, dest_f, VERBOSE)

        print(f"  Extracted using only-file-content-direct policy to: {output_dir}")

    finally:
        # 清理临时 content_dir
        if safe_exists(content_dir, VERBOSE):
            safe_rmtree(content_dir, VERBOSE)


def apply_file_content_collect_policy(tmp_dir, output_dir, archive_name, threshold, unique_suffix):
    """
    应用file-content-n-collect策略
    
    Args:
        tmp_dir: 临时目录
        output_dir: 输出目录
        archive_name: 归档名称
        threshold: 阈值N
        unique_suffix: 唯一后缀
    """
    if VERBOSE:
        print(f"  DEBUG: 应用file-content-{threshold}-collect策略")

    # 1. 查找file_content
    file_content = find_file_content(tmp_dir, VERBOSE)

    if not file_content['found']:
        if VERBOSE:
            print(f"  DEBUG: 未找到file_content，回退到{threshold}-collect策略")
        # 回退到n-collect策略
        files, dirs = count_items_in_dir(tmp_dir)
        total_items = files + dirs
        
        if total_items >= threshold:
            # Create archive folder
            archive_folder = os.path.join(output_dir, archive_name)
            archive_folder = ensure_unique_name(archive_folder, unique_suffix)
            safe_makedirs(archive_folder, debug=VERBOSE)

            # Move all items to archive folder
            for item in os.listdir(tmp_dir):
                src_item = os.path.join(tmp_dir, item)
                dest_item = os.path.join(archive_folder, item)
                safe_move(src_item, dest_item, VERBOSE)

            print(f"  Extracted to: {archive_folder} ({total_items} items >= {threshold})")
        else:
            # Extract directly using direct policy logic
            tmp_items = os.listdir(tmp_dir)
            conflicts = [item for item in tmp_items if safe_exists(os.path.join(output_dir, item), VERBOSE)]

            if conflicts:
                # Create archive folder for conflicts
                archive_folder = os.path.join(output_dir, archive_name)
                archive_folder = ensure_unique_name(archive_folder, unique_suffix)
                safe_makedirs(archive_folder, debug=VERBOSE)

                # Move all items to archive folder
                for item in tmp_items:
                    src_item = os.path.join(tmp_dir, item)
                    dest_item = os.path.join(archive_folder, item)
                    safe_move(src_item, dest_item, VERBOSE)

                print(f"  Extracted to: {archive_folder} (conflicts detected, {total_items} items < {threshold})")
            else:
                # Move directly to output directory
                for item in tmp_items:
                    src_item = os.path.join(tmp_dir, item)
                    dest_item = os.path.join(output_dir, item)
                    safe_move(src_item, dest_item, VERBOSE)

                print(f"  Extracted to: {output_dir} ({total_items} items < {threshold})")
        return

    # 2. 创建content临时目录
    content_dir = f"content_{unique_suffix}"

    try:
        safe_makedirs(content_dir, debug=VERBOSE)

        if VERBOSE:
            print(f"  DEBUG: 创建content目录: {content_dir}")

        # 3. 移动file_content到content目录
        for item in file_content['items']:
            src_path = item['path']
            dst_path = os.path.join(content_dir, item['name'])

            if VERBOSE:
                print(f"  DEBUG: 移动file_content项目: {src_path} -> {dst_path}")

            safe_move(src_path, dst_path, VERBOSE)

        # 4. 计算content目录中的项目数量
        files, dirs = count_items_in_dir(content_dir)
        total_items = files + dirs

        if VERBOSE:
            print(f"  DEBUG: content目录统计 - 文件: {files}, 目录: {dirs}, 总计: {total_items}, 阈值: {threshold}")

        # 5. 根据数量决定是否包裹
        if total_items >= threshold:
            # 创建归档文件夹包裹
            archive_folder = os.path.join(output_dir, archive_name)
            archive_folder = ensure_unique_name(archive_folder, unique_suffix)
            safe_makedirs(archive_folder, debug=VERBOSE)

            # 移动content到归档文件夹
            for item in os.listdir(content_dir):
                src_path = os.path.join(content_dir, item)
                dst_path = os.path.join(archive_folder, item)

                if VERBOSE:
                    print(f"  DEBUG: 移动到归档文件夹: {src_path} -> {dst_path}")

                safe_move(src_path, dst_path, VERBOSE)

            print(f"  Extracted using file-content-{threshold}-collect policy to: {archive_folder} ({total_items} items >= {threshold})")
        else:
            # 直接移动到输出目录，处理冲突
            conflict_found = False
            for root, dirs, files in safe_walk(content_dir, VERBOSE):
                rel_root = os.path.relpath(root, content_dir)
                rel_root = '' if rel_root == '.' else rel_root
                # 只检查文件冲突
                for f in files:
                    rel_path = os.path.join(rel_root, f) if rel_root else f
                    dest_path = os.path.join(output_dir, rel_path)
                    if safe_isfile(dest_path, VERBOSE):
                        if VERBOSE:
                            print(f"  DEBUG: 冲突文件检测到: {dest_path}")
                        conflict_found = True
                        break
                if conflict_found:
                    break

            if conflict_found:
                # 有冲突，创建归档文件夹
                archive_folder = os.path.join(output_dir, archive_name)
                archive_folder = ensure_unique_name(archive_folder, unique_suffix)
                safe_makedirs(archive_folder, debug=VERBOSE)

                # 移动content到归档文件夹
                for item in os.listdir(content_dir):
                    src_path = os.path.join(content_dir, item)
                    dst_path = os.path.join(archive_folder, item)

                    if VERBOSE:
                        print(f"  DEBUG: 移动到归档文件夹（冲突）: {src_path} -> {dst_path}")

                    safe_move(src_path, dst_path, VERBOSE)

                print(f"  Extracted using file-content-{threshold}-collect policy to: {archive_folder} (conflicts detected, {total_items} items < {threshold})")
            else:
                # 无冲突，直接移动到输出目录
                for root, dirs, files in safe_walk(content_dir, VERBOSE):
                    rel_root = os.path.relpath(root, content_dir)
                    target_root = output_dir if rel_root == '.' else os.path.join(output_dir, rel_root)
                    safe_makedirs(target_root, debug=VERBOSE)

                    for d in dirs:
                        dest_dir = os.path.join(target_root, d)
                        safe_makedirs(dest_dir, debug=VERBOSE)

                    for f in files:
                        src_f = os.path.join(root, f)
                        dest_f = os.path.join(target_root, f)
                        safe_move(src_f, dest_f, VERBOSE)

                print(f"  Extracted using file-content-{threshold}-collect policy to: {output_dir} ({total_items} items < {threshold})")

    finally:
        # 6. 清理content目录和tmp目录
        if safe_exists(content_dir, VERBOSE):
            safe_rmtree(content_dir, VERBOSE)


# ==================== 结束新增解压策略 ====================

# ==================== 新增RAR策略 ====================

def check_rar_available():
    """
    Check if rar command is available in PATH

    Returns:
        bool: True if rar command is available, False otherwise
    """
    try:
        if VERBOSE:
            print(f"  DEBUG: 检查rar命令可用性")
        
        # Try to run rar command to check if it's available
        result = safe_subprocess_run(['rar'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # rar command typically returns non-zero when run without arguments
        # but if it's found, we should get some output
        available = True  # If command runs without FileNotFoundError, it's available

        if VERBOSE:
            print(f"  DEBUG: rar命令{'可用' if available else '不可用'}")

        return available

    except FileNotFoundError:
        if VERBOSE:
            print(f"  DEBUG: rar命令未找到")
        return False
    except Exception as e:
        if VERBOSE:
            print(f"  DEBUG: 检查rar命令时出错: {e}")
        return False


def is_rar_format(archive_path):
    """
    判断文件是否为RAR格式或RAR分卷

    Args:
        archive_path: 归档文件路径

    Returns:
        bool: 如果是RAR格式或RAR分卷返回True，否则返回False
    """
    filename_lower = os.path.basename(archive_path).lower()

    if VERBOSE:
        print(f"  DEBUG: 检查是否为RAR格式: {archive_path}")

    # 检查文件扩展名
    if filename_lower.endswith('.rar'):
        if VERBOSE:
            print(f"  DEBUG: 检测到RAR文件（扩展名）")
        return True

    # 检查RAR分卷格式 (.part*.rar)
    if re.search(r'\.part\d+\.rar$', filename_lower):
        if VERBOSE:
            print(f"  DEBUG: 检测到RAR分卷文件（扩展名）")
        return True

    # 检查RAR老式分卷格式 (.r00, .r01, etc.)
    if re.search(r'\.r\d+$', filename_lower):
        if VERBOSE:
            print(f"  DEBUG: 检测到RAR老式分卷文件（扩展名）")
        return True

    # 检查文件魔术字节 (Rar! header)
    try:
        with safe_open(archive_path, 'rb') as f:
            header = f.read(4)
            if header == b'Rar!':
                if VERBOSE:
                    print(f"  DEBUG: 通过魔术字节检测到RAR格式")
                return True
    except Exception as e:
        if VERBOSE:
            print(f"  DEBUG: 读取文件头失败: {e}")

    if VERBOSE:
        print(f"  DEBUG: 非RAR格式")
    return False


def should_use_rar_extractor(archive_path, enable_rar=False, sfx_detector=None):
    """
    判断是否应该使用RAR命令解压文件

    Args:
        archive_path: 归档文件路径
        enable_rar: 是否启用RAR解压器
        sfx_detector: SFXDetector实例，用于检测SFX文件

    Returns:
        bool: 如果应该使用RAR解压返回True，否则返回False
    """
    if not enable_rar:
        if VERBOSE:
            print(f"  DEBUG: RAR解压器未启用，使用7z")
        return False

    filename_lower = os.path.basename(archive_path).lower()

    if VERBOSE:
        print(f"  DEBUG: 判断是否使用RAR解压: {archive_path}")

    # 对于明显的RAR文件，直接返回True
    if is_rar_format(archive_path):
        if VERBOSE:
            print(f"  DEBUG: 检测到RAR格式，使用RAR解压")
        return True

    # 对于SFX文件（.exe），需要检测内部格式
    if filename_lower.endswith('.exe') and sfx_detector:
        if VERBOSE:
            print(f"  DEBUG: 检测SFX文件格式")

        # 使用详细的SFX检测
        sfx_result = sfx_detector.is_sfx(archive_path, detailed=True)

        if sfx_result and sfx_result.get('is_sfx', False):
            # 检查是否找到了RAR签名或RAR标记
            signature_info = sfx_result.get('signature', {})
            rar_marker = sfx_result.get('rar_marker', False)

            if signature_info.get('found', False) and signature_info.get('format') == 'RAR':
                if VERBOSE:
                    print(f"  DEBUG: SFX文件包含RAR签名，使用RAR解压")
                return True

            if rar_marker:
                if VERBOSE:
                    print(f"  DEBUG: SFX文件包含RAR标记，使用RAR解压")
                return True

            if VERBOSE:
                print(f"  DEBUG: SFX文件非RAR格式，使用7z解压")
        else:
            if VERBOSE:
                print(f"  DEBUG: 非SFX文件，使用7z解压")

    if VERBOSE:
        print(f"  DEBUG: 使用7z解压")
    return False


# ==================== 结束新增RAR策略 ====================


def apply_file_content_auto_folder_collect_len_policy(tmp_dir, output_dir, archive_name, threshold, unique_suffix):
    """
    应用file-content-auto-folder-N-collect-len策略

    Args:
        tmp_dir: 临时目录
        output_dir: 输出目录
        archive_name: 归档名称
        threshold: 阈值N
        unique_suffix: 唯一后缀
    """
    if VERBOSE:
        print(f"  DEBUG: 应用file-content-auto-folder-{threshold}-collect-len策略")

    # 1. 查找file_content（不移动）
    file_content = find_file_content(tmp_dir, VERBOSE)

    if not file_content['found']:
        if VERBOSE:
            print(f"  DEBUG: 未找到file_content，回退到{threshold}-collect策略")
        # 回退到n-collect策略
        files, dirs = count_items_in_dir(tmp_dir)
        total_items = files + dirs

        if total_items >= threshold:
            # Create archive folder
            archive_folder = os.path.join(output_dir, archive_name)
            archive_folder = ensure_unique_name(archive_folder, unique_suffix)
            safe_makedirs(archive_folder, debug=VERBOSE)

            # Move all items to archive folder
            for item in os.listdir(tmp_dir):
                src_item = os.path.join(tmp_dir, item)
                dest_item = os.path.join(archive_folder, item)
                safe_move(src_item, dest_item, VERBOSE)

            print(f"  Extracted to: {archive_folder} ({total_items} items >= {threshold})")
        else:
            # Extract directly using direct policy logic
            tmp_items = os.listdir(tmp_dir)
            conflicts = [item for item in tmp_items if safe_exists(os.path.join(output_dir, item), VERBOSE)]

            if conflicts:
                # Create archive folder due to conflicts
                archive_folder = os.path.join(output_dir, archive_name)
                archive_folder = ensure_unique_name(archive_folder, unique_suffix)
                safe_makedirs(archive_folder, debug=VERBOSE)

                for item in tmp_items:
                    src_item = os.path.join(tmp_dir, item)
                    dest_item = os.path.join(archive_folder, item)
                    safe_move(src_item, dest_item, VERBOSE)

                print(f"  Extracted to: {archive_folder} (conflicts detected, {total_items} items < {threshold})")
            else:
                # No conflicts, extract directly
                for item in tmp_items:
                    src_item = os.path.join(tmp_dir, item)
                    dest_item = os.path.join(output_dir, item)
                    safe_move(src_item, dest_item, VERBOSE)

                print(f"  Extracted to: {output_dir} ({total_items} items < {threshold})")
        return

    # 2. 确定deepest_folder_name（在移动之前）
    deepest_folder_name = get_deepest_folder_name(file_content, tmp_dir, archive_name)
    if VERBOSE:
        print(f"  DEBUG: 确定的deepest_folder_name: {deepest_folder_name}")

    # 3. 创建content临时目录
    content_dir = f"content_{unique_suffix}"

    try:
        safe_makedirs(content_dir, debug=VERBOSE)

        if VERBOSE:
            print(f"  DEBUG: 创建content目录: {content_dir}")

        # 4. 移动file_content到content目录
        for item in file_content['items']:
            src_path = item['path']
            dst_path = os.path.join(content_dir, item['name'])

            if VERBOSE:
                print(f"  DEBUG: 移动file_content项目: {src_path} -> {dst_path}")

            safe_move(src_path, dst_path, VERBOSE)

        # 5. 计算content目录中的项目数量
        files, dirs = count_items_in_dir(content_dir)
        total_items = files + dirs

        if VERBOSE:
            print(f"  DEBUG: content目录统计 - 文件: {files}, 目录: {dirs}, 总计: {total_items}, 阈值: {threshold}")

        # 6. 根据数量决定是否包裹
        if total_items >= threshold:
            # 需要创建文件夹，进入步骤7
            need_folder = True
        else:
            # 检查冲突
            conflict_found = False
            for root, dirs, files in safe_walk(content_dir, VERBOSE):
                rel_root = os.path.relpath(root, content_dir)
                rel_root = '' if rel_root == '.' else rel_root
                # 只检查文件冲突
                for f in files:
                    rel_path = os.path.join(rel_root, f) if rel_root else f
                    dest_path = os.path.join(output_dir, rel_path)
                    if safe_isfile(dest_path, VERBOSE):
                        if VERBOSE:
                            print(f"  DEBUG: 冲突文件检测到: {dest_path}")
                        conflict_found = True
                        break
                if conflict_found:
                    break

            if conflict_found:
                # 有冲突，需要创建文件夹
                need_folder = True
            else:
                # 无冲突，直接移动到输出目录
                need_folder = False

        if need_folder:
            # 7. 判断新建文件夹的名称（len策略）
            len_d = len(deepest_folder_name)
            len_a = len(archive_name)

            if len_d >= len_a:
                folder_name = deepest_folder_name
            else:
                folder_name = archive_name

            if VERBOSE:
                print(f"  DEBUG: len策略 - deepest_folder_name长度: {len_d}, archive_name长度: {len_a}, 选择: {folder_name}")

            # 创建最终文件夹
            final_archive_dir = os.path.join(output_dir, folder_name)
            final_archive_dir = ensure_unique_name(final_archive_dir, unique_suffix)
            safe_makedirs(final_archive_dir, debug=VERBOSE)

            # 移动content到最终文件夹
            for item in os.listdir(content_dir):
                src_path = os.path.join(content_dir, item)
                dst_path = os.path.join(final_archive_dir, item)

                if VERBOSE:
                    print(f"  DEBUG: 移动到最终文件夹: {src_path} -> {dst_path}")

                safe_move(src_path, dst_path, VERBOSE)

            print(f"  Extracted using file-content-auto-folder-{threshold}-collect-len policy to: {final_archive_dir}")
        else:
            # 无冲突，直接移动到输出目录
            for root, dirs, files in safe_walk(content_dir, VERBOSE):
                rel_root = os.path.relpath(root, content_dir)
                target_root = output_dir if rel_root == '.' else os.path.join(output_dir, rel_root)
                safe_makedirs(target_root, debug=VERBOSE)

                for d in dirs:
                    dest_dir = os.path.join(target_root, d)
                    safe_makedirs(dest_dir, debug=VERBOSE)

                for f in files:
                    src_f = os.path.join(root, f)
                    dest_f = os.path.join(target_root, f)
                    safe_move(src_f, dest_f, VERBOSE)

            print(f"  Extracted using file-content-auto-folder-{threshold}-collect-len policy to: {output_dir} ({total_items} items < {threshold})")

    finally:
        # 8. 清理content目录
        if safe_exists(content_dir, VERBOSE):
            safe_rmtree(content_dir, VERBOSE)


def apply_file_content_auto_folder_collect_meaningful_policy(tmp_dir, output_dir, archive_name, threshold, unique_suffix):
    """
    应用file-content-auto-folder-N-collect-meaningful策略

    Args:
        tmp_dir: 临时目录
        output_dir: 输出目录
        archive_name: 归档名称
        threshold: 阈值N
        unique_suffix: 唯一后缀
    """
    if VERBOSE:
        print(f"  DEBUG: 应用file-content-auto-folder-{threshold}-collect-meaningful策略")

    # 1. 查找file_content（不移动）
    file_content = find_file_content(tmp_dir, VERBOSE)

    if not file_content['found']:
        if VERBOSE:
            print(f"  DEBUG: 未找到file_content，回退到{threshold}-collect策略")
        # 回退到n-collect策略
        files, dirs = count_items_in_dir(tmp_dir)
        total_items = files + dirs

        if total_items >= threshold:
            # Create archive folder
            archive_folder = os.path.join(output_dir, archive_name)
            archive_folder = ensure_unique_name(archive_folder, unique_suffix)
            safe_makedirs(archive_folder, debug=VERBOSE)

            # Move all items to archive folder
            for item in os.listdir(tmp_dir):
                src_item = os.path.join(tmp_dir, item)
                dest_item = os.path.join(archive_folder, item)
                safe_move(src_item, dest_item, VERBOSE)

            print(f"  Extracted to: {archive_folder} ({total_items} items >= {threshold})")
        else:
            # Extract directly using direct policy logic
            tmp_items = os.listdir(tmp_dir)
            conflicts = [item for item in tmp_items if safe_exists(os.path.join(output_dir, item), VERBOSE)]

            if conflicts:
                # Create archive folder due to conflicts
                archive_folder = os.path.join(output_dir, archive_name)
                archive_folder = ensure_unique_name(archive_folder, unique_suffix)
                safe_makedirs(archive_folder, debug=VERBOSE)

                for item in tmp_items:
                    src_item = os.path.join(tmp_dir, item)
                    dest_item = os.path.join(archive_folder, item)
                    safe_move(src_item, dest_item, VERBOSE)

                print(f"  Extracted to: {archive_folder} (conflicts detected, {total_items} items < {threshold})")
            else:
                # No conflicts, extract directly
                for item in tmp_items:
                    src_item = os.path.join(tmp_dir, item)
                    dest_item = os.path.join(output_dir, item)
                    safe_move(src_item, dest_item, VERBOSE)

                print(f"  Extracted to: {output_dir} ({total_items} items < {threshold})")
        return

    # 2. 确定deepest_folder_name（在移动之前）
    deepest_folder_name = get_deepest_folder_name(file_content, tmp_dir, archive_name)
    if VERBOSE:
        print(f"  DEBUG: 确定的deepest_folder_name: {deepest_folder_name}")

    # 3. 创建content临时目录
    content_dir = f"content_{unique_suffix}"

    try:
        safe_makedirs(content_dir, debug=VERBOSE)

        if VERBOSE:
            print(f"  DEBUG: 创建content目录: {content_dir}")

        # 4. 移动file_content到content目录
        for item in file_content['items']:
            src_path = item['path']
            dst_path = os.path.join(content_dir, item['name'])

            if VERBOSE:
                print(f"  DEBUG: 移动file_content项目: {src_path} -> {dst_path}")

            safe_move(src_path, dst_path, VERBOSE)

        # 5. 计算content目录中的项目数量
        files, dirs = count_items_in_dir(content_dir)
        total_items = files + dirs

        if VERBOSE:
            print(f"  DEBUG: content目录统计 - 文件: {files}, 目录: {dirs}, 总计: {total_items}, 阈值: {threshold}")

        # 6. 根据数量决定是否包裹
        if total_items >= threshold:
            # 需要创建文件夹，进入步骤7
            need_folder = True
        else:
            # 检查冲突
            conflict_found = False
            for root, dirs, files in safe_walk(content_dir, VERBOSE):
                rel_root = os.path.relpath(root, content_dir)
                rel_root = '' if rel_root == '.' else rel_root
                # 只检查文件冲突
                for f in files:
                    rel_path = os.path.join(rel_root, f) if rel_root else f
                    dest_path = os.path.join(output_dir, rel_path)
                    if safe_isfile(dest_path, VERBOSE):
                        if VERBOSE:
                            print(f"  DEBUG: 冲突文件检测到: {dest_path}")
                        conflict_found = True
                        break
                if conflict_found:
                    break

            if conflict_found:
                # 有冲突，需要创建文件夹
                need_folder = True
            else:
                # 无冲突，直接移动到输出目录
                need_folder = False

        if need_folder:
            # 7. 判断新建文件夹的名称（meaningful策略）
            meaningful_deepest = remove_ascii_non_meaningful_chars(deepest_folder_name)
            meaningful_archive = remove_ascii_non_meaningful_chars(archive_name)

            len_d = len(meaningful_deepest)
            len_a = len(meaningful_archive)

            if len_d >= len_a:
                folder_name = deepest_folder_name  # 使用原始名称
            else:
                folder_name = archive_name  # 使用原始名称

            if VERBOSE:
                print(f"  DEBUG: meaningful策略 - deepest_folder_name: '{deepest_folder_name}' -> '{meaningful_deepest}' (长度: {len_d})")
                print(f"  DEBUG: meaningful策略 - archive_name: '{archive_name}' -> '{meaningful_archive}' (长度: {len_a})")
                print(f"  DEBUG: meaningful策略 - 选择: {folder_name}")

            # 创建最终文件夹
            final_archive_dir = os.path.join(output_dir, folder_name)
            final_archive_dir = ensure_unique_name(final_archive_dir, unique_suffix)
            safe_makedirs(final_archive_dir, debug=VERBOSE)

            # 移动content到最终文件夹
            for item in os.listdir(content_dir):
                src_path = os.path.join(content_dir, item)
                dst_path = os.path.join(final_archive_dir, item)

                if VERBOSE:
                    print(f"  DEBUG: 移动到最终文件夹: {src_path} -> {dst_path}")

                safe_move(src_path, dst_path, VERBOSE)

            print(f"  Extracted using file-content-auto-folder-{threshold}-collect-meaningful policy to: {final_archive_dir}")
        else:
            # 无冲突，直接移动到输出目录
            for root, dirs, files in safe_walk(content_dir, VERBOSE):
                rel_root = os.path.relpath(root, content_dir)
                target_root = output_dir if rel_root == '.' else os.path.join(output_dir, rel_root)
                safe_makedirs(target_root, debug=VERBOSE)

                for d in dirs:
                    dest_dir = os.path.join(target_root, d)
                    safe_makedirs(dest_dir, debug=VERBOSE)

                for f in files:
                    src_f = os.path.join(root, f)
                    dest_f = os.path.join(target_root, f)
                    safe_move(src_f, dest_f, VERBOSE)

            print(f"  Extracted using file-content-auto-folder-{threshold}-collect-meaningful policy to: {output_dir} ({total_items} items < {threshold})")

    finally:
        # 8. 清理content目录
        if safe_exists(content_dir, VERBOSE):
            safe_rmtree(content_dir, VERBOSE)


def main():
    """Main function."""
    global VERBOSE

    # Setup UTF-8 environment early
    setup_windows_utf8()

    parser = argparse.ArgumentParser(
        description='Advanced archive decompressor supporting various formats and policies'
    )

    # Required argument
    parser.add_argument(
        'path',
        help='Path to file or folder to scan for archives'
    )

    # Optional arguments
    parser.add_argument(
        '-o', '--output',
        help='Output directory for extracted files'
    )

    parser.add_argument(
        '-p', '--password',
        help='Password for encrypted archives'
    )

    parser.add_argument(
        '-pf', '--password-file',
        help='Path to password file (one password per line)'
    )

    # 修正：移除choices限制，支持动态decode-${int}格式，设置默认值为decode-auto
    parser.add_argument(
        '-tzp', '--traditional-zip-policy',
        default='decode-auto',  # 新增：设置默认值为decode-auto
        help='Policy for traditional encoding ZIP files: '
             'move (move to specified directory), '
             'asis (skip processing), '
             'decode-auto (auto-detect encoding), '
             'decode-${int} (manual encoding, e.g., decode-932 for Shift-JIS, decode-936 for GBK). '
             'Only applies to ZIP files that use traditional encoding (non-UTF-8). '
             'Default: decode-auto'  # 新增：在帮助信息中说明默认值
    )

    parser.add_argument(
        '-tzt', '--traditional-zip-to',
        help='Directory to move traditional ZIP files (required with --traditional-zip-policy move)'
    )

    parser.add_argument(
        '-tzdc', '--traditional-zip-decode-confidence',
        type=int,
        default=90,
        help='Minimum confidence percentage for auto-detection (default: 90). '
             'Only used with --traditional-zip-policy decode-auto. '
             'Files with detection confidence below this threshold will be skipped.'
    )

    parser.add_argument(
        '-tzdm', '--traditional-zip-decode-model',
        choices=['chardet', 'charset_normalizer'],
        default='chardet',
        help='Library to use for encoding detection (default: chardet). '
             'chardet: Traditional chardet library. '
             'charset_normalizer: Modern charset-normalizer library with better accuracy.'
    )

    parser.add_argument(
        '-el', '--enable-llm',
        action='store_true',
        help='Enable LLM verification after chardet detection in decode-auto mode. '
             'LLM will verify the language consistency of decoded text.'
    )

    parser.add_argument(
        '-lc', '--llm-confidence',
        type=int,
        default=95,
        help='Minimum confidence percentage for LLM language verification (default: 95). '
             'Only used when --enable-llm is specified.'
    )

    parser.add_argument(
        '-er', '--enable-rar',
        action='store_true',
        help='Enable RAR command-line tool for extracting RAR archives and RAR SFX files. Falls back to 7z if RAR is not available.'
    )

    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=1,
        help='Number of concurrent extraction tasks (default: 1)'
    )

    parser.add_argument(
        '-dp', '--decompress-policy',
        default='2-collect',
        help='Decompress policy: separate/direct/only-file-content/file-content-with-folder/file-content-with-folder-separate/only-file-content-direct/N-collect/file-content-N-collect/file-content-auto-folder-N-collect-len/file-content-auto-folder-N-collect-meaningful (default: 2-collect)'
    )

    parser.add_argument(
        '-sp', '--success-policy',
        choices=['delete', 'asis', 'move'],
        default='asis',
        help='Policy for successful extractions (default: asis)'
    )

    parser.add_argument(
        '--success-to', '-st',  # 添加别名
        help='Directory to move successful archives (required with -sp move)'
    )

    parser.add_argument(
        '-fp', '--fail-policy',
        choices=['asis', 'move'],
        default='asis',
        help='Policy for failed extractions (default: asis)'
    )

    parser.add_argument(
        '--fail-to', '-ft',  # 添加别名
        help='Directory to move failed archives (required with -fp move)'
    )

    parser.add_argument(
        '-n', '--dry-run',
        action='store_true',
        help='Preview mode - do not actually extract'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    # Skip single archive format arguments
    parser.add_argument(
        '--skip-7z',
        action='store_true',
        help='Skip single .7z archive files'
    )

    parser.add_argument(
        '--skip-rar',
        action='store_true',
        help='Skip single .rar archive files'
    )

    parser.add_argument(
        '--skip-zip',
        action='store_true',
        help='Skip single .zip archive files'
    )

    parser.add_argument(
        '--skip-exe',
        action='store_true',
        help='Skip single .exe SFX archive files'
    )

    # Skip multi-volume archive format arguments
    parser.add_argument(
        '--skip-7z-multi',
        action='store_true',
        help='Skip multi-volume .7z archives (.7z.001, .7z.002, etc.)'
    )

    parser.add_argument(
        '--skip-rar-multi',
        action='store_true',
        help='Skip multi-volume RAR archives (.partN.rar, .rNN formats)'
    )

    parser.add_argument(
        '--skip-zip-multi',
        action='store_true',
        help='Skip multi-volume ZIP archives (.zip with .z01, .z02, etc.)'
    )

    parser.add_argument(
        '--skip-exe-multi',
        action='store_true',
        help='Skip multi-volume SFX archives (.partN.exe and related volumes)'
    )

    # 锁相关参数
    parser.add_argument(
        '--no-lock',
        action='store_true',
        help='不使用全局锁（谨慎使用）'
    )

    parser.add_argument(
        '--lock-timeout',
        type=int,
        default=30,
        help='锁定超时时间（最大重试次数）'
    )

    parser.add_argument(
        '-dr', '--depth-range',
        help='Depth range for recursive scanning. Format: "int1-int2" or "int". '
             'Controls which directory depths to scan for archives. '
             'Depth 0 means files directly in the root path, depth 1 means files in immediate subdirectories, etc. '
             'Examples: "0-1" (scan root and first level), "1" (only first level), "0" (only root level). '
             'If not specified, all depths are scanned.'
    )

    # Extension fix arguments (mutually exclusive)
    ext_group = parser.add_mutually_exclusive_group()
    ext_group.add_argument(
        '--fix-ext', '-fe',
        action='store_true',
        help='Enable archive extension fix logic. Detects archive type by file header and fixes incorrect extensions before processing.'
    )
    ext_group.add_argument(
        '--safe-fix-ext', '-sfe',
        action='store_true',
        help='Enable safe archive extension fix logic. Always appends correct extension without replacing existing one. Requires interactive confirmation.'
    )

    args = parser.parse_args()

    # Set global verbose flag
    VERBOSE = args.verbose

    # 设置信号处理器
    if hasattr(signal, 'SIGINT'):
        signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)

    try:
        # 获取锁（除非用户指定不使用锁）
        if not args.no_lock:
            if not acquire_lock(args.lock_timeout):
                print("无法获取全局锁，程序退出")
                return 1

        # Validate arguments
        if not safe_exists(args.path, VERBOSE):
            print(f"Error: Path does not exist: {args.path}")
            return 1

        if args.success_policy == 'move' and not args.success_to:
            print("Error: --success-to is required when using -sp move")
            return 1

        if args.fail_policy == 'move' and not args.fail_to:
            print("Error: --fail-to is required when using -fp move")
            return 1

        # 增强的传统ZIP策略参数验证
        if args.traditional_zip_policy:
            policy = args.traditional_zip_policy.lower()
            
            # 验证策略格式
            valid_policies = ['move', 'asis', 'decode-auto']
            is_valid_policy = False
            
            if policy in valid_policies:
                is_valid_policy = True
            elif policy.startswith('decode-') and policy != 'decode-auto':
                # 验证decode-${int}格式
                try:
                    encoding_str = policy[7:]  # 去掉'decode-'前缀
                    encoding_num = int(encoding_str)
                    if encoding_num < 0:
                        print(f"Error: Invalid encoding number in --traditional-zip-policy: {encoding_num}")
                        print("Encoding number must be non-negative")
                        return 1
                    is_valid_policy = True
                except ValueError:
                    print(f"Error: Invalid decode format in --traditional-zip-policy: {args.traditional_zip_policy}")
                    print("Use format: decode-${int}, e.g., decode-932")
                    return 1
            
            if not is_valid_policy:
                print(f"Error: Invalid --traditional-zip-policy: {args.traditional_zip_policy}")
                print("Valid options:")
                print("  move              - Move traditional ZIP files to specified directory")
                print("  asis              - Skip traditional ZIP files")
                print("  decode-auto       - Auto-detect encoding")
                print("  decode-${int}     - Manual encoding (e.g., decode-932, decode-936)")
                print("")
                print("Common encoding examples:")
                print("  decode-932        - Shift-JIS (Japanese)")
                print("  decode-936        - GBK/GB2312 (Simplified Chinese)")
                print("  decode-950        - Big5 (Traditional Chinese)")
                print("  decode-949        - EUC-KR (Korean)")
                print("  decode-1252       - Windows-1252 (Western European)")
                return 1
            
            # 验证move策略需要目标目录
            if policy == 'move' and not args.traditional_zip_to:
                print("Error: --traditional-zip-to is required when using --traditional-zip-policy move")
                return 1
            
            # 验证置信度参数范围
            if args.traditional_zip_decode_confidence < 0 or args.traditional_zip_decode_confidence > 100:
                print(f"Error: --traditional-zip-decode-confidence must be between 0 and 100")
                return 1
            
            # 验证LLM置信度参数范围
            if args.llm_confidence < 0 or args.llm_confidence > 100:
                print(f"Error: --llm-confidence must be between 0 and 100")
                return 1
            
            # 检查依赖库是否可用（仅对decode-auto策略）
            if policy == 'decode-auto':
                try:
                    import zipfile
                    if args.traditional_zip_decode_model == 'charset_normalizer':
                        from charset_normalizer import detect
                    else:
                        import chardet
                    if args.enable_llm:
                        from transformers import pipeline
                except ImportError as e:
                    if 'chardet' in str(e):
                        print(f"Error: chardet library is required for --traditional-zip-policy decode-auto: {e}")
                        print("Please install: pip install chardet")
                    elif 'charset_normalizer' in str(e):
                        print(f"Error: charset_normalizer library is required for --traditional-zip-decode-model charset_normalizer: {e}")
                        print("Please install: pip install charset-normalizer")
                    elif args.enable_llm and ('transformers' in str(e) or 'torch' in str(e)):
                        print(f"Error: transformers library is required for --enable-llm: {e}")
                        print("Please install: pip install transformers torch")
                    else:
                        print(f"Error: Required library not available: {e}")
                    return 1

        # Validate decompress policy
        if args.decompress_policy not in ['separate', 'direct', 'only-file-content', 'file-content-with-folder', 'file-content-with-folder-separate', 'only-file-content-direct']:
            if re.match(r'^\d+-collect$', args.decompress_policy):
                # Validate N-collect threshold
                threshold = int(args.decompress_policy.split('-')[0])
                if threshold < 0:
                    print(f"Error: N-collect threshold must be >= 0")
                    return 1
            elif re.match(r'^file-content-\d+-collect$', args.decompress_policy):
                # Validate file-content-N-collect threshold
                threshold = int(args.decompress_policy.split('-')[2])
                if threshold < 1:
                    print(f"Error: file-content-N-collect threshold must be >= 1")
                    return 1
            elif re.match(r'^file-content-auto-folder-\d+-collect-(len|meaningful)$', args.decompress_policy):
                # Validate file-content-auto-folder-N-collect-len/meaningful threshold
                parts = args.decompress_policy.split('-')
                threshold = int(parts[4])  # N值
                if threshold < 1:
                    print(f"Error: file-content-auto-folder-N-collect threshold must be >= 1")
                    return 1
            else:
                print(f"Error: Invalid decompress policy: {args.decompress_policy}")
                return 1

        # Validate depth range parameter
        if args.depth_range:
            try:
                depth_range = parse_depth_range(args.depth_range)
                if VERBOSE:
                    print(f"  DEBUG: 验证深度范围: {depth_range[0]}-{depth_range[1]}")
            except ValueError as e:
                print(f"Error: {e}")
                return 1

        # Check if 7z is available
        try:
            safe_subprocess_run(['7z'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except FileNotFoundError:
            print("Error: 7z command not found. Please install p7zip or 7-Zip.")
            return 1

        # Check if RAR is available when --enable-rar is used
        if args.enable_rar:
            if not check_rar_available():
                print("Warning: RAR command not found in PATH. Will fall back to 7z for all archives.")
                print("To use RAR extraction, please install WinRAR or RAR command-line tool.")
                # Don't return error, just warn and continue with 7z fallback

        # Create processor and find archives
        processor = ArchiveProcessor(args)
        abs_path = os.path.abspath(args.path)
        
        # Fix archive extensions if requested
        fix_archive_ext(processor, abs_path, args)
        
        archives = processor.find_archives(abs_path)

        if not archives:
            print("No archives found to process.")
            return 0

        print(f"Found {len(archives)} archive(s) to process.")

        # Process archives
        if args.threads == 1:
            # Single-threaded processing
            for archive in archives:
                try:
                    processor.process_archive(archive)
                except KeyboardInterrupt:
                    print("\nProcessing interrupted by user")
                    raise
        else:
            # Multi-threaded processing
            executor = ThreadPoolExecutor(max_workers=args.threads)
            futures = {}
            
            try:
                # Reset interrupt flag at start
                reset_interrupt_flag()
                
                # Submit all tasks
                futures = {executor.submit(processor.process_archive, archive): archive
                          for archive in archives}
                
                # Process results
                for future in as_completed(futures):
                    archive = futures[future]
                    try:
                        # Check for interrupt before getting result
                        check_interrupt()
                        future.result()
                    except KeyboardInterrupt:
                        # Interrupt detected - immediately shutdown executor
                        print(f"\nKeyboard interrupt detected, stopping all tasks...")
                        set_interrupt_flag()  # Ensure flag is set
                        
                        # Cancel all pending futures
                        cancelled_count = 0
                        for f in futures:
                            if not f.done():
                                if f.cancel():
                                    cancelled_count += 1
                        
                        if VERBOSE:
                            print(f"  DEBUG: Cancelled {cancelled_count} pending tasks")
                        
                        # Shutdown executor without waiting
                        executor.shutdown(wait=False)
                        
                        # Re-raise to exit
                        raise
                    except Exception as e:
                        # Check if this is a wrapped KeyboardInterrupt
                        if "KeyboardInterrupt" in str(e) or "Interrupt requested" in str(e):
                            print(f"\nInterrupt detected in worker thread")
                            set_interrupt_flag()
                            
                            # Cancel remaining tasks
                            for f in futures:
                                if not f.done():
                                    f.cancel()
                            
                            executor.shutdown(wait=False)
                            raise KeyboardInterrupt("Worker thread interrupted")
                        
                        # Normal exception - log and continue
                        print(f"Error processing {archive}: {e}")
                        processor.failed_archives.append(archive)
                
                # Normal completion - shutdown executor
                executor.shutdown(wait=True)
                
            except KeyboardInterrupt:
                print("\nShutting down due to interrupt...")
                # Make sure executor is shutdown
                try:
                    executor.shutdown(wait=False)
                except:
                    pass
                raise
            except Exception:
                # Ensure executor is shutdown on any error
                try:
                    executor.shutdown(wait=False)
                except:
                    pass
                raise

        # Print summary
        print("\n" + "=" * 50)
        print("PROCESSING SUMMARY")
        print("=" * 50)
        print(f"Total archives found: {len(archives)}")
        print(f"Successfully processed: {len(processor.successful_archives)}")
        print(f"Failed to process: {len(processor.failed_archives)}")
        print(f"Skipped: {len(processor.skipped_archives)}")
        
        # Extension fix summary
        if args.fix_ext or args.safe_fix_ext:
            print(f"Extension fix - Renamed: {len(processor.fixed_rename_archives)}")
            print(f"Extension fix - Skipped: {len(processor.skipped_rename_archives)}")

        if processor.failed_archives:
            print("\nFailed archives:")
            for archive in processor.failed_archives:
                print(f"  - {archive}")

        if processor.skipped_archives:
            print("\nSkipped archives:")
            for archive in processor.skipped_archives:
                print(f"  - {archive}")
        
        if (args.fix_ext or args.safe_fix_ext) and processor.fixed_rename_archives:
            print("\nRenamed archives (extension fix):")
            for old_path, new_path in processor.fixed_rename_archives:
                print(f"  - {old_path} -> {new_path}")
        
        if (args.fix_ext or args.safe_fix_ext) and processor.skipped_rename_archives:
            print("\nSkipped archives (extension fix):")
            for archive in processor.skipped_rename_archives:
                print(f"  - {archive}")

        return 0

    except KeyboardInterrupt:
        print("\n程序被用户中断")
        # 只有获取了锁的实例才释放锁
        if lock_owner:
            release_lock()
        return 1
    except Exception as e:
        print(f"\n程序异常退出: {e}")
        if VERBOSE:
            import traceback
            traceback.print_exc()
        # 只有获取了锁的实例才释放锁
        if lock_owner:
            release_lock()
        return 1
    finally:
        # 确保锁被释放
        if lock_owner:
            release_lock()

if __name__ == '__main__':
    sys.exit(main())
