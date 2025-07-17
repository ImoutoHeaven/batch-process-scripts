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

# Global verbose flag
VERBOSE = False

class SFXDetector:
    """Detects if an EXE file is a self-extracting archive by analyzing file headers"""

    # Common archive format signatures
    SIGNATURES = {
        'RAR': [b'Rar!'],
        '7Z': [b'\x37\x7A\xBC\xAF\x27\x1C'],
        'ZIP': [b'PK\x03\x04'],
        'CAB': [b'MSCF'],
        'ARJ': [b'\x60\xEA'],
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
        
        # 【新增】验证和修正参数
        self.validate_args()

    def find_archives(self, search_path):
        """重构后的查找归档文件函数（修正单文件volume处理）"""
        archives = []

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

        except Exception as e:
            if VERBOSE:
                print(f"  DEBUG: 遍历目录失败: {e}")

        if VERBOSE:
            print(f"  DEBUG: 总共找到 {len(archives)} 个归档文件")
            print(f"  DEBUG: 跳过 {len(self.skipped_archives)} 个文件")

        return archives

    def find_correct_password(self, archive_path, password_candidates, encryption_status='encrypted_content'):
        """
        Find correct password from candidates using is_password_correct.
        
        Args:
            archive_path: Path to the archive
            password_candidates: List of password candidates to test
            encryption_status: Type of encryption ('encrypted_header', 'encrypted_content', or 'plain')
        
        Returns:
            str or None: Correct password if found, None if no correct password found
        """
        if not password_candidates:
            return ""

        if VERBOSE:
            print(f"  DEBUG: Testing {len(password_candidates)} password candidates")
            print(f"  DEBUG: Encryption type: {encryption_status}")

        for i, password in enumerate(password_candidates):
            if VERBOSE:
                print(f"  DEBUG: Testing password {i + 1}/{len(password_candidates)}")

            if is_password_correct(archive_path, password, encryption_status):
                if VERBOSE:
                    print(f"  DEBUG: Found correct password (candidate {i + 1})")
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
        safe_makedirs(target_base, debug=VERBOSE)

        base_path = self.args.path if safe_isdir(self.args.path, VERBOSE) else os.path.dirname(self.args.path)

        if VERBOSE:
            print(f"  DEBUG: Moving {len(volumes)} volumes to {target_base}")
            for vol in volumes:
                print(f"  DEBUG: Volume to move: {vol}")

        for volume in volumes:
            try:
                rel_path = self.get_relative_path(volume, base_path)
                target_dir = os.path.join(target_base, rel_path) if rel_path else target_base
                safe_makedirs(target_dir, debug=VERBOSE)

                target_file = os.path.join(target_dir, os.path.basename(volume))
                safe_move(volume, target_file, VERBOSE)
                print(f"  Moved: {volume} -> {target_file}")
            except Exception as e:
                print(f"  Warning: Could not move {volume}: {e}")


    def process_archive(self, archive_path):
        """Process a single archive following the exact specification."""
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

        # Step 1: Determine if we need to test passwords
        need_password_testing = bool(self.args.password_file)

        if VERBOSE:
            print(f"  DEBUG: 需要密码测试: {need_password_testing}")

        # Step 2: Check encryption status
        encryption_status = 'plain'
        if need_password_testing:
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

        # Step 3: Prepare password candidates and find correct password
        password_candidates = []
        correct_password = ""

        if need_password_testing and encryption_status in ['encrypted_header', 'encrypted_content']:
            # Build password candidate list: -p first, then -pf
            if self.args.password:
                password_candidates.append(self.args.password)
                if VERBOSE:
                    print(f"  DEBUG: Added command line password")

            if self.args.password_file:
                try:
                    with safe_open(self.args.password_file, 'r', encoding='utf-8') as f:
                        for line in f:
                            password = line.strip()
                            if password and password not in password_candidates:
                                password_candidates.append(password)
                    if VERBOSE:
                        print(f"  DEBUG: Read {len(password_candidates)} passwords from password file")
                except Exception as e:
                    print(f"  Warning: Cannot read password file: {e}")

            # Test passwords using is_password_correct with encryption status
            correct_password = self.find_correct_password(archive_path, password_candidates, encryption_status)
            if correct_password is None:
                print(f"  Error: No correct password found for {archive_path}")
                # Apply fail policy before returning - 使用新的get_all_volumes方法
                all_volumes = self.get_all_volumes(archive_path)
                if self.args.fail_policy == 'move' and self.args.fail_to:
                    self.move_volumes_with_structure(all_volumes, self.args.fail_to)
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
            # Step 5: Extract using try_extract function
            final_zip_decode = zip_decode_from_policy if zip_decode_from_policy is not None else getattr(self.args, 'zip_decode', None)
            enable_rar = getattr(self.args, 'enable_rar', False)

            # Check RAR availability if needed
            if enable_rar and not check_rar_available():
                print(f"  Warning: RAR command not available, falling back to 7z")
                enable_rar = False

            success = try_extract(archive_path, correct_password, tmp_dir, final_zip_decode, enable_rar, self.sfx_detector)

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
                    self.move_volumes_with_structure(all_volumes, self.args.success_to)

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
                    self.move_volumes_with_structure(all_volumes, self.args.fail_to)

                self.failed_archives.append(archive_path)
                return False

        finally:
            # Step 9: Clean up temporary directory
            clean_temp_dir(tmp_dir)

    def apply_decompress_policy(self, archive_path, tmp_dir, unique_suffix):
        """Apply the specified decompress policy following exact specification."""
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
                self.move_volumes_with_structure(all_volumes, self.args.traditional_zip_to)
                
                print(f"  Traditional ZIP moved to: {self.args.traditional_zip_to}")
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
                try:
                    import zipfile
                    import chardet
                except ImportError as e:
                    if VERBOSE:
                        print(f"  DEBUG: decode-auto所需库不可用，跳过传统ZIP策略: {e}")
                    result['should_continue'] = False
                    result['reason'] = f'decode-auto依赖库不可用，跳过处理'
                    return result
                
                # 检测编码
                encoding_result = guess_zip_encoding(archive_path)
                
                if not encoding_result['success']:
                    if VERBOSE:
                        print(f"  DEBUG: 编码检测失败，跳过处理")
                    result['should_continue'] = False  
                    result['reason'] = '编码检测失败'
                    return result
                
                # 检查置信度
                confidence_threshold = getattr(self.args, 'traditional_zip_decode_confidence', 90) / 100.0
                detected_confidence = encoding_result['confidence']
                
                if VERBOSE:
                    print(f"  DEBUG: 检测置信度: {detected_confidence:.2%}, 阈值: {confidence_threshold:.2%}")
                
                if detected_confidence < confidence_threshold:
                    if VERBOSE:
                        print(f"  DEBUG: 置信度低于阈值，跳过处理")
                    result['should_continue'] = False
                    result['reason'] = f'编码检测置信度({detected_confidence:.1%})低于阈值({confidence_threshold:.1%})'
                    return result
                
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
        判断文件是单包、分卷还是非压缩包
        
        Args:
            file_path: 文件路径
            
        Returns:
            str: 'single' | 'volume' | 'notarchive'
        """
        if not safe_isfile(file_path, VERBOSE):
            return 'notarchive'
            
        filename = os.path.basename(file_path)
        filename_lower = filename.lower()
        dir_path = os.path.dirname(file_path)
        
        if VERBOSE:
            print(f"  DEBUG: 判断文件类型: {file_path}")
        
        # 提取文件扩展名
        if '.' not in filename_lower:
            return 'notarchive'
            
        file_ext = filename_lower.split('.')[-1]
        base_filename = '.'.join(filename.split('.')[:-1])
        base_filename_lower = base_filename.lower()
        
        if VERBOSE:
            print(f"  DEBUG: 文件扩展名: {file_ext}, 基础文件名: {base_filename}")
        
        # === 7z 文件处理 ===
        if file_ext == '7z':
            return 'single'
            
        # 7z 分卷文件 (.7z.001, .7z.002, etc.)
        if file_ext.isdigit() and filename_lower.endswith('.7z.' + file_ext):
            # 提取基础文件名（去除.7z）
            if filename_lower.count('.7z.') == 1:
                base_without_7z = '.'.join(filename.split('.')[:-2])  # 去除.7z.数字
                base_without_7z_lower = base_without_7z.lower()
                
                # 检查是否存在对应的.exe文件
                potential_exe = os.path.join(dir_path, base_without_7z + '.exe')
                if safe_exists(potential_exe, VERBOSE):
                    return 'notarchive'  # 这是exe SFX-7z分卷的分卷文件，不是独立的7z分卷
                else:
                    return 'volume'
        
        # === RAR 文件处理 ===
        if file_ext == 'rar':
            # 检查是否为RAR5分卷格式 (.part*.rar)
            part_match = re.search(r'\.part\d+$', base_filename_lower)
            if part_match:
                # RAR5分卷格式
                base_without_part = base_filename[:part_match.start()]
                
                # 检查是否存在对应的.exe文件
                potential_exe_pattern = base_without_part + '.part*.exe'
                exe_files = safe_glob(os.path.join(dir_path, potential_exe_pattern))
                if exe_files:
                    return 'notarchive'  # 这是exe SFX-RAR分卷的.rar文件
                else:
                    return 'volume'
            else:
                # 检查是否为RAR4分卷（存在.r*文件）
                rar4_volumes = safe_glob(os.path.join(dir_path, base_filename + '.r*'))
                if rar4_volumes:
                    return 'volume'
                else:
                    return 'single'
        
        # RAR4 分卷文件 (.r00, .r01, etc.)
        if re.match(r'^r\d+$', file_ext):
            rar_base = base_filename + '.rar'
            potential_main_rar = os.path.join(dir_path, rar_base)
            if safe_exists(potential_main_rar, VERBOSE):
                return 'volume'  # 这是RAR4分卷的从卷
        
        # === ZIP 文件处理 ===
        if file_ext == 'zip':
            # 检查是否存在.z*分卷文件
            zip_volumes = safe_glob(os.path.join(dir_path, base_filename + '.z*'))
            if zip_volumes:
                return 'volume'
            else:
                return 'single'
        
        # ZIP 分卷文件 (.z01, .z02, etc.)
        if re.match(r'^z\d+$', file_ext):
            zip_main = base_filename + '.zip'
            potential_main_zip = os.path.join(dir_path, zip_main)
            if safe_exists(potential_main_zip, VERBOSE):
                return 'volume'  # 这是ZIP分卷的从卷
        
        # === EXE 文件处理 ===
        if file_ext == 'exe':
            # 检查是否为SFX
            if not self.sfx_detector.is_sfx(file_path):
                return 'notarchive'
            
            # 获取详细的SFX检测结果
            sfx_result = self.sfx_detector.is_sfx(file_path, detailed=True)
            signature_info = sfx_result.get('signature', {})
            rar_marker = sfx_result.get('rar_marker', False)
            
            # 判断是RAR SFX还是7z SFX
            is_rar_sfx = False
            if signature_info.get('found', False) and signature_info.get('format') == 'RAR':
                is_rar_sfx = True
            elif rar_marker:
                is_rar_sfx = True
            
            if is_rar_sfx:
                # SFX-RAR文件
                part_match = re.search(r'\.part\d+$', base_filename_lower)
                if part_match:
                    # 检查是否存在对应的.rar分卷文件
                    base_without_part = base_filename[:part_match.start()]
                    rar_volumes = safe_glob(os.path.join(dir_path, base_without_part + '.part*.rar'))
                    if rar_volumes:
                        return 'volume'
                    else:
                        return 'single'  # 虽然有part标识，但没有对应rar分卷
                else:
                    return 'single'
            else:
                # SFX-7z文件
                # 检查是否存在对应的.7z.*分卷文件
                seven_volumes = safe_glob(os.path.join(dir_path, base_filename + '.7z.*'))
                if seven_volumes:
                    return 'volume'
                else:
                    return 'single'
        
        return 'notarchive'

    def is_main_volume(self, file_path):
        """
        判断分卷文件是否为主卷
        
        Args:
            file_path: 文件路径
            
        Returns:
            bool: True if main volume, False otherwise
        """
        if not safe_isfile(file_path, VERBOSE):
            return False
            
        filename = os.path.basename(file_path)
        filename_lower = filename.lower()
        dir_path = os.path.dirname(file_path)
        
        if VERBOSE:
            print(f"  DEBUG: 判断是否为主卷: {file_path}")
        
        # 提取文件扩展名
        if '.' not in filename_lower:
            return False
            
        file_ext = filename_lower.split('.')[-1]
        base_filename = '.'.join(filename.split('.')[:-1])
        base_filename_lower = base_filename.lower()
        
        # === 7z 分卷主卷 ===
        if file_ext.isdigit() and filename_lower.endswith('.7z.' + file_ext):
            # 检查扩展名是否为第一卷标识
            if file_ext in ['001', '0001', '00001']:
                # 确保不存在对应的.exe文件
                base_without_7z = '.'.join(filename.split('.')[:-2])
                potential_exe = os.path.join(dir_path, base_without_7z + '.exe')
                if not safe_exists(potential_exe, VERBOSE):
                    return True
        
        # === RAR5 分卷主卷 ===
        if file_ext == 'rar':
            part_match = re.search(r'\.part(\d+)$', base_filename_lower)
            if part_match:
                part_num = part_match.group(1)
                # 检查是否为第一分卷
                if part_num in ['1', '01', '001', '0001', '00001']:
                    # 确保不存在对应的.exe文件
                    base_without_part = base_filename[:part_match.start()]
                    potential_exe_pattern = base_without_part + '.part*.exe'
                    exe_files = safe_glob(os.path.join(dir_path, potential_exe_pattern))
                    if not exe_files:
                        return True
        
        # === RAR4 分卷主卷 ===
        if file_ext == 'rar':
            # RAR4分卷的主卷就是.rar文件（当存在.r*文件时）
            rar4_volumes = safe_glob(os.path.join(dir_path, base_filename + '.r*'))
            if rar4_volumes:
                return True
        
        # === ZIP 分卷主卷 ===
        if file_ext == 'zip':
            # ZIP分卷的主卷就是.zip文件（当存在.z*文件时）
            zip_volumes = safe_glob(os.path.join(dir_path, base_filename + '.z*'))
            if zip_volumes:
                return True
        
        # === EXE SFX-RAR 分卷主卷 ===
        if file_ext == 'exe':
            if not self.sfx_detector.is_sfx(file_path):
                return False
            
            # 获取详细的SFX检测结果
            sfx_result = self.sfx_detector.is_sfx(file_path, detailed=True)
            signature_info = sfx_result.get('signature', {})
            rar_marker = sfx_result.get('rar_marker', False)
            
            # 判断是RAR SFX还是7z SFX
            is_rar_sfx = False
            if signature_info.get('found', False) and signature_info.get('format') == 'RAR':
                is_rar_sfx = True
            elif rar_marker:
                is_rar_sfx = True
            
            if is_rar_sfx:
                # SFX-RAR分卷主卷
                part_match = re.search(r'\.part(\d+)$', base_filename_lower)
                if part_match:
                    part_num = part_match.group(1)
                    # 检查是否为第一分卷
                    if part_num in ['1', '01', '001', '0001', '00001']:
                        # 检查是否存在对应的.rar分卷文件
                        base_without_part = base_filename[:part_match.start()]
                        rar_volumes = safe_glob(os.path.join(dir_path, base_without_part + '.part*.rar'))
                        if rar_volumes:
                            return True
            else:
                # SFX-7z分卷主卷
                # 检查是否存在对应的.7z.*分卷文件
                seven_volumes = safe_glob(os.path.join(dir_path, base_filename + '.7z.*'))
                if seven_volumes:
                    return True
        
        return False

    def is_secondary_volume(self, file_path):
        """
        判断文件是否为从卷
        
        Args:
            file_path: 文件路径
            
        Returns:
            bool: True if secondary volume, False otherwise
        """
        if not safe_isfile(file_path, VERBOSE):
            return False
            
        filename = os.path.basename(file_path)
        filename_lower = filename.lower()
        dir_path = os.path.dirname(file_path)
        
        if VERBOSE:
            print(f"  DEBUG: 判断是否为从卷: {file_path}")
        
        # 提取文件扩展名
        if '.' not in filename_lower:
            return False
            
        file_ext = filename_lower.split('.')[-1]
        base_filename = '.'.join(filename.split('.')[:-1])
        base_filename_lower = base_filename.lower()
        
        # === 7z 分卷从卷 ===
        if file_ext.isdigit() and filename_lower.endswith('.7z.' + file_ext):
            # 检查扩展名是否不为第一卷标识
            if file_ext not in ['001', '0001', '00001']:
                # 确保不存在对应的.exe文件
                base_without_7z = '.'.join(filename.split('.')[:-2])
                potential_exe = os.path.join(dir_path, base_without_7z + '.exe')
                if not safe_exists(potential_exe, VERBOSE):
                    return True
                else:
                    # 如果存在exe文件，检查是否为SFX-7z分卷的从卷
                    if safe_isfile(potential_exe, VERBOSE) and self.sfx_detector.is_sfx(potential_exe):
                        sfx_result = self.sfx_detector.is_sfx(potential_exe, detailed=True)
                        signature_info = sfx_result.get('signature', {})
                        rar_marker = sfx_result.get('rar_marker', False)
                        
                        # 确认是7z SFX（非RAR SFX）
                        is_rar_sfx = False
                        if signature_info.get('found', False) and signature_info.get('format') == 'RAR':
                            is_rar_sfx = True
                        elif rar_marker:
                            is_rar_sfx = True
                        
                        if not is_rar_sfx:
                            return True
        
        # === RAR5 分卷从卷 ===
        if file_ext == 'rar':
            part_match = re.search(r'\.part(\d+)$', base_filename_lower)
            if part_match:
                part_num = part_match.group(1)
                # 检查是否不为第一分卷
                if part_num not in ['1', '01', '001', '0001', '00001']:
                    # 确保不存在对应的.exe文件或者存在但不是SFX-RAR分卷
                    base_without_part = base_filename[:part_match.start()]
                    potential_exe_pattern = base_without_part + '.part*.exe'
                    exe_files = safe_glob(os.path.join(dir_path, potential_exe_pattern))
                    if not exe_files:
                        return True
                    else:
                        # 如果存在exe文件，这是SFX-RAR分卷的.rar从卷
                        return True
        
        # === RAR4 分卷从卷 ===
        if re.match(r'^r\d+$', file_ext):
            # .r00, .r01, etc. 文件
            rar_base = base_filename + '.rar'
            potential_main_rar = os.path.join(dir_path, rar_base)
            if safe_exists(potential_main_rar, VERBOSE):
                return True
        
        # === ZIP 分卷从卷 ===
        if re.match(r'^z\d+$', file_ext):
            # .z01, .z02, etc. 文件
            zip_base = base_filename + '.zip'
            potential_main_zip = os.path.join(dir_path, zip_base)
            if safe_exists(potential_main_zip, VERBOSE):
                return True
        
        return False

    def get_all_volumes(self, file_path):
        """
        获取压缩包的所有分卷文件
        
        Args:
            file_path: 主卷文件路径
            
        Returns:
            list: 所有分卷文件路径列表（包括主卷）
        """
        if not safe_isfile(file_path, VERBOSE):
            return [file_path]
            
        filename = os.path.basename(file_path)
        filename_lower = filename.lower()
        dir_path = os.path.dirname(file_path)
        
        if VERBOSE:
            print(f"  DEBUG: 获取所有分卷: {file_path}")
        
        # 提取文件扩展名
        if '.' not in filename_lower:
            return [file_path]
            
        file_ext = filename_lower.split('.')[-1]
        base_filename = '.'.join(filename.split('.')[:-1])
        
        volumes = []
        
        # === 7z 分卷 ===
        if file_ext.isdigit() and filename_lower.endswith('.7z.' + file_ext):
            base_without_7z = '.'.join(filename.split('.')[:-2])
            potential_exe = os.path.join(dir_path, base_without_7z + '.exe')
            
            if not safe_exists(potential_exe, VERBOSE):
                # 纯7z分卷
                pattern = base_without_7z + '.7z.*'
                volume_files = safe_glob(os.path.join(dir_path, pattern))
                volumes.extend([f for f in volume_files if re.match(r'.*\.7z\.\d+$', f.lower())])
            else:
                # SFX-7z分卷（情况2：从.7z.*文件开始查找）
                if safe_isfile(potential_exe, VERBOSE) and self.sfx_detector.is_sfx(potential_exe):
                    volumes.append(potential_exe)  # 添加.exe主文件
                    pattern = base_without_7z + '.7z.*'
                    volume_files = safe_glob(os.path.join(dir_path, pattern))
                    volumes.extend([f for f in volume_files if re.match(r'.*\.7z\.\d+$', f.lower())])
        
        # === RAR5 分卷 ===
        elif file_ext == 'rar':
            part_match = re.search(r'\.part\d+$', base_filename.lower())
            if part_match:
                base_without_part = base_filename[:part_match.start()]
                potential_exe_pattern = base_without_part + '.part*.exe'
                exe_files = safe_glob(os.path.join(dir_path, potential_exe_pattern))
                
                if not exe_files:
                    # 纯RAR5分卷
                    pattern = base_without_part + '.part*.rar'
                    volumes.extend(safe_glob(os.path.join(dir_path, pattern)))
                else:
                    # SFX-RAR分卷（情况2：从.rar文件开始查找）
                    volumes.extend(exe_files)  # 添加所有.exe文件
                    pattern = base_without_part + '.part*.rar'
                    volumes.extend(safe_glob(os.path.join(dir_path, pattern)))
            else:
                # RAR4分卷
                rar4_volumes = safe_glob(os.path.join(dir_path, base_filename + '.r*'))
                if rar4_volumes:
                    volumes.append(file_path)  # 主.rar文件
                    volumes.extend(rar4_volumes)
        
        # === ZIP 分卷 ===
        elif file_ext == 'zip':
            zip_volumes = safe_glob(os.path.join(dir_path, base_filename + '.z*'))
            if zip_volumes:
                volumes.append(file_path)  # 主.zip文件
                volumes.extend(zip_volumes)
        
        # === EXE SFX 分卷 ===
        elif file_ext == 'exe':
            if self.sfx_detector.is_sfx(file_path):
                sfx_result = self.sfx_detector.is_sfx(file_path, detailed=True)
                signature_info = sfx_result.get('signature', {})
                rar_marker = sfx_result.get('rar_marker', False)
                
                # 判断是RAR SFX还是7z SFX
                is_rar_sfx = False
                if signature_info.get('found', False) and signature_info.get('format') == 'RAR':
                    is_rar_sfx = True
                elif rar_marker:
                    is_rar_sfx = True
                
                if is_rar_sfx:
                    # SFX-RAR分卷（情况1：从.exe文件开始查找）
                    part_match = re.search(r'\.part\d+$', base_filename.lower())
                    if part_match:
                        base_without_part = base_filename[:part_match.start()]
                        # 查找所有相关的.exe和.rar文件
                        exe_pattern = base_without_part + '.part*.exe'
                        rar_pattern = base_without_part + '.part*.rar'
                        volumes.extend(safe_glob(os.path.join(dir_path, exe_pattern)))
                        volumes.extend(safe_glob(os.path.join(dir_path, rar_pattern)))
                else:
                    # SFX-7z分卷（情况1：从.exe文件开始查找）
                    seven_volumes = safe_glob(os.path.join(dir_path, base_filename + '.7z.*'))
                    if seven_volumes:
                        volumes.append(file_path)  # 主.exe文件
                        volumes.extend([f for f in seven_volumes if re.match(r'.*\.7z\.\d+$', f.lower())])
        
        # 如果没有找到分卷，返回原文件
        if not volumes:
            volumes = [file_path]
        
        # 去重并排序
        volumes = list(set(volumes))
        volumes.sort()
        
        if VERBOSE:
            print(f"  DEBUG: 找到 {len(volumes)} 个分卷文件")
            for vol in volumes:
                print(f"    {vol}")
        
        return volumes

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


# ==================== 新增编码检测函数 ====================

def guess_zip_encoding(zip_path):
    """
    Detect the legacy code‑page used by a *non‑UTF‑8* ZIP file.

    改进要点
    --------
    1. 统一通过 `safe_path_for_operation()` 处理超长 / Unicode 路径。  
    2. **保证** 参与 `b'\\n'.join()` 的全部元素都是 `bytes`，  
       - `ZipInfo.orig_filename` 可能是 *str*，需转 CP437。  
       - 若属性不存在则退回 `info.filename`（同样转 bytes）。  
    3. 当所有条目均已设置 UTF‑8 标志时直接返回 `success=False`，避免误报。  
    """
    import zipfile, chardet

    result = {'encoding': None,
              'language': None,
              'confidence': 0.0,
              'success':   False}

    if VERBOSE:
        print(f"  DEBUG: 开始检测ZIP编码: {zip_path}")

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

        sample = b'\n'.join(filename_bytes)
        det    = chardet.detect(sample)

        if det.get('encoding'):
            result.update({'encoding':  det['encoding'],
                           'language':  det.get('language'),
                           'confidence':det.get('confidence', 0.0),
                           'success':   True})
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
    
    # chardet稳定输出的完整映射表
    encoding_map = {
        # ASCII和基础编码
        'ascii': '1252',  # ASCII可以安全地使用Windows-1252
        
        # Unicode编码系列
        'utf-8': 'UTF-8',
        'utf-16': 'UTF-16',
        'utf-16-be': 'UTF-16BE',
        'utf-16-le': 'UTF-16LE', 
        'utf-32': 'UTF-32',
        'utf-32-be': 'UTF-32BE',
        'utf-32-le': 'UTF-32LE',
        
        # 中文编码 (chardet返回的确切名称)
        'big5': '950',
        'gb2312': '936',
        'gb18030': '936',
        'euc-tw': '950',
        'hz-gb-2312': '936',
        'iso-2022-cn': '936',
        
        # 日文编码
        'shift_jis': '932',
        'euc-jp': '20932',
        'iso-2022-jp': '50222',
        
        # 韩文编码
        'euc-kr': '949',
        'iso-2022-kr': '50225',
        
        # 俄语/西里尔编码
        'koi8-r': '20866',
        'maccyrillic': '10007',
        'ibm855': '855',
        'ibm866': '866',
        'iso-8859-5': '28595',
        'windows-1251': '1251',
        
        # 西欧语言编码
        'iso-8859-1': '28591',
        'windows-1252': '1252',
        
        # 中欧语言编码（匈牙利语等）
        'iso-8859-2': '28592', 
        'windows-1250': '1250',
        
        # 希腊语编码
        'iso-8859-7': '28597',
        'windows-1253': '1253',
        
        # 希伯来语编码
        'iso-8859-8': '28598',
        'windows-1255': '1255',
        
        # 泰语编码
        'tis-620': '874',
    }
    
    # 标准化输入编码名称（只处理大小写）
    encoding_lower = encoding.lower().strip()
    
    # 精确匹配
    if encoding_lower in encoding_map:
        code_page = encoding_map[encoding_lower]
        if VERBOSE:
            print(f"  DEBUG: 编码映射 {encoding} -> {code_page}")
        return code_page
    
    # 处理chardet可能的命名变体（只处理连字符和下划线的差异）
    # 因为chardet在不同版本间可能有细微的命名差异
    normalized_variants = [
        encoding_lower.replace('-', '_'),  # ISO-8859-1 -> ISO_8859_1
        encoding_lower.replace('_', '-'),  # SHIFT_JIS -> SHIFT-JIS
        encoding_lower.replace('-', ''),   # ISO-8859-1 -> ISO88591
        encoding_lower.replace('_', ''),   # SHIFT_JIS -> SHIFTJIS
    ]
    
    for variant in normalized_variants:
        if variant in encoding_map:
            code_page = encoding_map[variant]
            if VERBOSE:
                print(f"  DEBUG: 编码变体映射 {encoding} -> {code_page}")
            return code_page
    
    # 如果完全没有匹配，记录并返回None
    if VERBOSE:
        print(f"  DEBUG: 未知编码，无法映射到7z参数: {encoding}")
        print(f"  DEBUG: 建议检查chardet版本和文档，确认 '{encoding}' 是否为有效输出")
    
    return None
    

# === 传统zip编码检测实现 ===
def is_traditional_zip(archive_path):
    """
    Return True **iff** at least one entry uses legacy CP437‑encoded name
    and **no** UTF‑8 flag/extra fields are present.
    """
    try:
        if not archive_path.lower().endswith('.zip'):
            return False
        with safe_open(archive_path, 'rb') as f:
            while True:
                sig = f.read(4)
                if sig != b'PK\x03\x04':          # Local‑file‑header 结束
                    break
                hdr = f.read(26)                  # 剩余固定区
                if len(hdr) < 26:
                    return False
                gpbf           = int.from_bytes(hdr[2:4], 'little')
                name_len       = int.from_bytes(hdr[22:24], 'little')
                extra_len      = int.from_bytes(hdr[24:26], 'little')
                is_utf8        = gpbf & (1 << 11)

                if is_utf8:                       # 出现 UTF‑8 标志 ➜ 不是传统 ZIP
                    return False
                if name_len == 0:
                    return False                  # 不合理

                f.seek(name_len, 1)               # skip name
                f.seek(extra_len, 1)              # skip extra

                has_dd = gpbf & (1 << 3)
                if not has_dd:
                    comp_size = int.from_bytes(hdr[10:14], 'little')
                    f.seek(comp_size, 1)
                else:
                    # 遇到 Data‑Descriptor 直接判定：已确认存在非 UTF‑8 条目
                    return True
            # 如果能循环到这里，说明出现过 ≥1 项非 UTF‑8
            return True
    except Exception as exc:
        if VERBOSE:
            print(f"  DEBUG: 传统ZIP检测异常: {exc}")
        return False



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
def is_zip_multi_volume(zip_path):
    """
    判断ZIP文件是否为分卷压缩的一部分（使用新的分类逻辑）
    
    Args:
        zip_path: ZIP文件路径

    Returns:
        bool: 如果是分卷ZIP返回True，否则返回False
    """
    if not zip_path.lower().endswith('.zip'):
        return False

    base_dir = os.path.dirname(zip_path)
    base_name = os.path.splitext(os.path.basename(zip_path))[0]

    if VERBOSE:
        print(f"  DEBUG: 检查ZIP是否为分卷: {zip_path}")

    # 查找.z01, .z02等文件
    try:
        for filename in os.listdir(base_dir):
            filename_lower = filename.lower()
            expected_pattern = f"{base_name.lower()}.z"
            if filename_lower.startswith(expected_pattern) and re.search(r'\.z\d+$', filename_lower):
                if VERBOSE:
                    print(f"  DEBUG: 发现ZIP分卷文件: {filename}")
                return True
    except Exception as e:
        if VERBOSE:
            print(f"  DEBUG: 检查ZIP分卷时出错: {e}")

    if VERBOSE:
        print(f"  DEBUG: ZIP文件为单个文件")
    return False



def is_exe_multi_volume(exe_path, processor=None):
    """
    判断EXE文件是否为分卷SFX的一部分（优化版本）

    Args:
        exe_path: EXE文件路径
        processor: ArchiveProcessor实例（推荐传入以避免重复创建）

    Returns:
        bool: 如果是分卷EXE返回True，否则返回False
    """
    if not exe_path.lower().endswith('.exe'):
        return False

    # 如果提供了processor，直接使用（避免重复创建）
    if processor:
        archive_type = processor.is_archive_single_or_volume(exe_path)
        return archive_type == 'volume'
    
    # 兼容性：如果没有提供processor，创建临时的
    if VERBOSE:
        print(f"  DEBUG: 创建临时processor检测EXE分卷")
    
    sfx_detector = SFXDetector(verbose=VERBOSE)
    class TempArgs:
        def __init__(self):
            self.verbose = VERBOSE
    
    temp_args = TempArgs()
    temp_processor = ArchiveProcessor(temp_args)
    temp_processor.sfx_detector = sfx_detector
    
    archive_type = temp_processor.is_archive_single_or_volume(exe_path)
    return archive_type == 'volume'
    
    
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
    """
    检查是否为多卷文件（优化版本，使用新的分类逻辑）
    
    Args:
        archive_path: 归档文件路径
        processor: ArchiveProcessor实例（推荐传入）
        
    Returns:
        bool: True if multi-volume, False otherwise
    """
    if processor:
        archive_type = processor.is_archive_single_or_volume(archive_path)
        return archive_type == 'volume'
    
    # 兼容性：创建临时processor
    temp_sfx_detector = SFXDetector(verbose=VERBOSE)
    class TempArgs:
        def __init__(self):
            self.verbose = VERBOSE
    
    temp_args = TempArgs()
    temp_processor = ArchiveProcessor(temp_args)
    temp_processor.sfx_detector = temp_sfx_detector
    
    archive_type = temp_processor.is_archive_single_or_volume(archive_path)
    return archive_type == 'volume'

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

# === 修复windows长路径 ===
def _normalize_windows_long_path(path: str) -> str:
    """
    Convert to Win32 long‑path form (\\?\\ or \\?\\UNC\\).
    Handles existing long paths and avoids duplicate back‑slashes.
    """
    if not is_windows():
        return path
    abs_path = os.path.abspath(os.path.expandvars(path))
    if abs_path.startswith(('\\\\?\\', '\\\\.\\')):
        return abs_path                       # 已是长路径
    if abs_path.startswith('\\\\'):           # UNC
        # 注意：lstrip 只能去掉 *一个* 前导反斜杠
        return '\\\\?\\UNC\\' + abs_path[2:]  # 去掉最前面的两个 '\'
    return '\\\\?\\' + abs_path



def safe_path_for_operation(path: str, debug: bool = False) -> str:
    """
    统一的“可安全参与文件系统/子进程操作”的路径转换：
    1. 若非 Windows：直接返回原始路径
    2. Windows：
       2.1 优先尝试扩展长度路径 `_normalize_windows_long_path`
       2.2 若生成路径仍超长或出现异常，再回退到 8.3 短路径 `get_short_path_name`
    """
    if not is_windows() or not path:
        return path

    try:
        long_path = _normalize_windows_long_path(path)
        # Win32 API 对扩展长度路径的上限是 32 k，足够使用
        return long_path
    except Exception as e:
        # 极端情况（如路径含保留字符）再尝试短路径
        if debug:
            print(f"  DEBUG: long‑path normalize failed for {path}: {e}; fallback to short path")
        return get_short_path_name(path) or path

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

def safe_glob(pattern: str, debug: bool = False):
    """
    glob.glob 的安全包装，使模式可以含有超长路径前缀。
    注意：glob / fnmatch 自身在 \\?\\ 前缀下仍工作良好。
    """
    safe_pattern = safe_path_for_operation(pattern, debug)
    return glob.glob(safe_pattern)

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
    """安全的递归目录删除"""
    try:
        safe_path = safe_path_for_operation(path, debug)
        shutil.rmtree(safe_path)
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
    """信号处理器，用于在程序被中断时清理锁文件"""
    print(f"\n  收到信号 {signum}，正在清理...")
    release_lock()  # 只有锁的拥有者才会释放锁
    sys.exit(1)


# ==================== 结束锁机制 ====================

def setup_windows_utf8():
    """Setup UTF-8 encoding for Windows console operations"""
    if sys.platform.startswith('win'):
        try:
            # Set environment variables for UTF-8 encoding
            os.environ['PYTHONIOENCODING'] = 'utf-8'
            os.environ['LC_ALL'] = 'C.UTF-8'
            os.environ['LANG'] = 'C.UTF-8'

            # Try to set console code page to UTF-8 (65001)
            try:
                subprocess.run(['chcp', '65001'],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL,
                               check=False)
            except:
                pass

            if VERBOSE:
                print("  DEBUG: Windows UTF-8 environment setup attempted")
        except Exception as e:
            if VERBOSE:
                print(f"  DEBUG: Could not setup UTF-8 environment: {e}")


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

            # 添加密码参数（如果有）
            if password:
                cmd.extend([f'-p{password}'])

            # 添加其他RAR参数
            cmd.extend(['-y'])  # 自动回答yes

            if VERBOSE:
                print(f"  DEBUG: RAR命令: {' '.join(cmd)}")
                print(f"  DEBUG: 原始路径: {archive_path}")
                print(f"  DEBUG: 安全路径: {safe_archive_path}")
            cmd = _patch_cmd_paths(cmd)
            result = safe_subprocess_run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        else:
            # 使用7z命令解压
            if VERBOSE:
                print(f"  DEBUG: 使用7z命令解压")

            # 7z命令也使用安全路径
            safe_archive_path = safe_path_for_operation(archive_path, VERBOSE)
            safe_tmp_dir = safe_path_for_operation(tmp_dir, VERBOSE)

            cmd = ['7z', 'x', safe_archive_path, f'-o{safe_tmp_dir}', f'-p{password}', '-y']

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
            cmd = _patch_cmd_paths(cmd)
            result = safe_subprocess_run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        success = result.returncode == 0

        if VERBOSE:
            extractor = 'RAR' if use_rar else '7z'
            print(f"  DEBUG: {extractor}解压结果: {'成功' if success else '失败'}")
            if not success and result.stderr:
                print(f"  DEBUG: 解压错误: {result.stderr[:300]}")

        return success

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
                src_item = os.path.join(tmp_dir, item)
                dest_item = os.path.join(archive_folder, item)
                safe_move(src_item, dest_item, VERBOSE)
        except Exception as e:
            if VERBOSE:
                print(f"  DEBUG: 移动内容失败: {e}")

        # Move archive folder to final destination
        final_archive_path = os.path.join(output_dir, archive_name)
        final_archive_path = ensure_unique_name(final_archive_path, unique_suffix)
        safe_move(archive_folder, final_archive_path, VERBOSE)

        print(f"  Extracted to: {final_archive_path}")

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

        # 5. 创建最终输出目录（使用archive_name/{deepest_folder_name}结构）
        archive_container_dir = os.path.join(output_dir, archive_name)
        archive_container_dir = ensure_unique_name(archive_container_dir, unique_suffix)
        safe_makedirs(archive_container_dir, debug=VERBOSE)
        
        final_archive_dir = os.path.join(archive_container_dir, deepest_folder_name)
        final_archive_dir = ensure_unique_name(final_archive_dir, unique_suffix)
        safe_makedirs(final_archive_dir, debug=VERBOSE)

        if VERBOSE:
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
    “only-file-content-direct” 策略：
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
        help='Decompress policy: separate/direct/only-file-content/file-content-with-folder/file-content-with-folder-separate/only-file-content-direct/N-collect (default: 2-collect)'
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
            
            # 检查依赖库是否可用（仅对decode-auto策略）
            if policy == 'decode-auto':
                try:
                    import zipfile
                    import chardet
                except ImportError as e:
                    print(f"Error: Required library not available for --traditional-zip-policy decode-auto: {e}")
                    print("Please install: pip install chardet")
                    return 1

        # Validate decompress policy
        if args.decompress_policy not in ['separate', 'direct', 'only-file-content', 'file-content-with-folder', 'file-content-with-folder-separate', 'only-file-content-direct']:
            if not re.match(r'^\d+-collect$', args.decompress_policy):
                print(f"Error: Invalid decompress policy: {args.decompress_policy}")
                return 1
            else:
                # Validate N-collect threshold
                threshold = int(args.decompress_policy.split('-')[0])
                if threshold < 0:
                    print(f"Error: N-collect threshold must be >= 0")
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
        archives = processor.find_archives(args.path)

        if not archives:
            print("No archives found to process.")
            return 0

        print(f"Found {len(archives)} archive(s) to process.")

        # Process archives
        if args.threads == 1:
            # Single-threaded processing
            for archive in archives:
                processor.process_archive(archive)
        else:
            # Multi-threaded processing
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = {executor.submit(processor.process_archive, archive): archive
                           for archive in archives}

                for future in as_completed(futures):
                    archive = futures[future]
                    try:
                        future.result()
                    except KeyboardInterrupt:
                        # 用户中断，立即重新抛出异常以终止程序
                        print(f"\nKeyboard interrupt detected during processing {archive}")
                        # 取消所有未完成的任务
                        for pending_future in futures:
                            if not pending_future.done():
                                pending_future.cancel()
                        raise
                    except SystemExit:
                        # 系统退出信号，立即重新抛出
                        print(f"\nSystem exit signal detected during processing {archive}")
                        # 取消所有未完成的任务
                        for pending_future in futures:
                            if not pending_future.done():
                                pending_future.cancel()
                        raise
                    except Exception as e:
                        # 普通异常，记录错误并继续处理下一个文件
                        print(f"Error processing {archive}: {e}")
                        processor.failed_archives.append(archive)

        # Print summary
        print("\n" + "=" * 50)
        print("PROCESSING SUMMARY")
        print("=" * 50)
        print(f"Total archives found: {len(archives)}")
        print(f"Successfully processed: {len(processor.successful_archives)}")
        print(f"Failed to process: {len(processor.failed_archives)}")
        print(f"Skipped: {len(processor.skipped_archives)}")

        if processor.failed_archives:
            print("\nFailed archives:")
            for archive in processor.failed_archives:
                print(f"  - {archive}")

        if processor.skipped_archives:
            print("\nSkipped archives:")
            for archive in processor.skipped_archives:
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
