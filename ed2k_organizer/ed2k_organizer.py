#!/usr/bin/env python3

import os
import sys
import argparse
import re
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple, Set


def parse_ed2k_line(line: str) -> Tuple[str, int, str]:
    """解析ed2k链接，返回(filename, filesize, original_line)"""
    line = line.strip()
    if not line.startswith('ed2k://|file|'):
        return None
    
    # ed2k://|file|filename|filesize|hash|/
    parts = line.split('|')
    if len(parts) < 5:
        return None
    
    filename = parts[2]
    try:
        filesize = int(parts[3])
    except ValueError:
        return None
    
    return filename, filesize, line


def scan_directory(root_path: Path) -> Dict[Tuple[str, int], List[str]]:
    """扫描目录，返回(filename, filesize) -> [relative_paths]的映射"""
    file_map = defaultdict(list)
    
    for file_path in root_path.rglob('*'):
        if file_path.is_file():
            try:
                filesize = file_path.stat().st_size
                filename = file_path.name
                relative_path = str(file_path.relative_to(root_path))
                
                key = (filename, filesize)
                file_map[key].append(relative_path)
            except (OSError, ValueError):
                continue
    
    return file_map


def process_matches(ed2k_entries: List[Tuple[str, int, str]], 
                   file_map: Dict[Tuple[str, int], List[str]]) -> Tuple[Dict[str, List[str]], List[str], List[str]]:
    """处理匹配，返回(valid_matches, multi_match_warnings, not_found_warnings)"""
    valid_matches = defaultdict(list)  # relative_dir -> [ed2k_lines]
    multi_match_warnings = []
    not_found_warnings = []
    
    # 检测文件到ed2k条目的映射，用于发现多对1情况
    file_to_ed2k = defaultdict(list)
    for filename, filesize, original_line in ed2k_entries:
        key = (filename, filesize)
        if key in file_map:
            for rel_path in file_map[key]:
                file_to_ed2k[rel_path].append(original_line)
    
    # 检查多对1映射
    multi_target_files = set()
    for rel_path, ed2k_lines in file_to_ed2k.items():
        if len(ed2k_lines) > 1:
            multi_target_files.add(rel_path)
            multi_match_warnings.append(f"多个ed2k条目匹配到同一文件: {rel_path}")
    
    # 处理每个ed2k条目
    for filename, filesize, original_line in ed2k_entries:
        key = (filename, filesize)
        
        if key not in file_map:
            not_found_warnings.append(f"未找到文件: {filename} ({filesize} bytes)")
            continue
        
        matched_paths = file_map[key]
        
        # 检查1对多映射
        if len(matched_paths) > 1:
            multi_match_warnings.append(f"ed2k条目匹配到多个文件: {filename} -> {matched_paths}")
            continue
        
        rel_path = matched_paths[0]
        
        # 检查多对1映射
        if rel_path in multi_target_files:
            continue
        
        # 获取目录路径
        rel_dir = str(Path(rel_path).parent)
        if rel_dir == '.':
            rel_dir = ''
        
        valid_matches[rel_dir].append(original_line)
    
    return valid_matches, multi_match_warnings, not_found_warnings


def create_output_structure(valid_matches: Dict[str, List[str]], output_root: Path):
    """创建输出目录结构并写入ed2k.log文件"""
    for rel_dir, ed2k_lines in valid_matches.items():
        if rel_dir:
            output_dir = output_root / rel_dir
        else:
            output_dir = output_root
        
        # 创建目录
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # 写入ed2k.log文件
        log_file = output_dir / 'ed2k.log'
        with log_file.open('a', encoding='utf-8') as f:
            for line in ed2k_lines:
                f.write(line + '\n')


def main():
    parser = argparse.ArgumentParser(description='Ed2k文件组织工具')
    parser.add_argument('search_path', help='要搜索的文件夹路径')
    parser.add_argument('-l', '--log', required=True, help='ed2k.log文件路径')
    parser.add_argument('-o', '--out', required=True, help='输出日志文件夹路径')
    
    args = parser.parse_args()
    
    # 转换为Path对象
    search_path = Path(args.search_path)
    log_path = Path(args.log)
    output_path = Path(args.out)
    
    # 验证输入路径
    if not search_path.exists():
        print(f"错误: 搜索路径不存在: {search_path}", file=sys.stderr)
        sys.exit(1)
    
    if not log_path.exists():
        print(f"错误: ed2k.log文件不存在: {log_path}", file=sys.stderr)
        sys.exit(1)
    
    # 读取并解析ed2k.log文件
    print("正在解析ed2k.log文件...")
    ed2k_entries = []
    with log_path.open('r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            result = parse_ed2k_line(line)
            if result:
                ed2k_entries.append(result)
            elif line.strip():  # 非空行但解析失败
                print(f"警告: 第{line_num}行格式无效: {line.strip()}")
    
    print(f"解析到 {len(ed2k_entries)} 个有效的ed2k条目")
    
    # 扫描目录
    print(f"正在扫描目录: {search_path}")
    file_map = scan_directory(search_path)
    total_files = sum(len(paths) for paths in file_map.values())
    print(f"扫描到 {total_files} 个文件")
    
    # 处理匹配
    print("正在匹配文件...")
    valid_matches, multi_match_warnings, not_found_warnings = process_matches(ed2k_entries, file_map)
    
    # 创建输出结构
    if valid_matches:
        print(f"正在创建输出结构: {output_path}")
        create_output_structure(valid_matches, output_path)
        
        total_matched = sum(len(lines) for lines in valid_matches.values())
        print(f"成功处理 {total_matched} 个匹配项")
        print(f"创建了 {len(valid_matches)} 个ed2k.log文件")
    else:
        print("没有找到有效的匹配项")
    
    # 打印警告信息
    if multi_match_warnings:
        print("\n=== 多重映射警告 ===")
        for warning in multi_match_warnings:
            print(f"警告: {warning}")
    
    if not_found_warnings:
        print(f"\n=== 未找到文件警告 ({len(not_found_warnings)}个) ===")
        for warning in not_found_warnings[:10]:  # 只显示前10个
            print(f"警告: {warning}")
        if len(not_found_warnings) > 10:
            print(f"... 还有 {len(not_found_warnings) - 10} 个未找到的文件")
    
    print("\n处理完成!")


if __name__ == '__main__':
    main()