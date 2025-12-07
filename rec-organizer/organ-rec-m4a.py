#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
文件自动分类脚本
根据文件名第一个方括号内的名字创建文件夹并移动文件
支持在 Linux/Windows 命令行直接运行
"""

import argparse
import re
import shutil
from pathlib import Path

def extract_first_bracket_name(filename):
    """
    提取文件名中第一个方括号内的内容
    
    Args:
        filename (str): 文件名
        
    Returns:
        str: 提取的名字，如果没有找到则返回None
    """
    # 使用正则表达式匹配第一个方括号内的内容
    pattern = r'^\[([^\]]+)\]'
    match = re.match(pattern, filename)
    
    if match:
        return match.group(1)
    return None

def get_base_filename(filename):
    """
    获取文件的基本名称（去除扩展名）
    
    Args:
        filename (str): 文件名
        
    Returns:
        str: 基本文件名
    """
    return Path(filename).stem

def collect_file_info(files):
    """
    收集所有文件信息，建立基本名称到文件的映射
    
    Args:
        files (list): 文件路径列表
        
    Returns:
        dict: {base_filename: {'m4a': Path or None, 'others': [Path]}}
    """
    file_map = {}
    
    for file_path in files:
        filename = file_path.name
        # 跳过脚本文件本身
        if filename.endswith('.py'):
            continue
            
        base_name = get_base_filename(filename)
        ext = file_path.suffix.lower()
        
        if base_name not in file_map:
            file_map[base_name] = {'m4a': None, 'others': []}
        
        if ext == '.m4a':
            file_map[base_name]['m4a'] = file_path
        else:
            file_map[base_name]['others'].append(file_path)
    
    return file_map

def create_folder_if_not_exists(folder_path):
    """
    如果文件夹不存在则创建
    
    Args:
        folder_path (str): 文件夹路径
    """
    folder_path = Path(folder_path)
    if not folder_path.exists():
        folder_path.mkdir(parents=True, exist_ok=True)
        print(f"创建文件夹: {folder_path}")

def process_single_file(file_path, current_dir):
    """
    处理单个非m4a文件，移动到[xxx]/文件夹
    
    Args:
        file_path (Path): 文件路径
        current_dir (Path): 当前目录
        
    Returns:
        str: 'processed', 'skipped', 'error'
    """
    filename = file_path.name
    print(f"处理文件: {filename}")
    
    # 提取第一个方括号内的名字
    extracted_name = extract_first_bracket_name(filename)
    
    if extracted_name is None:
        print(f"  - 跳过: 无法提取名字")
        return 'skipped'
    
    # 创建目标文件夹名
    folder_name = f"[{extracted_name}]"
    folder_path = current_dir / folder_name
    
    try:
        # 创建文件夹（如果不存在）
        create_folder_if_not_exists(folder_path)
        
        # 构建源文件和目标文件路径
        source_path = file_path
        target_path = folder_path / filename
        
        # 检查目标文件是否已存在
        if target_path.exists():
            print(f"  - 跳过: 目标文件已存在")
            return 'skipped'
        
        # 移动文件
        shutil.move(str(source_path), str(target_path))
        print(f"  - 移动到: {folder_name}")
        return 'processed'
        
    except Exception as e:
        print(f"  - 错误: {str(e)}")
        return 'error'

def process_m4a_file(file_path, current_dir, has_other_files):
    """
    处理m4a文件，根据是否存在同名非m4a文件决定目标文件夹
    
    Args:
        file_path (Path): m4a文件路径
        current_dir (Path): 当前目录
        has_other_files (bool): 是否存在同名的非m4a文件
        
    Returns:
        str: 'processed', 'skipped', 'error'
    """
    filename = file_path.name
    print(f"处理文件: {filename}")
    
    # 提取第一个方括号内的名字
    extracted_name = extract_first_bracket_name(filename)
    
    if extracted_name is None:
        print(f"  - 跳过: 无法提取名字")
        return 'skipped'
    
    # 根据是否存在同名非m4a文件决定目标文件夹
    if has_other_files:
        folder_name = f"[{extracted_name}][M4A]"
        print(f"  - 检测到同名非M4A文件，移动到M4A专用文件夹")
    else:
        folder_name = f"[{extracted_name}]"
        print(f"  - 仅存在M4A文件，移动到常规文件夹")
    
    folder_path = current_dir / folder_name
    
    try:
        # 创建文件夹（如果不存在）
        create_folder_if_not_exists(folder_path)
        
        # 构建源文件和目标文件路径
        source_path = file_path
        target_path = folder_path / filename
        
        # 检查目标文件是否已存在
        if target_path.exists():
            print(f"  - 跳过: 目标文件已存在")
            return 'skipped'
        
        # 移动文件
        shutil.move(str(source_path), str(target_path))
        print(f"  - 移动到: {folder_name}")
        return 'processed'
        
    except Exception as e:
        print(f"  - 错误: {str(e)}")
        return 'error'

def organize_files(base_dir):
    """
    主函数：组织当前目录下的文件
    """
    current_dir = Path(base_dir).resolve()
    if not current_dir.exists():
        raise FileNotFoundError(f"指定目录不存在: {current_dir}")
    if not current_dir.is_dir():
        raise NotADirectoryError(f"指定路径不是目录: {current_dir}")

    print(f"当前工作目录: {current_dir}")
    print("=" * 50)
    
    # 获取当前目录下的所有文件
    files = [p for p in current_dir.iterdir() if p.is_file()]
    
    # 第一阶段：收集文件信息
    print("第一阶段：分析文件...")
    file_map = collect_file_info(files)
    
    # 统计信息
    processed_count = 0
    skipped_count = 0
    error_count = 0
    
    # 第二阶段：处理文件
    print("第二阶段：移动文件...")
    for base_name, file_info in file_map.items():
        m4a_file = file_info['m4a']
        other_files = file_info['others']
        
        # 处理非m4a文件
        for file_path in other_files:
            result = process_single_file(file_path, current_dir)
            if result == 'processed':
                processed_count += 1
            elif result == 'skipped':
                skipped_count += 1
            elif result == 'error':
                error_count += 1
        
        # 处理m4a文件
        if m4a_file:
            # 检查是否存在其他扩展名的同名文件
            has_other_files = len(other_files) > 0
            result = process_m4a_file(m4a_file, current_dir, has_other_files)
            if result == 'processed':
                processed_count += 1
            elif result == 'skipped':
                skipped_count += 1
            elif result == 'error':
                error_count += 1
    
    # 输出统计信息
    print("=" * 50)
    print("处理完成！")
    print(f"成功处理: {processed_count} 个文件")
    print(f"跳过文件: {skipped_count} 个文件")
    print(f"错误文件: {error_count} 个文件")
    
    # 显示创建的文件夹
    folders = [d for d in current_dir.iterdir() if d.is_dir() and d.name.startswith('[')]
    if folders:
        print(f"\n创建的文件夹数量: {len(folders)}")
        print("文件夹列表:")
        for folder in sorted(folders, key=lambda p: p.name):
            file_count = len([f for f in folder.iterdir() if f.is_file()])
            print(f"  - {folder.name} ({file_count} 个文件)")

def parse_arguments():
    parser = argparse.ArgumentParser(description="根据方括号中的名字整理文件和 M4A")
    parser.add_argument(
        "-d",
        "--directory",
        default=".",
        help="需要整理的目录，默认使用当前工作目录",
    )
    return parser.parse_args()

def main():
    """
    主程序入口
    """
    print("文件自动分类脚本")
    print("=" * 50)
    args = parse_arguments()
    
    try:
        organize_files(args.directory)
    except KeyboardInterrupt:
        print("\n\n程序被用户中断")
    except Exception as e:
        print(f"\n程序执行出错: {str(e)}")

if __name__ == "__main__":
    main()
