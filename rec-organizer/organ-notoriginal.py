#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
基于文件名编号和类型的整理脚本
在 Linux/Windows 命令行直接运行，默认处理当前工作目录
"""

import argparse
import re
import shutil
from collections import defaultdict
from pathlib import Path

def extract_code_and_filetype_from_filename(filename):
    """从文件名中提取编号和文件类型"""
    # 匹配第一个【】内的编号和第二个【】内的文件类型
    pattern = r'[【\[]([^】\]]+)[】\]][【\[]([^】\]]+)[】\]]'
    match = re.search(pattern, filename)
    
    if match:
        code = match.group(1)
        filetype = match.group(2)
        
        # 统一格式：d_保持小写，其他保持大写
        if code.lower().startswith('d_'):
            code = code.lower()
        else:
            code = code.upper()
            
        return code, filetype
    return None, None


def organize_files(base_dir):
    current_dir = Path(base_dir).resolve()
    if not current_dir.exists():
        raise FileNotFoundError(f"指定目录不存在: {current_dir}")
    if not current_dir.is_dir():
        raise NotADirectoryError(f"指定路径不是目录: {current_dir}")

    print(f"当前目录: {current_dir}")
    
    # 获取所有文件
    all_files = [p for p in current_dir.iterdir() if p.is_file()]
    
    # 按编号分组文件，同时收集文件类型
    code_files = defaultdict(list)
    code_filetypes = defaultdict(set)
    unmatched_files = []
    
    for file_path in all_files:
        filename = file_path.name

        # 跳过Python脚本文件
        if filename.endswith('.py'):
            continue
            
        code, filetype = extract_code_and_filetype_from_filename(filename)
        if code and filetype:
            code_files[code].append(file_path)
            code_filetypes[code].add(filetype)
        else:
            unmatched_files.append(filename)
    
    print(f"找到 {len(code_files)} 个编号，共 {sum(len(files) for files in code_files.values())} 个文件")
    if unmatched_files:
        print(f"无法匹配的文件: {len(unmatched_files)} 个")
        for f in unmatched_files[:5]:  # 只显示前5个
            print(f"  - {f}")
        if len(unmatched_files) > 5:
            print(f"  ... 还有 {len(unmatched_files) - 5} 个")
    
    # 处理每个编号的文件
    for code, file_list in code_files.items():
        print(f"\n处理编号: {code} ({len(file_list)} 个文件)")
        
        # 获取该编号对应的所有文件类型
        filetypes = sorted(list(code_filetypes[code]))
        filetypes_str = "+".join(filetypes)
        
        # 确定文件夹名
        folder_name = f"{code} {filetypes_str}"
        print(f"  文件类型: {filetypes_str} -> 文件夹名: {folder_name}")
        
        # 创建文件夹
        folder_path = current_dir / folder_name
        if not folder_path.exists():
            folder_path.mkdir(parents=True, exist_ok=True)
            print(f"  创建文件夹: {folder_name}")
        
        # 移动文件
        success_count = 0
        for file_path in file_list:
            dst_path = folder_path / file_path.name
            try:
                # 如果目标文件已存在，先删除
                if dst_path.exists():
                    dst_path.unlink()
                shutil.move(str(file_path), str(dst_path))
                success_count += 1
            except Exception as e:
                print(f"  移动文件失败: {file_path.name}, 错误: {e}")
        
        print(f"  成功移动: {success_count}/{len(file_list)} 个文件")
    
    print(f"\n文件整理完成！")
    print(f"总共创建了 {len(code_files)} 个文件夹")

def parse_arguments():
    parser = argparse.ArgumentParser(description="根据文件名中的编号和类型整理文件")
    parser.add_argument(
        "-d",
        "--directory",
        default=".",
        help="需要整理的目录，默认使用当前工作目录",
    )
    return parser.parse_args()

def main():
    args = parse_arguments()
    organize_files(args.directory)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"程序执行出错: {e}")
