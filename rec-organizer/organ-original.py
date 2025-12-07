#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
文件整理脚本
自动提取文件名中的编号（d_/D_/RJ/BJ/VJ/RE + 数字）并创建对应文件夹进行整理
支持在 Linux/Windows 等 CLI 环境直接运行
"""

import argparse
import re
import shutil
from pathlib import Path

def extract_file_code(filename):
    """
    从文件名中提取编号
    支持的格式：d_/D_/RJ/BJ/VJ/RE + 数字
    """
    # 正则表达式匹配模式
    patterns = [
        r'([dD]_\d+)',           # d_数字 或 D_数字 (保持原始大小写)
        r'(RJ\d+)',              # RJ数字
        r'(BJ\d+)',              # BJ数字  
        r'(VJ\d+)',              # VJ数字
        r'(RE\d+)',              # RE数字
    ]
    
    for pattern in patterns:
        match = re.search(pattern, filename)  # 移除 re.IGNORECASE，保持原始大小写
        if match:
            return match.group(1)  # 保持原始大小写，不转换
    
    return None

def create_folder_if_not_exists(folder_path):
    """
    如果文件夹不存在则创建
    """
    folder_path = Path(folder_path)
    if not folder_path.exists():
        folder_path.mkdir(parents=True, exist_ok=True)
        print(f"创建文件夹: {folder_path}")

def move_file_safely(src_path, dst_path):
    """
    安全移动文件，如果目标文件已存在则跳过
    """
    src_path = Path(src_path)
    dst_path = Path(dst_path)

    if dst_path.exists():
        print(f"目标文件已存在，跳过: {dst_path.name}")
        return False
    
    try:
        shutil.move(str(src_path), str(dst_path))
        print(f"移动文件: {src_path.name} -> {dst_path.parent}")
        return True
    except Exception as e:
        print(f"移动文件失败: {src_path.name} - {str(e)}")
        return False

def organize_files(base_dir):
    """
    主函数：整理当前目录下的文件
    """
    current_dir = Path(base_dir).resolve()
    if not current_dir.exists():
        raise FileNotFoundError(f"指定目录不存在: {current_dir}")
    if not current_dir.is_dir():
        raise NotADirectoryError(f"指定路径不是目录: {current_dir}")

    print(f"当前工作目录: {current_dir}")
    print("开始整理文件...")
    print("-" * 50)
    
    # 统计信息
    total_files = 0
    organized_files = 0
    skipped_files = 0
    
    # 遍历当前目录下的所有文件
    for item in current_dir.iterdir():
        # 跳过文件夹和脚本自身
        if item.is_dir() or item.suffix == '.py':
            continue
            
        total_files += 1
        
        # 提取文件编号
        file_code = extract_file_code(item.name)
        
        if file_code:
            # 创建对应的文件夹
            folder_name = file_code
            folder_path = current_dir / folder_name
            create_folder_if_not_exists(folder_path)
            
            # 移动文件到对应文件夹
            dst_path = folder_path / item.name
            if move_file_safely(item, dst_path):
                organized_files += 1
            else:
                skipped_files += 1
        else:
            print(f"未识别的文件格式，跳过: {item.name}")
            skipped_files += 1
    
    # 输出统计结果
    print("-" * 50)
    print("整理完成！")
    print(f"总文件数: {total_files}")
    print(f"成功整理: {organized_files}")
    print(f"跳过文件: {skipped_files}")
    
    # 显示创建的文件夹
    folders = [
        d for d in current_dir.iterdir()
        if d.is_dir() and re.match(r'([dD]_\d+|RJ\d+|BJ\d+|VJ\d+|RE\d+)', d.name)
    ]
    
    if folders:
        print(f"\n创建的文件夹 ({len(folders)} 个):")
        for folder in sorted(folders, key=lambda p: p.name):
            file_count = len([f for f in folder.iterdir() if f.is_file()])
            print(f"  {folder.name} ({file_count} 个文件)")

def parse_arguments():
    parser = argparse.ArgumentParser(description="根据文件名编号自动整理文件夹")
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
    print("=" * 60)
    print("           文件自动整理工具")
    print("=" * 60)
    print("本工具将自动识别以下格式的文件编号：")
    print("- d_数字 或 D_数字 (区分大小写)")
    print("- RJ数字")  
    print("- BJ数字")
    print("- VJ数字")
    print("- RE数字")
    print()

    args = parse_arguments()
    
    try:
        organize_files(Path(args.directory))
    except KeyboardInterrupt:
        print("\n\n操作被用户中断。")
    except Exception as e:
        print(f"\n发生错误: {str(e)}")

if __name__ == "__main__":
    main()
