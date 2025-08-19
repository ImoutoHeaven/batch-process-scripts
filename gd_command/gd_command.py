#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import subprocess
import sys
import os
import re
import time
from datetime import datetime, timezone, timedelta

# 定义单位到字节的转换字典
# 同时处理标准 (KB, MB) 和二进制 (KiB, MiB) 单位
SIZE_UNITS = {
    'b': 1,
    'kib': 1024, 'kb': 1000,
    'mib': 1024**2, 'mb': 1000**2,
    'gib': 1024**3, 'gb': 1000**3,
    'tib': 1024**4, 'tb': 1000**4,
    'pib': 1024**5, 'pb': 1000**5,
}

def parse_size(size_str: str) -> int:
    """
    将带有单位的字符串 (例如 '1.5 TiB', '750MB') 转换为字节。
    """
    size_str = size_str.strip().lower()
    # 正则表达式匹配数字和单位
    match = re.match(r'(\d+\.?\d*)\s*([a-zib]+)', size_str)
    if not match:
        raise ValueError(f"无法解析的大小字符串: '{size_str}'")

    value, unit = match.groups()
    value = float(value)
    
    # 兼容 'k', 'm', 'g', 't', 'p' 等缩写
    if unit.endswith('b'):
        unit_key = unit
    else: # 处理 'k', 'm' 等
        unit_key = unit + 'b'
        if unit_key not in SIZE_UNITS:
             unit_key = unit + 'ib' # 优先匹配 KiB, MiB

    if unit_key not in SIZE_UNITS:
        raise ValueError(f"未知的单位: '{unit}' in '{size_str}'")

    return int(value * SIZE_UNITS[unit_key])

def get_seconds_until_utc_midnight() -> int:
    """
    计算距离下一个UTC午夜0点的秒数。
    """
    now_utc = datetime.now(timezone.utc)
    # 明天的UTC日期
    tomorrow_utc = now_utc + timedelta(days=1)
    # 明天UTC午夜的时间点
    midnight_utc = tomorrow_utc.replace(hour=0, minute=0, second=0, microsecond=0)
    # 计算时间差并返回总秒数
    return int((midnight_utc - now_utc).total_seconds())

def main():
    """
    主执行函数
    """
    parser = argparse.ArgumentParser(
        description="一个rclone的wrapper脚本，用于控制每日上传量。",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '-shell', '--shell-command',
        required=True,
        help="要执行的实际shell命令，例如 'rclone sync /path/to/local remote:path -P'"
    )
    parser.add_argument(
        '--max-transfer',
        required=True,
        help="24小时（UTC日）内的最大传输量，例如 '750GiB', '1.5TB'"
    )
    args = parser.parse_args()

    # --- 平台特定设置 ---
    if sys.platform == "win32":
        # 在Windows上，尝试将控制台输出编码设置为UTF-8 (chcp 65001)
        # 这有助于在CMD和PowerShell中正确显示 Unicode 文件名
        try:
            os.system("chcp 65001 > nul")
            print("Windows detected: Set console code page to 65001 (UTF-8).")
        except Exception as e:
            print(f"Warning: Failed to set Windows console code page. Unicode filenames might not display correctly. Error: {e}")

    try:
        max_bytes_per_day = parse_size(args.max_transfer)
    except ValueError as e:
        print(f"错误: 无效的 --max-transfer 参数. {e}")
        sys.exit(1)

    print(f"命令: {args.shell_command}")
    print(f"每日最大传输量: {args.max_transfer} ({max_bytes_per_day / (1024**3):.2f} GiB)")
    print("-" * 30)

    bytes_transferred_today = 0
    today_utc = datetime.now(timezone.utc).date()

    while True:
        # --- 检查日期是否变更，如果变更则重置计数器 ---
        current_utc_date = datetime.now(timezone.utc).date()
        if current_utc_date != today_utc:
            print(f"UTC日期已变更为 {current_utc_date}. 重置每日传输量计数器。")
            bytes_transferred_today = 0
            today_utc = current_utc_date

        # --- 启动子进程 ---
        quota_remaining = max_bytes_per_day - bytes_transferred_today
        print(f"[{datetime.now()}] 启动子进程...")
        print(f"今日已用配额: {bytes_transferred_today / (1024**3):.2f} GiB. 剩余配额: {quota_remaining / (1024**3):.2f} GiB.")
        
        # 使用 shell=True 来正确处理带引号和参数的复杂命令字符串
        # 注意：在可信环境中这是安全的
        try:
            process = subprocess.Popen(
                args.shell_command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, # 将stderr重定向到stdout以统一处理
                bufsize=1, # 行缓冲
            )
        except FileNotFoundError:
            print(f"错误: 命令未找到. 请确保 '{args.shell_command.split()[0]}' 在您的系统PATH中。")
            sys.exit(1)


        limit_reached = False
        last_reported_bytes_this_run = 0

        # --- 实时读取和解析输出 ---
        # iter(process.stdout.readline, b'') 会在进程结束后自动停止循环
        for line_bytes in iter(process.stdout.readline, b''):
            # 解码时处理潜在的编码错误
            line = line_bytes.decode('utf-8', errors='replace').strip()
            print(line) # 将原始输出实时转发到控制台
            sys.stdout.flush()

            # 核心解析逻辑
            if line.startswith("Transferred:"):
                # 匹配数据传输行: Transferred: 1.195 TiB / ...
                # 修正正则表达式以正确匹配完整的单位格式
                match = re.search(r"Transferred:\s*([\d\.]+\s*(?:TiB|GiB|MiB|KiB|TB|GB|MB|KB|B))\s*/", line, re.IGNORECASE)
                if match:
                    try:
                        size_str = match.group(1)
                        current_total_bytes_this_run = parse_size(size_str)
                        
                        # 添加调试信息
                        print(f"[调试] 解析传输量: '{size_str}' -> {current_total_bytes_this_run} 字节")
                        
                        # 计算自上次报告以来新增的传输量
                        delta = current_total_bytes_this_run - last_reported_bytes_this_run
                        
                        if delta > 0:
                            bytes_transferred_today += delta
                            last_reported_bytes_this_run = current_total_bytes_this_run
                            print(f"[调试] 今日累计传输: {bytes_transferred_today / (1024**2):.2f} MiB")

                        # 检查是否达到限额
                        if bytes_transferred_today >= max_bytes_per_day:
                            print("\n" + "="*50)
                            print(f"每日传输限额已达到! ({bytes_transferred_today / (1024**3):.2f} GiB / {max_bytes_per_day / (1024**3):.2f} GiB)")
                            print("正在优雅地停止子进程...")
                            print("="*50 + "\n")
                            
                            process.terminate() # 发送SIGTERM (Linux) / CTRL_BREAK_EVENT (Windows)
                            limit_reached = True
                            break # 退出输出读取循环
                    except ValueError as e:
                        # 解析失败时立即退出
                        print(f"[错误] 无法解析传输行: '{line}'. 错误: {e}", file=sys.stderr)
                        print("解析失败，立即退出脚本。", file=sys.stderr)
                        process.terminate()
                        sys.exit(1)

        # --- 处理子进程结束后的逻辑 ---
        # 等待进程完全终止并获取返回码
        return_code = process.wait()

        if limit_reached:
            seconds_to_wait = get_seconds_until_utc_midnight()
            # 增加60秒的缓冲时间，确保配额已刷新
            wait_with_buffer = seconds_to_wait + 60 
            wait_hours = wait_with_buffer / 3600
            
            print(f"子进程已停止。脚本将休眠直到下一个UTC日 ({wait_hours:.2f} 小时)。")
            print(f"将在 UTC {datetime.now(timezone.utc) + timedelta(seconds=wait_with_buffer)} 再次启动。")
            
            try:
                time.sleep(wait_with_buffer)
                continue # 继续外层while循环，重新开始任务
            except KeyboardInterrupt:
                print("\n用户中断休眠。正在退出。")
                break
        else:
            if return_code == 0:
                print("\n" + "="*50)
                print("命令执行成功完成，所有任务已结束。")
                print("="*50)
            else:
                print("\n" + "="*50)
                print(f"命令因错误而终止，返回码: {return_code}.")
                print("Wrapper脚本将不会自动重试。")
                print("="*50)
            
            break # 退出外层while循环，脚本结束

if __name__ == "__main__":
    main()