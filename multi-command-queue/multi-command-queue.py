#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
并发执行命令脚本
2025‑07 — 在 v0.9 基础上：
  • 新增 --sequence/-s <expression> 执行次序控制
  • 兼容原有 --max-concurrent 模式，两者互斥（-s 优先）
"""
import argparse
import subprocess
import sys
import time
import threading
import queue
import os
import signal
import platform
import re
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import datetime

try:
    import psutil           # 仅用于进程检测；若缺失可继续运行
except ImportError:
    psutil = None

# ---------------------- 命令状态 & 全局变量 ----------------------
class CommandStatus:
    INQUEUE   = "INQUEUE"    # 等待执行
    RUNNING   = "RUNNING"    # 正在执行
    PAUSED    = "PAUSED"     # 被暂停
    COMPLETED = "COMPLETED"  # 成功结束
    FAILED    = "FAILED"     # 最终失败

input_queue = queue.Queue()
command_lock = threading.Lock()           # 更新 command_states 的互斥锁
stop_event = threading.Event()            # 全局停止标志
keyboard_interrupt_flag = threading.Event()
debug_mode = False

# {id: {command, status, process, retry_count, start_time, end_time, pid}}
command_states = {}

# ---------------------- 解析命令行参数 ----------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="并发执行命令并支持重试、暂停/恢复、执行次序控制")
    parser.add_argument(
        "--total-retries", type=int, default=3,
        help="失败命令的最大重试次数 (0 表示不重试)")
    parser.add_argument(
        "--max-concurrent", type=int, default=5,
        help="最大并发命令数；若使用 -s/--sequence 则忽略")
    parser.add_argument(
        "-s", "--sequence", type=str, default=None,
        help=("执行次序表达式，例如 1-2-3 或 1,2--3；"
              "'-' 顺序、',' 并行、'--' 顺序且前块失败停止"))
    parser.add_argument(
        "--status-interval", type=int, default=10,
        help="定期打印状态的间隔（秒）")
    parser.add_argument(
        "--debug", action="store_true",
        help="启用调试模式，显示更多内部信息")
    return parser.parse_args()

# ---------------------- 序列表达式解析 ----------------------
class SequenceParseError(Exception):
    """序列表达式非法"""
    pass

def parse_sequence_expression(expr: str, total_cmds: int):
    """
    把 <expr> 解析成逻辑块列表
    返回: [{"cmds": [idx...], "require_prev_success": bool}, ...]
    """
    expr = expr.replace(" ", "")  # 去空格
    if not expr:
        raise SequenceParseError("sequence 表达式为空")

    # token = 数字 | ',' | '-' | '--'
    tokens = re.findall(r'\d+|--|-|,', expr)
    if ''.join(tokens) != expr:
        raise SequenceParseError(f"表达式包含非法字符: {expr}")

    blocks = []
    current_cmds = []
    require_prev_success = False           # 下一块是否必须前块成功

    for token in tokens:
        if token.isdigit():
            n = int(token)
            if n < 1 or n > total_cmds:
                raise SequenceParseError(
                    f"序号 {n} 超出范围 (1‑{total_cmds})")
            current_cmds.append(n - 1)     # 转成 0‑based
        elif token == ',':
            if not current_cmds:
                raise SequenceParseError("',' 前缺少指令序号")
            # 同一逻辑块内并行，无需动作
        elif token in ('-', '--'):
            if not current_cmds:
                raise SequenceParseError("分隔符前缺少指令序号")
            blocks.append({
                "cmds": current_cmds,
                "require_prev_success": require_prev_success
            })
            current_cmds = []
            require_prev_success = (token == '--')
        else:                              # 不会到此
            raise SequenceParseError(f"未知 token: {token}")

    if not current_cmds:
        raise SequenceParseError("表达式结尾缺少指令序号")
    blocks.append({
        "cmds": current_cmds,
        "require_prev_success": require_prev_success
    })
    _check_duplicate_indices(blocks)
    return blocks

def _check_duplicate_indices(blocks):
    seen = set()
    for blk in blocks:
        for idx in blk["cmds"]:
            if idx in seen:
                raise SequenceParseError(
                    f"指令 {idx+1} 在表达式中出现了多次")
            seen.add(idx)

# ---------------------- 工具函数 ----------------------
def is_process_running(pid):
    """检查进程是否在运行（需要 psutil）"""
    if not psutil:
        return False
    try:
        return psutil.pid_exists(pid) and \
               psutil.Process(pid).status() != psutil.STATUS_ZOMBIE
    except Exception:
        return False

def terminate_process(process, cmd_states=None):
    """
    尝试终止 Popen 进程及其子进程（跨平台）
    """
    if not process:
        return
    pid = process.pid
    if cmd_states is not None:
        cmd_states['pid'] = pid
    if debug_mode:
        print(f"[DEBUG] 终止进程 {pid}")

    try:
        if platform.system() == "Windows":
            # Windows：先 soft，再 hard，再 taskkill
            try:
                process.terminate()
                time.sleep(0.5)
                if process.poll() is None:
                    process.kill()
                    time.sleep(0.5)
                if process.poll() is None:
                    subprocess.run(
                        f'taskkill /F /T /PID {pid}',
                        shell=True, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, timeout=5)
            except Exception as e:
                if debug_mode:
                    print(f"[DEBUG] Windows 终止进程异常: {e}")
        else:
            # Unix：杀进程组
            try:
                pgid = os.getpgid(pid)
                os.killpg(pgid, signal.SIGTERM)
                time.sleep(0.5)
                if is_process_running(pid):
                    os.killpg(pgid, signal.SIGKILL)
            except Exception as e:
                if debug_mode:
                    print(f"[DEBUG] Unix 终止进程组异常: {e}")
                try:
                    os.kill(pid, signal.SIGTERM)
                    time.sleep(0.5)
                    if is_process_running(pid):
                        os.kill(pid, signal.SIGKILL)
                except Exception:
                    pass
    except Exception:
        pass  # 尽量不要抛出

def terminate_all_processes():
    """终止所有 RUNNING 的进程"""
    print("\n[正在终止所有进程...]")
    terminated = 0
    with command_lock:
        for st in command_states.values():
            if st["status"] == CommandStatus.RUNNING and st["process"]:
                terminate_process(st["process"], cmd_states=st)
                terminated += 1
    print(f"[已终止 {terminated} 个进程]")

def format_command_list(cmds):
    out = ["\n--- 命令列表 ---"]
    for i, c in enumerate(cmds, 1):
        out.append(f"{i}. {c}")
    out.append("-----------------\n")
    return "\n".join(out)

def format_command_status():
    with command_lock:
        now = datetime.datetime.now()
        status_groups = {
            CommandStatus.RUNNING:   [],
            CommandStatus.INQUEUE:   [],
            CommandStatus.PAUSED:    [],
            CommandStatus.COMPLETED: [],
            CommandStatus.FAILED:    []
        }
        for cid, st in sorted(command_states.items()):
            status_groups[st["status"]].append((cid, st))
        lines = ["\n--- 命令状态 ---"]
        for status, group in status_groups.items():
            if not group:
                continue
            lines.append(f"\n--- {status} ({len(group)}) ---")
            for cid, st in group:
                dur = ""
                if st["start_time"]:
                    end = st["end_time"] or now
                    td = int((end - st["start_time"]).total_seconds())
                    h, m = divmod(td, 3600)
                    m, s = divmod(m, 60)
                    dur = f"{h:02d}:{m:02d}:{s:02d}"
                retry = f" (重试:{st['retry_count']})" if st["retry_count"] else ""
                pid = f" [PID:{st['pid']}]" if debug_mode and st.get("pid") else ""
                lines.append(f"ID {cid+1}: [{dur}]{retry}{pid} {st['command']}")
        lines.append("\n-----------------\n")
        return "\n".join(lines)

# ---------------------- 输入监听线程 ----------------------
def input_listener():
    while not stop_event.is_set() and not keyboard_interrupt_flag.is_set():
        try:
            user_input = input().strip().lower()
            input_queue.put(user_input)

            if user_input == "exit":
                print("\n[停止所有命令并退出]")
                stop_event.set()
                terminate_all_processes()
                break
            elif user_input == "status":
                print(format_command_status())
            elif user_input.startswith(("pause", "resume")):
                _handle_pause_resume(user_input)
            elif user_input == "debug":
                global debug_mode
                debug_mode = not debug_mode
                print(f"\n[调试模式: {'启用' if debug_mode else '关闭'}]")
        except EOFError:
            break
        except KeyboardInterrupt:
            keyboard_interrupt_flag.set()
            stop_event.set()
            break
        except Exception as e:
            if not keyboard_interrupt_flag.is_set():
                print(f"输入监听器错误: {e}")

def _handle_pause_resume(cmd_str):
    parts = cmd_str.split()
    action = parts[0]
    target_id = int(parts[1]) - 1 if len(parts) > 1 and parts[1].isdigit() else None
    with command_lock:
        if target_id is not None and target_id not in command_states:
            print(f"\n[命令 {target_id+1} 不存在]")
            return
    if action == "pause":
        if target_id is None:
            _pause_all()
        else:
            _pause_cmd(target_id)
    else:
        if target_id is None:
            _resume_all()
        else:
            _resume_cmd(target_id)

def _pause_cmd(cmd_id):
    with command_lock:
        st = command_states[cmd_id]
        if st["status"] == CommandStatus.RUNNING:
            st["status"] = CommandStatus.PAUSED
            if st["process"]:
                terminate_process(st["process"], cmd_states=st)
            print(f"\n[命令 {cmd_id+1} 已暂停]")
        else:
            print(f"\n[命令 {cmd_id+1} 不在运行，无法暂停]")

def _resume_cmd(cmd_id):
    with command_lock:
        st = command_states[cmd_id]
        if st["status"] == CommandStatus.PAUSED:
            st["status"] = CommandStatus.INQUEUE
            print(f"\n[命令 {cmd_id+1} 已恢复]")
        else:
            print(f"\n[命令 {cmd_id+1} 未暂停]")

def _pause_all():
    cnt = 0
    with command_lock:
        for st in command_states.values():
            if st["status"] == CommandStatus.RUNNING:
                st["status"] = CommandStatus.PAUSED
                if st["process"]:
                    terminate_process(st["process"], cmd_states=st)
                cnt += 1
    print(f"\n[已暂停 {cnt} 个命令]")

def _resume_all():
    cnt = 0
    with command_lock:
        for st in command_states.values():
            if st["status"] == CommandStatus.PAUSED:
                st["status"] = CommandStatus.INQUEUE
                cnt += 1
    print(f"\n[已恢复 {cnt} 个命令]")

# ---------------------- 状态定期打印线程 ----------------------
def status_updater(interval):
    while not stop_event.is_set() and not keyboard_interrupt_flag.is_set():
        time.sleep(interval)
        if not stop_event.is_set() and not keyboard_interrupt_flag.is_set():
            print(format_command_status())

# ---------------------- 核心：执行单条指令 ----------------------
def execute_command(cmd_id, cmd, total_retries):
    """
    返回 True = 成功；False = 最终失败 / 被中断
    """
    with command_lock:
        st = command_states[cmd_id]
        st.update({
            "status": CommandStatus.INQUEUE,
            "process": None,
            "retry_count": 0,
            "start_time": st["start_time"] or None,
            "end_time": None,
            "pid": None
        })

    retry = 0
    prefix = f"[CMD-{cmd_id+1}] "

    while retry <= total_retries \
          and not stop_event.is_set() \
          and not keyboard_interrupt_flag.is_set():

        with command_lock:
            if st["status"] == CommandStatus.PAUSED:
                time.sleep(0.5)
                continue
            st["status"] = CommandStatus.RUNNING
            if st["start_time"] is None:
                st["start_time"] = datetime.datetime.now()

        if retry:
            print(f"{prefix}重试 ({retry}/{total_retries})")

        # 启动子进程
        popen_kwargs = {
            "shell": True,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.STDOUT,
            "bufsize": 1
        }
        if platform.system() != "Windows":
            popen_kwargs["preexec_fn"] = os.setsid
        else:
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        process = subprocess.Popen(cmd, **popen_kwargs)

        with command_lock:
            st["process"] = process
            st["pid"] = process.pid
            if debug_mode:
                print(f"{prefix}[DEBUG] PID={process.pid}")

        # 实时读取输出
        try:
            while True:
                if stop_event.is_set() or keyboard_interrupt_flag.is_set():
                    break
                with command_lock:
                    if st["status"] == CommandStatus.PAUSED:
                        print(f"{prefix}被暂停，稍后重启")
                        break
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                if line:
                    sys.stdout.write(f"{prefix}{line.decode(errors='replace')}")
                    sys.stdout.flush()
                else:
                    time.sleep(0.05)
        except KeyboardInterrupt:
            pass

        # 若因暂停跳出，则重启循环
        with command_lock:
            if st["status"] == CommandStatus.PAUSED:
                terminate_process(process, cmd_states=st)
                continue

        # 关闭输出
        if process.stdout:
            process.stdout.close()

        rc = process.poll()
        with command_lock:
            st["process"] = None

        if rc == 0:
            print(f"{prefix}成功")
            with command_lock:
                st["status"] = CommandStatus.COMPLETED
                st["end_time"] = datetime.datetime.now()
            return True
        else:
            print(f"{prefix}失败，退出码 {rc}")
            retry += 1
            with command_lock:
                st["retry_count"] = retry
            if retry > total_retries:
                with command_lock:
                    st["status"] = CommandStatus.FAILED
                    st["end_time"] = datetime.datetime.now()
                return False
    return False

# ---------------------- 逻辑块执行 ----------------------
def run_sequence_blocks(blocks, commands, total_retries):
    """
    blocks: list of dict {"cmds":[idx...],"require_prev_success":bool}
    """
    prev_success = True
    for i, blk in enumerate(blocks, 1):
        if stop_event.is_set() or keyboard_interrupt_flag.is_set():
            break
        if blk["require_prev_success"] and not prev_success:
            print(f"\n[跳过后续逻辑块 {i}，因前一块执行失败]")
            break

        cmd_indices = blk["cmds"]
        idx_str = ','.join(str(x+1) for x in cmd_indices)
        print(f"\n[逻辑块 {i}: 执行指令 {idx_str}]")

        with ThreadPoolExecutor(max_workers=len(cmd_indices)) as exe:
            futures = [
                exe.submit(execute_command, cid, commands[cid], total_retries)
                for cid in cmd_indices
            ]
            # 循环等待，允许 status/exit 指令即时响应
            while futures:
                done, not_done = wait(futures, timeout=1.0,
                                      return_when=FIRST_COMPLETED)
                futures = list(not_done)
                if stop_event.is_set() or keyboard_interrupt_flag.is_set():
                    for fut in futures:
                        fut.cancel()
                    break
                # 清掉 input_queue 防胀
                while not input_queue.empty():
                    input_queue.get()

        with command_lock:
            prev_success = all(
                command_states[c]["status"] == CommandStatus.COMPLETED
                for c in cmd_indices)

    # 逻辑块结束后，让剩余 RUNNING 的命令先行退出
    if stop_event.is_set() or keyboard_interrupt_flag.is_set():
        terminate_all_processes()

# ---------------------- 主程序 ----------------------
def signal_handler(sig, frame):
    print("\n\n[收到 Ctrl+C，正在退出...]")
    keyboard_interrupt_flag.set()
    stop_event.set()
    terminate_all_processes()

signal.signal(signal.SIGINT, signal_handler)
if platform.system() == "Windows":
    signal.signal(signal.SIGBREAK, signal_handler)

def main():
    args = parse_args()
    global debug_mode
    debug_mode = args.debug

    # 收集命令
    print("输入命令（每行一条），两次回车结束：")
    commands = []
    try:
        while True:
            line = input().strip()
            if not line:
                break
            commands.append(line)
    except KeyboardInterrupt:
        print("\n输入被中断，退出")
        sys.exit(1)

    if not commands:
        print("未输入有效命令，退出")
        return

    # 初始化 command_states
    for i, c in enumerate(commands):
        command_states[i] = {
            "command": c, "status": CommandStatus.INQUEUE,
            "process": None, "retry_count": 0,
            "start_time": None, "end_time": None, "pid": None
        }

    print(format_command_list(commands))

    # 启动后台线程
    threading.Thread(target=input_listener, daemon=True).start()
    threading.Thread(target=status_updater,
                     args=(args.status_interval,), daemon=True).start()

    try:
        if args.sequence:
            try:
                blocks = parse_sequence_expression(
                    args.sequence, len(commands))
            except SequenceParseError as e:
                print(f"[sequence 解析错误] {e}")
                sys.exit(1)
            if debug_mode:
                print("[DEBUG] 解析后的逻辑块：", blocks)
            run_sequence_blocks(blocks, commands, args.total_retries)
        else:
            # 原先的“最大并发”模式
            with ThreadPoolExecutor(max_workers=args.max_concurrent) as exe:
                futures = {
                    exe.submit(execute_command, i, cmd, args.total_retries)
                    for i, cmd in enumerate(commands)
                }
                while futures and not stop_event.is_set() \
                      and not keyboard_interrupt_flag.is_set():
                    done, not_done = wait(
                        futures, timeout=1.0,
                        return_when=FIRST_COMPLETED)
                    futures = not_done
                    while not input_queue.empty():
                        input_queue.get()
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()

    # 总结结果
    print(format_command_status())
    with command_lock:
        succ = sum(st["status"] == CommandStatus.COMPLETED
                   for st in command_states.values())
        fail = sum(st["status"] == CommandStatus.FAILED
                   for st in command_states.values())
    print(f"\n执行结束：成功 {succ}/{len(commands)}，失败 {fail}/{len(commands)}")

if __name__ == "__main__":
    main()
