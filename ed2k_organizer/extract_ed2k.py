#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
提取 ed2k 链接脚本（Linux/Windows/macOS 通用）

默认递归扫描指定目录（默认当前目录）下的 .log/.txt 文件，提取 ed2k 链接并合并输出。
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Iterable
from pathlib import Path

ED2K_RE = re.compile(r"(ed2k://\|file\|.*?\|/)", re.IGNORECASE)


def iter_candidate_files(paths: Iterable[Path], *, recursive: bool, suffixes: tuple[str, ...]) -> list[Path]:
    candidates: list[Path] = []
    for p in paths:
        if p.is_file():
            if p.suffix.lower() in suffixes:
                candidates.append(p)
            continue

        if p.is_dir():
            glob = "**/*" if recursive else "*"
            for f in p.glob(glob):
                if f.is_file() and f.suffix.lower() in suffixes:
                    candidates.append(f)
            continue

        raise FileNotFoundError(str(p))

    return sorted(set(candidates))


def read_lines_with_fallback(path: Path, encodings: list[str]) -> list[str] | None:
    for encoding in encodings:
        try:
            return path.read_text(encoding=encoding).splitlines()
        except UnicodeDecodeError:
            continue
        except OSError:
            return None
    return None


def extract_ed2k_links(path: Path, *, encodings: list[str]) -> list[str]:
    lines = read_lines_with_fallback(path, encodings)
    if lines is None:
        print(f"警告: 无法读取文件: {path}", file=sys.stderr)
        return []

    links: list[str] = []
    for line in lines:
        for match in ED2K_RE.findall(line):
            links.append(match.strip())
    return links


def dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def build_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        prog="extract_ed2k.py",
        description="递归扫描目录中的 .log/.txt 文件，提取 ed2k 链接并合并输出。",
        add_help=False,
        epilog=(
            "示例:\n"
            "  # 扫描当前目录并输出到 ./combined.log\n"
            "  python3 extract_ed2k.py .\n"
            "\n"
            "  # 扫描指定目录并指定输出文件\n"
            "  python3 extract_ed2k.py /path/to/dir -o /tmp/combined.log\n"
            "\n"
            "  # 只处理某个文件\n"
            "  python3 extract_ed2k.py ./a.log\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    parser.add_argument(
        "-h",
        "--help",
        action="help",
        help="显示此帮助并退出",
    )
    parser.add_argument(
        "paths",
        nargs="?",
        default=".",
        help="要扫描的目录或文件路径（默认: 当前目录）",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="combined.log",
        help="输出文件路径（默认: ./combined.log）",
    )
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="不递归子目录（默认递归）",
    )
    parser.add_argument(
        "--dedupe",
        action="store_true",
        help="对提取到的链接去重（保持原始顺序）",
    )
    parser.add_argument(
        "--encoding",
        action="append",
        default=None,
        help="指定文本编码（可重复；未指定则自动尝试常见编码）",
    )

    args = parser.parse_args(argv)

    input_path = Path(args.paths).expanduser()
    output_path = Path(args.output).expanduser()
    recursive = not args.no_recursive

    encodings = args.encoding or ["utf-8", "utf-8-sig", "gb18030", "gbk", "cp1252", "latin-1"]

    try:
        target_files = iter_candidate_files([input_path], recursive=recursive, suffixes=(".log", ".txt"))
    except FileNotFoundError as e:
        print(f"错误: 路径不存在: {e}", file=sys.stderr)
        return 2

    if not target_files:
        print("未找到任何 .log 或 .txt 文件", file=sys.stderr)
        return 1

    all_links: list[str] = []
    for i, file_path in enumerate(target_files, 1):
        rel = file_path if input_path.is_file() else file_path.relative_to(input_path)
        print(f"处理文件 {i}/{len(target_files)}: {rel}")
        links = extract_ed2k_links(file_path, encodings=encodings)
        all_links.extend(links)
        print(f"  提取到 {len(links)} 个链接")

    if args.dedupe:
        all_links = dedupe_preserve_order(all_links)

    if not all_links:
        print("未找到任何 ed2k 链接", file=sys.stderr)
        return 1

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("".join(f"{link}\n" for link in all_links), encoding="utf-8")
    except OSError as e:
        print(f"保存文件时出错: {e}", file=sys.stderr)
        return 3

    print("\n成功！")
    print(f"总共提取 {len(all_links)} 个 ed2k 链接")
    print(f"已保存到: {output_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
