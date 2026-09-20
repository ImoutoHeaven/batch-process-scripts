#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from urllib.parse import quote, urlsplit


def http_addr(value: str) -> str:
    try:
        parsed = urlsplit(value)
        parsed.port
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"无效地址: {error}") from error
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.query or parsed.fragment:
        raise argparse.ArgumentTypeError("地址必须是 http(s)://主机[:端口][/路径]")
    return value.rstrip("/")


def make_link(addr: str, path: str, base: str = "") -> str:
    path = f"{base.rstrip('/')}/{path.lstrip('/')}" if base else path
    return f"{addr}/{quote(path.lstrip('/'))}"


def main() -> None:
    parser = argparse.ArgumentParser(description="从目录或 JSON 生成 HTTP(S) 直链")
    sources = parser.add_mutually_exclusive_group(required=True)
    sources.add_argument("folder", nargs="?", type=Path, help="要递归扫描的目录")
    sources.add_argument("--json", type=Path, dest="json_file", help="包含 files[].path 的 JSON 文件")
    parser.add_argument("--addr", required=True, type=http_addr, help="HTTP(S) 基础地址")
    parser.add_argument("--base", default="", help="JSON 路径前缀，例如 /path")
    args = parser.parse_args()

    if args.base and not args.json_file:
        parser.error("--base 只能与 --json 一起使用")

    output = (Path.cwd() / "out.txt").resolve()
    if args.json_file:
        try:
            data = json.loads(args.json_file.read_text(encoding="utf-8"))
            paths = [item["path"] for item in data["files"]]
            if not all(isinstance(path, str) and path for path in paths):
                raise ValueError("path 必须是非空字符串")
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            parser.error(f"无法读取 JSON: {error}")
        links = [make_link(args.addr, path, args.base) for path in paths]
    else:
        root = args.folder.resolve()
        if not root.is_dir():
            parser.error(f"不是目录: {args.folder}")
        files = sorted(path for path in root.rglob("*") if path.is_file() and path.resolve() != output)
        links = [make_link(args.addr, path.relative_to(root).as_posix()) for path in files]

    output.write_text("\n".join(links) + ("\n" if links else ""), encoding="utf-8")
    print(f"已写入 {len(links)} 条直链: {output}")


if __name__ == "__main__":
    assert http_addr("https://example.com:8000/") == "https://example.com:8000"
    assert make_link("https://example.com", "/目录/a b.txt") == "https://example.com/%E7%9B%AE%E5%BD%95/a%20b.txt"
    assert make_link("https://example.com", "/file.txt", "/path/") == "https://example.com/path/file.txt"
    main()
