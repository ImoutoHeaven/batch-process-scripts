#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path
from urllib.parse import quote


LOG_FILE = "generated_urls.log"


def build_url(prefix: str, relative_path: Path) -> str:
    encoded_path = quote(relative_path.as_posix(), safe="/")
    return f"{prefix.rstrip('/')}/{encoded_path}"


def generate_urls(folder: Path, prefix: str) -> list[str]:
    return [
        build_url(prefix, path.relative_to(folder))
        for path in sorted(folder.rglob("*"))
        if path.is_file()
    ]


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate HTTP URLs for files served from a local folder."
    )
    parser.add_argument("folder", type=Path, help="Local folder being served")
    parser.add_argument("--prefix", required=True, help="URL prefix of the HTTP server")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    folder = args.folder.resolve()

    if not folder.is_dir():
        print(f"error: {args.folder} is not a directory", file=sys.stderr)
        return 1

    urls = generate_urls(folder, args.prefix)
    output = "\n".join(urls)
    if output:
        print(output)

    Path(LOG_FILE).write_text(output + ("\n" if output else ""), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
