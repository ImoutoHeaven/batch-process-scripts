import argparse
import os
import re
import sys
from collections.abc import Sequence
from typing import cast

import importlib


SHARED_SKIP_PREFIX = "--skip-"
PROTECTED_VALUE_PREFIX = "__advarchiver_protected_value__"
TAR_FORMATS = ("tar", "tar.gz", "tgz", "tar.xz", "txz", "tar.bz2", "tbz2")
SPLIT_PROFILE_PATTERN = re.compile(
    r"^(parted|best)-(\d+)(g|gb|m|mb|k|kb)$", re.IGNORECASE
)


class ParserFacade:
    def __init__(self, parser: argparse.ArgumentParser):
        self._parser = parser
        self._known_option_strings = self._collect_known_option_strings()
        self._value_option_strings = self._collect_value_option_strings()

    def __getattr__(self, name):
        return getattr(self._parser, name)

    def _collect_known_option_strings(self) -> set[str]:
        option_strings = set(self._parser._option_string_actions)
        for action in self._iter_subparser_actions():
            option_strings.update(action._option_string_actions)
        return option_strings

    def _collect_value_option_strings(self) -> set[str]:
        option_strings = set()
        for action in self._parser._actions:
            if action.option_strings and action.nargs != 0:
                option_strings.update(action.option_strings)
        for action in self._iter_subparser_actions():
            for subparser_action in action._actions:
                if subparser_action.option_strings and subparser_action.nargs != 0:
                    option_strings.update(subparser_action.option_strings)
        return option_strings

    def _iter_subparser_actions(self):
        for action in self._parser._actions:
            if not isinstance(action, argparse._SubParsersAction):
                continue
            for subparser in action.choices.values():
                yield subparser

    def _is_dynamic_skip_token(self, arg: str) -> bool:
        return (
            arg.startswith(SHARED_SKIP_PREFIX)
            and len(arg) > len(SHARED_SKIP_PREFIX)
            and arg not in self._known_option_strings
        )

    def _protect_dynamic_skip_option_values(
        self, args: Sequence[str] | None
    ) -> tuple[list[str], dict[str, str]]:
        if args is None:
            raw_args = list(sys.argv[1:])
        else:
            raw_args = list(args)

        protected_args = []
        protected_values = {}
        index = 0

        while index < len(raw_args):
            arg = raw_args[index]
            protected_args.append(arg)

            if arg == "--":
                protected_args.extend(raw_args[index + 1 :])
                break

            if (
                arg in self._value_option_strings
                and index + 1 < len(raw_args)
                and self._is_dynamic_skip_token(raw_args[index + 1])
            ):
                placeholder = f"{PROTECTED_VALUE_PREFIX}{len(protected_values)}"
                protected_values[placeholder] = raw_args[index + 1]
                protected_args.append(placeholder)
                index += 2
                continue

            index += 1

        return protected_args, protected_values

    def _restore_protected_value(self, value, protected_values: dict[str, str]):
        if isinstance(value, str):
            return protected_values.get(value, value)
        if isinstance(value, list):
            return [
                self._restore_protected_value(item, protected_values) for item in value
            ]
        if isinstance(value, tuple):
            return tuple(
                self._restore_protected_value(item, protected_values) for item in value
            )
        return value

    def parse_known_args(
        self,
        args: Sequence[str] | None = None,
        namespace: argparse.Namespace | None = None,
    ) -> tuple[argparse.Namespace, list[str]]:
        protected_args, protected_values = self._protect_dynamic_skip_option_values(
            args
        )
        parsed_args, extras = self._parser.parse_known_args(protected_args, namespace)
        parsed_args = cast(argparse.Namespace, parsed_args)
        for key, value in vars(parsed_args).items():
            setattr(
                parsed_args,
                key,
                self._restore_protected_value(value, protected_values),
            )

        restored_extras = []
        for extra in extras:
            restored = self._restore_protected_value(extra, protected_values)
            if not isinstance(restored, str):
                restored = str(restored)
            restored_extras.append(restored)
        skip_extensions = []
        remaining_extras = []
        for extra in restored_extras:
            if self._is_dynamic_skip_token(extra):
                skip_extensions.append(extra[len(SHARED_SKIP_PREFIX) :].lower())
            else:
                remaining_extras.append(extra)

        parsed_args.skip_extensions = list(getattr(parsed_args, "skip_extensions", []))
        parsed_args.skip_extensions.extend(skip_extensions)
        return parsed_args, remaining_extras

    def parse_args(
        self,
        args: Sequence[str] | None = None,
        namespace: argparse.Namespace | None = None,
    ) -> argparse.Namespace:
        parsed_args, extras = self.parse_known_args(args, namespace)
        if extras:
            self._parser.error(f"unrecognized arguments: {' '.join(extras)}")
        return parsed_args


def default_rec_threads():
    count = os.cpu_count()
    if count is None:
        return 4
    return max(1, count // 2)


def sevenzip_rar_profile(value):
    if value in {"store", "best", "fastest"}:
        return value
    if SPLIT_PROFILE_PATTERN.match(value):
        return value
    raise argparse.ArgumentTypeError(
        "expected 'store', 'best', 'fastest', or a split profile like 'parted-10g' or 'best-100mb'"
    )


def zip_profile(value):
    if value in {"store", "best", "fastest"}:
        return value
    raise argparse.ArgumentTypeError("expected 'store', 'best', or 'fastest'")


def code_page(value):
    if value == "mcu":
        return value
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "expected 'mcu' or a positive integer code page"
        ) from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError(
            "expected 'mcu' or a positive integer code page"
        )
    return str(parsed)


def existing_file_path(value):
    resolved = os.path.abspath(value)
    if not os.path.isfile(resolved):
        raise argparse.ArgumentTypeError(
            f"expected an existing file path, got: {value}"
        )
    return value


def build_shared_parent_parser():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("input_path")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--depth", type=int, default=0)
    parser.add_argument("-d", "--delete", action="store_true")
    parser.add_argument("-t", "--threads", type=int, default=1)
    parser.add_argument("--rec-threads", type=int, default=default_rec_threads())
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--no-lock", action="store_true")
    parser.add_argument("--lock-timeout", type=int, default=30)
    parser.add_argument("--out")
    parser.add_argument("--no-rec", action="store_true")
    parser.add_argument("--skip-files", action="store_true")
    parser.add_argument("--skip-folders", action="store_true")
    parser.add_argument("--ext-skip-folder-tree", action="store_true")
    return parser


def add_7z_subcommand(subparsers, shared_parent):
    parser = subparsers.add_parser("7z", parents=[shared_parent])
    parser.add_argument("-p", "--password")
    parser.add_argument("--profile", type=sevenzip_rar_profile, default="best")
    parser.add_argument("--no-emb", action="store_true")
    return parser


def add_rar_subcommand(subparsers, shared_parent):
    parser = subparsers.add_parser("rar", parents=[shared_parent])
    parser.add_argument("-p", "--password")
    parser.add_argument("--profile", type=sevenzip_rar_profile, default="best")
    comment_group = parser.add_mutually_exclusive_group()
    comment_group.add_argument("-c", "--comments")
    comment_group.add_argument("-cp", "--comments-path", type=existing_file_path)
    return parser


def add_zip_subcommand(subparsers, shared_parent):
    parser = subparsers.add_parser("zip", parents=[shared_parent])
    parser.add_argument("-p", "--password")
    parser.add_argument("--profile", type=zip_profile, default="best")
    parser.add_argument("--code-page", type=code_page, default="mcu")
    return parser


def add_tar_subcommand(subparsers, shared_parent):
    parser = subparsers.add_parser("tar", parents=[shared_parent])
    parser.add_argument("--format", choices=TAR_FORMATS, required=True)
    return parser


def build_parser():
    parser = argparse.ArgumentParser(prog="advArchiver.py")
    subparsers = parser.add_subparsers(dest="backend", required=True)
    shared_parent = build_shared_parent_parser()

    add_7z_subcommand(subparsers, shared_parent)
    add_rar_subcommand(subparsers, shared_parent)
    add_zip_subcommand(subparsers, shared_parent)
    add_tar_subcommand(subparsers, shared_parent)

    return ParserFacade(parser)


def build_backend(backend_name):
    backends = {
        "7z": (
            "advArchiver.advArchiver.backends.sevenzip",
            "SevenZipBackend",
        ),
        "rar": ("advArchiver.advArchiver.backends.rar", "RarBackend"),
        "zip": ("advArchiver.advArchiver.backends.zip_backend", "ZipBackend"),
        "tar": ("advArchiver.advArchiver.backends.tar", "TarBackend"),
    }
    module_name, class_name = backends[backend_name]
    module = importlib.import_module(module_name)
    return getattr(module, class_name)()


def select_item_paths(args):
    fs = importlib.import_module("advArchiver.advArchiver.common.fs")
    discovery = importlib.import_module("advArchiver.advArchiver.common.discovery")
    input_info = fs.validate_input_path(getattr(args, "input_path"), debug=args.debug)
    skip_extensions = list(getattr(args, "skip_extensions", []))

    if input_info.is_file:
        if getattr(args, "skip_files", False):
            return [], os.path.dirname(input_info.path)
        if discovery.should_skip_file(input_info.path, skip_extensions):
            return [], os.path.dirname(input_info.path)
        return [input_info.path], os.path.dirname(input_info.path)

    base_path = input_info.path
    items = discovery.get_items_at_depth(
        input_info.path,
        getattr(args, "depth", 0),
        skip_files=getattr(args, "skip_files", False),
        skip_folders=getattr(args, "skip_folders", False),
        skip_extensions=skip_extensions,
        ext_skip_folder_tree=getattr(args, "ext_skip_folder_tree", False),
        debug=getattr(args, "debug", False),
    )
    return sorted(items["files"]) + sorted(items["folders"]), base_path


def run(args):
    backend = build_backend(args.backend)
    backend.validate_args(args)

    engine = importlib.import_module("advArchiver.advArchiver.engine")
    item_paths, base_path = select_item_paths(args)
    if not item_paths:
        return 0
    summary = engine.run(item_paths, backend, args, base_path)
    return summary.exit_code


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except Exception as exc:
        if getattr(args, "debug", False):
            raise
        print(str(exc), file=sys.stderr)
        return 1
