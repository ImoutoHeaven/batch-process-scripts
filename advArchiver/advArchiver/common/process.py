from __future__ import annotations

import os
import platform
import shlex
import shutil
import subprocess


class MissingToolError(RuntimeError):
    pass


TAR_FORMAT_TOOLING = {
    "tar": ("tar",),
    "tar.gz": ("tar", "gzip"),
    "tgz": ("tar", "gzip"),
    "tar.xz": ("tar", "xz"),
    "txz": ("tar", "xz"),
    "tar.bz2": ("tar", "bzip2"),
    "tbz2": ("tar", "bzip2"),
}


def format_command(command):
    parts = [str(part) for part in command]
    if platform.system() == "Windows":
        return subprocess.list2cmdline(parts)
    return shlex.join(parts)


def require_tool(tool_name):
    if shutil.which(tool_name) is None:
        raise MissingToolError(f"required tool not found on PATH: {tool_name}")


def missing_tools(tool_names):
    return [tool_name for tool_name in tool_names if shutil.which(tool_name) is None]


def has_tools(tool_names):
    return not missing_tools(tool_names)


def required_tools_for_tar_format(format_name):
    tool_names = TAR_FORMAT_TOOLING.get(format_name)
    if tool_names is None:
        raise ValueError(f"unsupported tar format: {format_name}")
    return tool_names


def run_command(command, debug=False):
    del debug
    parts = [str(part) for part in command]
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")

    if platform.system() == "Windows":
        return subprocess.run(
            format_command(parts),
            shell=True,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )

    env.setdefault("LC_ALL", "C.UTF-8")
    env.setdefault("LANG", "C.UTF-8")
    return subprocess.run(
        parts,
        shell=False,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )
