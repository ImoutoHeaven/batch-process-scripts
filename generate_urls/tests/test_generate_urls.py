import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "generate_urls.py"


def run_generator(folder: Path, prefix: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(folder), "--prefix", prefix],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def test_generates_recursive_urls_and_writes_log(tmp_path: Path) -> None:
    served = tmp_path / "served"
    served.mkdir()
    (served / "1.mp4").write_text("video", encoding="utf-8")
    nested = served / "sub dir"
    nested.mkdir()
    (nested / "clip 2.mp4").write_text("video", encoding="utf-8")

    result = run_generator(served, "https://abc.xyz/prefix", tmp_path)

    expected = [
        "https://abc.xyz/prefix/1.mp4",
        "https://abc.xyz/prefix/sub%20dir/clip%202.mp4",
    ]
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == expected
    assert (tmp_path / "generated_urls.log").read_text(encoding="utf-8").splitlines() == expected


def test_urlencodes_unicode_and_emoji_file_names(tmp_path: Path) -> None:
    served = tmp_path / "served"
    served.mkdir()
    (served / "中日英한🙂.mp4").write_text("video", encoding="utf-8")

    result = run_generator(served, "https://abc.xyz/prefix/", tmp_path)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "https://abc.xyz/prefix/%E4%B8%AD%E6%97%A5%E8%8B%B1%ED%95%9C%F0%9F%99%82.mp4"


def test_urlencodes_all_url_unsafe_characters(tmp_path: Path) -> None:
    served = tmp_path / "served"
    served.mkdir()
    (served / "a b#c?d&x=1%+中🙂.txt").write_text("file", encoding="utf-8")

    result = run_generator(served, "https://abc.xyz/prefix", tmp_path)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "https://abc.xyz/prefix/a%20b%23c%3Fd%26x%3D1%25%2B%E4%B8%AD%F0%9F%99%82.txt"


def test_rejects_non_directory_path(tmp_path: Path) -> None:
    not_directory = tmp_path / "file.txt"
    not_directory.write_text("not a folder", encoding="utf-8")

    result = run_generator(not_directory, "https://abc.xyz", tmp_path)

    assert result.returncode != 0
    assert "not a directory" in result.stderr
