import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from dir_zmv_flatten import dir_zmv_flatten as dzf


def test_flatten_moves_entries_and_renames_conflicts(tmp_path: Path):
    root = tmp_path / "root"
    sub_a = root / "a"
    sub_b = root / "b"
    sub_a.mkdir(parents=True)
    sub_b.mkdir(parents=True)
    (sub_a / "file.txt").write_text("a")
    (sub_b / "file.txt").write_text("b")

    dzf.flatten_root(str(root))

    assert (root / "file.txt").read_text() == "a"
    assert (root / "file (1).txt").read_text() == "b"


def test_dry_run_does_not_move_or_delete(tmp_path: Path):
    root = tmp_path / "root"
    sub = root / "a"
    sub.mkdir(parents=True)
    (sub / "file.txt").write_text("x")

    dzf.flatten_root(str(root), dry_run=True, delete_empty_src_dirs=True)

    assert (sub / "file.txt").exists()
    assert not (root / "file.txt").exists()
    assert sub.exists()


def test_delete_empty_src_dirs_and_out_dir(tmp_path: Path):
    root = tmp_path / "root"
    sub = root / "a"
    out_dir = tmp_path / "out"
    sub.mkdir(parents=True)
    (sub / "file.txt").write_text("x")

    dzf.flatten_root(str(root), out_dir=str(out_dir), delete_empty_src_dirs=True)

    assert (out_dir / "file.txt").read_text() == "x"
    assert not sub.exists()


def test_main_dry_run(tmp_path: Path):
    root = tmp_path / "root"
    sub = root / "a"
    sub.mkdir(parents=True)
    (sub / "file.txt").write_text("x")

    rc = dzf.main([str(root), "--dry-run"])

    assert rc == 0
    assert (sub / "file.txt").exists()
    assert not (root / "file.txt").exists()
