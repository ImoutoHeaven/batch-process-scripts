import argparse
import concurrent.futures
import hashlib
import importlib
import os
import sqlite3
import struct
import tempfile
from pathlib import Path
from typing import Callable, cast
from urllib.parse import quote


ED2K_CHUNK_SIZE = 9728000
SQLITE_UPSERT_BATCH_SIZE = 1000


def _load_native_hasher():
    try:
        native = importlib.import_module("ed2k115_native")
        module_file = getattr(native, "__file__", None)
        if module_file is not None:
            module_path = Path(module_file).resolve()
            repo_root_native = Path(__file__).resolve().parents[1] / module_path.name
            if module_path == repo_root_native:
                return None

        return native
    except Exception:
        return None


def hash_file_with_best_backend(file_path: Path, size: int) -> str:
    native = _load_native_hasher()
    if native is not None:
        file_hasher = cast(Callable[[str, int], str] | None, getattr(native, "ed2k115_file_hex", None))
        if callable(file_hasher):
            try:
                return file_hasher(str(file_path), size)
            except AttributeError:
                pass
    with file_path.open("rb") as fp:
        return ed2k_115_stream(fp, size)


def build_parser():
    parser = argparse.ArgumentParser(description="115-compatible ED2K calculator")
    parser.add_argument("input", nargs="?")
    parser.add_argument("--out")
    parser.add_argument("--keep-dirs", action="store_true")
    parser.add_argument("--url-encode", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.input:
        return 0

    input_path = Path(args.input)
    if not input_path.exists():
        parser.error(f"input path does not exist: {input_path}")
    if not args.out:
        parser.error("--out is required when input is provided")

    out_path = Path(args.out)

    if args.dry_run:
        planned_files = 0
        planned_targets = set()
        for file_path, rel_parent in iter_input_files(input_path):
            if should_skip_input_file(file_path, input_path, out_path, args.keep_dirs):
                continue
            planned_files += 1
            planned_targets.add(target_log_path(rel_parent, out_path, args.keep_dirs))

        print(f"planned files: {planned_files}")
        print(f"planned targets: {len(planned_targets)}")
        for target in sorted(planned_targets, key=str):
            print(target)
        return 0

    task_key = build_task_key(input_path, out_path, args.keep_dirs, args.url_encode)
    conn = open_state_db(task_key)
    grouped_lines = {}
    pending_upserts = []
    try:
        ordered_items = []
        for file_path, rel_parent in iter_input_files(input_path):
            if should_skip_input_file(file_path, input_path, out_path, args.keep_dirs):
                continue
            name = encode_name_for_ed2k(file_path.name, args.url_encode)
            stat = file_path.stat()
            size = stat.st_size
            mtime_ns = stat.st_mtime_ns
            rel_key = stable_rel_path(input_path, file_path)

            mark_path_seen(conn, rel_key)
            digest = get_file_state_hash(conn, rel_key, size, mtime_ns)
            ordered_items.append(
                {
                    "file_path": file_path,
                    "log_path": target_log_path(rel_parent, out_path, args.keep_dirs),
                    "name": name,
                    "size": size,
                    "mtime_ns": mtime_ns,
                    "rel_key": rel_key,
                    "digest": digest,
                }
            )

        pending_hashes = [item for item in ordered_items if item["digest"] is None]
        if pending_hashes:
            max_workers = min(32, os.cpu_count() or 4)
            jobs = [(item["file_path"], item["size"]) for item in pending_hashes]
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                for item, digest in zip(pending_hashes, executor.map(_hash_work_item, jobs)):
                    item["digest"] = digest
                    pending_upserts.append((item["rel_key"], item["size"], item["mtime_ns"], digest))
                    if len(pending_upserts) >= SQLITE_UPSERT_BATCH_SIZE:
                        flush_file_state_upserts(conn, pending_upserts)
                        pending_upserts.clear()

        if pending_upserts:
            flush_file_state_upserts(conn, pending_upserts)
            pending_upserts.clear()

        for item in ordered_items:
            link = f"ed2k://|file|{item['name']}|{item['size']}|{item['digest']}|/"
            grouped_lines.setdefault(item["log_path"], []).append(link)

        for log_path, lines in grouped_lines.items():
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        prune_unseen_file_state(conn)
    except Exception:
        if pending_upserts:
            flush_file_state_upserts(conn, pending_upserts)
        raise
    finally:
        conn.close()

    return 0


def _hash_work_item(work_item):
    file_path, size = work_item
    return hash_file_with_best_backend(file_path, size)


def iter_input_files(input_path: Path):
    if input_path.is_file():
        yield input_path, Path(".")
        return

    for root_str, dir_names, file_names in os.walk(input_path):
        dir_names.sort()
        file_names.sort()
        root_path = Path(root_str)
        rel_parent = root_path.relative_to(input_path)
        for file_name in file_names:
            yield root_path / file_name, rel_parent


def target_log_path(rel_parent: Path, out_path: Path, keep_dirs: bool) -> Path:
    if not keep_dirs:
        return out_path

    if rel_parent == Path("."):
        return out_path / "files.ed2k.log"
    return out_path / rel_parent / "files.ed2k.log"


def should_skip_input_file(file_path: Path, input_path: Path, out_path: Path, keep_dirs: bool) -> bool:
    if not input_path.is_dir():
        return False

    resolved_file = file_path.resolve()
    resolved_out = out_path.resolve()

    if not keep_dirs:
        return resolved_file == resolved_out

    return resolved_file.name == "files.ed2k.log" and resolved_out in resolved_file.parents


def build_task_key(input_path: Path, out_path: Path, keep_dirs: bool, url_encode: bool) -> str:
    material = "\n".join(
        [
            str(input_path.resolve()),
            str(out_path.resolve()),
            "1" if keep_dirs else "0",
            "1" if url_encode else "0",
        ]
    )
    return hashlib.sha1(material.encode("utf-8")).hexdigest()


def open_state_db(task_key: str) -> sqlite3.Connection:
    root = Path(tempfile.gettempdir()) / "ed2k115-checkpoints"
    root.mkdir(parents=True, exist_ok=True)
    db_path = root / f"{task_key}.sqlite3"
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS file_state (
            rel_path TEXT PRIMARY KEY,
            size INTEGER NOT NULL,
            mtime_ns INTEGER NOT NULL,
            hash_blob BLOB NOT NULL
        )
        """
    )
    ensure_file_state_hash_blob(conn)
    conn.execute("CREATE TEMP TABLE IF NOT EXISTS seen_paths (rel_path TEXT PRIMARY KEY)")
    conn.execute("DELETE FROM seen_paths")
    conn.commit()
    return conn


def ensure_file_state_hash_blob(conn: sqlite3.Connection):
    cols = [row[1] for row in conn.execute("PRAGMA table_info(file_state)").fetchall()]
    if cols == ["rel_path", "size", "mtime_ns", "hash_blob"]:
        return

    has_blob = "hash_blob" in cols
    has_hex = "hash_hex" in cols
    rows_to_copy = []

    if has_blob and has_hex:
        rows = conn.execute("SELECT rel_path, size, mtime_ns, hash_blob, hash_hex FROM file_state").fetchall()
        for rel_path, size, mtime_ns, hash_blob, hash_hex in rows:
            blob_value = hash_blob if hash_blob is not None else _hash_hex_to_blob(hash_hex)
            rows_to_copy.append((rel_path, size, mtime_ns, blob_value))
    elif has_blob:
        rows_to_copy = conn.execute("SELECT rel_path, size, mtime_ns, hash_blob FROM file_state").fetchall()
    elif has_hex:
        rows = conn.execute("SELECT rel_path, size, mtime_ns, hash_hex FROM file_state").fetchall()
        rows_to_copy = [(rel_path, size, mtime_ns, _hash_hex_to_blob(hash_hex)) for rel_path, size, mtime_ns, hash_hex in rows]

    conn.execute(
        """
        CREATE TABLE file_state_new (
            rel_path TEXT PRIMARY KEY,
            size INTEGER NOT NULL,
            mtime_ns INTEGER NOT NULL,
            hash_blob BLOB NOT NULL
        )
        """
    )
    if rows_to_copy:
        conn.executemany(
            "INSERT INTO file_state_new (rel_path, size, mtime_ns, hash_blob) VALUES (?, ?, ?, ?)",
            rows_to_copy,
        )
    conn.execute("DROP TABLE file_state")
    conn.execute("ALTER TABLE file_state_new RENAME TO file_state")


def mark_path_seen(conn: sqlite3.Connection, rel_path: str):
    conn.execute("INSERT OR IGNORE INTO seen_paths(rel_path) VALUES (?)", (rel_path,))


def prune_unseen_file_state(conn: sqlite3.Connection):
    conn.execute("DELETE FROM file_state WHERE rel_path NOT IN (SELECT rel_path FROM seen_paths)")
    conn.commit()


def stable_rel_path(input_path: Path, file_path: Path) -> str:
    if input_path.is_file():
        return file_path.name
    return file_path.relative_to(input_path).as_posix()


def get_file_state_hash(conn: sqlite3.Connection, rel_path: str, size: int, mtime_ns: int):
    row = conn.execute(
        "SELECT hash_blob FROM file_state WHERE rel_path = ? AND size = ? AND mtime_ns = ?",
        (rel_path, size, mtime_ns),
    ).fetchone()
    if row is None:
        return None
    return _hash_blob_to_hex(row[0])


def upsert_file_state(conn: sqlite3.Connection, rel_path: str, size: int, mtime_ns: int, hash_hex: str):
    flush_file_state_upserts(conn, [(rel_path, size, mtime_ns, hash_hex)])


def flush_file_state_upserts(conn: sqlite3.Connection, upserts):
    if not upserts:
        return

    conn.executemany(
        """
        INSERT INTO file_state (rel_path, size, mtime_ns, hash_blob)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(rel_path)
        DO UPDATE SET size = excluded.size, mtime_ns = excluded.mtime_ns, hash_blob = excluded.hash_blob
        """,
        [(rel_path, size, mtime_ns, _hash_hex_to_blob(hash_hex)) for rel_path, size, mtime_ns, hash_hex in upserts],
    )
    conn.commit()


def _hash_hex_to_blob(hash_hex: str) -> bytes:
    return bytes.fromhex(hash_hex)


def _hash_blob_to_hex(hash_blob: bytes) -> str:
    return hash_blob.hex().upper()


def _left_rotate_32(x: int, n: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def md4_raw(msg: bytes) -> bytes:
    """Return RFC 1320 MD4 digest bytes using the in-file pure Python implementation."""
    # RFC 1320 section 3.3 initial state.
    a = 0x67452301
    b = 0xEFCDAB89
    c = 0x98BADCFE
    d = 0x10325476

    bit_len = (len(msg) * 8) & 0xFFFFFFFFFFFFFFFF
    padded = bytearray(msg)
    padded.append(0x80)
    while (len(padded) % 64) != 56:
        padded.append(0)
    padded.extend(struct.pack("<Q", bit_len))

    for offset in range(0, len(padded), 64):
        block = padded[offset : offset + 64]
        x = list(struct.unpack("<16I", block))
        aa, bb, cc, dd = a, b, c, d

        def f(x0, y0, z0):
            return ((x0 & y0) | (~x0 & z0)) & 0xFFFFFFFF

        def g(x0, y0, z0):
            return ((x0 & y0) | (x0 & z0) | (y0 & z0)) & 0xFFFFFFFF

        def h(x0, y0, z0):
            return (x0 ^ y0 ^ z0) & 0xFFFFFFFF

        # Round 1
        a = _left_rotate_32((a + f(b, c, d) + x[0]) & 0xFFFFFFFF, 3)
        d = _left_rotate_32((d + f(a, b, c) + x[1]) & 0xFFFFFFFF, 7)
        c = _left_rotate_32((c + f(d, a, b) + x[2]) & 0xFFFFFFFF, 11)
        b = _left_rotate_32((b + f(c, d, a) + x[3]) & 0xFFFFFFFF, 19)
        a = _left_rotate_32((a + f(b, c, d) + x[4]) & 0xFFFFFFFF, 3)
        d = _left_rotate_32((d + f(a, b, c) + x[5]) & 0xFFFFFFFF, 7)
        c = _left_rotate_32((c + f(d, a, b) + x[6]) & 0xFFFFFFFF, 11)
        b = _left_rotate_32((b + f(c, d, a) + x[7]) & 0xFFFFFFFF, 19)
        a = _left_rotate_32((a + f(b, c, d) + x[8]) & 0xFFFFFFFF, 3)
        d = _left_rotate_32((d + f(a, b, c) + x[9]) & 0xFFFFFFFF, 7)
        c = _left_rotate_32((c + f(d, a, b) + x[10]) & 0xFFFFFFFF, 11)
        b = _left_rotate_32((b + f(c, d, a) + x[11]) & 0xFFFFFFFF, 19)
        a = _left_rotate_32((a + f(b, c, d) + x[12]) & 0xFFFFFFFF, 3)
        d = _left_rotate_32((d + f(a, b, c) + x[13]) & 0xFFFFFFFF, 7)
        c = _left_rotate_32((c + f(d, a, b) + x[14]) & 0xFFFFFFFF, 11)
        b = _left_rotate_32((b + f(c, d, a) + x[15]) & 0xFFFFFFFF, 19)

        # Round 2
        a = _left_rotate_32((a + g(b, c, d) + x[0] + 0x5A827999) & 0xFFFFFFFF, 3)
        d = _left_rotate_32((d + g(a, b, c) + x[4] + 0x5A827999) & 0xFFFFFFFF, 5)
        c = _left_rotate_32((c + g(d, a, b) + x[8] + 0x5A827999) & 0xFFFFFFFF, 9)
        b = _left_rotate_32((b + g(c, d, a) + x[12] + 0x5A827999) & 0xFFFFFFFF, 13)
        a = _left_rotate_32((a + g(b, c, d) + x[1] + 0x5A827999) & 0xFFFFFFFF, 3)
        d = _left_rotate_32((d + g(a, b, c) + x[5] + 0x5A827999) & 0xFFFFFFFF, 5)
        c = _left_rotate_32((c + g(d, a, b) + x[9] + 0x5A827999) & 0xFFFFFFFF, 9)
        b = _left_rotate_32((b + g(c, d, a) + x[13] + 0x5A827999) & 0xFFFFFFFF, 13)
        a = _left_rotate_32((a + g(b, c, d) + x[2] + 0x5A827999) & 0xFFFFFFFF, 3)
        d = _left_rotate_32((d + g(a, b, c) + x[6] + 0x5A827999) & 0xFFFFFFFF, 5)
        c = _left_rotate_32((c + g(d, a, b) + x[10] + 0x5A827999) & 0xFFFFFFFF, 9)
        b = _left_rotate_32((b + g(c, d, a) + x[14] + 0x5A827999) & 0xFFFFFFFF, 13)
        a = _left_rotate_32((a + g(b, c, d) + x[3] + 0x5A827999) & 0xFFFFFFFF, 3)
        d = _left_rotate_32((d + g(a, b, c) + x[7] + 0x5A827999) & 0xFFFFFFFF, 5)
        c = _left_rotate_32((c + g(d, a, b) + x[11] + 0x5A827999) & 0xFFFFFFFF, 9)
        b = _left_rotate_32((b + g(c, d, a) + x[15] + 0x5A827999) & 0xFFFFFFFF, 13)

        # Round 3
        a = _left_rotate_32((a + h(b, c, d) + x[0] + 0x6ED9EBA1) & 0xFFFFFFFF, 3)
        d = _left_rotate_32((d + h(a, b, c) + x[8] + 0x6ED9EBA1) & 0xFFFFFFFF, 9)
        c = _left_rotate_32((c + h(d, a, b) + x[4] + 0x6ED9EBA1) & 0xFFFFFFFF, 11)
        b = _left_rotate_32((b + h(c, d, a) + x[12] + 0x6ED9EBA1) & 0xFFFFFFFF, 15)
        a = _left_rotate_32((a + h(b, c, d) + x[2] + 0x6ED9EBA1) & 0xFFFFFFFF, 3)
        d = _left_rotate_32((d + h(a, b, c) + x[10] + 0x6ED9EBA1) & 0xFFFFFFFF, 9)
        c = _left_rotate_32((c + h(d, a, b) + x[6] + 0x6ED9EBA1) & 0xFFFFFFFF, 11)
        b = _left_rotate_32((b + h(c, d, a) + x[14] + 0x6ED9EBA1) & 0xFFFFFFFF, 15)
        a = _left_rotate_32((a + h(b, c, d) + x[1] + 0x6ED9EBA1) & 0xFFFFFFFF, 3)
        d = _left_rotate_32((d + h(a, b, c) + x[9] + 0x6ED9EBA1) & 0xFFFFFFFF, 9)
        c = _left_rotate_32((c + h(d, a, b) + x[5] + 0x6ED9EBA1) & 0xFFFFFFFF, 11)
        b = _left_rotate_32((b + h(c, d, a) + x[13] + 0x6ED9EBA1) & 0xFFFFFFFF, 15)
        a = _left_rotate_32((a + h(b, c, d) + x[3] + 0x6ED9EBA1) & 0xFFFFFFFF, 3)
        d = _left_rotate_32((d + h(a, b, c) + x[11] + 0x6ED9EBA1) & 0xFFFFFFFF, 9)
        c = _left_rotate_32((c + h(d, a, b) + x[7] + 0x6ED9EBA1) & 0xFFFFFFFF, 11)
        b = _left_rotate_32((b + h(c, d, a) + x[15] + 0x6ED9EBA1) & 0xFFFFFFFF, 15)

        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF

    return struct.pack("<4I", a, b, c, d)


def _read_exact(fp, size: int) -> bytes:
    if size == 0:
        return b""

    chunks = bytearray()
    while len(chunks) < size:
        chunk = fp.read(size - len(chunks))
        if not chunk:
            raise ValueError("Unexpected EOF while reading stream")
        chunks.extend(chunk)
    return bytes(chunks)


def ed2k_115_stream(fp, file_size: int) -> str:
    if file_size < ED2K_CHUNK_SIZE:
        data = _read_exact(fp, file_size)
        return md4_raw(md4_raw(data)).hex().upper()

    chunk_digests = bytearray()
    remaining = file_size
    while remaining > 0:
        to_read = min(ED2K_CHUNK_SIZE, remaining)
        chunk = _read_exact(fp, to_read)
        chunk_digests.extend(md4_raw(chunk))
        remaining -= to_read
    if file_size % ED2K_CHUNK_SIZE == 0:
        chunk_digests.extend(md4_raw(b""))
    return md4_raw(bytes(chunk_digests)).hex().upper()


def ed2k_115_bytes(data: bytes) -> str:
    if len(data) < ED2K_CHUNK_SIZE:
        return md4_raw(md4_raw(data)).hex().upper()
    chunk_digests = bytearray()
    for offset in range(0, len(data), ED2K_CHUNK_SIZE):
        chunk_digests.extend(md4_raw(data[offset : offset + ED2K_CHUNK_SIZE]))
    if len(data) % ED2K_CHUNK_SIZE == 0:
        chunk_digests.extend(md4_raw(b""))
    return md4_raw(bytes(chunk_digests)).hex().upper()


def encode_name_for_ed2k(name: str, url_encode_all: bool) -> str:
    """Encode ED2K link name with delimiter-only or full URL encoding."""
    if url_encode_all:
        return quote(name, safe="-._~")

    encoded = name
    encoded = encoded.replace("|", "%7C")
    encoded = encoded.replace("\n", "%0A")
    encoded = encoded.replace("\r", "%0D")
    encoded = encoded.replace("\t", "%09")
    return encoded


if __name__ == "__main__":
    raise SystemExit(main())
