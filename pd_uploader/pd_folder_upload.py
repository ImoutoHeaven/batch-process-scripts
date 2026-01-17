#!/usr/bin/env python3
import argparse
import base64
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib import error as urlerror
from urllib import request as urlrequest

STATE_VERSION = 1
PIXELDRAIN_URL_RE = re.compile(r"https?://(?:www\.)?pixeldrain\.com/\S+", re.I)
FILE_ID_RE = re.compile(r"/(?:u|file)/([A-Za-z0-9_-]+)")


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Upload a folder to Pixeldrain via pd with retries and resume. "
            "API key required."
        )
    )
    parser.add_argument("folder", help="Folder to upload")
    parser.add_argument("--pd-path", default=None, help="Path to pd executable")
    parser.add_argument(
        "--state",
        default=None,
        help="Path to state JSON (default: <folder>/.pd_upload_state.json)",
    )
    parser.add_argument("--retries", type=int, default=3, help="Retry attempts per file")
    parser.add_argument(
        "--retry-delay",
        type=float,
        default=2.0,
        help="Initial retry delay in seconds",
    )
    parser.add_argument(
        "--retry-backoff",
        type=float,
        default=2.0,
        help="Backoff multiplier for retries",
    )
    parser.add_argument(
        "--retry-jitter",
        type=float,
        default=0.3,
        help="Random jitter (0-1) as fraction of delay",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="Pixeldrain API key (required; can also use PIXELDRAIN_API_KEY)",
    )
    parser.add_argument(
        "--album-name",
        default=None,
        help="Album title (default: folder name)",
    )
    parser.add_argument(
        "--no-album",
        action="store_true",
        help="Skip creating album/list even if all uploads succeed",
    )
    parser.add_argument(
        "--recreate-album",
        action="store_true",
        help=(
            "Create a new album/list if one already exists and changed files "
            "were reuploaded or deletions were detected"
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print actions without uploading",
    )
    return parser.parse_args()


def resolve_pd_path(pd_path):
    if pd_path:
        return pd_path
    for name in ("pd", "pd.exe"):
        found = shutil.which(name)
        if found:
            return found
    script_dir = Path(__file__).resolve().parent
    local_pd = script_dir / "pd.exe"
    if local_pd.exists():
        return str(local_pd)
    return "pd"


def load_state(state_path, root):
    if not state_path.exists():
        return {
            "version": STATE_VERSION,
            "root": str(root),
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "files": {},
            "album": {"status": "not_created"},
        }
    try:
        with state_path.open("r", encoding="utf-8") as f:
            state = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {
            "version": STATE_VERSION,
            "root": str(root),
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "files": {},
            "album": {"status": "not_created"},
        }
    if not isinstance(state, dict):
        state = {}
    state.setdefault("version", STATE_VERSION)
    state.setdefault("files", {})
    state.setdefault("album", {"status": "not_created"})
    state["root"] = str(root)
    return state


def save_state(state_path, state):
    state_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = state_path.with_suffix(state_path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(state, f, indent=2, sort_keys=True)
        f.write("\n")
    tmp_path.replace(state_path)


def iter_files(root, state_path):
    state_abs = state_path.resolve()
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            if path.resolve() == state_abs:
                continue
        except OSError:
            pass
        yield path


def extract_url(output):
    match = PIXELDRAIN_URL_RE.search(output or "")
    if not match:
        return None
    return match.group(0).strip()


def extract_file_id(url):
    if not url:
        return None
    match = FILE_ID_RE.search(url)
    if not match:
        return None
    return match.group(1)


def pd_upload_file(pd_path, file_path, api_key):
    cmd = [pd_path, "upload", "--", str(file_path)]
    env = os.environ.copy()
    if api_key:
        env["PIXELDRAIN_API_KEY"] = api_key
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env,
    )
    combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if proc.returncode != 0:
        return False, None, combined.strip()
    url = extract_url(combined)
    if not url:
        return False, None, combined.strip() or "pd returned no URL"
    return True, url, combined.strip()


def create_list(file_ids, title, api_key):
    payload = {
        "title": title,
        "files": [{"id": file_id} for file_id in file_ids],
    }
    data = json.dumps(payload).encode("utf-8")
    req = urlrequest.Request("https://pixeldrain.com/api/list", data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if api_key:
        token = base64.b64encode(f":{api_key}".encode("utf-8")).decode("ascii")
        req.add_header("Authorization", f"Basic {token}")
    try:
        with urlrequest.urlopen(req, timeout=60) as resp:
            body = resp.read().decode("utf-8")
    except urlerror.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return False, None, f"HTTP {e.code}: {body}"
    except urlerror.URLError as e:
        return False, None, f"Network error: {e}"
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return False, None, f"Unexpected response: {body[:200]}"
    if not parsed.get("success", True) and not parsed.get("id"):
        return False, None, f"API error: {parsed}"
    list_id = parsed.get("id")
    if not list_id:
        return False, None, f"API response missing id: {parsed}"
    return True, list_id, None


def main():
    args = parse_args()
    root = Path(args.folder).resolve()
    if not root.exists() or not root.is_dir():
        print(f"Folder not found: {root}", file=sys.stderr)
        return 2

    pd_path = resolve_pd_path(args.pd_path)
    if not shutil.which(pd_path) and not Path(pd_path).exists():
        print(f"pd not found: {pd_path}", file=sys.stderr)
        return 2
    state_path = Path(args.state).resolve() if args.state else root / ".pd_upload_state.json"
    api_key = args.api_key or os.environ.get("PIXELDRAIN_API_KEY")
    if not api_key:
        print("API key required: use --api-key or set PIXELDRAIN_API_KEY.", file=sys.stderr)
        return 2

    state = load_state(state_path, root)

    files = []
    duplicates = {}
    changed_files = set()
    for file_path in iter_files(root, state_path):
        rel = file_path.relative_to(root).as_posix()
        stat = file_path.stat()
        size = stat.st_size
        mtime_ns = stat.st_mtime_ns
        record = state["files"].get(rel)
        if record and record.get("size") == size and record.get("mtime_ns") == mtime_ns:
            pass
        else:
            changed_files.add(rel)
            state["files"][rel] = {
                "size": size,
                "mtime_ns": mtime_ns,
                "status": "pending",
                "attempts": 0,
                "url": None,
                "id": None,
                "last_error": None,
            }
        files.append(rel)
        base = Path(rel).name
        duplicates[base] = duplicates.get(base, 0) + 1

    current_files = set(files)
    deleted_files = set()
    for rel in list(state["files"].keys()):
        if rel in current_files:
            continue
        rec = state["files"].get(rel, {})
        if rec.get("status") == "deleted":
            continue
        rec["status"] = "deleted"
        rec["deleted_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        rec["last_error"] = "deleted"
        state["files"][rel] = rec
        deleted_files.add(rel)

    save_state(state_path, state)

    if not files:
        print("No files found.")
        return 0

    dup_names = [name for name, count in duplicates.items() if count > 1]
    if dup_names:
        print(
            f"Warning: {len(dup_names)} duplicate basenames detected. "
            "Pixeldrain allows duplicates, but names may be ambiguous."
        )
    if deleted_files:
        print(f"Detected {len(deleted_files)} deleted file(s).")

    max_attempts = max(1, args.retries + 1)
    uploaded = 0
    failed = 0
    skipped = 0
    changed_reuploaded = False

    for rel in sorted(files):
        rec = state["files"].get(rel, {})
        if rec.get("status") == "success":
            skipped += 1
            continue

        file_path = root / Path(rel)
        if not file_path.exists():
            rec["status"] = "failed"
            rec["last_error"] = "file missing"
            state["files"][rel] = rec
            save_state(state_path, state)
            failed += 1
            continue

        print(f"Uploading {rel} ...")
        attempt = 0
        delay = args.retry_delay
        success = False
        last_error = None
        while attempt < max_attempts:
            attempt += 1
            rec["attempts"] = rec.get("attempts", 0) + 1
            if args.dry_run:
                success = True
                url = "https://pixeldrain.com/u/DRYRUN"
                break
            ok, url, info = pd_upload_file(pd_path, file_path, api_key)
            if ok:
                success = True
                break
            last_error = info
            if attempt < max_attempts:
                jitter = delay * args.retry_jitter * random.random()
                time.sleep(delay + jitter)
                delay *= args.retry_backoff

        if success:
            rec["status"] = "success"
            rec["url"] = url
            rec["id"] = extract_file_id(url)
            rec["last_error"] = None
            rec["uploaded_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            uploaded += 1
            if rel in changed_files:
                changed_reuploaded = True
        else:
            rec["status"] = "failed"
            rec["last_error"] = last_error or "upload failed"
            failed += 1

        state["files"][rel] = rec
        save_state(state_path, state)

    total = len(files)
    print(f"Done. total={total} uploaded={uploaded} skipped={skipped} failed={failed}")

    if args.no_album:
        return 0

    if failed == 0:
        album_state = state.get("album", {})
        album_exists = album_state.get("status") == "created"
        if album_exists and not args.recreate_album:
            print(f"Album already created: {album_state.get('url')}")
            return 0
        if album_exists and args.recreate_album and not (changed_reuploaded or deleted_files):
            print("No changed files reuploaded or deletions detected; album not recreated.")
            return 0

        file_ids = []
        for rel in sorted(files):
            rec = state["files"].get(rel, {})
            file_id = rec.get("id")
            if file_id:
                file_ids.append(file_id)
        if not file_ids:
            print("No file IDs available, cannot create album/list.")
            return 1

        title = args.album_name or root.name
        if args.dry_run:
            list_id = "DRYRUNLIST"
            album_url = f"https://pixeldrain.com/l/{list_id}"
            state["album"] = {
                "status": "created",
                "id": list_id,
                "url": album_url,
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            save_state(state_path, state)
            print(f"Album created: {album_url}")
            return 0

        ok, list_id, err = create_list(file_ids, title, api_key)
        if ok:
            album_url = f"https://pixeldrain.com/l/{list_id}"
            state["album"] = {
                "status": "created",
                "id": list_id,
                "url": album_url,
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            save_state(state_path, state)
            print(f"Album created: {album_url}")
            return 0

        state["album"] = {
            "status": "failed",
            "error": err,
            "attempted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        save_state(state_path, state)
        print(f"Album creation failed: {err}", file=sys.stderr)
        return 1

    print("Not all files uploaded successfully; album/list not created.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
