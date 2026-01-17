#!/usr/bin/env python3
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import random
import re
import signal
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib import error as urlerror
from urllib import request as urlrequest

STATE_VERSION = 1
PIXELDRAIN_URL_RE = re.compile(r"https?://(?:www\.)?pixeldrain\.com/\S+", re.I)
FILE_ID_RE = re.compile(r"/(?:u|file)/([A-Za-z0-9_-]+)")
INTERRUPTED_ERROR = "interrupted"
STATE_LOCK = threading.Lock()
LOG_LOCK = threading.Lock()
STOP_EVENT = threading.Event()
SIGNAL_STATE = {"received": False, "signum": None}
DRY_RUN_MODE = False


def log(message, stream=sys.stdout):
    with LOG_LOCK:
        print(message, file=stream, flush=True)


def handle_signal(signum, frame):
    SIGNAL_STATE["received"] = True
    SIGNAL_STATE["signum"] = signum
    STOP_EVENT.set()


def register_signal_handlers():
    signal.signal(signal.SIGINT, handle_signal)
    sigterm = getattr(signal, "SIGTERM", None)
    if sigterm is not None:
        signal.signal(sigterm, handle_signal)


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
        "--jobs",
        type=int,
        default=6,
        help="Number of parallel uploads (default: 6)",
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
    if DRY_RUN_MODE:
        return
    with STATE_LOCK:
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


def terminate_process(proc):
    try:
        proc.terminate()
    except Exception:
        return
    try:
        proc.communicate(timeout=5)
        return
    except Exception:
        pass
    try:
        proc.kill()
    except Exception:
        return
    try:
        proc.communicate(timeout=5)
    except Exception:
        pass


def pd_upload_file(pd_path, file_path, api_key, stop_event):
    cmd = [pd_path, "upload", "--", str(file_path)]
    env = os.environ.copy()
    if api_key:
        env["PIXELDRAIN_API_KEY"] = api_key
    if stop_event.is_set():
        return False, None, INTERRUPTED_ERROR
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    while True:
        if stop_event.is_set():
            terminate_process(proc)
            return False, None, INTERRUPTED_ERROR
        ret = proc.poll()
        if ret is not None:
            stdout, stderr = proc.communicate()
            combined = (stdout or "") + "\n" + (stderr or "")
            if ret != 0:
                return False, None, combined.strip()
            url = extract_url(combined)
            if not url:
                return False, None, combined.strip() or "pd returned no URL"
            return True, url, combined.strip()
        time.sleep(0.2)


def sleep_with_stop(delay, stop_event):
    end = time.time() + delay
    while time.time() < end:
        if stop_event.is_set():
            return False
        time.sleep(min(0.2, end - time.time()))
    return True


def upload_worker(
    rel,
    root,
    pd_path,
    api_key,
    max_attempts,
    retry_delay,
    retry_backoff,
    retry_jitter,
    dry_run,
    prev_attempts,
    stop_event,
):
    if stop_event.is_set():
        return {
            "rel": rel,
            "status": "aborted",
            "url": None,
            "attempts": prev_attempts,
            "last_error": INTERRUPTED_ERROR,
        }
    file_path = root / Path(rel)
    if not file_path.exists():
        return {
            "rel": rel,
            "status": "failed",
            "url": None,
            "attempts": prev_attempts,
            "last_error": "file missing",
        }
    attempt = 0
    attempts = prev_attempts
    delay = retry_delay
    last_error = None
    while attempt < max_attempts:
        if stop_event.is_set():
            return {
                "rel": rel,
                "status": "aborted",
                "url": None,
                "attempts": attempts,
                "last_error": INTERRUPTED_ERROR,
            }
        attempt += 1
        attempts += 1
        if dry_run:
            return {
                "rel": rel,
                "status": "success",
                "url": "https://pixeldrain.com/u/DRYRUN",
                "attempts": attempts,
                "last_error": None,
            }
        try:
            ok, url, info = pd_upload_file(pd_path, file_path, api_key, stop_event)
        except Exception as exc:
            ok = False
            url = None
            info = f"upload error: {exc}"
        if info == INTERRUPTED_ERROR or stop_event.is_set():
            return {
                "rel": rel,
                "status": "aborted",
                "url": None,
                "attempts": attempts,
                "last_error": INTERRUPTED_ERROR,
            }
        if ok:
            return {
                "rel": rel,
                "status": "success",
                "url": url,
                "attempts": attempts,
                "last_error": None,
            }
        last_error = info
        if attempt < max_attempts:
            jitter = delay * retry_jitter * random.random()
            if not sleep_with_stop(delay + jitter, stop_event):
                return {
                    "rel": rel,
                    "status": "aborted",
                    "url": None,
                    "attempts": attempts,
                    "last_error": INTERRUPTED_ERROR,
                }
            delay *= retry_backoff
    return {
        "rel": rel,
        "status": "failed",
        "url": None,
        "attempts": attempts,
        "last_error": last_error or "upload failed",
    }


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
    global DRY_RUN_MODE
    DRY_RUN_MODE = bool(args.dry_run)
    register_signal_handlers()
    root = Path(args.folder).resolve()
    if not root.exists() or not root.is_dir():
        log(f"Folder not found: {root}", stream=sys.stderr)
        return 2

    pd_path = resolve_pd_path(args.pd_path)
    if not shutil.which(pd_path) and not Path(pd_path).exists():
        log(f"pd not found: {pd_path}", stream=sys.stderr)
        return 2
    if args.jobs < 1:
        log("--jobs must be >= 1", stream=sys.stderr)
        return 2
    state_path = Path(args.state).resolve() if args.state else root / ".pd_upload_state.json"
    api_key = args.api_key or os.environ.get("PIXELDRAIN_API_KEY")
    if not api_key:
        log("API key required: use --api-key or set PIXELDRAIN_API_KEY.", stream=sys.stderr)
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
        log("No files found.")
        return 0

    dup_names = [name for name, count in duplicates.items() if count > 1]
    if dup_names:
        log(
            f"Warning: {len(dup_names)} duplicate basenames detected. "
            "Pixeldrain allows duplicates, but names may be ambiguous."
        )
    if deleted_files:
        log(f"Detected {len(deleted_files)} deleted file(s).")

    max_attempts = max(1, args.retries + 1)
    uploaded = 0
    failed = 0
    skipped = 0
    aborted = 0
    interrupted = False
    changed_reuploaded = False

    futures = {}
    with ThreadPoolExecutor(max_workers=args.jobs) as executor:
        for rel in sorted(files):
            if STOP_EVENT.is_set():
                interrupted = True
                break
            rec = state["files"].get(rel, {})
            if rec.get("status") == "success":
                skipped += 1
                continue
            log(f"Uploading {rel} ...")
            prev_attempts = rec.get("attempts", 0)
            future = executor.submit(
                upload_worker,
                rel,
                root,
                pd_path,
                api_key,
                max_attempts,
                args.retry_delay,
                args.retry_backoff,
                args.retry_jitter,
                args.dry_run,
                prev_attempts,
                STOP_EVENT,
            )
            futures[future] = rel

        for future in as_completed(futures):
            rel = futures[future]
            if STOP_EVENT.is_set():
                interrupted = True
            try:
                result = future.result()
            except Exception as exc:
                result = {
                    "rel": rel,
                    "status": "failed",
                    "url": None,
                    "attempts": state["files"].get(rel, {}).get("attempts", 0),
                    "last_error": f"unexpected error: {exc}",
                }

            rec = state["files"].get(rel, {})
            rec["attempts"] = result.get("attempts", rec.get("attempts", 0))
            if result.get("status") == "success":
                rec["status"] = "success"
                rec["url"] = result.get("url")
                rec["id"] = extract_file_id(rec["url"])
                rec["last_error"] = None
                rec["uploaded_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                uploaded += 1
                if rel in changed_files:
                    changed_reuploaded = True
            elif result.get("status") == "aborted":
                rec["status"] = "pending"
                rec["last_error"] = INTERRUPTED_ERROR
                aborted += 1
                interrupted = True
            else:
                rec["status"] = "failed"
                rec["last_error"] = result.get("last_error") or "upload failed"
                failed += 1

            state["files"][rel] = rec
            save_state(state_path, state)

    total = len(files)
    log(
        "Done. total={total} uploaded={uploaded} skipped={skipped} failed={failed} "
        "aborted={aborted}".format(
            total=total,
            uploaded=uploaded,
            skipped=skipped,
            failed=failed,
            aborted=aborted,
        )
    )

    if args.no_album:
        return 0

    if interrupted:
        log("Interrupted; skipping album creation.", stream=sys.stderr)
        return 130

    if failed == 0:
        album_state = state.get("album", {})
        album_exists = album_state.get("status") == "created"
        if album_exists and not args.recreate_album:
            log(f"Album already created: {album_state.get('url')}")
            return 0
        if album_exists and args.recreate_album and not (changed_reuploaded or deleted_files):
            log("No changed files reuploaded or deletions detected; album not recreated.")
            return 0

        file_ids = []
        for rel in sorted(files):
            rec = state["files"].get(rel, {})
            file_id = rec.get("id")
            if file_id:
                file_ids.append(file_id)
        if not file_ids:
            log("No file IDs available, cannot create album/list.", stream=sys.stderr)
            return 1

        title = args.album_name or root.name
        if args.dry_run:
            log(
                "Dry run: album would be created with {count} file(s).".format(
                    count=len(file_ids)
                )
            )
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
            log(f"Album created: {album_url}")
            return 0

        state["album"] = {
            "status": "failed",
            "error": err,
            "attempted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        save_state(state_path, state)
        log(f"Album creation failed: {err}", stream=sys.stderr)
        return 1

    log("Not all files uploaded successfully; album/list not created.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
