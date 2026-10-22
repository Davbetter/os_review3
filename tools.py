"""Atomic, safe primitives. All hashing is done by the host's native sha256sum, never by an LLM."""
import json
import os
import shutil
import subprocess
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from guardrails import resolve_in_workspace

try:  # POSIX file locking; on Windows the lock is a no-op
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

MANIFEST_NAME = ".integrity_manifest.json"
EXCLUDED_DIRS = {".git", "__pycache__", "node_modules", ".venv"}
EXCLUDED_FILES = {MANIFEST_NAME, MANIFEST_NAME + ".lock", MANIFEST_NAME + ".tmp"}
CHUNK = 200  # files per sha256sum invocation


class ToolError(Exception):
    """Structured, LLM-readable error returned through the feedback loop."""


def workspace() -> Path:
    return Path(os.environ.get("INTEGRITY_WORKSPACE", os.getcwd())).resolve()


def _dir(path: str) -> Path:
    p = resolve_in_workspace(path, workspace())
    if not p.exists():
        raise ToolError(f"Directory does not exist: '{path}'. Check the path and retry.")
    if not p.is_dir():
        raise ToolError(f"Not a directory: '{path}'.")
    return p


def _files(root: Path) -> list[str]:
    """Sorted relative POSIX paths of regular, non-excluded files (symlinks are not followed)."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDED_DIRS)
        for name in sorted(filenames):
            full = Path(dirpath) / name
            if name in EXCLUDED_FILES or full.is_symlink():
                continue
            out.append(full.relative_to(root).as_posix())
    return out


def _sha256sum_bin() -> str:
    for name in ("sha256sum", "gsha256sum"):
        if shutil.which(name):
            return name
    raise ToolError("Native sha256sum not found on this host (macOS: `brew install coreutils`).")


def _hash_files(root: Path, rels: list[str]) -> dict[str, str]:
    binary = _sha256sum_bin()
    digests: dict[str, str] = {}
    for i in range(0, len(rels), CHUNK):
        batch = rels[i:i + CHUNK]
        proc = subprocess.run([binary, "-z", "--", *batch], cwd=root, capture_output=True)
        if proc.returncode != 0:
            raise ToolError("sha256sum failed: " + proc.stderr.decode(errors="replace").strip())
        for rec in proc.stdout.split(b"\0"):
            if rec:
                text = rec.decode(errors="surrogateescape")
                digests[text[66:]] = text[:64]  # "<64 hex><space><space or *><name>"
    return digests


@contextmanager
def _locked(root: Path, exclusive: bool):
    lock = open(root / (MANIFEST_NAME + ".lock"), "a+")
    try:
        if fcntl:
            fcntl.flock(lock, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        if fcntl:
            fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()


# ---------------------------------------------------------------- tools
def list_directory(path: str) -> dict:
    root = _dir(path)
    entries = []
    for rel in _files(root):
        st = (root / rel).stat()
        entries.append({
            "path": rel,
            "size_bytes": st.st_size,
            "modified_utc": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(timespec="seconds"),
        })
    return {"directory": path, "file_count": len(entries), "files": entries}


def hash_directory(path: str) -> dict:
    root = _dir(path)
    digests = _hash_files(root, _files(root))
    return {"directory": path, "algorithm": "sha256", "file_count": len(digests), "hashes": digests}


def read_json_state(path: str) -> dict:
    root = _dir(path)
    mf = root / MANIFEST_NAME
    if not mf.exists():
        raise ToolError(
            f"No baseline manifest found in '{path}' ({MANIFEST_NAME} is missing). "
            "A baseline must be created with write_snapshot first."
        )
    with _locked(root, exclusive=False):
        try:
            return json.loads(mf.read_text())
        except json.JSONDecodeError as e:
            raise ToolError(f"Baseline manifest is corrupted (invalid JSON): {e}")


def write_snapshot(path: str) -> dict:
    """STATE-CHANGING. Creates or overwrites the baseline manifest. The client enforces HITL approval."""
    root = _dir(path)
    digests = _hash_files(root, _files(root))
    manifest = {
        "version": 1,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "algorithm": "sha256",
        "file_count": len(digests),
        "files": digests,
    }
    with _locked(root, exclusive=True):
        tmp = root / (MANIFEST_NAME + ".tmp")
        tmp.write_text(json.dumps(manifest, indent=2, sort_keys=True))
        os.replace(tmp, root / MANIFEST_NAME)  # atomic
    return {"manifest": MANIFEST_NAME, "directory": path, "file_count": len(digests),
            "created_utc": manifest["created_utc"]}


def compare_diffs(path: str) -> dict:
    root = _dir(path)
    baseline = read_json_state(path)["files"]
    current = _hash_files(root, _files(root))
    added = sorted(set(current) - set(baseline))
    removed = sorted(set(baseline) - set(current))
    modified = sorted(f for f in set(baseline) & set(current) if baseline[f] != current[f])
    return {
        "directory": path,
        "clean": not (added or removed or modified),
        "added": added,
        "modified": modified,
        "removed": removed,
        "unchanged_count": len(set(baseline) & set(current)) - len(modified),
    }


TOOLS = {f.__name__: f for f in (list_directory, hash_directory, read_json_state, write_snapshot, compare_diffs)}
