"""
Phase 6 — JADX Decompilation Engine
Runs jadx-cli as a subprocess to decompile APK DEX → Java source.

Two public functions:
  get_class_tree(apk_path)                  → nested package/class tree
  get_class_source(apk_path, class_path)    → Java source for one class

Decompilation output is cached on disk in /tmp/jadx_cache/<sha256>/ so
repeated requests for the same APK are instant.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from loguru import logger

# ── Configuration ────────────────────────────────────────────────────────────
JADX_BIN = os.getenv("JADX_BIN", "jadx")          # must be on PATH in container
JADX_CACHE_DIR = os.getenv("JADX_CACHE_DIR", "/tmp/jadx_cache")
JADX_TIMEOUT = int(os.getenv("JADX_TIMEOUT", "120"))  # seconds

os.makedirs(JADX_CACHE_DIR, exist_ok=True)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _sha256(apk_path: str) -> str:
    h = hashlib.sha256()
    with open(apk_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _cache_dir(apk_path: str) -> Path:
    sha = _sha256(apk_path)
    return Path(JADX_CACHE_DIR) / sha


def _is_cached(apk_path: str) -> bool:
    d = _cache_dir(apk_path)
    return d.exists() and any(d.rglob("*.java"))


def _run_jadx(apk_path: str, output_dir: Path) -> tuple[bool, str]:
    """Run jadx CLI. Returns (success, error_message)."""
    try:
        result = subprocess.run(
            [
                JADX_BIN,
                "--no-res",          # skip resources (only decompile code)
                "--show-bad-code",   # include partially-decompiled classes
                "--threads-count", "4",
                "--output-dir", str(output_dir),
                apk_path,
            ],
            capture_output=True,
            text=True,
            timeout=JADX_TIMEOUT,
        )
        if result.returncode != 0:
            err = result.stderr[:500] if result.stderr else "jadx exited non-zero"
            return False, err
        return True, ""
    except FileNotFoundError:
        return False, "jadx binary not found. Ensure Java + jadx are installed in the container."
    except subprocess.TimeoutExpired:
        return False, f"jadx timed out after {JADX_TIMEOUT}s (APK may be too large)"
    except Exception as e:
        return False, str(e)


def _ensure_decompiled(apk_path: str) -> tuple[Path | None, str]:
    """Ensure the APK is decompiled. Returns (sources_dir, error)."""
    out = _cache_dir(apk_path)
    sources_dir = out / "sources"

    if _is_cached(apk_path):
        logger.debug(f"JADX cache hit: {out}")
        return sources_dir, ""

    logger.info(f"Running jadx on {apk_path} → {out}")
    out.mkdir(parents=True, exist_ok=True)

    ok, err = _run_jadx(apk_path, out)
    if not ok:
        logger.warning(f"jadx failed: {err}")
        # Clean up partial output so next call retries
        shutil.rmtree(out, ignore_errors=True)
        return None, err

    logger.info(f"jadx complete → {sources_dir}")
    return sources_dir, ""


# ── Node builder ─────────────────────────────────────────────────────────────

def _build_tree(root: Path, base: Path) -> list[dict[str, Any]]:
    """
    Recursively build a sorted file-tree list of dicts:
      { name, path, type: "dir"|"file", children? }
    `path` is relative to `base` using forward slashes.
    """
    nodes: list[dict[str, Any]] = []
    try:
        entries = sorted(root.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
    except PermissionError:
        return nodes

    for entry in entries:
        rel = entry.relative_to(base).as_posix()
        if entry.is_dir():
            children = _build_tree(entry, base)
            if children:  # prune empty dirs
                nodes.append({"name": entry.name, "path": rel, "type": "dir", "children": children})
        elif entry.suffix == ".java":
            nodes.append({"name": entry.name, "path": rel, "type": "file"})

    return nodes


# ── Public API ───────────────────────────────────────────────────────────────

def get_class_tree(apk_path: str) -> dict[str, Any]:
    """
    Decompile the APK (cached) and return the package/class tree.

    Returns:
      { available: bool, tree: [...], error?: str, cached: bool }
    """
    was_cached = _is_cached(apk_path)
    sources_dir, err = _ensure_decompiled(apk_path)

    if sources_dir is None or not sources_dir.exists():
        return {"available": False, "tree": [], "error": err or "Decompilation produced no output"}

    tree = _build_tree(sources_dir, sources_dir)
    total_files = sum(1 for _ in sources_dir.rglob("*.java"))

    return {
        "available": True,
        "tree": tree,
        "total_classes": total_files,
        "cached": was_cached,
        "error": None,
    }


def get_class_source(apk_path: str, class_path: str) -> dict[str, Any]:
    """
    Return the decompiled Java source for a specific class file.

    `class_path` is a forward-slash path relative to the sources root,
    e.g. "com/example/myapp/MainActivity.java"

    Returns:
      { available: bool, source?: str, class_path: str, error?: str }
    """
    sources_dir, err = _ensure_decompiled(apk_path)
    if sources_dir is None:
        return {"available": False, "class_path": class_path, "source": None, "error": err}

    # Sanitize path to prevent directory traversal
    safe_path = Path(class_path).as_posix().lstrip("/")
    target = (sources_dir / safe_path).resolve()

    # Ensure target is inside sources_dir
    try:
        target.relative_to(sources_dir.resolve())
    except ValueError:
        return {"available": False, "class_path": class_path, "source": None, "error": "Invalid class path"}

    if not target.exists() or not target.suffix == ".java":
        return {"available": False, "class_path": class_path, "source": None, "error": "Class file not found"}

    try:
        source = target.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return {"available": False, "class_path": class_path, "source": None, "error": str(e)}

    return {
        "available": True,
        "class_path": class_path,
        "source": source,
        "error": None,
    }
