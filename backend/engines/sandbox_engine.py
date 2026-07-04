"""
Sandbox Engine — Docker orchestrator for DroidRaksha APK Sandbox.

Responsibilities:
  1. Check if Docker daemon is reachable (graceful fallback if not)
  2. Build/pull the sandbox image (once)
  3. Spin up a container per APK, mount input/output dirs
  4. Stream container logs for real-time progress
  5. Parse /output/result.json and return structured dict

If Docker is unavailable → returns {"sandbox_available": False, "error": "..."}
so the rest of the pipeline is unaffected.
"""
from __future__ import annotations
import json
import os
import platform
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Optional

from loguru import logger

# ── Config ─────────────────────────────────────────────────────────────────────
JADX_BIN = os.getenv("JADX_BIN", "jadx")          # must be on PATH in container
SANDBOX_IMAGE   = os.getenv("SANDBOX_IMAGE", "droidraksha-sandbox:latest")
SANDBOX_DIR     = Path(__file__).parent.parent.parent / "sandbox"
SANDBOX_TIMEOUT = int(os.getenv("SANDBOX_TIMEOUT", "300"))   # 5 min max per APK
DOCKER_ENABLED  = os.getenv("SANDBOX_ENABLED", "true").lower() == "true"

# Host-side path for uploads dir — used to build host-resolvable paths for
# docker run -v mounts. When running inside a container, UPLOAD_DIR is the
# container-internal path, but the HOST daemon needs the real host path.
# Set UPLOADS_HOST_PATH in docker-compose to the absolute host path.
UPLOAD_DIR_CONTAINER = os.getenv("UPLOAD_DIR", "./uploads")   # path inside backend container
UPLOAD_DIR_HOST      = os.getenv("UPLOADS_HOST_PATH", UPLOAD_DIR_CONTAINER)  # path on host


# ── Docker availability check ──────────────────────────────────────────────────

def _docker_available() -> tuple[bool, str]:
    """Return (True, version_str) if Docker daemon is reachable, else (False, error)."""
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return True, result.stdout.strip()
        return False, result.stderr.strip() or "Docker daemon not responding"
    except FileNotFoundError:
        return False, "Docker CLI not found in PATH"
    except subprocess.TimeoutExpired:
        return False, "Docker daemon connection timed out"
    except Exception as e:
        return False, str(e)


# ── Image build/check ──────────────────────────────────────────────────────────

def _ensure_image() -> tuple[bool, str]:
    """
    Check if sandbox image exists locally. If not, build it.
    Returns (success, message).
    """
    # Check if image exists
    check = subprocess.run(
        ["docker", "image", "inspect", SANDBOX_IMAGE],
        capture_output=True, text=True, timeout=10,
    )
    if check.returncode == 0:
        return True, f"Image {SANDBOX_IMAGE} ready"

    # Build it
    logger.info(f"Building sandbox image {SANDBOX_IMAGE}...")
    if not SANDBOX_DIR.exists():
        return False, f"Sandbox directory not found: {SANDBOX_DIR}"

    build = subprocess.run(
        ["docker", "build", "-t", SANDBOX_IMAGE, str(SANDBOX_DIR)],
        capture_output=True, text=True, timeout=600,  # 10 min for first build
    )
    if build.returncode == 0:
        logger.info("Sandbox image built successfully")
        return True, "Image built successfully"
    return False, f"Image build failed: {build.stderr[-500:]}"


# ── Container runner ───────────────────────────────────────────────────────────

def _run_container(apk_path: str) -> dict:
    """
    Spin up sandbox container, mount APK, collect results.
    Returns the parsed JSON result from the container.

    IMPORTANT — Docker-in-Docker path translation:
    When the backend runs inside Docker, `apk_path` is a container-internal
    path (e.g. /app/uploads/abc.apk). We must translate it to the equivalent
    HOST path so the HOST Docker daemon can mount it into the sandbox container.
    """
    apk_abs = Path(apk_path).resolve()
    if not apk_abs.exists():
        return {"sandbox_available": False, "error": f"APK not found: {apk_path}"}

    # ── Translate container path → host path ─────────────────────────────────
    # If UPLOADS_HOST_PATH is set, replace the container uploads prefix with
    # the host uploads prefix so the HOST daemon can resolve the volume mount.
    upload_container = Path(UPLOAD_DIR_CONTAINER).resolve()
    upload_host      = Path(UPLOAD_DIR_HOST).resolve() if Path(UPLOAD_DIR_HOST).is_absolute() \
                       else (Path.cwd() / UPLOAD_DIR_HOST).resolve()

    try:
        # Will succeed only if apk_abs is under upload_container
        rel = apk_abs.relative_to(upload_container)
        apk_host_path = upload_host / rel
    except ValueError:
        # APK is not in the uploads dir — use as-is (may fail if not on host)
        apk_host_path = apk_abs

    logger.info(f"Sandbox APK host path: {apk_host_path}")

    # Use a named temp dir under uploads so it's on the same host-accessible volume
    # IMPORTANT: Docker requires absolute paths for -v mounts — resolve relative dirs
    upload_dir_abs = Path(UPLOAD_DIR_CONTAINER).resolve()
    tmp_out  = upload_dir_abs / f"sandbox_out_{uuid.uuid4().hex[:8]}"
    tmp_out.mkdir(parents=True, exist_ok=True)
    out_file = tmp_out / "result.json"

    # Host-side output dir
    try:
        rel_out = tmp_out.relative_to(upload_container)
        out_host_path = upload_host / rel_out
    except ValueError:
        out_host_path = tmp_out

    # Container name for tracking
    container_name = f"droidraksha-sandbox-{uuid.uuid4().hex[:8]}"

    # Format paths for docker CLI (forward slashes, Windows compatible)
    apk_mount = str(apk_host_path).replace("\\", "/")
    out_mount = str(out_host_path).replace("\\", "/")

    cmd = [
        "docker", "run",
        "--rm",                              # auto-remove after exit
        "--name", container_name,
        "--memory", "2g",                    # 2GB RAM limit
        "--cpus", "2",                       # 2 CPU cores max
        "--network", "none",                 # no network access from sandbox
        "--tmpfs", "/tmp:size=256m",          # allow writes to /tmp
        "--tmpfs", "/work:size=1g",           # decompile workspace
        "-v", f"{apk_mount}:/input/app.apk:ro",  # APK input (read-only)
        "-v", f"{out_mount}:/output",             # results output
        SANDBOX_IMAGE,
        "--apk", "/input/app.apk",
        "--out", "/output/result.json",
    ]

    logger.info(f"Starting sandbox container {container_name} for {apk_abs.name}")
    start = time.time()

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SANDBOX_TIMEOUT,
        )

        elapsed = round(time.time() - start, 1)
        logger.info(f"Container {container_name} exited in {elapsed}s (rc={proc.returncode})")

        if proc.stdout:
            for line in proc.stdout.strip().split("\n"):
                logger.debug(f"[container] {line}")

        if not out_file.exists():
            return {
                "sandbox_available": False,
                "error": f"Container produced no output. stderr: {proc.stderr[-300:]}",
                "container_logs": proc.stdout[-500:],
            }

        raw = out_file.read_text(encoding="utf-8")
        result = json.loads(raw)
        result["container_elapsed_sec"] = elapsed
        return result

    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "kill", container_name], capture_output=True)
        return {
            "sandbox_available": False,
            "error": f"Sandbox timed out after {SANDBOX_TIMEOUT}s",
        }
    except json.JSONDecodeError as e:
        return {
            "sandbox_available": False,
            "error": f"Invalid JSON from container: {e}",
        }
    except Exception as e:
        return {
            "sandbox_available": False,
            "error": f"Container error: {e}",
        }
    finally:
        # Clean up the temp output dir
        shutil.rmtree(tmp_out, ignore_errors=True)



# ── Public API ─────────────────────────────────────────────────────────────────

def run(apk_path: str) -> dict:
    """
    Main entry point. Run full sandbox analysis on an APK.

    Returns a dict with keys:
      sandbox_available (bool)
      behavioral_score  (dict: score, level, flags, summary)
      smali_analysis    (dict: api calls, crypto, antianalysis...)
      manifest          (dict)
      resources         (dict)
      error             (str | None)
    """
    if not DOCKER_ENABLED:
        return {
            "sandbox_available": False,
            "error": "Sandbox disabled via SANDBOX_ENABLED=false",
        }

    # 1. Check Docker daemon
    docker_ok, docker_msg = _docker_available()
    if not docker_ok:
        logger.warning(f"Docker unavailable: {docker_msg}")
        return {
            "sandbox_available": False,
            "error": f"Docker daemon not running: {docker_msg}. Start Docker Desktop to enable sandbox.",
        }

    logger.info(f"Docker OK (v{docker_msg})")

    # 2. Ensure sandbox image exists
    image_ok, image_msg = _ensure_image()
    if not image_ok:
        logger.error(f"Sandbox image unavailable: {image_msg}")
        return {
            "sandbox_available": False,
            "error": image_msg,
        }

    # 3. Run container
    return _run_container(apk_path)
