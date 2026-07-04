"""
P2 — APK File Tree & Manifest XML Extractor
Parses the APK ZIP structure and returns a nested JSON tree.
Flags suspicious entries: hidden DEX files, .so in assets, etc.
"""
from __future__ import annotations
import zipfile
import os
from typing import Any
from loguru import logger

# Suspicious pattern definitions
SUSPICIOUS_EXTENSIONS = {".so", ".jar", ".dex", ".bin", ".dat", ".enc", ".pak", ".png"}
SUSPICIOUS_PATHS = {"assets/", "res/raw/"}
DANGEROUS_FILENAMES = {
    "classes2.dex", "classes3.dex", "classes4.dex",  # multi-dex hidden payloads
    "core.dex", "payload.dex", "update.dex", "patch.dex",
}
_SYSTEM_PKGS = {"com.android", "android.", "androidx.", "kotlin.", "kotlinx.", "org.jetbrains"}


def _is_suspicious(name: str, ext: str) -> str | None:
    """Return a warning string if the file is suspicious, else None."""
    lower = name.lower()
    basename = os.path.basename(lower)

    if basename in DANGEROUS_FILENAMES:
        return f"Hidden/extra DEX payload: {basename}"

    # .so native library in assets (not lib/) is red flag
    if ext == ".so" and "assets/" in lower:
        return "Native .so library hidden in assets (dropper pattern)"

    # Encrypted-looking binaries in assets/raw
    if ext in {".bin", ".enc", ".dat"} and any(p in lower for p in SUSPICIOUS_PATHS):
        return f"Encrypted/obfuscated binary in {lower.split('/')[0]}/"

    # Disguised files (image extension with non-image magic)
    if ext == ".png" and "assets/" in lower and lower.endswith(".png"):
        return "Possible disguised binary with .png extension in assets"

    return None


def _build_tree(entries: list[tuple[str, int]]) -> list[dict]:
    """Convert a flat list of (path, size) into a nested tree structure."""
    root: list[dict] = []
    path_map: dict[str, dict] = {}

    for path, size in sorted(entries):
        parts = path.strip("/").split("/")
        current_level = root

        for i, part in enumerate(parts):
            full_path = "/".join(parts[: i + 1])
            is_last = i == len(parts) - 1

            if full_path not in path_map:
                ext = os.path.splitext(part)[1].lower() if is_last else ""
                node: dict[str, Any] = {
                    "name": part,
                    "path": full_path,
                    "type": "file" if is_last else "dir",
                }
                if is_last:
                    node["size"] = size
                    node["ext"] = ext
                    warning = _is_suspicious(full_path, ext)
                    if warning:
                        node["suspicious"] = True
                        node["warning"] = warning
                else:
                    node["children"] = []

                path_map[full_path] = node
                current_level.append(node)

            if not is_last:
                current_level = path_map[full_path].get("children", [])

    return root


def _count_tree_stats(entries: list[tuple[str, int]]) -> dict:
    total_files = len(entries)
    dex_files = [e for e in entries if e[0].endswith(".dex")]
    so_files = [e for e in entries if e[0].endswith(".so")]
    suspicious = [e for e in entries if _is_suspicious(e[0], os.path.splitext(e[0])[1].lower())]
    total_size = sum(e[1] for e in entries)

    return {
        "total_files": total_files,
        "total_size_bytes": total_size,
        "dex_count": len(dex_files),
        "dex_files": [e[0] for e in dex_files],
        "native_libs": len(so_files),
        "suspicious_count": len(suspicious),
        "suspicious_files": [e[0] for e in suspicious],
    }


def extract_file_tree(apk_path: str) -> dict:
    """
    Parse APK ZIP structure → nested JSON tree + stats.
    Returns dict with keys: tree, stats, error (if any).
    """
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            entries: list[tuple[str, int]] = []
            for info in zf.infolist():
                if not info.filename.endswith("/"):  # skip directory entries
                    entries.append((info.filename, info.file_size))

        tree = _build_tree(entries)
        stats = _count_tree_stats(entries)

        return {
            "tree": tree,
            "stats": stats,
            "error": None,
        }
    except zipfile.BadZipFile:
        logger.error(f"Not a valid ZIP/APK: {apk_path}")
        return {"tree": [], "stats": {}, "error": "Not a valid APK (bad ZIP format)"}
    except Exception as e:
        logger.error(f"File tree extraction failed: {e}")
        return {"tree": [], "stats": {}, "error": str(e)}


def get_manifest_xml(apk_path: str) -> dict:
    """
    Extract and return the decoded AndroidManifest.xml as a readable string.
    Uses Androguard's AXMLPrinter for binary XML decoding.
    Returns dict: {xml_string, error}.
    """
    try:
        # Try androguard first (best quality decode)
        try:
            from androguard.core.bytecodes.apk import APK
            apk = APK(apk_path)
            xml_bytes = apk.get_android_manifest_xml()
            # androguard returns lxml element
            try:
                from lxml import etree
                xml_str = etree.tostring(xml_bytes, pretty_print=True, encoding="unicode")
            except Exception:
                xml_str = str(xml_bytes)
            return {"xml_string": xml_str, "error": None}
        except Exception as ag_err:
            logger.warning(f"Androguard manifest decode failed: {ag_err}, trying raw extract")

        # Fallback: extract raw binary XML and try to decode
        with zipfile.ZipFile(apk_path, "r") as zf:
            if "AndroidManifest.xml" not in zf.namelist():
                return {"xml_string": None, "error": "AndroidManifest.xml not found in APK"}
            raw = zf.read("AndroidManifest.xml")

        # Try to parse as plain text (some APKs have pre-decoded manifests)
        if raw.startswith(b"<?xml"):
            return {"xml_string": raw.decode("utf-8", errors="replace"), "error": None}

        # Binary AXML — return hex fallback notice
        return {
            "xml_string": None,
            "error": "Binary XML — install androguard for full decode: pip install androguard",
        }

    except Exception as e:
        logger.error(f"Manifest XML extraction failed: {e}")
        return {"xml_string": None, "error": str(e)}
