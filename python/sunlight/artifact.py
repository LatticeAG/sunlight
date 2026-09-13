"""Artifact profiles (spec §2.1): bytes/1, jcs/1, tree/1.

Tree enumeration rejects symlinks, multiply-hardlinked names, non-regular
files, invalid/traversal paths, and case-insensitive collisions; manifests
sort by path before hashing.  All hashing is bounded and streaming.
"""

from __future__ import annotations

import hashlib
import os
import tempfile

from .domains import B
from .errors import SunlightError
from .jcs import jcs
from .schema import (
    MAX_MANIFEST_BYTES, MAX_MANIFEST_FILES, is_valid_tree_path, parse_tree_manifest,
)
from .strictjson import parse_strict_json

_HASH_BUF = 4 * 1024 * 1024
_JCS_RAW_CAP = 1024 * 1024


def hash_file_bytes(path: str) -> dict:
    st = os.lstat(path)
    if not os.path.isfile(path) or os.path.islink(path):
        raise SunlightError("ARTIFACT_CHANGED", cause=ValueError("not a regular file"))
    h = hashlib.sha256()
    total = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(_HASH_BUF)
            if not chunk:
                break
            h.update(chunk)
            total += len(chunk)
    return {"digest": "sha256:" + h.hexdigest(), "bytes": total}


def _snap(path: str):
    st = os.lstat(path)
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)


def hash_jcs_file(path: str) -> dict:
    st = os.lstat(path)
    if not os.path.isfile(path) or os.path.islink(path):
        raise SunlightError("ARTIFACT_CHANGED")
    if st.st_size > _JCS_RAW_CAP:
        raise SunlightError("BODY_LIMIT")
    with open(path, "rb") as f:
        raw = f.read()
    canon = jcs(parse_strict_json(raw))
    return {"profile": "jcs/1", "digest": B(canon), "bytes": len(canon)}


def enumerate_tree(root: str) -> list[str]:
    st = os.lstat(root)
    if not os.path.isdir(root) or os.path.islink(root):
        raise SunlightError("USAGE", cause=ValueError("tree root is not a directory"))
    out: list[str] = []
    stack = [(root, "")]
    while stack:
        d, rel = stack.pop()
        for name in os.listdir(d):
            full = os.path.join(d, name)
            r = name if rel == "" else rel + "/" + name
            st = os.lstat(full)
            if os.path.islink(full):
                raise SunlightError("SCHEMA_INVALID", cause=ValueError(f"symlink rejected: {r}"))
            if os.path.isdir(full):
                stack.append((full, r))
                continue
            if not os.path.isfile(full):
                raise SunlightError("SCHEMA_INVALID", cause=ValueError(f"non-regular file: {r}"))
            if st.st_nlink > 1:
                raise SunlightError("SCHEMA_INVALID", cause=ValueError(f"multiply-linked file: {r}"))
            if not is_valid_tree_path(r):
                raise SunlightError("SCHEMA_INVALID", cause=ValueError(f"invalid tree path: {r}"))
            out.append(r)
    out.sort()
    if len(out) > MAX_MANIFEST_FILES:
        raise SunlightError("BODY_LIMIT")
    fold = set()
    for p in out:
        f = p.lower()
        if f in fold:
            raise SunlightError("SCHEMA_INVALID", cause=ValueError(f"case collision: {p}"))
        fold.add(f)
    return out


def stage_tree(root: str, staging_dir: str):
    """Copy the tree into private staging, hashing the staged copies."""
    rels = enumerate_tree(root)
    files = []
    for rel in rels:
        src = os.path.join(root, *rel.split("/"))
        dst = os.path.join(staging_dir, *rel.split("/"))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        before = _snap(src)
        fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with open(src, "rb") as f:
                while True:
                    chunk = f.read(_HASH_BUF)
                    if not chunk:
                        break
                    os.write(fd, chunk)
            os.fsync(fd)
        finally:
            os.close(fd)
        if _snap(src) != before:
            raise SunlightError("ARTIFACT_CHANGED", cause=ValueError(f"changed during capture: {rel}"))
        files.append({"path": rel, **hash_file_bytes(dst)})
    manifest = parse_tree_manifest({"v": "sunlight.tree/1", "files": files})
    if len(jcs(manifest)) > MAX_MANIFEST_BYTES:
        raise SunlightError("BODY_LIMIT")
    return manifest


def manifest_artifact(manifest) -> dict:
    canon = jcs(manifest)
    return {"profile": "tree/1", "digest": B(canon), "bytes": len(canon)}


def hash_artifact(path: str, profile: str) -> dict:
    if profile == "bytes/1":
        st = os.lstat(path)
        if not os.path.isfile(path) or os.path.islink(path):
            raise SunlightError("USAGE", cause=ValueError("not a regular file"))
        before = _snap(path)
        r = hash_file_bytes(path)
        if _snap(path) != before:
            raise SunlightError("ARTIFACT_CHANGED")
        return {"profile": "bytes/1", "digest": r["digest"], "bytes": r["bytes"]}
    if profile == "jcs/1":
        return hash_jcs_file(path)
    if profile == "tree/1":
        staging = tempfile.mkdtemp(prefix="sunlight-tree-")
        try:
            os.chmod(staging, 0o700)
            return manifest_artifact(stage_tree(path, staging))
        finally:
            import shutil

            shutil.rmtree(staging, ignore_errors=True)
    raise SunlightError("USAGE", cause=ValueError("unknown profile"))
