"""Filesystem helpers: bounded reads, exclusive 0600 writes, fsync+rename."""

from __future__ import annotations

import os

from .errors import SunlightError


def read_file_bytes(path: str, max_bytes: int = 32 * 1024 * 1024) -> bytes:
    st = os.lstat(path)
    if not os.path.isfile(path):
        raise SunlightError("IO_ERROR")
    if st.st_size > max_bytes:
        raise SunlightError("BODY_LIMIT")
    with open(path, "rb") as f:
        return f.read()


def write_file_exclusive(path: str, data, mode: int = 0o600) -> None:
    """Exclusive-create write (no overwrite flag in v1) with fsync."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except FileExistsError as e:
        raise SunlightError("OUTPUT_EXISTS") from e
    try:
        buf = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        os.write(fd, buf)
        os.fsync(fd)
    finally:
        os.close(fd)


def write_file_atomic(path: str, data, mode: int = 0o600) -> None:
    """fsync a temp file then atomically rename it into place."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.tmp-{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, data if isinstance(data, bytes) else data.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def dir_fsync(path: str) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass
