#!/usr/bin/env python3
"""
11-Step Race-Safe Artifact Promotion (trusted parent-side code only).

Implements the exact descriptor-based promotion procedure required by
skills/security-audit/SKILL.md and HUNTING.md:
1. Validate declared relative path (reject absolute, empty, `.`, `..`, control chars).
2. Walk each parent component from retained scratch-root descriptor with O_NOFOLLOW.
3. Open leaf O_NOFOLLOW | O_NONBLOCK | O_RDONLY.
4. Verify with fstat: regular file, st_nlink == 1, within per-file and cumulative byte limits.
5. Enforce limits while reading from that descriptor.
6. Copy verified size, repeat fstat, reject changed identity/type/nlink/size.
7. Walk destination parents from retained artifacts-root descriptor with O_NOFOLLOW,
   creating missing directories exclusively before reopening O_NOFOLLOW.
8. Create destination leaf exclusively (O_CREAT | O_EXCL | O_NOFOLLOW), verify fstat
   regular file with st_nlink == 1, and write from verified buffer.
"""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path
from typing import Dict, List


class PromotionError(Exception):
    """Raised when a scratch file violates any of the 11 safety checks."""


def _validate_relative_path(rel_path: str) -> List[str]:
    if not isinstance(rel_path, str) or not rel_path:
        raise PromotionError("Step 1 failed: path is empty or not a string")
    if rel_path.startswith("/") or rel_path.startswith("\\") or "\x00" in rel_path:
        raise PromotionError(f"Step 1 failed: absolute or NUL path rejected: {rel_path!r}")
    if "\\" in rel_path:
        raise PromotionError(f"Step 1 failed: backslash separator rejected: {rel_path!r}")

    parts = rel_path.split("/")
    for part in parts:
        if not part or part in (".", ".."):
            raise PromotionError(f"Step 1 failed: invalid path component {part!r} in {rel_path!r}")
        if any(ord(ch) < 32 for ch in part):
            raise PromotionError(f"Step 1 failed: control character in component {part!r}")
    return parts


def _open_root_dir_fd(root_path: Path) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    fd = os.open(str(root_path), flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode):
            raise PromotionError(f"Root is not a directory: {root_path}")
        return fd
    except Exception:
        os.close(fd)
        raise


def promote_agent_artifacts(
    *,
    scratch_root: Path,
    artifacts_root: Path,
    allowlisted_files: List[str],
    max_file_bytes: int = 262144,
    max_cumulative_bytes: int = 1048576,
) -> Dict[str, str]:
    """
    Promotes allowlisted relative files from `scratch_root` to `artifacts_root`
    following the 11-step race-safe descriptor protocol.
    Returns a dict mapping each promoted relative path to `"promoted"`.
    """
    scratch_dir_fd = _open_root_dir_fd(scratch_root)
    artifacts_dir_fd = _open_root_dir_fd(artifacts_root)
    cumulative_bytes = 0
    results: Dict[str, str] = {}

    dir_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    leaf_read_flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    leaf_write_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )

    try:
        for rel_path in allowlisted_files:
            parts = _validate_relative_path(rel_path)
            parent_parts, leaf_name = parts[:-1], parts[-1]

            # Step 2: Walk each parent component from retained scratch-root descriptor
            current_src_fd = os.dup(scratch_dir_fd)
            try:
                for comp in parent_parts:
                    next_fd = os.open(comp, dir_flags, dir_fd=current_src_fd)
                    os.close(current_src_fd)
                    current_src_fd = next_fd
                    st_dir = os.fstat(current_src_fd)
                    if not stat.S_ISDIR(st_dir.st_mode):
                        raise PromotionError(f"Step 2 failed: {comp!r} is not a real directory")

                # Step 3: Open the leaf no-follow and nonblocking
                try:
                    src_leaf_fd = os.open(leaf_name, leaf_read_flags, dir_fd=current_src_fd)
                except OSError as exc:
                    if exc.errno in (errno.ELOOP, errno.EACCES, errno.ENOENT):
                        raise PromotionError(f"Step 3 failed opening {rel_path!r}: {exc}") from exc
                    raise
            finally:
                os.close(current_src_fd)

            try:
                # Step 4: Verify with fstat that it is a regular file with link count 1 and within bounds
                st1 = os.fstat(src_leaf_fd)
                if not stat.S_ISREG(st1.st_mode):
                    raise PromotionError(f"Step 4 failed: {rel_path!r} is not a regular file")
                if st1.st_nlink != 1:
                    raise PromotionError(f"Step 4 failed: {rel_path!r} has link count {st1.st_nlink} != 1")
                if st1.st_size > max_file_bytes:
                    raise PromotionError(
                        f"Step 4 failed: {rel_path!r} size {st1.st_size} exceeds per-file limit {max_file_bytes}"
                    )
                if cumulative_bytes + st1.st_size > max_cumulative_bytes:
                    raise PromotionError(
                        f"Step 4 failed: {rel_path!r} exceeds cumulative byte limit {max_cumulative_bytes}"
                    )

                # Step 5: Enforce limits while reading from descriptor
                chunks: List[bytes] = []
                bytes_read = 0
                while True:
                    chunk = os.read(src_leaf_fd, min(65536, max_file_bytes - bytes_read + 1))
                    if not chunk:
                        break
                    bytes_read += len(chunk)
                    if bytes_read > st1.st_size or bytes_read > max_file_bytes:
                        raise PromotionError(f"Step 5 failed: file grew during read for {rel_path!r}")
                    chunks.append(chunk)

                data = b"".join(chunks)

                # Step 6: Verify exact size and repeat fstat to reject changed identity, type, nlink, or size
                st2 = os.fstat(src_leaf_fd)
                if (
                    bytes_read != st1.st_size
                    or st2.st_ino != st1.st_ino
                    or st2.st_dev != st1.st_dev
                    or not stat.S_ISREG(st2.st_mode)
                    or st2.st_nlink != 1
                    or st2.st_size != st1.st_size
                ):
                    raise PromotionError(f"Step 6 failed: file changed during read for {rel_path!r}")
            finally:
                os.close(src_leaf_fd)

            # Step 7: Walk destination parents from retained artifacts-root descriptor
            current_dst_fd = os.dup(artifacts_dir_fd)
            try:
                for comp in parent_parts:
                    try:
                        os.mkdir(comp, 0o700, dir_fd=current_dst_fd)
                    except FileExistsError:
                        pass
                    next_dst_fd = os.open(comp, dir_flags, dir_fd=current_dst_fd)
                    os.close(current_dst_fd)
                    current_dst_fd = next_dst_fd
                    st_dst_dir = os.fstat(current_dst_fd)
                    if not stat.S_ISDIR(st_dst_dir.st_mode):
                        raise PromotionError(
                            f"Step 7 failed: destination parent {comp!r} is not a real directory"
                        )

                # Step 8: Create destination leaf exclusively without following links
                dst_leaf_fd = os.open(leaf_name, leaf_write_flags, 0o600, dir_fd=current_dst_fd)
                try:
                    st_dst = os.fstat(dst_leaf_fd)
                    if not stat.S_ISREG(st_dst.st_mode) or st_dst.st_nlink != 1:
                        raise PromotionError(
                            f"Step 8 failed: destination {rel_path!r} is not an exclusive regular file"
                        )
                    total_written = 0
                    while total_written < len(data):
                        written = os.write(dst_leaf_fd, data[total_written:])
                        if written <= 0:
                            raise PromotionError(f"Step 8 failed: short write on {rel_path!r}")
                        total_written += written
                finally:
                    os.close(dst_leaf_fd)
            finally:
                os.close(current_dst_fd)

            cumulative_bytes += len(data)
            results[rel_path] = "promoted"
    finally:
        os.close(scratch_dir_fd)
        os.close(artifacts_dir_fd)

    return results
