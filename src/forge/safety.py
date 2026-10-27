"""Conservative path checks, recorded identities, and strict identifiers."""
import os
from pathlib import Path
import re
import stat


class SafetyError(Exception):
    pass


def task_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,47}", value):
        raise SafetyError("invalid task or repository ID")
    return value


def branch_name(value):
    if not isinstance(value, str) or len(value) > 160 or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9/_-]*", value):
        raise SafetyError("invalid branch name")
    if any(not part or part.startswith("-") for part in value.split("/")):
        raise SafetyError("invalid branch component")
    return value


def checked_path(value, *, missing=False):
    """Require absolute canonical spelling and no symlink in any component.

    Also reject foreign-owned or broadly writable ancestors (except root-owned
    sticky directories such as /private/tmp). No resolve() follows untrusted links.
    """
    raw = os.fspath(value)
    path = Path(raw)
    if not path.is_absolute() or raw != str(path) or any(x in (".", "..") for x in raw.split("/")):
        raise SafetyError("path must have canonical absolute spelling")
    current = Path("/")
    for index, component in enumerate(path.parts[1:]):
        current /= component
        try:
            info = current.lstat()
        except FileNotFoundError:
            if missing and index == len(path.parts) - 2:
                return path
            raise SafetyError("missing path component") from None
        if stat.S_ISLNK(info.st_mode):
            raise SafetyError("symlinks are forbidden")
        if info.st_uid not in (0, os.getuid()):
            raise SafetyError("foreign-owned path")
        sticky_root = info.st_uid == 0 and stat.S_ISDIR(info.st_mode) and info.st_mode & stat.S_ISVTX
        if info.st_mode & 0o022 and not sticky_root:
            raise SafetyError("group/world writable path")
        if current != path and not stat.S_ISDIR(info.st_mode):
            raise SafetyError("non-directory ancestor")
    return path


def identity(path):
    path = checked_path(path)
    return [[str(p), p.lstat().st_dev, p.lstat().st_ino] for p in reversed((path, *path.parents))]


def verify(path, expected):
    if identity(path) != expected:
        raise SafetyError("path identity changed")


def beneath(path, roots):
    path = checked_path(path)
    if not any(path != Path(root) and Path(root) in path.parents for root in roots):
        raise SafetyError("path is outside allowed roots (or equals a root)")
    return path
