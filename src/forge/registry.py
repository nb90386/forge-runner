"""Private, atomic JSON registry, serialized with a no-follow advisory lock."""
from contextlib import contextmanager
import fcntl
import json
import os
import stat
import tempfile

from .safety import SafetyError, checked_path, identity, verify


class Registry:
    def __init__(self, directory):
        self.directory = checked_path(directory)
        info = self.directory.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise SafetyError("registry directory must be owned by this user and mode 0700")
        self.anchor = identity(self.directory)

    def checkpoint(self, data):
        """Persist intent while the caller holds the directory lock."""
        verify(self.directory, self.anchor)
        fd, name = tempfile.mkstemp(prefix=".registry-", dir=self.directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            verify(self.directory, self.anchor)
            os.replace(name, self.directory / "registry.json")
            directory = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    @contextmanager
    def locked(self, *, write):
        verify(self.directory, self.anchor)
        directory = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptor = None
        try:
            if os.fstat(directory).st_ino != self.anchor[-1][2]:
                raise SafetyError("registry directory replaced")
            # A dry run uses the directory itself for locking and creates no files.
            fcntl.flock(directory, fcntl.LOCK_EX if write else fcntl.LOCK_SH)
            try:
                descriptor = os.open("registry.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            except FileNotFoundError:
                data = {"version": 1, "config": None, "repositories": {}, "tasks": {}}
            else:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
                    raise SafetyError("unsafe registry file")
                with os.fdopen(descriptor, encoding="utf-8") as handle:
                    descriptor = None
                    data = json.load(handle)
                if (not isinstance(data, dict) or data.get("version") != 1
                        or not all(key in data for key in ("config", "repositories", "tasks"))
                        or not isinstance(data["repositories"], dict)
                        or not isinstance(data["tasks"], dict)
                        or any(not isinstance(item, dict) for item in
                               [*data["repositories"].values(), *data["tasks"].values()])):
                    raise SafetyError("unsupported registry")
            yield data
            if write:
                self.checkpoint(data)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            raise SafetyError("unsafe or invalid registry: " + str(exc)) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(directory)
