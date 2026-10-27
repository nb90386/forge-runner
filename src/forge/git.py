"""Only fixed, local Git operations. Never a shell or an execution facility."""
import os
import subprocess

from .safety import SafetyError


def git(repo, *args):
    # No inherited Git overrides, credential helpers, pagers, or user config.
    env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"}
    command = ["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-c",
               "core.fsmonitor=false", "-c", "core.untrackedCache=false",
               "-c", "protocol.allow=never", "-c", "submodule.recurse=false",
               "-C", str(repo), *args]
    try:
        result = subprocess.run(command, env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SafetyError("local Git operation failed") from exc
    if result.returncode:
        raise SafetyError("Git refused operation: " + result.stderr.decode("utf-8", "replace")[:1000])
    return result.stdout.decode("utf-8", "strict").strip()


def clean(repo):
    if git(repo, "status", "--porcelain=v1", "--untracked-files=all", "--ignored", "--ignore-submodules=none"):
        raise SafetyError("repository contains changes, untracked, or ignored files")
