"""Explicit approval and local worktree lifecycle; no job execution."""
import os
import secrets

from .git import clean, git
from .registry import Registry
from .safety import (SafetyError, beneath, branch_name, checked_path, identity,
                     task_id, verify)


def result(operation, dry_run, **details):
    return {"ok": True, "operation": operation, "dry_run": dry_run, **details}


class Manager:
    def __init__(self, registry, allowed_roots, worktree_root):
        self.registry = Registry(registry)
        self.roots = [str(checked_path(root)) for root in allowed_roots]
        if not self.roots:
            raise SafetyError("at least one allowed root is required")
        self.work = beneath(worktree_root, self.roots)
        if not self.work.is_dir() or any(self.work == root or self.work in root.parents or root in self.work.parents
                                          for root in [self.registry.directory]):
            raise SafetyError("worktree and registry directories must be separate")
        self.config = {"roots": [identity(root) for root in self.roots], "work": identity(self.work),
                       "registry": identity(self.registry.directory)}

    def _config(self, data):
        for chain in self.config["roots"] + [self.config["work"], self.config["registry"]]:
            verify(chain[-1][0], chain)
        if data["config"] is not None and data["config"] != self.config:
            raise SafetyError("configuration or configured path identity changed")
        data["config"] = self.config

    def _repository(self, path):
        path = beneath(path, self.roots)
        if not path.is_dir() or not (path / ".git").is_dir():
            raise SafetyError("only standalone non-bare repositories are supported")
        checked_path(path / ".git")
        # Reject symlinked metadata, including objects, refs, config, and hooks.
        for directory, dirs, files in os.walk(path / ".git", followlinks=False):
            for name in dirs + files:
                checked_path(os.path.join(directory, name))
        safe_keys = {"core.repositoryformatversion", "core.filemode", "core.bare",
                     "core.logallrefupdates", "core.ignorecase", "core.precomposeunicode",
                     "user.name", "user.email"}
        config = git(path, "config", "--local", "--no-includes", "--list")
        if any(line.split("=", 1)[0].lower() not in safe_keys for line in config.splitlines()):
            raise SafetyError("unsupported repository config; includes, filters and helpers are forbidden")
        if git(path, "rev-parse", "--show-toplevel") != str(path):
            raise SafetyError("repository root mismatch")
        if git(path, "rev-parse", "--is-bare-repository") != "false":
            raise SafetyError("bare repository")
        git(path, "rev-parse", "--verify", "HEAD^{commit}")
        if any(entry.startswith("160000 ") for entry in git(path, "ls-files", "--stage").splitlines()):
            raise SafetyError("submodules are unsupported")
        return path

    def approve(self, repository_id, path, *, dry_run=False):
        repository_id = task_id(repository_id)
        with self.registry.locked(write=not dry_run) as data:
            self._config(data)
            path = self._repository(path)
            if path == self.work or self.work in path.parents or path in self.work.parents:
                raise SafetyError("source and worktree root must be disjoint")
            if path == self.registry.directory or path in self.registry.directory.parents or self.registry.directory in path.parents:
                raise SafetyError("source and registry must be disjoint")
            entry = {"path": str(path), "identity": identity(path), "git_identity": identity(path / ".git")}
            previous = data["repositories"].get(repository_id)
            if previous and previous != entry:
                raise SafetyError("repository ID already approved for a different identity")
            if any(key != repository_id and item["path"] == str(path) for key, item in data["repositories"].items()):
                raise SafetyError("repository already has another ID")
            data["repositories"][repository_id] = entry
            return result("approve", dry_run, repository_id=repository_id, path=str(path), already_approved=bool(previous))

    def _approved(self, data, repository_id):
        entry = data["repositories"].get(task_id(repository_id))
        if not entry:
            raise SafetyError("repository is not explicitly approved")
        verify(entry["path"], entry["identity"])
        verify(os.path.join(entry["path"], ".git"), entry["git_identity"])
        return self._repository(entry["path"])

    def _task(self, data, repository_id, identifier):
        task_id(identifier)
        return data["tasks"].get(repository_id + ":" + identifier)

    def _validate_worktree(self, repo, record):
        if record.get("state") != "active":
            raise SafetyError("interrupted operation requires manual reconciliation; automatic mutation refused")
        path = checked_path(record["path"])
        if path.parent != self.work:
            raise SafetyError("invalid registered worktree path")
        branch_name(record["branch"])
        verify(path, record["identity"])
        checked_path(path / ".git")
        if git(path, "rev-parse", "--git-common-dir") != str(repo / ".git"):
            raise SafetyError("worktree common directory mismatch")
        if git(path, "symbolic-ref", "--quiet", "HEAD") != "refs/heads/" + record["branch"]:
            raise SafetyError("worktree branch changed")
        return path

    def create(self, repository_id, identifier, *, dry_run=False):
        task_id(identifier)
        with self.registry.locked(write=not dry_run) as data:
            return self._create_locked(data, repository_id, identifier, dry_run=dry_run)

    def _create_locked(self, data, repository_id, identifier, *, dry_run=False, commit=None):
        self._config(data)
        repo = self._approved(data, repository_id)
        previous = self._task(data, repository_id, identifier)
        if previous:
            self._validate_worktree(repo, previous)
            return result("create", dry_run, already_exists=True, **previous)
        if commit is not None and git(repo, "rev-parse", "--verify", "HEAD^{commit}") != commit:
            raise SafetyError("approved commit differs from local HEAD")
        clean(repo)
        nonce = secrets.token_hex(12)
        branch = branch_name("forge/" + repository_id + "/" + identifier + "-" + nonce)
        path = checked_path(self.work / (repository_id + "-" + identifier + "-" + nonce), missing=True)
        if path.exists():
            raise SafetyError("worktree destination already exists")
        record = {"path": str(path), "branch": branch}
        if not dry_run:
            self._config(data)
            self._approved(data, repository_id)
            record["state"] = "creating"
            data["tasks"][repository_id + ":" + identifier] = record
            self.registry.checkpoint(data)
            git(repo, "worktree", "add", "--no-track", "-b", branch, str(path), commit or "HEAD")
            self._config(data)
            record["identity"] = identity(path)
            record["state"] = "active"
            self._validate_worktree(repo, record)
            data["tasks"][repository_id + ":" + identifier] = record
        return result("create", dry_run, already_exists=False, **record)

    def cleanup(self, repository_id, identifier, *, dry_run=False):
        task_id(identifier)
        with self.registry.locked(write=not dry_run) as data:
            self._config(data)
            repo = self._approved(data, repository_id)
            record = self._task(data, repository_id, identifier)
            if record is None:
                return result("cleanup", dry_run, already_absent=True)
            path = self._validate_worktree(repo, record)
            clean(path)
            if not dry_run:
                self._config(data)
                self._approved(data, repository_id)
                self._validate_worktree(repo, record)
                record["state"] = "removing"
                self.registry.checkpoint(data)
                # Git's own non-force removal checks dirtiness again.
                git(repo, "worktree", "remove", str(path))
                del data["tasks"][repository_id + ":" + identifier]
            return result("cleanup", dry_run, already_absent=False, path=str(path), branch=record["branch"], branch_preserved=True)
