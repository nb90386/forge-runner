import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

# Make the src layout importable during discovery without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from forge import Manager, SafetyError
from forge.__main__ import main
from forge.safety import branch_name, checked_path, identity, task_id, verify


def git(path, *args):
    return subprocess.run(["/usr/bin/git", "-C", str(path), *args], check=True,
                          env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1",
                               "GIT_CONFIG_GLOBAL": "/dev/null"},
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().strip()


class ValidationTests(unittest.TestCase):
    def test_ids(self):
        for bad in ("", "../x", "-x", "UPPER", "a/b", "x\n", "é", "x" * 49, None):
            with self.subTest(bad=bad), self.assertRaises(SafetyError):
                task_id(bad)
        self.assertEqual(task_id("job-23"), "job-23")

    def test_branches(self):
        for bad in ("-x", "a..b", "a.lock", "a@{x}", "a b", "a//b", "a/", "a/-b", "a\\b", "a\n"):
            with self.subTest(bad=bad), self.assertRaises(SafetyError):
                branch_name(bad)
        self.assertEqual(branch_name("forge/repo/task-123"), "forge/repo/task-123")


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        # Resolve the system temp alias only for creating our disposable fixture.
        self.temp = tempfile.TemporaryDirectory(dir=str(Path(tempfile.gettempdir()).resolve()))
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.work = self.root / "work"
        self.work.mkdir()
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        git(self.repo, "init", "-b", "main")
        git(self.repo, "config", "user.name", "Fixture")
        git(self.repo, "config", "user.email", "fixture@example.invalid")
        (self.repo / "tracked").write_text("initial\n")
        git(self.repo, "add", "tracked")
        git(self.repo, "commit", "-m", "fixture")
        self.manager = Manager(self.state, [self.root], self.work)

    def tearDown(self):
        self.temp.cleanup()

    def approve(self):
        return self.manager.approve("repo", self.repo)

    def test_lifecycle_persistence_idempotency_and_unique_branches(self):
        self.approve()
        self.assertTrue(self.approve()["already_approved"])
        first = self.manager.create("repo", "one")
        second = self.manager.create("repo", "two")
        self.assertNotEqual(first["branch"], second["branch"])
        self.assertNotEqual(first["path"], second["path"])
        manager = Manager(self.state, [self.root], self.work)
        self.assertTrue(manager.create("repo", "one")["already_exists"])
        self.assertFalse(manager.cleanup("repo", "one")["already_absent"])
        self.assertFalse(Path(first["path"]).exists())
        self.assertTrue(manager.cleanup("repo", "one")["already_absent"])
        self.assertEqual(git(self.repo, "rev-parse", first["branch"]), git(self.repo, "rev-parse", "HEAD"))

    def test_unapproved_and_dirty_source(self):
        with self.assertRaises(SafetyError):
            self.manager.create("repo", "one")
        self.approve()
        for filename in ("tracked", "untracked"):
            path = self.repo / filename
            original = path.read_bytes() if path.exists() else None
            path.write_text("changed")
            with self.assertRaises(SafetyError):
                self.manager.create("repo", "one")
            if original is None:
                path.unlink()
            else:
                path.write_bytes(original)
        self.assertEqual(list(self.work.iterdir()), [])

    def test_cleanup_protects_tracked_untracked_ignored_and_staged(self):
        self.approve()
        record = self.manager.create("repo", "one")
        path = Path(record["path"])
        for name in ("tracked", "untracked"):
            target = path / name
            original = target.read_bytes() if target.exists() else None
            target.write_text("valuable")
            with self.assertRaises(SafetyError):
                self.manager.cleanup("repo", "one")
            self.assertTrue(target.exists())
            if original is None:
                target.unlink()
            else:
                target.write_bytes(original)
        (path / "tracked").write_text("staged")
        git(path, "add", "tracked")
        with self.assertRaises(SafetyError):
            self.manager.cleanup("repo", "one")
        git(path, "restore", "--staged", "tracked")
        git(path, "restore", "tracked")
        (self.repo / ".git" / "info" / "exclude").write_text("ignored\n")
        (path / "ignored").write_text("valuable")
        with self.assertRaises(SafetyError):
            self.manager.cleanup("repo", "one")

    def test_dry_runs_do_not_mutate(self):
        self.manager.approve("repo", self.repo, dry_run=True)
        self.assertEqual(list(self.state.iterdir()), [])
        self.approve()
        before = (self.state / "registry.json").read_bytes()
        refs = git(self.repo, "show-ref")
        record = self.manager.create("repo", "one", dry_run=True)
        self.assertFalse(Path(record["path"]).exists())
        self.assertEqual(before, (self.state / "registry.json").read_bytes())
        self.assertEqual(refs, git(self.repo, "show-ref"))
        record = self.manager.create("repo", "one")
        self.manager.cleanup("repo", "one", dry_run=True)
        self.assertTrue(Path(record["path"]).exists())

    def test_cli_json(self):
        args = ["--registry", str(self.state), "--allowed-root", str(self.root),
                "--worktree-root", str(self.work), "--dry-run", "create", "repo", "one"]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(args), 1)
        self.assertEqual(json.loads(output.getvalue())["error"]["code"], "safety_refusal")
        self.approve()
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(args), 0)
        self.assertTrue(json.loads(output.getvalue())["dry_run"])

    def test_symlinks_and_noncanonical_paths(self):
        alias = self.root / "alias"
        alias.symlink_to(self.repo, target_is_directory=True)
        for path in (alias, str(self.root) + "/../repo", str(self.root) + "//repo"):
            with self.assertRaises(SafetyError):
                self.manager.approve("repo", path)
        (self.repo / ".git" / "evil").symlink_to(self.root)
        with self.assertRaises(SafetyError):
            self.approve()

    def test_replacement_detection(self):
        self.approve()
        self.repo.rename(self.root / "old")
        self.repo.mkdir()
        with self.assertRaises(SafetyError):
            self.manager.create("repo", "one")

    def test_worktree_replacement(self):
        self.approve()
        record = self.manager.create("repo", "one")
        path = Path(record["path"])
        path.rename(self.root / "saved")
        path.mkdir()
        with self.assertRaises(SafetyError):
            self.manager.cleanup("repo", "one")
        self.assertTrue(path.exists())

    def test_config_replacement_and_outside_root(self):
        self.approve()
        with self.assertRaises(SafetyError):
            Manager(self.state, [self.repo], self.work)
        moved = self.root / "new-work"
        moved.mkdir()
        with self.assertRaises(SafetyError):
            Manager(self.state, [self.root], moved).create("repo", "one")

    def test_unsafe_repository_config(self):
        git(self.repo, "config", "filter.evil.smudge", "never-run-this")
        with self.assertRaises(SafetyError):
            self.approve()

    def test_registry_symlink_and_permissions(self):
        target = self.root / "target"
        target.write_text("valuable")
        (self.state / "registry.json").symlink_to(target)
        with self.assertRaises(SafetyError):
            self.approve()
        self.assertEqual(target.read_text(), "valuable")
        self.state.chmod(0o755)
        with self.assertRaises(SafetyError):
            Manager(self.state, [self.root], self.work)

    def test_changed_worktree_branch(self):
        self.approve()
        record = self.manager.create("repo", "one")
        git(record["path"], "switch", "-c", "unexpected")
        with self.assertRaises(SafetyError):
            self.manager.cleanup("repo", "one")

    def test_interruption_blocks_retry(self):
        self.approve()
        from forge.manager import git as real_git

        def interrupt(repo, *args):
            if args[:2] == ("worktree", "add"):
                raise SafetyError("simulated interruption")
            return real_git(repo, *args)

        with patch("forge.manager.git", side_effect=interrupt):
            with self.assertRaises(SafetyError):
                self.manager.create("repo", "one")
        record = json.loads((self.state / "registry.json").read_text())["tasks"]["repo:one"]
        self.assertEqual(record["state"], "creating")
        with self.assertRaisesRegex(SafetyError, "manual reconciliation"):
            self.manager.create("repo", "one")
        self.assertEqual(list(self.work.iterdir()), [])

    def test_cleanup_interruption_blocks_retry(self):
        self.approve()
        self.manager.create("repo", "one")
        from forge.manager import git as real_git

        def interrupt(repo, *args):
            if args[:2] == ("worktree", "remove"):
                raise SafetyError("simulated interruption")
            return real_git(repo, *args)

        with patch("forge.manager.git", side_effect=interrupt):
            with self.assertRaises(SafetyError):
                self.manager.cleanup("repo", "one")
        with self.assertRaisesRegex(SafetyError, "manual reconciliation"):
            self.manager.cleanup("repo", "one")

    def test_maximum_ids_and_duplicate_approval(self):
        self.manager.approve("r" * 48, self.repo)
        record = self.manager.create("r" * 48, "t" * 48)
        self.assertTrue(Path(record["path"]).is_dir())
        with self.assertRaises(SafetyError):
            self.manager.approve("alias", self.repo)

    def test_unsafe_ancestor_and_corrupt_registry(self):
        self.repo.chmod(0o777)
        with self.assertRaises(SafetyError):
            self.approve()
        self.repo.chmod(0o755)
        (self.state / "registry.json").write_text("{invalid")
        (self.state / "registry.json").chmod(0o600)
        with self.assertRaises(SafetyError):
            self.approve()

    def test_registry_schema_refusal(self):
        for invalid in ([], {"version": 1, "config": None, "repositories": [], "tasks": {}},
                        {"version": 1, "config": None, "repositories": {"repo": []}, "tasks": {}}):
            registry = self.state / "registry.json"
            registry.write_text(json.dumps(invalid))
            registry.chmod(0o600)
            with self.subTest(invalid=invalid), self.assertRaises(SafetyError):
                self.approve()


if __name__ == "__main__":
    unittest.main()
