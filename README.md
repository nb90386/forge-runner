# Forge 0.5 — milestone A

Python standard-library library for explicitly approved local Git repositories
and task worktrees. Requires Python 3.9+ and `/usr/bin/git` on macOS (also tested
with POSIX directory locking). No package installation or network access needed.

`safety.py` validates paths and names and records ancestor device/inode identities.
`registry.py` serializes operations with advisory directory locks and atomically
replaces a private JSON registry with fsync. `manager.py` approves repositories,
checks status, creates worktrees, and removes clean worktrees. `git.py` invokes
fixed local Git argument lists with a minimal environment and disabled hooks,
fsmonitor, submodule recursion, and transport. The CLI only inspects dry runs.

## Library

Prepare three disjoint directories yourself: a standalone source repository with
a committed HEAD, an empty worktree directory, and a private mode-0700 registry
directory. Source and worktree directories must be strict descendants of allowed
roots. Use absolute paths with canonical spelling; on macOS `/tmp` and `/var`
often require their `/private/...` spelling. The library creates no parent dirs.

```python
from forge import Manager, SafetyError

manager = Manager('/private/local/state', ['/private/local'], '/private/local/work')
approval = manager.approve('example', '/private/local/source')  # explicit approval
plan = manager.create('example', 'task-1', dry_run=True)
created = manager.create('example', 'task-1')
removed = manager.cleanup('example', 'task-1')
```

Successful calls return JSON-serializable dictionaries with `ok`, `operation`,
`dry_run`, and operation-specific fields. Refusals raise `SafetyError`; the CLI
turns these into JSON errors and exits 1. Argument syntax errors exit 2 via argparse.
Approval and successful creation/cleanup are idempotent. Each new task lifecycle
gets a random 96-bit suffix in its branch and directory. Cleanup preserves the
branch and its commits, and refuses staged, unstaged, untracked, or ignored files.
Repeated creation returns the existing worktree, including if it has local edits.

IDs are lowercase ASCII letters/digits/hyphens, start with a letter or digit, and
are at most 48 characters. Branches use a conservative ASCII subset, at most 160
characters, and are generated internally; callers cannot supply Git arguments.

## Commands

Run from this checkout:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
PYTHONPATH=src python3 -m forge --help
PYTHONPATH=src python3 -m forge --registry /private/local/state --allowed-root /private/local --worktree-root /private/local/work --dry-run approve example /private/local/source
PYTHONPATH=src python3 -m forge --registry /private/local/state --allowed-root /private/local --worktree-root /private/local/work --dry-run create example task-1
PYTHONPATH=src python3 -m forge --registry /private/local/state --allowed-root /private/local --worktree-root /private/local/work --dry-run cleanup example task-1
```

Dry runs inspect the current filesystem and Git state without writing the registry,
creating branches/directories, or deleting files. Generated dry-run names are
previews, not reservations. A dry-run approval does not authorize later operations.

## Restrictions and unresolved risks

- A worktree is **not a security boundary**. No jobs or user commands are executed.
  A future runner must use a separate OS account or container, with explicit mounts,
  restricted credentials/network, and no write access to this control registry.
- Trust the current account, Git binary, and filesystem. No-follow checks reject
  symlinks in control paths and Git metadata, foreign ownership, broadly writable
  paths, and recorded identity changes. Root-owned sticky ancestors are permitted.
  Worktree content may contain ordinary tracked symlinks; no jobs follow them here.
- Git accepts pathname arguments rather than directory descriptors. Checks before
  and after operations cannot eliminate races with a hostile same-account/root
  process or out-of-band Git operations. Advisory locks serialize cooperating
  managers only. Do not use shared mutable directories or hostile repositories;
  these conditions require OS isolation, not more pathname checks.
- Only standalone non-bare repositories are approved. Linked-worktree sources,
  symlinked Git metadata, custom local configuration, includes, filters, helpers,
  and extensions are rejected. The allowlist permits only basic core settings and
  user name/email. Submodules and LFS workflows are not supported. Existing hooks
  never run. Creation requires a fully clean source, including ignored files.
- Configured root, registry, source, `.git`, and worktree ancestor identities are
  pinned. Moving/replacing paths or changing configuration causes refusal.
  Filesystem inode reuse and hostile filesystem semantics remain limitations.
- Before Git mutations, durable `creating`/`removing` intent is saved. An interrupted
  operation blocks automatic retries and cleanup; manually inspect the registry,
  `git worktree list`, directories, and preserved branches before reconciling.
  There is no automatic crash recovery or approval revocation API in this milestone.
- Standard-library subprocess timeouts cannot make Git mutations transactional.
  Failure can leave a worktree or branch; the durable intent prevents blind retries.
  Local disk exhaustion and power-loss guarantees depend on the filesystem.

Tests use only disposable repositories and exercise lifecycle persistence,
idempotency, uniqueness, path/config replacement, symlinks, invalid identifiers,
dirty-work protection, dry-run JSON behavior, and interrupted-operation refusals.
