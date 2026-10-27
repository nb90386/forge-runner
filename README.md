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
python3 -m unittest discover -s tests -v
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

## Forge 0.5B — offline approved-job dispatch adapter

`forge.dispatch` adds a read-only metadata client, explicit Mac-local bindings,
strict immutable approval envelopes, and durable preparation manifests. It uses
only the standard library and the manager's fixed local Git operations. It never
runs request content, claims/completes queue jobs, merges, pushes, or deploys.
No dependencies were added. No live HTTP transport is implemented or enabled.

### Inspected contracts and integration blocker

Inspected local production source in
`~/Forge/projects/forge-control-development/forge/{api,implementation,projects,db,paths}.py`
and the queue routes in its `server.py`, plus
`~/Forge/worker/mac-worker.py` (source only; no credential files).

The existing worker uses a bearer token through its `token()` provider, an HTTP
loopback base, GET `/api/worker/claim`, and POST `/api/worker/complete`. Claim is
state changing despite being GET; neither route is used here. Existing worker
planning subprocesses are not imported or reused.

Production already exposes read-only
`GET /api/ui/implementation-jobs?status=approved` to a worker bearer token. Its
rows include `id`, `project_id`, `task_id`, `title`, `description`, `status`,
`requested_by`, `created`, `updated`, `decided_by`, `decided_at`, `decision_note`,
and joined `project_name`, `project_path`, `project_status`. Request content and
final decisions are protected by SQLite triggers. The server records a digest in
an audit event, but it hashes the VPS path and does not return it as a versioned,
portable approval envelope. Project device/inode checks validate VPS files only.

**Missing capability:** a versioned approved-job metadata response binding the
immutable request to a portable repository identity, a full approved commit SHA,
a stable approval ID, explicit expiry/freshness semantics, and a digest of all
approved request fields. Approval metadata must be delivered consistently with
current active-project status, and polling needs pagination/completeness semantics
for more than the existing maximum 200 rows. There is no safe production mapping
for the envelope below today. The adapter deliberately rejects existing rows;
it does not derive missing values from VPS paths, local HEAD, or audit guesses.
Production source and services are unchanged.

### Offline interface

1. Explicitly approve the Mac repository using `Manager.approve(local_id, path)`.
2. Locally configure `Dispatcher(manager).bind(project_id, local_id,
   repository_identity)`. These IDs and identity labels are operator-selected;
   they are never inferred from a server pathname, URL, or basename. The binding
   is immutable. The manager pins the actual Mac filesystem identities.
3. Supply `DispatchClient(MockTransport(responses), token_provider)` with mocked
   `(HTTP status, JSON bytes)` responses. In a future reviewed live integration,
   `token_provider` should be the existing worker's `token` function, passed as a
   callable, reusing its bearer credential in memory. This adapter does not read,
   store, copy, or log credentials. Tests use dummy strings only.
4. Call `client.poll()` and then `dispatcher.prepare(job)` for each envelope.
   All jobs in a poll are validated before any are returned. Failures raise
   `SafetyError`; never proceed after a metadata failure. No cached fallback.
   The returned dictionary is a JSON manifest, durably stored in `registry.json`.

The **proposed offline envelope**, not an existing production contract, has exactly
these keys:

```json
{
  "job_id": "job-1",
  "project_id": "project-1",
  "repository_identity": "forge/example",
  "commit_sha": "<full lowercase 40- or 64-character Git SHA>",
  "task_id": "task-1",
  "title": "Approved title",
  "description": "Approved implementation request",
  "approval": {
    "id": "approval-1",
    "state": "approved",
    "actor": "operator",
    "approved_at": "2026-10-27T12:00:00Z",
    "expires_at": "2026-10-27T13:00:00Z",
    "digest": "<SHA-256 of canonical request fields excluding approval>"
  }
}
```

`digest()` specifies canonicalization: Python JSON with sorted keys, ASCII
escaping, and compact separators. It detects inconsistencies, not authenticity;
a future live transport must authenticate the service and forbid redirects.
Unknown fields, including server filesystem paths, are rejected. Approval windows
must include timezones, be current, and span at most 24 hours. The SHA must equal
the approved local repository's HEAD; no fetch, checkout of a remote ref, or path
translation occurs. A label is explicitly trusted local configuration, not proof
of remote provenance. Worktree creation uses the exact approved SHA.

The manifest includes job/project/local repository IDs, repository identity,
commit SHA, worktree path, local task ID, full approval metadata, preparation time,
envelope digest, adapter version, and mock-only/no-execution audit flags. Intent
is fsynced before creation; approval IDs and job IDs cannot create a second
worktree, even after cleanup. Replays validate the current approval, pinned
repository/worktree, manifest checksum, and worktree HEAD. Changed content,
expired approval, removed worktree, inconsistent record, or interrupted intent
requires manual investigation. Do not delete dispatch records to retry.
Idempotency assumes the private registry is preserved; backups/rollback and
hostile same-account edits have the same trust limitations as milestone A.

Timeouts are bounded to 30 seconds per attempt (default 10), with at most three
attempts and bounded exponential delay. Only 429/502/503/504 and transport errors
are retried. Other HTTP errors, redirects, malformed/oversize JSON (1 MiB), and
invalid envelopes fail closed. Error messages never include response bodies,
transport exception text, or tokens. Mock transports are immediate; a future
transport must actually enforce the supplied timeout and response-size bound.

Next integration step: extend and review the production metadata contract
separately, define approval revocation/freshness and authenticated transport
semantics, then implement a GET-only transport with redirect refusal. Do not
connect this adapter to the existing claim protocol or enable execution.
