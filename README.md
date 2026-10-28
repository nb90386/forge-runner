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

## Forge 0.5D — control-plane approval integration

`forge.dispatch` consumes the version-1 contract in the control development
repository's `PROTOCOL.md`. It prepares local worktrees only. Execution remains
disabled: no claim, completion, subprocess job, merge, push, or deployment route
is exposed by dispatch.

Explicitly approve the local repository and configure an immutable project binding.
Supply the existing worker's token provider as a callable; do not import or start
its planning loop. No credentials are loaded, persisted, or logged by dispatch.
The existing worker and deployed services are unchanged.

```python
from forge.dispatch import DispatchClient, Dispatcher, LoopbackTransport

# Operator-configured trusted local listener/tunnel; no default destination.
client = DispatchClient(LoopbackTransport('http://127.0.0.1:8000'), token_provider)
dispatcher = Dispatcher(manager, client)
dispatcher.bind('project-1', 'example', 'forge/example')
for envelope in client.poll():
    manifest = dispatcher.prepare(envelope)
```

The port above is illustrative. This change neither opens a tunnel nor contacts a
service automatically. IPv6 requires `http://[::1]:<port>`. Only canonical HTTP
origins with explicitly configured `127.0.0.1` or `::1` and a port are accepted.
The transport uses numeric sockets directly, checks the connected peer, ignores
proxy environment variables, never resolves DNS, never follows redirects, and
allows only the exact two read-only worker endpoint/query shapes. Loopback HTTP
relies on the operator's trusted listener/tunnel; it does not authenticate the
remote server behind that listener. Socket operations use the bounded timeout.

Every poll starts at `after=0`, requests `limit=100`, and follows every nonnull
cursor, even on empty or short pages. A cursor must strictly increase and fit a
signed 64-bit positive integer. Exact schema keys/version, immutable envelope
metadata/digests, and uniqueness of job and approval identities are checked. Exact
approval/envelope duplicates are deduplicated idempotently; a changed envelope
for an existing approval or multiple approvals for one job fail closed. Replay
across complete polling cycles is handled by durable preparation records. Failed page attempts never
append jobs or advance the cursor. No partial scan is returned or persisted.

Bounds are 100 pages, 900 KiB per response, 32 MiB of successful response bytes
per scan, and 10,000 jobs. Each page has at most three attempts with bounded
backoff for transport errors or 429/502/503/504; all other errors block. These
limits deliberately refuse an oversized feed rather than authorize a prefix.
Restart from zero after failure. Large descriptions can cause short pages;
page length never indicates completion. JSON duplicate keys are rejected.

`Dispatcher.prepare` requires a `DispatchClient`. An envelope or manifest alone
cannot authorize preparation. Immediately before creation and before returning
an existing prepared manifest, dispatch requests
`GET /api/worker/approval-authorization?approval_id=<id>&envelope_digest=<digest>`.
The digest covers the full canonical envelope, including approval metadata; it
is distinct from the request-content digest inside `approval`. Authorization
requires HTTP 200, exact schema/ID/digest and literal `authorized:true`. There
are no authorization retries or cached fallbacks. Archive, expiry, corruption,
401/403, changed responses and network errors block. Local validity, bindings,
repository identity, exact HEAD, manifests and worktree records are also checked.

Preparation checkpoints a durable `preparing` intent before contacting current
authorization and creating the worktree. It rechecks server authorization and
local validity after creation, before publishing a `prepared` manifest. Failure
or interruption after intent leaves a blocked record, possibly with a worktree
or branch. Automatic recovery is refused, including after restart; manually
inspect registry, Git worktrees and branches before reconciliation. Do not erase
records to retry. Manifest audit metadata records `forge-0.5D` and
`execution:false`. A manifest is an audit artifact, never an execution permit.

### Remaining execution boundary

HTTP authorization is point-in-time, not a lease. Archival can occur between a
successful check and Git creation, during creation, or after the final check.
The post-creation check detects archival already visible to that request, but
cannot eliminate the concurrent archival race. A detected change leaves durable
blocked intent and never publishes a successful manifest. A later archive may
leave a previously prepared worktree; every replay still requires authorization.
This milestone permits that preparation-only residual race and never runs code.

Final execution requires a server-side lease bound to the immutable envelope,
cancellation/revocation handling, a fresh authorization boundary at execution,
and an isolated execution environment. Those capabilities are not implemented
here and remain execution blockers. Live tunnel/service deployment and production
smoke validation are also outside this offline change; no deployed worker has
been switched to this adapter.

Unit tests use disposable Git repositories and scripted HTTP/socket responses.
The final staging integration additionally starts the local control plane and uses
real loopback HTTP:

```sh
python3 tests/test_staging_integration.py
```

Requires the local control checkout at
`~/Forge/projects/forge-control-development`, Python 3.10+ (required by the
control plane), Git, and permission to
bind a loopback listener. No installation is needed. Unittest discovery also runs
this test. A sandbox that denies socket binding will report a failure, not a pass
or skip; run the command in an environment allowing loopback to complete validation.

The harness uses a fresh committed repository, separate temporary control-plane
SQLite data and runner registry, synthetic distinct worker/operator tokens, and an
OS-assigned port on `127.0.0.1`. It starts the real server in an isolated interpreter
to separate the two `forge` packages, authenticates an operator session, verifies
worker approval refusal, polls through `LoopbackTransport`, explicitly binds the
local repository, and prepares one worktree. Repeated polling and reconstruction
of the dispatcher must return the same manifest without another worktree. Archive
must hide the feed entry and refuse replay of the cached approval with HTTP 403.

Assertions cover original content/HEAD/branch, manifest and registry digests,
SQLite approval/audit history, and an empty execution queue. The server forbids
subprocesses and outgoing connections; the runner phase restricts subprocesses to
local Git preparation/inspection and connections to the test listener. No Claude,
Codex, shell task, merge, deployment, production, existing credentials, or existing
project is used. The temporary manifest is verified and then removed with all
fixture state; the server is terminated and reaped even on failure.

## Forge 0.6B — isolated runtime foundation (fail closed)

`forge.runtime` separates trusted local runtime configuration from untrusted job
content. It is deliberately disconnected from dispatch and the server execution
lease APIs. Real Claude/Codex execution remains disabled, with no enable switch.
No server settings, production code, credentials or services are changed.

```python
from forge.runtime import Runtime, SyntheticRequest, detect_capabilities

inventory = detect_capabilities()  # passive executable discovery only
runtime = Runtime(['/private/local/work/explicit-task-directory'])
result = runtime.execute(SyntheticRequest('/private/local/work/explicit-task-directory'))
manifest = result.manifest()  # JSON serializable audit; unsupported, started=False
```

The approved list is explicit trusted operator configuration of exact directories;
parent approval does not approve children. Paths must be canonical, contain no
symlink components, and retain recorded ancestor device/inode identities. These
checks are defense in depth, **not isolation or execution authorization**. A
worktree and a preparation manifest are never security boundaries or permits.
Worktree contents are never opened, imported, or executed by this module.

Inventory detects Docker (including an OrbStack-provided Docker CLI), Podman,
nerdctl, macOS sandbox-exec, and bubblewrap executables without invoking them.
Presence does not verify a daemon, VM sharing, filesystem isolation, network
isolation, resource enforcement or process-tree termination. All mechanisms are
reported unverified and unsupported. There is no approved container adapter in
this milestone and no host execution fallback. No images are pulled or built.

Only runner-owned synthetic identifiers are accepted: noop, capture-fixture,
artifact-fixture, timeout-fixture, cancel-fixture and resource-fixture. These
reserve future fixed test implementations; they do not execute today. Requests
have no command, shell, description, environment, credential or mount fields.
Network must be literal False. Workspace access is explicitly ro or rw. CPU,
memory, process, wall-time, termination-grace, stdout/stderr byte and artifact
count/total-byte requests have finite positive upper bounds; invalid or unsupported
configurations are rejected. Valid requests return structured `unsupported`.
A trusted Cancellation signal can return `canceled` before start.

Results include status, reason, started flag, empty bounded capture fields and a
JSON audit manifest recording requested limits, capabilities, and explicitly
unverified guarantees. The manifest is returned to the trusted caller, not written
into an untrusted workspace. It contains no job descriptions or credentials and
is not an execution permit. This runtime neither claims nor acknowledges leases.

**Actually enforced:** no execution, no network connections, no mount creation,
no credential loading, exact workspace admission, synthetic operation allowlist,
configuration bounds and empty capture. **Unverified / release blockers:** actual
read/write filesystem boundary, home/credential exclusion during execution,
network denial inside a runtime, CPU/memory/process limits, monotonic wall-time
kill, streaming capture/artifact limits, and graceful cancellation followed by
forced termination of an entire isolated process tree. The interface documents
these future backend obligations; it does not simulate successful enforcement.
Tests verify timeout/cancellation/resource/capture requests fail closed, not that
an OS enforces those limits. Enabling a backend requires disposable isolation
conformance tests, including hostile symlinks and cleanup failures, plus separate
lease integration and durable execution fencing. No agent execution is authorized.
