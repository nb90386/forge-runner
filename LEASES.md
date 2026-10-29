# Forge 0.6D: offline lease foundation

`forge.lease.LeaseWorker` validates the immutable dispatch envelope before a claim,
then durably writes intent under the existing private Registry lock. The exact
job, approval, project, worker, repository identity, commit and envelope digest
are pinned throughout the lifecycle. Claim deduplication covers both job and
approval IDs. Records are capped at 256 attempts and are never automatically
evicted. A full store requires operator reconciliation, not deletion of fences.

The only accepted transport, clock and supervisor are the concrete
`MockLeaseTransport`, `FakeClock` and `MockSupervisor` types. The transport models
serialized claims, acknowledgments, heartbeats, credential rotation, generation
fencing, cancellation, expiry and terminal reports. Registration and cancellation
are explicit mock operator controls; cancellation is not a worker API. It has no
HTTP adapter, worker authentication secret, credential provider or process launcher.
Its predictable dummy permits are solely test fixtures.

The supervisor explicitly attests to mock mode with execution disabled before
claim and synthetic activation. Acknowledgment must precede synthetic activation
and terminal reporting. Neither an approval, preparation manifest, heartbeat nor
mock attestation authorizes real execution. `LeaseWorker.execute` always refuses.
The existing Runtime and ContainerAdapter are not connected to this lease path.

Call `claim(envelope, attempt_key)`, `step('acknowledge')`, and optionally
`start_synthetic()` to model an active worker. Call `step()` for heartbeat,
`step('renew')` for rotation, or `step('finish', state='completed'|'failed'|'canceled')`.
Only a redacted manifest is returned. Permits stay in memory and never enter the
registry or manifests. Transport bodies and exception details are never logged.
Attempt keys are represented durably by a digest, and no automatic claim retry
or credential recovery is attempted. Failed or ambiguous operations terminate
the synthetic supervisor, erase the local permit, and fence subsequent work.

Deadlines use the monotonic request-start time and a maximum 60-second duration,
with an independently pinned approval deadline. Response delay consumes the
budget. Renewal cannot cross the previous deadline, and heartbeat cannot extend
it. Wall-clock rollback cannot extend an existing local deadline. An expired
local permit is refused before any transport call. A trusted caller must drive
`step` to detect remote cancellation or connectivity loss. Local cancellation
uses the supervisor's Cancellation signal and terminates on the next step.

Restarted workers cannot recover authority from state files: any existing intent,
including an interrupted claim or renewal, blocks another claim. Terminal reports
are final at the mock authority; local uncertainty is recorded as `blocked`, never
as a successful terminal report. A server report describes worker status, not
correctness, deployment authorization, or prevention of prior side effects.

## Remaining integration and isolation blockers

- No authenticated real lease transport, deployment wiring, real server contract
  tests, transactionally coupled server audit validation, or server restart/clock
  reconciliation test is supplied by this mock authority. The control-plane
  checkout is read only and unchanged.
- No production supervisor loop or independent watchdog enforces deadlines during
  a stalled caller, blocked I/O, process crash or host suspension. No production
  polling cadence or cancellation latency bound is established. Real transports
  require bounded I/O and conservative server/worker clock-skew handling.
- No real runtime attestation is accepted. Container inventory and earlier synthetic
  conformance do not attest an agent runtime. Whole-process-tree termination,
  escalation and confirmed cleanup remain unimplemented in this lease path.
- Exact on-disk repository identity, clean worktree and commit must be reverified
  immediately before any future launch, with a boundary preventing mutation after
  verification. The envelope binding here checks metadata only and performs no Git
  operations. Preparation is deliberately not invoked.
- OS identities, filesystem and home/credential isolation, restricted network,
  resource limits, bounded output/artifacts and a supervisor outside agent control
  require independent verification. This milestone establishes none of those.
- Downstream systems must enforce fencing generations where supported. Revocation
  cannot prevent all in-flight side effects, especially across partitions or escaped
  processes. Safe distributed execution is not claimed.
- Registry tombstones assume private local storage under a trusted OS identity.
  Rollback, tampering, loss, multi-host deduplication, and safe capacity rollover
  require a durable external reconciliation design. Persisted monotonic timestamps
  are intentionally not reused across restarts.

Offline verification: `PYTHONPATH=src:tests python3 -m unittest test_lease
 test_runtime test_container.ContainerTests test_dispatch.ClientTests
 test_dispatch.HardenedClientTests test_dispatch.TransportTests
 test_forge.ValidationTests` (join as one command), plus
`python3 -m compileall -q src tests`. Existing Git lifecycle, real HTTP staging and
live container suites are excluded because they launch processes or services.

## Forge 0.6E: opt-in loopback lease integration

`forge.lease_http.HTTPLeaseTransport(origin, secret_provider, timeout=2)` accepts
only explicit numeric-loopback HTTP origins. It obtains a dedicated execution
secret once from the caller's configuration-time callable. It never discovers
credentials, reads the environment, retries writes, follows redirects, uses DNS,
or contacts a configured service automatically. Rotation requires a fresh
transport. Protect and authenticate the local listener/tunnel independently.

`HTTPLeaseWorker(registry, transport, worker_id, poll_interval=.25)` retains the
0.6D durable job/approval tombstones and unconditional `execute` refusal. It can
claim, acknowledge, heartbeat, rotate, and report synthetic terminal status using
the exact execution endpoints documented in the read-only control-plane checkout.
Responses require exact fields, finite and consistent timestamps, pinned bindings,
integer generations, opaque server-format credentials, and the documented HTTP
framing and no-store headers. Duplicate JSON keys and unknown fields are refused.
Future server timestamps are refused rather than assuming a clock-skew allowance.
No server audit atomicity can be proved from this worker response alone.

The transport limits request/response bodies to 4096 bytes. An independent socket
shutdown timer bounds the entire connected I/O exchange (including slow-drip
headers/body), with a configurable timeout in `(0, 5]` seconds. There are no claim,
renewal, or credential recovery retries after ambiguous outcomes. A separate
polling thread checks remote cancellation every configured interval (`.01` to `1`
second), plus transport time and scheduling delay. While claimed it uses renewal;
after acknowledgment it uses heartbeat without extending the lease. Operators
must explicitly request renewal once running. No worker cancellation endpoint is
invented: local cancellation stops locally; remote cancellation is a rejection.

A separate trusted watchdog thread checks local monotonic deadlines and local
cancellation at most every 50 ms of scheduled running time, independent of the
caller, network and registry locks. It terminates the synthetic boundary before
attempting durable writes. A late response cannot restore authority after the
watchdog has stopped it. Response delay consumes the request-start deadline;
renewal must also arrive within the old deadline. Wall rollback never extends an
existing deadline. Pending claims have the transport timeout as their deadline.
Use `close()` to stop and join background loops; do not reuse a closed worker.

Startup reconciliation converts unresolved local records to `blocked`, preserving
identity and attempt digests. No credentials or persisted monotonic deadlines are
recovered. Every existing record still fences another claim. Persistence failures
leave the earlier intent as the fence; diagnostics contain fixed messages rather
than request bodies, credentials, server errors, or exception details.

`ProcessGroupCancellation` provides explicit TERM/KILL signaling for an externally
owned POSIX process group, without launching or discovering processes. It always
reports cleanup uncertainty: portable process groups cannot prove the absence of
escaped descendants. It is deliberately **not accepted as an execution supervisor**.
The only accepted supervisor remains synthetic and execution remains disabled.
The watchdog thread cannot survive interpreter failure, establish OS isolation,
or provide a host-suspension or scheduler-independent termination guarantee.
A separate OS-supervised watchdog and verified containment are still release
blockers for actual agent execution. No Runtime/ContainerAdapter wiring is added.

Verification includes `test_lease_http`: a local fake HTTP authority and byte-level
HTTPConnection fixtures cover claims, renewals, stale fencing, expiry independent
of caller locks, cancellation polling, lost replies, bounded stalled I/O,
reconciliation, redaction, strict parsing and simulated persisted server restart.
The server is a test double, not proof of real control-plane audit/storage behavior.
Loopback tests explicitly skip when the host sandbox denies binding; wire tests
still run without sockets. No agents, production services or real credentials are
used. Existing 0.6D tests remain unchanged.

## Forge 0.6F: separate operator isolation check

`PYTHONPATH=src python3 -m forge.conformance` emits UNVERIFIED and exits 2 without
explicit live configuration. See README.md for the complete Mac live command and
local audited image prerequisites. The opt-in runner exercises only the existing
fixed disposable container fixtures and reports PASS only after complete live
conformance with confirmed removal. Missing prerequisites and skips cannot attest
isolation. Reports do not authorize execution, satisfy lease supervisor blockers,
or connect Runtime/ContainerAdapter to either lease worker. All 0.6D/0.6E execution
refusals and remaining integration requirements above remain in force.

## Forge 0.7: first local synthetic supervisor increment

`forge.supervisor.SyntheticSupervisor(registry, mock_transport, worker_id,
 fake_clock, runtime)` connects the concrete local mock lease state machine to
`Runtime`. `run(job, attempt_key, request, approval)` is one-shot, including after
refusal. The caller must explicitly supply a `SyntheticApproval` with literal
`approved=True`, the full envelope digest, exact task ID, attempt-key digest and
`request_digest(request)`. This is trusted local operator configuration, not an
approval inferred from dispatch content. The dispatch operator approval is also
validated before any claim. Existing worker `execute` methods still refuse.

The supervisor claims, acknowledges, obtains fresh heartbeat authority, saves
synthetic intent, then invokes only the typed synthetic Runtime. No preparation,
Git, repository content, agents, HTTP services or credential discovery is involved.
Runtime still requires process-local live conformance of the exact typed adapter,
immutable image checks and the approved Unix socket. It admits only empty temporary
workspace tokens and mounts no host content. No conformance bit is persisted.

A separate 20 ms scheduled watchdog signals cancellation independently of caller,
registry and transport locks. It observes both the mock monotonic deadline and a
conservative real monotonic deadline anchored before claim; wall rollback or a
stalled fake clock cannot extend the real budget. Another lane polls heartbeat
without renewal. The launch generation is pinned; remote cancellation, generation
change, lease loss or ambiguity revokes local authority without retries. The
existing container adapter owns bounded TERM/KILL, forced removal and confirmed
absence. Signal detection is subject to Python scheduling; daemon operations may
consume their existing bounded API timeouts before teardown completes. No strict
host-suspension or interpreter-crash termination guarantee is claimed.

Only confirmed Runtime outcomes with all enforced guarantees can be terminally
reported, after a final heartbeat and generation check. Cleanup uncertainty,
expiry, cancellation or uncertain terminal reporting leaves a durable `blocked`
fence and raises a fixed redacted error. Results expose only binding digests,
IDs, generation, state and bounded capture/artifact counts. No raw output,
artifacts, workspace paths, permits or exception text leave this supervisor.
Startup marks unresolved records blocked; neither old workers nor new instances
may overwrite that fence. Interrupted launches are never automatically resumed,
retried or declared cleaned up. The trusted private registry assumptions above
still apply.

This increment deliberately accepts only the local mock authority and its
FakeClock. It is not wired to HTTPLeaseWorker, dispatch CLI or production. Offline
integration tests replace container execution and do not attest live isolation.
Run `PYTHONPATH=src:tests python3 -m unittest test_supervisor -q`.

**Next integration gate:** explicitly configured disposable live Engine testing
of this supervisor with a newly conformed adapter and audited immutable image:
verify exact approval/attempt binding, revoke a lease and expire a deadline while
a fixture is running, observe bounded stop/escalation and confirmed absence,
inject cleanup/terminal-report uncertainty, then verify restart refuses the same
job/approval. No skips count as PASS. Complete this local synthetic gate before
considering HTTP lease wiring; real agents remain separately blocked on the
OS-supervised crash watchdog and other release requirements above.

### Disposable live supervisor gate

Run the dedicated module directly from the runner checkout with all four
operator-approved values (the executable is validated but never executed):

```sh
FORGE_TEST_DOCKER=/CANONICAL/PATH/TO/docker \
FORGE_TEST_SOCKET=/CANONICAL/PATH/TO/docker.sock \
FORGE_TEST_IMAGE='AUDITED-REPOSITORY@sha256:64-LOWERCASE-HEX-DIGEST' \
FORGE_TEST_EXPECTED_ID='sha256:64-LOWERCASE-HEX-IMAGE-ID' \
PYTHONPATH=src:tests python3 tests/test_supervisor_live_integration.py
```

The direct gate exits **0 PASS**, **1 FAIL**, or **2 SKIP/unverified**. Discovery
also lists explicit skips, but its successful exit alone is not live evidence.
Every case conforms a new adapter against the existing local immutable fixture;
no images are pulled or built. Cases cover exact attempt approval, completion,
supervisor cancellation and mock lease expiry after verified live startup,
wall timeout, bounded TERM/KILL teardown, and actual exact-name absence queries.
The termination fixtures ignore TERM and have a child; the existing adapter
checks exited state and zero PID before removal. The elapsed assertion is a
conservative 120-second scheduled-run bound covering existing daemon API bounds,
not a scheduler-independent latency or crash guarantee.

Controlled mocks suppress only fixture self-cancellation after real startup
validation, then drive the supervisor or clock. Cleanup uncertainty is injected
only after actual removal and empty absence confirmation. A separate checkpoint
fault simulates local durable terminal-report failure after authority acceptance.
Both must block and refuse replay through a reopened Registry without Engine or
transport calls. Fault injection is not evidence of a real daemon outage, disk
failure, power loss or interpreter-crash recovery. The local mock lease authority
remains the only authority exercised; HTTP and real agents remain out of scope.

Offline validation for this increment (skips remain unverified):

```sh
PYTHONPATH=src:tests python3 -m unittest test_supervisor test_conformance test_container.ContainerTests test_container.ResourceFixtureTests test_container.EffectiveLimitsTests test_container.TerminationEvidenceTests test_container.FailClosedContainmentTests test_engine test_runtime test_lease test_lease_http test_dispatch.ClientTests test_dispatch.HardenedClientTests test_dispatch.TransportTests test_forge.ValidationTests -q
python3 -m compileall -q src tests
git diff --check
```
