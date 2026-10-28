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
