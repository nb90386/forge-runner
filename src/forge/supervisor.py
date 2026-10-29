"""One-shot local synthetic supervision. No HTTP, agents, Git or recovery."""
import copy
from dataclasses import asdict, dataclass
import threading
import time

from .dispatch import digest, validate
from .lease import FakeClock, LeaseWorker, MockLeaseTransport, MockSupervisor, refuse
from .runtime import GUARANTEES, Runtime, SyntheticRequest, SYNTHETIC_OPERATIONS, Limits
from .safety import SafetyError, task_id


def request_digest(request):
    if (type(request) is not SyntheticRequest or type(request.limits) is not Limits
            or type(request.operation) is not str or request.operation not in SYNTHETIC_OPERATIONS
            or request.network is not False or request.workspace_access not in ('ro', 'rw')
            or type(request.workspace) is not str):
        refuse()
    request.limits.validate()
    return digest(asdict(request))


@dataclass(frozen=True)
class SyntheticApproval:
    """Trusted operator configuration; never derived from a dispatch manifest."""
    envelope_digest: str
    task_id: str
    attempt_digest: str
    request_digest: str
    approved: bool = False


class SyntheticSupervisor:
    """Fixed fixtures under a mock local lease; each instance is one attempt.

    FakeClock remains the mock authority clock. A second, real monotonic deadline
    ensures stopping even if that test clock stalls or wall time rolls back.
    Runtime owns bounded container teardown and confirms absence before returning.
    """
    INTERVAL = .02

    def __init__(self, registry, transport, worker_id, clock, runtime):
        if (type(transport) is not MockLeaseTransport or type(clock) is not FakeClock
                or transport.clock is not clock or type(runtime) is not Runtime):
            refuse()
        self._worker = LeaseWorker(registry, transport, worker_id, clock, MockSupervisor())
        self._runtime = runtime
        self._once = threading.Lock()
        self._used = False
        self._closed = threading.Event()
        self._deadline = None
        # A persisted record never recovers execution authority or cleanup proof.
        with registry.locked(write=True) as data:
            rows = data.setdefault('lease_records', {})
            if type(rows) is not dict or any(type(r) is not dict for r in rows.values()):
                refuse()
            for row in rows.values():
                if row.get('state') not in ('completed', 'failed', 'canceled', 'expired'):
                    row['state'] = 'blocked'

    def cancel(self):
        """Independent of worker, transport and registry locks."""
        self._worker.supervisor.cancellation.cancel()

    def _block(self):
        w = self._worker
        w._stop()  # signal containment before trying persistence
        if w._job is not None:
            try:
                with w.registry.locked(write=True) as data:
                    row = data['lease_records'][w._job['job_id']]
                    row.update(state='blocked', synthetic_state='blocked')
            except Exception:
                pass  # original intent remains a fence

    def _watch(self):
        w = self._worker
        while not self._closed.wait(self.INTERVAL):
            # This lane must never wait for transport, caller or durable writes.
            deadline = w._deadline
            if (deadline is None or time.monotonic() >= self._deadline
                    or w.clock.monotonic >= deadline
                    or w.supervisor.cancellation.requested):
                w._stop()
                return

    def _poll(self):
        while not self._closed.wait(self.INTERVAL):
            try:
                self._worker.step()
            except Exception:
                self._worker._stop()
                return

    def run(self, job, attempt_key, request, approval):
        with self._once:
            if self._used:
                refuse()
            self._used = True
        w = self._worker
        job = copy.deepcopy(job)
        task_id(attempt_key)
        fingerprint = validate(job, w.clock.wall)
        expected = SyntheticApproval(fingerprint, job['task_id'], digest(attempt_key),
                                     request_digest(request), True)
        if type(approval) is not SyntheticApproval or approval != expected or approval.approved is not True:
            refuse()
        threads = []
        try:
            started = time.monotonic()
            w.claim(job, attempt_key)
            w.step('acknowledge')
            # No renewals: the launch generation and its deadline stay fixed.
            w.step()
            generation = w._permit['generation']
            self._deadline = started + max(0, w._deadline - w.clock.monotonic)
            with w.registry.locked(write=True) as data:
                row = data['lease_records'][job['job_id']]
                row.update(synthetic_state='intent', task_id=job['task_id'],
                           request_digest=expected.request_digest)
            for target in (self._watch, self._poll):
                thread = threading.Thread(target=target, daemon=True, name='forge-synthetic-supervisor')
                threads.append(thread)
                thread.start()
            result = self._runtime.execute(request, w.supervisor.cancellation)
            # Success is possible only after Runtime's confirmed bounded cleanup,
            # with fresh authority for exactly the launch generation.
            if (result.status not in ('completed', 'failed', 'canceled', 'timeout')
                    or result.audit.get('enforced_guarantees') != list(GUARANTEES)):
                refuse()
            with w._lock:
                if time.monotonic() >= self._deadline:
                    refuse()
                w.step()
                if w._permit['generation'] != generation:
                    refuse()
                state = {'timeout': 'failed'}.get(result.status, result.status)
                w.step('finish', state=state)
                with w.registry.locked(write=True) as data:
                    data['lease_records'][job['job_id']]['synthetic_state'] = state
            # Only allowlisted metadata and lengths leave this supervisor. Raw
            # streams, artifacts, paths and backend diagnostics are never returned.
            return dict(adapter='forge-0.7-synthetic', real_agent_execution=False,
                        job_id=job['job_id'], task_id=job['task_id'],
                        envelope_digest=fingerprint, attempt_digest=digest(attempt_key),
                        request_digest=expected.request_digest, generation=generation,
                        state=state, stdout_bytes=len(result.stdout),
                        stderr_bytes=len(result.stderr), artifact_count=len(result.artifacts))
        except BaseException as exc:
            self._block()
            if not isinstance(exc, Exception):
                raise
            raise SafetyError('supervisor: attempt blocked; reconciliation required') from None
        finally:
            self._closed.set()
            for thread in threads:
                thread.join(timeout=1)
