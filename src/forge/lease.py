"""0.6D offline lease model. No network, processes, runtime or credential loading.

The supervisor must be driven by a trusted polling loop. Its synthetic termination
signal models cooperation only; it cannot revoke already performed side effects.
"""
import copy
import math
from threading import RLock

from .dispatch import digest, stamp, validate
from .runtime import Cancellation
from .safety import SafetyError, task_id

ACTIVE = ('claimed', 'running')
TERMINAL = ('completed', 'failed', 'canceled', 'expired')
BINDING = ('job_id', 'approval_id', 'project_id', 'repository_identity',
           'commit_sha', 'envelope_digest', 'worker_id')


def refuse():
    raise SafetyError('lease: authority unavailable; execution prohibited')


class FakeClock:
    def __init__(self, wall=1800000000.0):
        self.wall = wall
        self.monotonic = 0.0

    def advance(self, seconds):
        if type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds < 0:
            refuse()
        self.wall += seconds
        self.monotonic += seconds


def binding(job, worker):
    return {**{k: job[k] for k in ('job_id', 'project_id', 'repository_identity', 'commit_sha')},
            'approval_id': job['approval']['id'], 'envelope_digest': digest(job), 'worker_id': worker}


class MockLeaseTransport:
    """Serialized mock authority. Dummy credentials are deliberately not real secrets.

    register/cancel are test/operator controls, never worker endpoints. No request
    bodies, permits, or exception details are recorded. faults model lost replies.
    """
    def __init__(self, clock):
        if type(clock) is not FakeClock:
            refuse()
        self.clock = clock
        self._lock = RLock()
        self._jobs, self._rows, self._keys = {}, {}, {}
        self._serial = 0
        self.fault = None
        self.calls = 0

    def register(self, job):
        with self._lock:
            validate(job, self.clock.wall)
            old = self._jobs.get(job['job_id'])
            if old is not None and old != job:
                refuse()
            self._jobs[job['job_id']] = copy.deepcopy(job)

    def _expire(self, row):
        if row['state'] in ACTIVE and self.clock.wall >= row['expires_at']:
            row.update(state='expired', lease_credential='')

    def _public(self, row, secret=False):
        return {k: copy.deepcopy(v) for k, v in row.items()
                if k != 'idempotency_key' and (secret or k != 'lease_credential')}

    def cancel(self, job_id):
        with self._lock:
            if job_id not in self._jobs:
                refuse()
            row = self._rows.get(job_id)
            if row is None:
                row = {**binding(self._jobs[job_id], ''), 'state': 'canceled',
                       'generation': 1, 'expires_at': self.clock.wall, 'lease_credential': ''}
                self._rows[job_id] = row
            self._expire(row)
            if row['state'] in ACTIVE:
                row.update(state='canceled', lease_credential='')

    def request(self, action, data, worker):
        with self._lock:
            self.calls += 1
            fault, self.fault = self.fault, None
            if fault == 'disconnect':
                refuse()
            task_id(worker)
            claim_fields = {'job_id', 'approval_id', 'repository_identity', 'commit_sha',
                            'envelope_digest', 'idempotency_key'}
            fields = claim_fields if action == 'claim' else {'job_id', 'generation', 'lease_credential'}
            if action == 'finish':
                fields = fields | {'state'}
            if action not in ('claim', 'acknowledge', 'heartbeat', 'renew', 'finish') or set(data) != fields:
                refuse()
            job = self._jobs.get(data['job_id'])
            if job is None:
                refuse()
            row = self._rows.get(data['job_id'])
            if row:
                self._expire(row)
            if action == 'claim':
                validate(job, self.clock.wall)
                expected = binding(job, worker)
                if any(data[k] != expected[k] for k in claim_fields - {'idempotency_key'}):
                    refuse()
                key = data['idempotency_key']
                if not isinstance(key, str) or not 1 <= len(key) <= 200:
                    refuse()
                if row:
                    if (row['state'] not in ACTIVE or row['generation'] != 1
                            or row['worker_id'] != worker or row.get('idempotency_key') != key):
                        refuse()
                else:
                    if (worker, key) in self._keys or any(r['approval_id'] == expected['approval_id'] for r in self._rows.values()):
                        refuse()
                    self._serial += 1
                    row = {**expected, 'state': 'claimed', 'generation': 1,
                           'idempotency_key': key, 'lease_credential': 'mock-permit-' + str(self._serial),
                           'expires_at': min(self.clock.wall + 60, stamp(job['approval']['expires_at'])),
                           'created_at': self.clock.wall, 'updated_at': self.clock.wall,
                           'heartbeat_at': None, 'acknowledged_at': None}
                    self._rows[data['job_id']] = row
                    self._keys[worker, key] = data['job_id']
            else:
                if (not row or row['state'] not in ACTIVE or row['worker_id'] != worker
                        or type(data['generation']) is not int or data['generation'] != row['generation']
                        or not data['lease_credential'] or data['lease_credential'] != row['lease_credential']):
                    refuse()
                if action == 'renew':
                    validate(job, self.clock.wall)
                    self._serial += 1
                    row.update(generation=row['generation'] + 1,
                               lease_credential='mock-permit-' + str(self._serial),
                               expires_at=min(self.clock.wall + 60, stamp(job['approval']['expires_at'])))
                elif action == 'acknowledge':
                    row.update(state='running', acknowledged_at=row['acknowledged_at'] or self.clock.wall,
                               heartbeat_at=self.clock.wall)
                elif action == 'heartbeat':
                    if row['state'] != 'running':
                        refuse()
                    row['heartbeat_at'] = self.clock.wall
                else:
                    if row['state'] != 'running' or data['state'] not in ('completed', 'failed', 'canceled'):
                        refuse()
                    row.update(state=data['state'], lease_credential='')
                row['updated_at'] = self.clock.wall
            if fault == 'lost-response':
                refuse()
            return self._public(row, action in ('claim', 'renew'))


class MockSupervisor:
    """Trusted synthetic termination boundary. Cannot execute anything."""
    def __init__(self):
        self.cancellation = Cancellation()
        self.active = False
        self.terminated = False

    def attest(self):
        return {'mock_only': True, 'execution_enabled': False}

    def terminate(self):
        self.cancellation.cancel()
        self.active = False
        self.terminated = True


class LeaseWorker:
    """One durable attempt per job/approval; credentials and deadlines stay in RAM.

    No resumed authority after restart. Records are capped, never evicted: dropping
    a tombstone would allow duplicate attempts. The caller supplies a private Registry.
    """
    MAX_RECORDS = 256

    def __init__(self, registry, transport, worker_id, clock, supervisor):
        if (type(transport) is not MockLeaseTransport or type(clock) is not FakeClock
                or type(supervisor) is not MockSupervisor):
            refuse()
        task_id(worker_id)
        self.registry, self.transport, self.worker_id = registry, transport, worker_id
        self.clock, self.supervisor = clock, supervisor
        self._lock = RLock()
        self._authority_lock = RLock()
        self._permit = None
        self._deadline = None
        self._job = None
        self._approval_deadline = None

    def manifest(self):
        return {'adapter': 'forge-0.6D', 'transport': 'mock', 'execution_enabled': False,
                'synthetic_active': self.supervisor.active, 'terminated': self.supervisor.terminated}

    def _stop(self):
        with self._authority_lock:
            self.supervisor.terminate()
            self._permit = None
            self._deadline = None

    def _save(self, state, generation):
        with self.registry.locked(write=True) as data:
            row = data['lease_records'][self._job['job_id']]
            row.update(state=state, generation=generation)

    def claim(self, job, attempt_key):
        with self._lock:
            if (self._job is not None or self.supervisor.terminated
                    or self.supervisor.cancellation.requested):
                refuse()
            job = copy.deepcopy(job)
            validate(job, self.clock.wall)  # before any transport call or durable intent
            task_id(attempt_key)
            if self.supervisor.attest() != {'mock_only': True, 'execution_enabled': False}:
                refuse()
            expected = binding(job, self.worker_id)
            with self.registry.locked(write=True) as data:
                records = data.setdefault('lease_records', {})
                if (not isinstance(records, dict) or len(records) >= self.MAX_RECORDS
                        or job['job_id'] in records
                        or any(r.get('approval_id') == expected['approval_id'] for r in records.values())):
                    refuse()
                # A non-secret digest persists the attempt identity; no raw key or content.
                records[job['job_id']] = {**expected, 'attempt_digest': digest(attempt_key),
                                          'state': 'claiming', 'generation': 0}
            self._job = job
            self._approval_deadline = self.clock.monotonic + stamp(job['approval']['expires_at']) - self.clock.wall
            return self._request('claim', {**{k: expected[k] for k in
                                 ('job_id', 'approval_id', 'repository_identity', 'commit_sha', 'envelope_digest')},
                                 'idempotency_key': attempt_key})

    def _request(self, action, payload):
        start, wall = self.clock.monotonic, self.clock.wall
        old = self._permit
        try:
            if self.supervisor.terminated:
                refuse()
            response = self.transport.request(action, payload, self.worker_id)
            self._validate_response(response, action)
            expected = binding(self._job, self.worker_id)
            generation = 1 if action == 'claim' else old['generation'] + (action == 'renew')
            state = ('claimed' if action == 'claim' else payload['state'] if action == 'finish'
                     else old['state'] if action == 'renew' else 'running')
            if (not isinstance(response, dict) or any(response.get(k) != v for k, v in expected.items())
                    or type(response.get('generation')) is not int or response['generation'] != generation
                    or response.get('state') != state):
                refuse()
            expiry = response.get('expires_at')
            if type(expiry) not in (int, float) or not math.isfinite(expiry):
                refuse()
            if action in ('claim', 'renew'):
                credential = response.get('lease_credential')
                if not isinstance(credential, str) or not 1 <= len(credential) <= 200:
                    refuse()
                duration = min(60, expiry - wall, stamp(self._job['approval']['expires_at']) - wall)
                deadline = min(start + duration, self._approval_deadline)
            else:
                credential, deadline = old['lease_credential'], self._deadline
                if expiry != old['expires_at'] or 'lease_credential' in response:
                    refuse()
            if (self.clock.monotonic >= deadline or
                    old is not None and self.clock.monotonic >= self._deadline):
                refuse()
            self._save(state, generation)
            with self._authority_lock:
                if self.supervisor.terminated:
                    refuse()
                self._permit = {**expected, 'generation': generation, 'lease_credential': credential,
                                'state': state, 'expires_at': expiry}
                self._deadline = deadline
            if state in TERMINAL:
                self._stop()
            return self.manifest()
        except Exception:
            self._stop()
            try:
                self._save('blocked', old['generation'] if old else 0)
            except Exception:
                pass  # durable claim intent still fences restart
            raise SafetyError('lease: operation uncertain; supervisor terminated') from None

    def _validate_response(self, response, action):
        """Additional transport-specific contract checks, inside the stop boundary."""

    def step(self, action='heartbeat', *, state=None):
        with self._lock:
            with self._authority_lock:
                permit, deadline = self._permit, self._deadline
            if (permit is None or deadline is None or self.clock.monotonic >= deadline
                    or self.supervisor.cancellation.requested):
                if permit is not None:
                    generation = permit['generation']
                    state = 'canceled' if self.supervisor.cancellation.requested else 'expired'
                    self._stop()
                    self._save(state, generation)
                self._stop()
                refuse()
            if action not in ('acknowledge', 'heartbeat', 'renew', 'finish'):
                self._stop()
                refuse()
            payload = {k: permit[k] for k in ('job_id', 'generation', 'lease_credential')}
            if action == 'finish':
                payload['state'] = state
            return self._request(action, payload)

    def start_synthetic(self):
        with self._lock:
            if self.supervisor.attest() != {'mock_only': True, 'execution_enabled': False}:
                self._stop()
                refuse()
            self.step('heartbeat')  # fresh authority plus local monotonic check
            if self._permit['state'] != 'running':
                self._stop()
                refuse()
            self.supervisor.active = True
            return self.manifest()

    def execute(self, *args, **kwargs):
        """Actual execution is unconditionally disabled, even with a live lease."""
        refuse()
