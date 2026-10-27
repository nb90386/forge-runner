"""Fail-closed approved-job adapter. No live HTTP implementation or job execution.

Transport is deliberately injectable and mock-only until Forge supplies the
approval envelope documented in README. Secrets are supplied in memory by the
existing worker, never loaded from disk by this module.
"""
import copy
import hashlib
import json
import math
import re
import time
from datetime import datetime, timezone
from typing import Protocol

from .git import git
from .safety import SafetyError, task_id


class MetadataTransport(Protocol):
    def get(self, path, *, bearer_token, timeout):
        """Return (HTTP status, JSON bytes); GET metadata only, no redirects."""
        ...


class MockTransport:
    """Scripted HTTP responses for offline integration; performs no network I/O."""
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = 0

    def get(self, path, *, bearer_token, timeout):
        self.calls += 1
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return response


def fail(message):
    raise SafetyError("dispatch: " + message)


def stamp(value):
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if result.tzinfo is None:
            fail("approval timestamps must include timezone")
        return result.timestamp()
    except (ValueError, TypeError, AttributeError, OverflowError):
        fail("invalid approval timestamp")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True).encode()).hexdigest()


def validate(job, now):
    fields = {'job_id', 'project_id', 'repository_identity', 'commit_sha',
              'task_id', 'title', 'description', 'approval'}
    if not isinstance(job, dict) or set(job) != fields:
        fail("unsupported immutable job envelope")
    for key in ('job_id', 'project_id', 'task_id'):
        task_id(job[key])
    if not isinstance(job['repository_identity'], str) or not re.fullmatch(r'[a-zA-Z0-9._:/-]{1,200}', job['repository_identity']):
        fail("invalid repository identity")
    if not isinstance(job['commit_sha'], str) or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', job['commit_sha']):
        fail("full commit SHA required")
    for key, limit in (('title', 180), ('description', 12000)):
        if not isinstance(job[key], str) or not job[key].strip() or len(job[key]) > limit:
            fail("invalid request content")
    approval = job['approval']
    if not isinstance(approval, dict) or set(approval) != {'id', 'state', 'actor', 'approved_at', 'expires_at', 'digest'}:
        fail("incomplete approval metadata")
    task_id(approval['id'])
    if approval['state'] != 'approved' or approval['actor'] != 'operator':
        fail("operator approval required")
    approved, expires = stamp(approval['approved_at']), stamp(approval['expires_at'])
    if not approved <= now < expires or expires - approved > 86400:
        fail("stale or invalid approval window (maximum 24 hours)")
    content = {key: value for key, value in job.items() if key != 'approval'}
    if approval['digest'] != digest(content):
        fail("immutable request digest mismatch")
    return digest(job)


class DispatchClient:
    """Read-only client; token provider reuses the worker's existing token in memory.

    Only MockTransport is enabled in this milestone. A production transport must
    be reviewed after the API contract is extended, rather than opting in here.
    """
    def __init__(self, transport, token_provider, *, timeout=10, attempts=3, sleep=time.sleep):
        if type(transport) is not MockTransport:
            fail("live transport disabled: production approval contract incomplete")
        if (not isinstance(timeout, (int, float)) or not math.isfinite(timeout)
                or not 0 < timeout <= 30 or type(attempts) is not int or not 1 <= attempts <= 3):
            fail("invalid timeout or retry bounds")
        self.transport, self.token_provider = transport, token_provider
        self.timeout, self.attempts, self.sleep = timeout, attempts, sleep

    def poll(self):
        for attempt in range(self.attempts):
            try:
                token = self.token_provider()
                if not isinstance(token, str) or not token or any(c.isspace() for c in token):
                    fail("worker token unavailable")
                status, body = self.transport.get('/api/ui/implementation-jobs?status=approved',
                                                   bearer_token=token, timeout=self.timeout)
            except SafetyError:
                raise
            except Exception:
                status, body = 503, b''
            if status == 200:
                try:
                    if not isinstance(body, bytes) or len(body) > 1024 * 1024:
                        fail("metadata response exceeds bounds")
                    payload = json.loads(body)
                    if (not isinstance(payload, dict) or set(payload) != {'jobs'}
                            or not isinstance(payload['jobs'], list) or len(payload['jobs']) > 200):
                        fail("invalid metadata response")
                    jobs = copy.deepcopy(payload['jobs'])
                    for job in jobs:
                        validate(job, time.time())
                    return jobs
                except (ValueError, TypeError):
                    fail("invalid JSON metadata")
            if status not in (429, 502, 503, 504):
                fail("metadata request refused (HTTP %s)" % (status if type(status) is int else 'invalid'))
            if attempt + 1 < self.attempts:
                self.sleep(0.1 * (2 ** attempt))
        fail("metadata service unavailable after bounded retries")


class Dispatcher:
    def __init__(self, manager, *, clock=time.time):
        self.manager, self.clock = manager, clock

    def bind(self, project_id, repository_id, repository_identity):
        """Explicit local operator configuration, never called from remote data."""
        task_id(project_id)
        task_id(repository_id)
        if not isinstance(repository_identity, str) or not re.fullmatch(r'[a-zA-Z0-9._:/-]{1,200}', repository_identity):
            fail("invalid local repository identity")
        m = self.manager
        with m.registry.locked(write=True) as data:
            m._config(data)
            m._approved(data, repository_id)
            bindings = data.setdefault('dispatch_bindings', {})
            if not isinstance(bindings, dict):
                fail("inconsistent project bindings")
            binding = {'repository_id': repository_id, 'repository_identity': repository_identity}
            if project_id in bindings and bindings[project_id] != binding:
                fail("project binding is immutable")
            bindings[project_id] = binding

    def prepare(self, job):
        job = copy.deepcopy(job)
        fingerprint = validate(job, self.clock())
        m = self.manager
        with m.registry.locked(write=True) as data:
            m._config(data)
            validate(job, self.clock())
            bindings = data.get('dispatch_bindings', {})
            if not isinstance(bindings, dict):
                fail("inconsistent project bindings")
            binding = bindings.get(job['project_id'])
            if not isinstance(binding, dict) or binding.get('repository_identity') != job['repository_identity']:
                fail("unknown project or repository identity mismatch")
            repo_id = binding['repository_id']
            repo = m._approved(data, repo_id)
            records = data.setdefault('dispatch_records', {})
            if not isinstance(records, dict) or any(not isinstance(r, dict) for r in records.values()):
                fail("inconsistent dispatch records")
            key = job['approval']['id']
            previous = records.get(key)
            if previous:
                if previous.get('fingerprint') != fingerprint or previous.get('state') != 'prepared':
                    fail("inconsistent or interrupted dispatch; manual reconciliation required")
                manifest = previous['manifest']
                if (not isinstance(manifest, dict) or previous.get('manifest_sha256') != digest(manifest)
                        or manifest.get('repository_id') != repo_id):
                    fail("inconsistent manifest")
                task = data['tasks'].get(repo_id + ':' + manifest['local_task_id'])
                if not task or task.get('path') != manifest['worktree_path']:
                    fail("dispatch worktree record missing or inconsistent")
                path = m._validate_worktree(repo, task)
                if git(path, 'rev-parse', '--verify', 'HEAD^{commit}') != job['commit_sha']:
                    fail("prepared worktree commit changed")
                return copy.deepcopy(manifest)
            if any(r.get('job_id') == job['job_id'] for r in records.values()):
                fail("job already associated with another approval")
            local_task = 'dispatch-' + hashlib.sha256(key.encode()).hexdigest()[:32]
            if m._task(data, repo_id, local_task):
                fail("dispatch task collision")
            if git(repo, 'rev-parse', '--verify', 'HEAD^{commit}') != job['commit_sha']:
                fail("approved commit differs from local repository HEAD")
            # Intent survives every failure, including a crash after Git succeeds.
            records[key] = {'state': 'preparing', 'fingerprint': fingerprint, 'job_id': job['job_id']}
            m.registry.checkpoint(data)
            created = m._create_locked(data, repo_id, local_task, commit=job['commit_sha'])
            validate(job, self.clock())  # expiry during preparation leaves a blocked intent
            manifest = {'schema_version': 1, 'job_id': job['job_id'], 'project_id': job['project_id'],
                        'repository_id': repo_id, 'repository_identity': job['repository_identity'],
                        'commit_sha': job['commit_sha'], 'worktree_path': created['path'],
                        'local_task_id': local_task, 'approval': job['approval'],
                        'audit': {'prepared_at': datetime.fromtimestamp(self.clock(), timezone.utc).isoformat(),
                                  'envelope_sha256': fingerprint, 'adapter': 'forge-0.5B',
                                  'execution': False, 'transport': 'mock-only'}}
            records[key].update(state='prepared', manifest=manifest, manifest_sha256=digest(manifest))
            return copy.deepcopy(manifest)
