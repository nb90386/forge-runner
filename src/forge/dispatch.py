"""Bounded read-only control-plane integration; preparation only, never execution."""
import copy
import hashlib
import http.client
import json
import math
import socket
import re
import time
from datetime import datetime, timezone
from typing import Protocol
from urllib.parse import urlsplit

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


class LoopbackTransport:
    """Direct numeric-loopback HTTP only. No DNS, proxy support or redirects.

    The local operator must provide a trusted tunnel/listener and explicit port.
    Loopback HTTP is not authentication of the remote end of that tunnel.
    """
    MAX_BODY = 921600

    def __init__(self, base_url):
        try:
            url = urlsplit(base_url)
            if (url.scheme != 'http' or url.hostname not in ('127.0.0.1', '::1')
                    or url.username is not None or url.password is not None
                    or url.path or url.query or url.fragment or url.port is None
                    or not 1 <= url.port <= 65535
                    or base_url != 'http://' + ('[::1]' if url.hostname == '::1' else '127.0.0.1') + ':' + str(url.port)):
                fail("explicit numeric loopback origin and port required")
            self.host, self.port = url.hostname, url.port
        except (ValueError, TypeError):
            fail("invalid loopback origin")

    def get(self, path, *, bearer_token, timeout):
        if not isinstance(path, str) or not (
                re.fullmatch(r'/api/worker/approved-jobs\?limit=100&after=(0|[1-9][0-9]{0,18})', path)
                or re.fullmatch(r'/api/worker/approval-authorization\?approval_id=[a-z0-9][a-z0-9-]{0,47}&envelope_digest=[0-9a-f]{64}', path)):
            fail("unexpected metadata path")
        connection = http.client.HTTPConnection(self.host, self.port, timeout=timeout)
        sock = socket.socket(socket.AF_INET6 if self.host == '::1' else socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            # Numeric address and fixed address family avoid name resolution entirely.
            sock.connect((self.host, self.port))
            if sock.getpeername()[:2] != (self.host, self.port):
                fail("unexpected network destination")
            connection.sock = sock
            connection.request('GET', path, headers={'Authorization': 'Bearer ' + bearer_token,
                                                    'Accept': 'application/json'})
            response = connection.getresponse()
            if response.status != 200:
                return response.status, b''
            if response.getheader('Content-Encoding', 'identity') != 'identity':
                fail("unsupported metadata encoding")
            length = response.getheader('Content-Length')
            if length is not None:
                if not re.fullmatch(r'[0-9]+', length) or len(length) > 10 or int(length) > self.MAX_BODY:
                    fail("metadata response exceeds bounds")
            body = response.read(self.MAX_BODY + 1)
            if length is not None and len(body) != int(length):
                fail("incomplete metadata response")
            if len(body) > self.MAX_BODY:
                fail("metadata response exceeds bounds")
            return response.status, body
        finally:
            connection.close()
            sock.close()


class DispatchClient:
    """Supply the existing worker token callable; credentials stay in memory."""
    MAX_PAGES = 100
    MAX_BYTES = 32 * 1024 * 1024
    MAX_JOBS = 10000

    def __init__(self, transport, token_provider, *, timeout=10, attempts=3, sleep=time.sleep):
        if type(transport) not in (MockTransport, LoopbackTransport):
            fail("unsupported metadata transport")
        if (not isinstance(timeout, (int, float)) or not math.isfinite(timeout)
                or not 0 < timeout <= 30 or type(attempts) is not int or not 1 <= attempts <= 3):
            fail("invalid timeout or retry bounds")
        self.transport, self.token_provider = transport, token_provider
        self.timeout, self.attempts, self.sleep = timeout, attempts, sleep

    def _request(self, path, *, retry=True):
        for attempt in range(self.attempts if retry else 1):
            try:
                token = self.token_provider()
                if not isinstance(token, str) or not token or not all(33 <= ord(c) <= 126 for c in token):
                    fail("worker token unavailable")
                status, body = self.transport.get(path, bearer_token=token, timeout=self.timeout)
            except SafetyError:
                raise SafetyError("dispatch: metadata transport refused") from None
            except Exception:
                status, body = 503, b''
            if type(status) is not int:
                fail("invalid HTTP status")
            if status == 200:
                if not isinstance(body, bytes) or len(body) > LoopbackTransport.MAX_BODY:
                    fail("metadata response exceeds bounds")
                try:
                    def unique(pairs):
                        result = {}
                        for key, value in pairs:
                            if key in result:
                                raise ValueError()
                            result[key] = value
                        return result
                    payload = json.loads(body.decode('utf-8'), object_pairs_hook=unique)
                except (ValueError, TypeError, RecursionError):
                    fail("invalid JSON metadata")
                return payload, len(body)
            if not retry or status not in (429, 502, 503, 504):
                fail("metadata request refused (HTTP %s)" % status)
            if attempt + 1 < self.attempts:
                self.sleep(0.1 * (2 ** attempt))
        fail("metadata service unavailable after bounded retries")

    def poll(self):
        after, total = 0, 0
        jobs, approvals, job_ids = [], {}, set()
        for _ in range(self.MAX_PAGES):
            payload, size = self._request('/api/worker/approved-jobs?limit=100&after=' + str(after))
            total += size
            if (total > self.MAX_BYTES or not isinstance(payload, dict)
                    or set(payload) != {'schema_version', 'jobs', 'next_cursor'}
                    or type(payload['schema_version']) is not int or payload['schema_version'] != 1
                    or not isinstance(payload['jobs'], list) or len(payload['jobs']) > 100):
                fail("invalid or unbounded feed")
            for job in payload['jobs']:
                fingerprint = validate(job, time.time())
                key = job['approval']['id']
                if key in approvals:
                    if approvals[key] != fingerprint:
                        fail("inconsistent approval in feed")
                    continue  # Exact envelope replay is idempotent, never a second job.
                if job['job_id'] in job_ids:
                    fail("job associated with multiple approvals in feed")
                approvals[key] = fingerprint
                job_ids.add(job['job_id'])
                jobs.append(copy.deepcopy(job))
                if len(jobs) > self.MAX_JOBS:
                    fail("job count exceeds bounds")
            cursor = payload['next_cursor']
            if cursor is None:
                for job in jobs:
                    validate(job, time.time())
                return jobs
            if type(cursor) is not int or not after < cursor <= 9223372036854775807:
                fail("nonmonotonic feed cursor")
            after = cursor
        fail("incomplete feed: page bound exceeded")

    def authorize(self, job):
        fingerprint = validate(job, time.time())
        key = job['approval']['id']
        # Authorization is never retried or cached: fail at this boundary.
        payload, _ = self._request('/api/worker/approval-authorization?approval_id=' + key
                                   + '&envelope_digest=' + fingerprint, retry=False)
        expected = {'schema_version': 1, 'authorized': True, 'approval_id': key,
                    'envelope_digest': fingerprint}
        if (not isinstance(payload, dict) or payload != expected
                or type(payload.get('schema_version')) is not int
                or payload.get('authorized') is not True):
            fail("current authorization mismatch")
        validate(job, time.time())


class Dispatcher:
    def __init__(self, manager, client=None, *, clock=time.time):
        self.manager, self.client, self.clock = manager, client, clock

    def _authorize(self, job):
        if type(self.client) is not DispatchClient:
            fail("current authorization client required")
        self.client.authorize(job)
        validate(job, self.clock())

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
                self._authorize(job)
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
            self._authorize(job)
            created = m._create_locked(data, repo_id, local_task, commit=job['commit_sha'])
            self._authorize(job)  # revocation/expiry leaves durable blocked intent
            manifest = {'schema_version': 1, 'job_id': job['job_id'], 'project_id': job['project_id'],
                        'repository_id': repo_id, 'repository_identity': job['repository_identity'],
                        'commit_sha': job['commit_sha'], 'worktree_path': created['path'],
                        'local_task_id': local_task, 'approval': job['approval'],
                        'audit': {'prepared_at': datetime.fromtimestamp(self.clock(), timezone.utc).isoformat(),
                                  'envelope_sha256': fingerprint, 'adapter': 'forge-0.5D',
                                  'execution': False, 'transport': type(self.client.transport).__name__}}
            records[key].update(state='prepared', manifest=manifest, manifest_sha256=digest(manifest))
            return copy.deepcopy(manifest)
