"""Fake loopback authority only. No credentials, agents, Git or control-plane writes."""
import copy
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from forge.dispatch import digest
from forge.lease import FakeClock, MockLeaseTransport
from forge.lease_http import HTTPLeaseTransport, HTTPLeaseWorker, ProcessGroupCancellation
from forge.registry import Registry
from forge.safety import SafetyError

SECRET = 'test-only-execution-secret-' + 'x' * 40


class FakeServer:
    def __init__(self):
        self.clock = FakeClock(time.time())
        self.authority = MockLeaseTransport(self.clock)
        self.fault = None
        outer = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                if (self.headers.get('Authorization') != 'Bearer ' + SECRET
                        or self.headers.get('X-Forge-Worker-ID') != 'worker-1'):
                    self.send_error(401)
                    return
                data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                action = self.path.rsplit('/', 1)[-1]
                fault, outer.fault = outer.fault, None
                if fault == 'hang':
                    time.sleep(.4)
                    self.close_connection = True
                    return
                try:
                    outer.clock.wall = max(outer.clock.wall, time.time())
                    row = outer.authority.request(action, data, 'worker-1')
                    if 'lease_credential' in row:
                        # Fake authority credentials are mapped to server wire format.
                        row['lease_credential'] = digest(row['lease_credential'])
                        outer.credentials[row['lease_credential']] = outer.authority._rows[data['job_id']]['lease_credential']
                    if fault == 'extra':
                        row['unexpected'] = SECRET
                    if fault == 'generation':
                        row['generation'] = True
                    if fault == 'disconnect':
                        self.connection.shutdown(socket.SHUT_RDWR)
                        return
                    raw = json.dumps(row).encode()
                    if fault == 'duplicate':
                        raw = raw[:-1] + b', "generation": 1}'
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Cache-Control', 'no-store')
                    self.send_header('Content-Length', str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                except SafetyError:
                    self.send_error(409)
        self.credentials = {}
        original = self.authority.request
        def translated(action, data, worker):
            data = dict(data)
            if 'lease_credential' in data:
                data['lease_credential'] = self.credentials.get(data['lease_credential'], 'invalid')
            return original(action, data, worker)
        self.authority.request = translated
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        self.thread.start()
        self.origin = 'http://127.0.0.1:' + str(self.server.server_port)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


class HTTPLeaseTests(unittest.TestCase):
    def setUp(self):
        try:
            self.server = FakeServer()
        except PermissionError:
            self.skipTest("sandbox prohibits loopback bind; wire tests run separately")
        self.addCleanup(self.server.close)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        Path(self.tmp.name).chmod(0o700)
        self.registry = Registry(str(Path(self.tmp.name).resolve()))
        self.transport = HTTPLeaseTransport(self.server.origin, lambda: SECRET, timeout=.2)
        self.worker = HTTPLeaseWorker(self.registry, self.transport, 'worker-1', poll_interval=1)
        self.addCleanup(self.worker.close)
        now = time.time()
        self.job = dict(job_id='job-1', project_id='project-1', repository_identity='org/repo',
                        commit_sha='a' * 40, task_id='task-1', title='Test', description='Test')
        iso = lambda t: datetime.fromtimestamp(t, timezone.utc).isoformat()
        self.job['approval'] = dict(id='approval-1', state='approved', actor='operator',
                                   approved_at=iso(now-1), expires_at=iso(now+600), digest=digest(self.job))
        self.server.authority.register(self.job)

    def running(self):
        self.worker.claim(self.job, 'attempt-1')
        self.worker.step('acknowledge')

    def test_claim_renew_fence_finish_redaction(self):
        self.running()
        old = copy.deepcopy(self.worker._permit)
        self.worker.step('renew')
        self.assertEqual(self.worker._permit['generation'], 2)
        with self.assertRaises(SafetyError):
            self.transport.request('heartbeat', {k: old[k] for k in ('job_id', 'generation', 'lease_credential')}, 'worker-1')
        self.worker.step('finish', state='completed')
        text = (Path(self.tmp.name) / 'registry.json').read_text() + json.dumps(self.worker.manifest())
        self.assertNotIn(SECRET, text)
        self.assertNotIn(old['lease_credential'], text)
        self.assertNotIn('attempt-1', text)
        with self.assertRaises(SafetyError):
            self.worker.execute()

    def test_cancellation_polled_without_caller(self):
        self.running()
        self.server.authority.cancel('job-1')
        self.wait_stopped(1.5)

    def wait_stopped(self, bound):
        until = time.monotonic() + bound
        while not self.worker.supervisor.terminated and time.monotonic() < until:
            time.sleep(.01)
        self.assertTrue(self.worker.supervisor.terminated)

    def test_expiry_independent_of_worker_lock(self):
        self.running()
        with self.worker._lock:
            self.worker._deadline = time.monotonic() + .05
            self.wait_stopped(.3)
        self.assertIsNone(self.worker._permit)

    def test_lost_rotation_blocks_restart_and_reconciles(self):
        self.running()
        self.server.fault = 'disconnect'
        with self.assertRaises(SafetyError):
            self.worker.step('renew')
        fresh = HTTPLeaseWorker(self.registry, self.transport, 'worker-1')
        self.addCleanup(fresh.close)
        with self.assertRaises(SafetyError):
            fresh.claim(self.job, 'attempt-2')
        with self.registry.locked(write=False) as data:
            self.assertEqual(data['lease_records']['job-1']['state'], 'blocked')

    def test_authentication(self):
        bad = HTTPLeaseTransport(self.server.origin, lambda: 'z' * 40)
        with self.assertRaises(SafetyError):
            bad.request('claim', {}, 'worker-1')
        self.transport._secret = 'z' * 40
        with self.assertRaises(SafetyError):
            self.worker.claim(self.job, 'attempt-1')

    def test_timeout_bounded_and_redacted(self):
        self.running()
        self.server.fault = 'hang'
        start = time.monotonic()
        with self.assertRaises(SafetyError) as caught:
            self.worker.step('renew')
        self.assertLess(time.monotonic() - start, .6)
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertTrue(self.worker.supervisor.terminated)

    def test_exact_contract(self):
        for fault in ('extra', 'generation', 'duplicate'):
            with self.subTest(fault=fault):
                self.server.fault = fault
                from forge.lease import binding
                bound = binding(self.job, 'worker-1')
                payload = {k: bound[k] for k in ('job_id', 'approval_id', 'repository_identity', 'commit_sha', 'envelope_digest')}
                payload['idempotency_key'] = 'attempt-1'
                with self.assertRaises(SafetyError):
                    self.transport.request('claim', payload, 'worker-1')

    def test_server_restart_preserves_expiry_and_revocation(self):
        self.running()
        deadline = self.worker._deadline
        # Restart fake authority from persisted rows; no lease extension.
        before = copy.deepcopy(self.server.authority._rows)
        replacement = MockLeaseTransport(self.server.clock)
        replacement._jobs = copy.deepcopy(self.server.authority._jobs)
        replacement._rows = before
        # Preserve wire credential translation across simulated service restart.
        original = replacement.request
        def translated(action, data, worker):
            data = dict(data)
            if 'lease_credential' in data:
                data['lease_credential'] = self.server.credentials.get(data['lease_credential'], 'invalid')
            return original(action, data, worker)
        replacement.request = translated
        self.server.authority = replacement
        self.worker.step()
        self.assertEqual(self.worker._deadline, deadline)
        replacement.cancel('job-1')  # disabled/changed-secret startup reconciliation
        with self.assertRaises(SafetyError):
            self.worker.step()

    def test_loopback_only_and_tree_guarantee_refused(self):
        for origin in ('https://127.0.0.1:1', 'http://localhost:1', 'http://192.0.2.1:1', 'http://127.0.0.1:1/'):
            with self.assertRaises(SafetyError):
                HTTPLeaseTransport(origin, lambda: SECRET)
        with patch('os.killpg') as kill:
            with self.assertRaises(SafetyError):
                ProcessGroupCancellation(999999).terminate()
            self.assertEqual(kill.call_count, 2)


class WireSocket:
    """HTTPConnection byte-level socket fixture; no operating-system sockets."""
    def __init__(self, fixture):
        self.fixture = fixture
        self.sent = b''
        self.interrupted = threading.Event()

    def settimeout(self, timeout):
        pass

    def connect(self, address):
        self.address = address

    def getpeername(self):
        return self.address

    def sendall(self, data):
        self.sent += bytes(data)

    def shutdown(self, how):
        self.interrupted.set()

    def close(self):
        pass

    def makefile(self, mode):
        import io
        headers, body = self.sent.split(b'\r\n\r\n', 1)
        f = self.fixture
        self.fixture.requests.append(headers)
        action = headers.split(b' ')[1].decode().rsplit('/', 1)[-1]
        if b'Authorization: Bearer ' + SECRET.encode() not in headers:
            return io.BytesIO(b'HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n')
        fault, f.fault = f.fault, None
        if fault == 'hang':
            self.interrupted.wait(1)
            return io.BytesIO(b'')
        try:
            data = json.loads(body)
            if 'lease_credential' in data:
                data['lease_credential'] = f.credentials.get(data['lease_credential'], 'invalid')
            f.clock.wall = max(f.clock.wall, time.time())
            row = f.authority.request(action, data, 'worker-1')
            if 'lease_credential' in row:
                wire = digest(row['lease_credential'])
                f.credentials[wire] = row['lease_credential']
                row['lease_credential'] = wire
            if fault == 'disconnect':
                return io.BytesIO(b'')
            if fault == 'extra':
                row['unexpected'] = SECRET
            if fault == 'generation':
                row['generation'] = True
            if fault == 'future':
                row['updated_at'] += 500
            raw = json.dumps(row).encode()
            if fault == 'duplicate':
                raw = raw[:-1] + b', "generation":1}'
            return io.BytesIO(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
                              b'Cache-Control: no-store\r\nContent-Length: ' + str(len(raw)).encode()
                              + b'\r\n\r\n' + raw)
        except SafetyError:
            return io.BytesIO(b'HTTP/1.1 409 Conflict\r\nContent-Length: 0\r\n\r\n')


class WireLeaseTests(HTTPLeaseTests):
    """Run lifecycle contract tests through real HTTPConnection and JSON parsing."""
    def setUp(self):
        from types import SimpleNamespace
        self.server = SimpleNamespace(clock=FakeClock(time.time()), fault=None,
                                      credentials={}, requests=[], origin='http://127.0.0.1:12345')
        self.server.authority = MockLeaseTransport(self.server.clock)
        self.socket_patch = patch('forge.lease_http.socket.socket', side_effect=lambda *a: WireSocket(self.server))
        self.socket_patch.start()
        self.addCleanup(self.socket_patch.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        Path(self.tmp.name).chmod(0o700)
        self.registry = Registry(str(Path(self.tmp.name).resolve()))
        self.transport = HTTPLeaseTransport('http://127.0.0.1:12345', lambda: SECRET, timeout=.2)
        self.worker = HTTPLeaseWorker(self.registry, self.transport, 'worker-1', poll_interval=1)
        self.addCleanup(self.worker.close)
        now = time.time()
        self.job = dict(job_id='job-1', project_id='project-1', repository_identity='org/repo',
                        commit_sha='a' * 40, task_id='task-1', title='Test', description='Test')
        iso = lambda t: datetime.fromtimestamp(t, timezone.utc).isoformat()
        self.job['approval'] = dict(id='approval-1', state='approved', actor='operator',
                                   approved_at=iso(now-1), expires_at=iso(now+600), digest=digest(self.job))
        self.server.authority.register(self.job)

    def test_server_restart_preserves_expiry_and_revocation(self):
        self.running()
        deadline = self.worker._deadline
        # JSON round trip represents persisted fake-server state, never control-plane files.
        state = json.loads(json.dumps({'rows': self.server.authority._rows,
                                      'jobs': self.server.authority._jobs}))
        replacement = MockLeaseTransport(self.server.clock)
        replacement._rows, replacement._jobs = state['rows'], state['jobs']
        self.server.authority = replacement
        self.worker.step()
        self.assertEqual(self.worker._deadline, deadline)
        replacement.cancel('job-1')
        with self.assertRaises(SafetyError):
            self.worker.step()

    def test_late_reply_after_watchdog_never_restores_authority(self):
        self.running()
        original = self.transport.request
        def delayed(*args):
            result = original(*args)
            time.sleep(.12)
            return result
        self.worker._deadline = time.monotonic() + .03
        with patch.object(self.transport, 'request', side_effect=delayed):
            with self.assertRaises(SafetyError):
                self.worker.step('renew')
        self.assertIsNone(self.worker._permit)
        self.assertTrue(self.worker.supervisor.terminated)

    def test_future_clock_fails_closed(self):
        self.server.fault = 'future'
        with self.assertRaises(SafetyError):
            self.worker.claim(self.job, 'attempt-1')

    def test_local_cancel_without_caller(self):
        self.running()
        self.worker.supervisor.cancellation.cancel()
        self.wait_stopped(.3)
        self.assertIsNone(self.worker._permit)

    def test_persistence_failure_stops_and_redacts(self):
        self.running()
        with patch.object(self.registry, 'checkpoint', side_effect=OSError(SECRET)):
            with self.assertRaises(SafetyError) as caught:
                self.worker.step('renew')
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertTrue(self.worker.supervisor.terminated)
        fresh = HTTPLeaseWorker(self.registry, self.transport, 'worker-1')
        self.addCleanup(fresh.close)
        with self.assertRaises(SafetyError):
            fresh.claim(self.job, 'attempt-2')

    def test_reconciled_record_cannot_be_reanimated_by_old_worker(self):
        self.running()
        fresh = HTTPLeaseWorker(self.registry, self.transport, 'worker-1')
        self.addCleanup(fresh.close)
        with self.assertRaises(SafetyError):
            self.worker.step()
        self.assertTrue(self.worker.supervisor.terminated)
        with self.registry.locked(write=False) as data:
            self.assertEqual(data['lease_records']['job-1']['state'], 'blocked')

    def test_server_expiry_refused(self):
        self.running()
        self.server.clock.advance(61)
        with self.assertRaises(SafetyError):
            self.worker.step()
        self.assertEqual(self.server.authority._rows['job-1']['state'], 'expired')

    def test_wall_rollback_does_not_change_deadline(self):
        self.running()
        deadline = self.worker._deadline
        with patch('forge.lease_http.time.time', return_value=time.time() - 10000):
            self.worker._deadline = time.monotonic() + .03
            self.wait_stopped(.3)
        self.assertLess(self.worker.clock.monotonic, deadline)
        self.assertIsNone(self.worker._deadline)
