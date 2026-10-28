"""Offline lease tests: no Git, container, shell, network or credential access."""
import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from forge.dispatch import digest
from forge.lease import FakeClock, LeaseWorker, MockLeaseTransport, MockSupervisor
from forge.registry import Registry
from forge.safety import SafetyError


class LeaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        Path(self.tmp.name).chmod(0o700)
        self.registry = Registry(str(Path(self.tmp.name).resolve()))
        self.clock = FakeClock()
        self.transport = MockLeaseTransport(self.clock)
        self.supervisor = MockSupervisor()
        self.worker = self.new_worker()
        self.job = dict(job_id='job-1', project_id='project-1', repository_identity='org/repo',
                        commit_sha='a' * 40, task_id='task-1', title='Test', description='Test request')
        iso = lambda t: datetime.fromtimestamp(t, timezone.utc).isoformat()
        self.job['approval'] = dict(id='approval-1', state='approved', actor='operator',
                                   approved_at=iso(self.clock.wall - 1),
                                   expires_at=iso(self.clock.wall + 600), digest=digest(self.job))
        self.transport.register(self.job)

    def new_worker(self):
        return LeaseWorker(self.registry, self.transport, 'worker-1', self.clock, self.supervisor)

    def claim(self):
        return self.worker.claim(self.job, 'attempt-1')

    def running(self):
        self.claim()
        self.worker.step('acknowledge')
        self.worker.start_synthetic()

    def test_approval_before_transport(self):
        for change in ({'title': 'tampered'}, {'approval': {}}, {'commit_sha': 'HEAD'}):
            job = copy.deepcopy(self.job)
            job.update(change)
            with self.assertRaises(SafetyError):
                self.worker.claim(job, 'attempt-1')
        self.assertEqual(self.transport.calls, 0)

    def test_concurrent_claims_and_restart_fenced(self):
        workers = [self.new_worker(), self.new_worker()]
        def attempt(worker):
            try:
                worker.claim(self.job, 'attempt-1')
                return True
            except SafetyError:
                return False
        with ThreadPoolExecutor(2) as pool:
            self.assertEqual(sorted(pool.map(attempt, workers)), [False, True])
        self.assertEqual(self.transport.calls, 1)
        with self.assertRaises(SafetyError):
            self.new_worker().claim(self.job, 'attempt-2')

    def test_atomic_mock_claim_idempotency_and_competing_attempts(self):
        from forge.lease import binding
        b = binding(self.job, 'worker-1')
        payload = {k: b[k] for k in ('job_id', 'approval_id', 'repository_identity', 'commit_sha', 'envelope_digest')}
        payload['idempotency_key'] = 'attempt-1'
        def request(_):
            return self.transport.request('claim', payload, 'worker-1')
        with ThreadPoolExecutor(2) as pool:
            a, b = pool.map(request, range(2))
        self.assertEqual(a, b)
        payload['idempotency_key'] = 'attempt-2'
        with self.assertRaises(SafetyError):
            request(None)

    def test_cancel_stops_supervisor(self):
        self.running()
        self.transport.cancel('job-1')
        with self.assertRaises(SafetyError):
            self.worker.step()
        self.assertTrue(self.supervisor.terminated)
        self.assertTrue(self.supervisor.cancellation.requested)
        self.assertFalse(self.supervisor.active)
        self.assertIsNone(self.worker._permit)

    def test_cancel_before_claim(self):
        self.transport.cancel('job-1')
        with self.assertRaises(SafetyError):
            self.claim()
        self.assertTrue(self.supervisor.terminated)

    def test_rotation_stale_fencing_and_heartbeat_deadline(self):
        self.running()
        old = copy.deepcopy(self.worker._permit)
        deadline = self.worker._deadline
        self.clock.advance(20)
        self.worker.step()
        self.assertEqual(self.worker._deadline, deadline)
        self.worker.step('renew')
        self.assertEqual(self.worker._permit['generation'], 2)
        self.assertGreater(self.worker._deadline, deadline)
        for action in ('acknowledge', 'heartbeat', 'renew', 'finish'):
            payload = {k: old[k] for k in ('job_id', 'generation', 'lease_credential')}
            if action == 'finish':
                payload['state'] = 'completed'
            with self.assertRaises(SafetyError):
                self.transport.request(action, payload, 'worker-1')

    def test_local_expiry_wall_rollback_no_transport(self):
        self.running()
        self.clock.advance(60)
        self.clock.wall -= 10000
        calls = self.transport.calls
        with self.assertRaises(SafetyError):
            self.worker.step('renew')
        self.assertEqual(self.transport.calls, calls)
        self.assertTrue(self.supervisor.terminated)

    def test_renewal_failure_never_retries_or_recovers(self):
        for fault in ('disconnect', 'lost-response'):
            with self.subTest(fault=fault):
                # Each subcase uses a fresh registry and authority.
                if self.worker._job is not None:
                    self.tearDown()
                    self.setUp()
                self.running()
                self.transport.fault = fault
                calls = self.transport.calls
                with self.assertRaises(SafetyError) as caught:
                    self.worker.step('renew')
                self.assertEqual(self.transport.calls, calls + 1)
                self.assertNotIn('mock-permit', str(caught.exception))
                self.assertTrue(self.supervisor.terminated)
                with self.assertRaises(SafetyError):
                    self.worker.step()
                with self.assertRaises(SafetyError):
                    self.new_worker().claim(self.job, 'attempt-1')

    def test_terminal_states_final_and_redacted(self):
        self.running()
        secret = self.worker._permit['lease_credential']
        self.worker.step('finish', state='completed')
        text = (Path(self.tmp.name) / 'registry.json').read_text()
        self.assertNotIn(secret, text)
        self.assertNotIn('lease_credential', text)
        self.assertNotIn('attempt-1', text)
        self.assertNotIn('description', text)
        self.assertEqual(json.loads(text)['lease_records']['job-1']['state'], 'completed')
        self.assertNotIn(secret, json.dumps(self.worker.manifest()))
        self.assertTrue(self.supervisor.terminated)
        with self.assertRaises(SafetyError):
            self.worker.step('finish', state='completed')
        self.transport.cancel('job-1')
        self.assertEqual(self.transport._rows['job-1']['state'], 'completed')

    def test_execution_disabled_and_attestation_required(self):
        with patch.object(MockSupervisor, 'attest', return_value={'execution_enabled': True}):
            with self.assertRaises(SafetyError):
                self.claim()
        self.assertEqual(self.transport.calls, 0)
        self.running()
        with patch('subprocess.Popen', side_effect=AssertionError('execution forbidden')):
            with self.assertRaises(SafetyError):
                self.worker.execute('codex')
        self.assertFalse(self.worker.manifest()['execution_enabled'])

    def test_finish_requires_ack_and_server_expiry(self):
        self.claim()
        with self.assertRaises(SafetyError):
            self.worker.step('finish', state='failed')
        self.clock.advance(60)
        row = self.transport._rows['job-1']
        payload = {k: row[k] for k in ('job_id', 'generation', 'lease_credential')}
        with self.assertRaises(SafetyError):
            self.transport.request('acknowledge', payload, 'worker-1')
        self.assertEqual(row['state'], 'expired')

    def test_wrong_binding_response_fails_closed(self):
        original = self.transport.request
        def wrong(*args):
            response = original(*args)
            response['worker_id'] = 'other-worker'
            return response
        with patch.object(self.transport, 'request', side_effect=wrong):
            with self.assertRaises(SafetyError):
                self.claim()
        self.assertTrue(self.supervisor.terminated)

    def test_slow_renewal_cannot_cross_old_deadline(self):
        self.running()
        self.clock.advance(59)
        original = self.transport.request
        def delayed(*args):
            response = original(*args)
            self.clock.advance(2)
            return response
        with patch.object(self.transport, 'request', side_effect=delayed):
            with self.assertRaises(SafetyError):
                self.worker.step('renew')
        self.assertTrue(self.supervisor.terminated)

    def test_persistence_failure_stops_and_intent_fences_restart(self):
        self.claim()
        with patch.object(self.registry, 'checkpoint', side_effect=OSError('mock-permit-secret')):
            with self.assertRaises(SafetyError) as caught:
                self.worker.step('acknowledge')
        self.assertNotIn('mock-permit-secret', str(caught.exception))
        self.assertTrue(self.supervisor.terminated)
        with self.assertRaises(SafetyError):
            self.new_worker().claim(self.job, 'attempt-1')

    def test_bounded_records_fail_without_eviction(self):
        with patch.object(LeaseWorker, 'MAX_RECORDS', 0):
            with self.assertRaises(SafetyError):
                self.claim()
        self.assertEqual(self.transport.calls, 0)

    def test_all_worker_terminal_reports(self):
        for state in ('failed', 'canceled'):
            if self.worker._job is not None:
                self.setUp()
            self.running()
            self.worker.step('finish', state=state)
            self.assertEqual(self.transport._rows['job-1']['state'], state)
            self.assertTrue(self.supervisor.terminated)

    def test_concurrent_renewal_only_one_generation_wins(self):
        self.running()
        payload = {k: self.worker._permit[k] for k in ('job_id', 'generation', 'lease_credential')}
        def renew(_):
            try:
                self.transport.request('renew', payload, 'worker-1')
                return True
            except SafetyError:
                return False
        with ThreadPoolExecutor(2) as pool:
            self.assertEqual(sorted(pool.map(renew, range(2))), [False, True])
        with self.assertRaises(SafetyError):
            self.worker.step()
        self.assertTrue(self.supervisor.terminated)

    def test_wrong_worker_and_credential_refused(self):
        self.running()
        payload = {k: self.worker._permit[k] for k in ('job_id', 'generation', 'lease_credential')}
        with self.assertRaises(SafetyError):
            self.transport.request('heartbeat', payload, 'worker-2')
        payload['lease_credential'] = 'wrong'
        with self.assertRaises(SafetyError):
            self.transport.request('heartbeat', payload, 'worker-1')


if __name__ == '__main__':
    unittest.main()
