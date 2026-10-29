"""Offline composed lease/runtime tests. No daemon, agents or host commands."""
from dataclasses import replace
import json
from pathlib import Path
import unittest
import time
from unittest.mock import patch

import test_lease
from forge.container import ContainerAdapter, ContainerConfig
from forge.dispatch import digest
from forge.runtime import Runtime, SyntheticRequest
from forge.supervisor import SyntheticApproval, SyntheticSupervisor, request_digest
from forge.safety import SafetyError


class SupervisorTests(unittest.TestCase):
    new_worker = test_lease.LeaseTests.new_worker
    claim = test_lease.LeaseTests.claim
    # Reuse the local mock authority and private registry fixture only.
    def setUp(self):
        test_lease.LeaseTests.setUp(self)
        self.workspace = Path(self.tmp.name) / 'workspace'
        self.workspace.mkdir()
        with patch.object(ContainerConfig, 'validate'):
            self.adapter = ContainerAdapter(ContainerConfig('/docker', '/socket', 'unused'))
        self.adapter._attested = True  # Test double only, never live evidence.
        self.runtime = Runtime([str(self.workspace.resolve())], container=self.adapter)
        self.request = SyntheticRequest(str(self.workspace.resolve()))
        self.approval = SyntheticApproval(digest(self.job), self.job['task_id'],
                                          digest('attempt-1'), request_digest(self.request), True)
        self.subject = self.make_supervisor()

    def make_supervisor(self):
        return SyntheticSupervisor(self.registry, self.transport, 'worker-1', self.clock, self.runtime)

    def run_subject(self, approval=None):
        return self.subject.run(self.job, 'attempt-1', self.request, approval or self.approval)

    def test_composed_success_redacted_and_one_shot(self):
        with patch.object(self.adapter, 'execute', return_value=('completed', 0, b'private-output', b'', ())):
            result = self.run_subject()
        self.assertEqual(result['state'], 'completed')
        self.assertEqual(result['stdout_bytes'], 14)
        text = json.dumps(result) + (Path(self.tmp.name) / 'registry.json').read_text()
        for secret in ('private-output', 'mock-permit', 'attempt-1', str(self.workspace), 'description'):
            self.assertNotIn(secret, text)
        with self.assertRaises(SafetyError): self.run_subject()
        with self.assertRaises(SafetyError): self.make_supervisor().run(self.job, 'attempt-1', self.request, self.approval)

    def test_exact_operator_binding(self):
        for changes in ({'approved': False}, {'approved': 1}, {'task_id': 'other'},
                        {'attempt_digest': 'a' * 64}, {'envelope_digest': 'b' * 64},
                        {'request_digest': 'c' * 64}):
            self.subject = self.make_supervisor()
            with self.assertRaises(SafetyError): self.run_subject(replace(self.approval, **changes))
        self.assertEqual(self.transport.calls, 0)

    def test_cancellation_expiry_remote_loss_and_stale_generation(self):
        for mode in ('cancel', 'expiry', 'monotonic', 'remote', 'stale', 'lost'):
            if mode != 'cancel': self.setUp()
            def execute(request, signal):
                if mode == 'cancel': self.subject.cancel()
                if mode == 'expiry':
                    self.clock.advance(60)
                    self.clock.wall -= 10000
                if mode == 'monotonic': self.subject._deadline = time.monotonic() + .03
                if mode == 'remote': self.transport.cancel('job-1')
                if mode == 'lost': self.transport.fault = 'lost-response'
                if mode == 'stale':
                    row = self.transport._rows['job-1']
                    payload = {k: row[k] for k in ('job_id', 'generation', 'lease_credential')}
                    self.transport.request('renew', payload, 'worker-1')
                self.assertTrue(signal._event.wait(.5), mode)
                return 'canceled', None, b'', b'', ()
            with patch.object(self.adapter, 'execute', side_effect=execute):
                with self.assertRaises(SafetyError): self.run_subject()
            with self.registry.locked(write=False) as data:
                self.assertEqual(data['lease_records']['job-1']['state'], 'blocked')
            calls = self.transport.calls
            time.sleep(.04)
            self.assertEqual(self.transport.calls, calls)

    def test_cleanup_failure_never_reports_terminal_success(self):
        def fail(*args):
            self.adapter._failed = True
            raise SafetyError('private cleanup error')
        with patch.object(self.adapter, 'execute', side_effect=fail):
            with self.assertRaisesRegex(SafetyError, '^supervisor: attempt blocked; reconciliation required$'):
                self.run_subject()
        self.assertEqual(self.transport._rows['job-1']['state'], 'running')
        with self.registry.locked(write=False) as data:
            self.assertEqual(data['lease_records']['job-1']['synthetic_state'], 'blocked')

    def test_watchdog_independent_of_registry_and_caller(self):
        def execute(request, signal):
            # Deliberately hold bookkeeping lock: cancellation must still arrive.
            with self.registry.locked(write=True):
                self.subject.cancel()
                self.assertTrue(signal._event.wait(.5))
                # Cancellation itself sets signal; wait for supervisor to revoke.
                deadline = time.monotonic() + .5
                while not self.subject._worker.supervisor.terminated and time.monotonic() < deadline:
                    time.sleep(.005)
                self.assertTrue(self.subject._worker.supervisor.terminated)
            return 'canceled', None, b'', b'', ()
        with patch.object(self.adapter, 'execute', side_effect=execute):
            with self.assertRaises(SafetyError): self.run_subject()

    def test_restart_unresolved_intent_is_blocked(self):
        self.claim()
        self.make_supervisor()
        with self.registry.locked(write=False) as data:
            self.assertEqual(data['lease_records']['job-1']['state'], 'blocked')
        with self.assertRaises(SafetyError): self.run_subject()

    def test_no_attestation_or_nonempty_workspace_never_completes(self):
        self.adapter._attested = False
        with self.assertRaises(SafetyError): self.run_subject()

    def test_reconciliation_cannot_be_overwritten_by_old_worker(self):
        self.claim()
        self.make_supervisor()
        with self.assertRaises(SafetyError): self.worker.step('acknowledge')
        with self.registry.locked(write=False) as data:
            self.assertEqual(data['lease_records']['job-1']['state'], 'blocked')

    def test_interrupted_runtime_keeps_durable_fence(self):
        with patch.object(self.adapter, 'execute', side_effect=SystemExit(1)):
            with self.assertRaises(SystemExit): self.run_subject()
        with self.assertRaises(SafetyError):
            self.make_supervisor().run(self.job, 'attempt-1', self.request, self.approval)

    def test_request_change_and_agent_commands_refused_before_claim(self):
        for operation in ('codex', 'claude', 'sh -c id', [], 'capture-fixture'):
            self.subject = self.make_supervisor()
            self.request = replace(self.request, operation=operation)
            with self.assertRaises(SafetyError): self.run_subject()
        self.assertEqual(self.transport.calls, 0)

    def test_durable_intent_failure_prevents_container_invocation(self):
        original = self.registry.checkpoint
        def save(data):
            if any(row.get('synthetic_state') == 'intent'
                   for row in data.get('lease_records', {}).values()):
                raise OSError('private error')
            original(data)
        with patch.object(self.registry, 'checkpoint', side_effect=save), \
                patch.object(self.adapter, 'execute') as execute:
            with self.assertRaises(SafetyError): self.run_subject()
            execute.assert_not_called()
        with self.assertRaises(SafetyError):
            self.make_supervisor().run(self.job, 'attempt-1', self.request, self.approval)
