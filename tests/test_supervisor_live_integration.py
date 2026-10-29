"""Disposable Engine/SyntheticSupervisor gate; no agents or host subprocesses.

Direct execution exits 0 PASS, 1 FAIL, 2 SKIP (unverified). Discovery retains
unittest's explicit skips; its exit status alone is never live PASS evidence.
All four FORGE_TEST_* settings are mandatory. No image provisioning is done.
"""
from dataclasses import replace
import json
import os
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import test_lease
from forge.container import ContainerAdapter, ContainerConfig
from forge.dispatch import digest
from forge.registry import Registry
from forge.runtime import Limits, Runtime, SyntheticRequest
from forge.safety import SafetyError
from forge.supervisor import SyntheticApproval, SyntheticSupervisor, request_digest

SETTINGS = ('FORGE_TEST_DOCKER', 'FORGE_TEST_SOCKET', 'FORGE_TEST_IMAGE',
            'FORGE_TEST_EXPECTED_ID')


@unittest.skipUnless(all(os.environ.get(key) for key in SETTINGS),
                     'SKIP: all four explicit FORGE_TEST_* settings required; live gate unverified')
class LiveSyntheticSupervisorIntegration(unittest.TestCase):
    new_worker = test_lease.LeaseTests.new_worker

    def setUp(self):
        # Reuse only the disposable registry/envelope and local mock authority.
        test_lease.LeaseTests.setUp(self)
        self.workspace = Path(self.tmp.name) / 'workspace'
        self.workspace.mkdir(mode=0o700)
        self.adapter = ContainerAdapter(ContainerConfig(*(os.environ[key] for key in SETTINGS)))
        self.adapter.conform()  # New real attestation for every test, never mocked.
        self.assertTrue(self.adapter._attested)
        self.assertFalse(self.adapter._failed)
        self.runtime = Runtime([str(self.workspace.resolve())], container=self.adapter)
        self.request = SyntheticRequest(str(self.workspace.resolve()), limits=Limits(wall_seconds=3, grace_seconds=1))
        self.subject = self.new_subject(self.registry)
        self.operations = []
        self.names = set()
        self.confirmed = set()
        self.started = False
        self.mode = None

    def new_subject(self, registry):
        return SyntheticSupervisor(registry, self.transport, 'worker-1', self.clock, self.runtime)

    def run_subject(self, approval=None):
        approval = approval or SyntheticApproval(digest(self.job), self.job['task_id'],
                    digest('attempt-1'), request_digest(self.request), True)
        return self.subject.run(self.job, 'attempt-1', self.request, approval)

    def observe(self, args, **kwargs):
        self.operations.append(args[0])
        if args[0] == 'create':
            self.names.add(args[args.index('--name') + 1])
        callback = kwargs.get('on_started')
        if callback:
            def started():
                # Preserve actual marker/running/PID/timestamp checks, suppress
                # only the conformance fixture's automatic self-cancellation.
                signal = kwargs['cancellation']
                with patch.object(signal, 'cancel'):
                    callback()
                self.started = True
                if self.mode == 'cancel':
                    self.subject.cancel()
                elif self.mode == 'expiry':
                    self.clock.advance(60)
            kwargs['on_started'] = started
        result = self.real_operation(args, **kwargs)
        if args[0] == 'ps':
            self.assertEqual(result, (0, b'', b''), 'real absence confirmation failed')
            name = args[3][7:-1]
            self.assertIn(name, self.names)
            self.confirmed.add(name)
            if self.mode == 'cleanup':
                return 0, b'controlled-uncertainty', b''
        return result

    def exercise(self, mode):
        self.mode = mode
        self.real_operation = self.adapter._engine.operation
        started = time.monotonic()
        with patch.object(self.adapter._engine, 'operation', side_effect=self.observe):
            if mode in ('success', 'timeout'):
                result = self.run_subject()
                self.assertEqual(result['state'], 'completed' if mode == 'success' else 'failed')
                self.assertIs(result['real_agent_execution'], False)
                serialized = json.dumps(result)
                for private in (str(self.workspace), 'mock-permit', 'attempt-1', 'Test request'):
                    self.assertNotIn(private, serialized)
            else:
                with self.assertRaisesRegex(SafetyError, '^supervisor: attempt blocked; reconciliation required$'):
                    self.run_subject()
        # Existing bounds: daemon/image/create/inspect calls at 10s each,
        # attach at wall_seconds, stop at grace+3, and remove/query at 10s.
        # This is a conservative scheduled-run bound, not a crash watchdog.
        self.assertLess(time.monotonic() - started, 120)
        self.assertEqual(len(self.names), 1)
        self.assertEqual(self.confirmed, self.names)
        self.assertFalse(list(self.workspace.iterdir()))
        if mode in ('cancel', 'expiry', 'timeout'):
            self.assertTrue(self.started)
            self.assertIn('stop', self.operations)
            self.assertLess(self.operations.index('stop'), self.operations.index('rm'))
        self.assertLess(self.operations.index('rm'), self.operations.index('ps'))
        with self.registry.locked(write=False) as data:
            row = data['lease_records'][self.job['job_id']]
            self.assertEqual(row['state'], 'completed' if mode == 'success' else 'failed' if mode == 'timeout' else 'blocked')
        # Reopen storage, reconstruct supervision, and prove refusal before Engine
        # or transport access; persisted state is never execution authority.
        before = self.transport.calls
        restarted = self.new_subject(Registry(str(Path(self.tmp.name).resolve())))
        with patch.object(self.adapter._engine, 'operation', side_effect=AssertionError('restart executed')):
            with self.assertRaises(SafetyError):
                restarted.run(self.job, 'attempt-2', self.request,
                    SyntheticApproval(digest(self.job), self.job['task_id'], digest('attempt-2'), request_digest(self.request), True))
        self.assertEqual(self.transport.calls, before)

    def test_approved_job_and_restart_refusal(self):
        approval = SyntheticApproval(digest(self.job), self.job['task_id'], digest('wrong-attempt'), request_digest(self.request), True)
        with patch.object(self.adapter._engine, 'operation', side_effect=AssertionError('unapproved execution')):
            with self.assertRaises(SafetyError):
                self.run_subject(approval)
        self.assertEqual(self.transport.calls, 0)
        self.subject = self.new_subject(self.registry)
        self.exercise('success')

    def test_supervisor_cancellation_after_confirmed_start(self):
        self.request = replace(self.request, operation='cancel-fixture')
        self.exercise('cancel')

    def test_lease_expiry_after_confirmed_start(self):
        self.request = replace(self.request, operation='timeout-fixture')
        self.exercise('expiry')

    def test_wall_timeout_and_bounded_termination(self):
        self.request = replace(self.request, operation='timeout-fixture')
        self.exercise('timeout')

    def test_cleanup_uncertainty_poison_and_restart_refusal(self):
        self.exercise('cleanup')
        self.assertTrue(self.adapter._failed)
        with self.assertRaises(SafetyError):
            self.adapter.conform()
        self.assertEqual(self.transport._rows[self.job['job_id']]['state'], 'running')

    def test_durable_terminal_reporting_failure_and_restart_refusal(self):
        checkpoint = self.registry.checkpoint
        failures = []
        def fail_terminal(data):
            row = data.get('lease_records', {}).get(self.job['job_id'], {})
            if row.get('state') == 'completed':
                failures.append(True)
                raise OSError('controlled durable report failure')
            checkpoint(data)
        with patch.object(self.registry, 'checkpoint', side_effect=fail_terminal):
            self.exercise('report')
        self.assertTrue(failures)
        # Authority accepted finish, but failed local persistence must still fence.
        self.assertEqual(self.transport._rows[self.job['job_id']]['state'], 'completed')


def main():
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(LiveSyntheticSupervisorIntegration)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    status = 'FAIL' if not result.wasSuccessful() else 'SKIP' if result.skipped or result.testsRun != 6 else 'PASS'
    print('Forge 0.7 disposable live supervisor gate: ' + status)
    return {'PASS': 0, 'FAIL': 1, 'SKIP': 2}[status]


if __name__ == '__main__':
    sys.exit(main())
