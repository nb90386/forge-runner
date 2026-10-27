import copy
import json
import unittest
from unittest.mock import patch
from datetime import datetime, timezone

import test_forge
from test_forge import git
from forge import Manager, SafetyError
from forge.dispatch import DispatchClient, Dispatcher, MockTransport, digest, validate


def job(sha='a' * 40):
    content = dict(job_id='job-1', project_id='project-1', repository_identity='forge/example',
                   commit_sha=sha, task_id='task-1', title='Implement', description='Approved request')
    now = datetime.now(timezone.utc).timestamp()
    content['approval'] = dict(id='approval-1', state='approved', actor='operator',
                               approved_at=datetime.fromtimestamp(now - 10, timezone.utc).isoformat(),
                               expires_at=datetime.fromtimestamp(now + 600, timezone.utc).isoformat(),
                               digest=digest(content))
    return content


class ClientTests(unittest.TestCase):
    def test_poll_retry_and_no_mutation(self):
        transport = MockTransport([(503, b'token-secret'), (200, json.dumps({'jobs': [job()]}).encode())])
        client = DispatchClient(transport, lambda: 'token-secret', sleep=lambda _: None)
        self.assertEqual(client.poll()[0]['job_id'], 'job-1')
        self.assertEqual(transport.calls, 2)

    def test_failures_redact_and_bound(self):
        for responses in ([(503, b'')] * 3, [TimeoutError('token-secret')] * 3,
                          [(401, b'token-secret')], [(302, b'')], [(200, b'invalid')],
                          [(200, json.dumps({'jobs': [{'path': '/etc'}]}).encode())],
                          [(200, b'x' * (1024 * 1024 + 1))]):
            transport = MockTransport(responses)
            with self.assertRaises(SafetyError) as caught:
                DispatchClient(transport, lambda: 'token-secret', sleep=lambda _: None).poll()
            self.assertNotIn('token-secret', str(caught.exception))
            self.assertLessEqual(transport.calls, 3)

    def test_live_disabled(self):
        with self.assertRaises(SafetyError):
            DispatchClient(object(), lambda: 'secret')

    def test_validation(self):
        for change in ({'path': '/etc'}, {'commit_sha': 'HEAD'}, {'project_id': '../etc'},
                       {'approval': {}}, {'title': 'changed'}):
            value = job()
            value.update(change)
            with self.assertRaises(SafetyError):
                validate(value, datetime.now(timezone.utc).timestamp())
        for change in ({'state': 'pending'}, {'actor': 'worker'}, {'expires_at': '2000-01-01T00:00:00Z'},
                       {'approved_at': '2999-01-01T00:00:00Z'}, {'approved_at': '2026-01-01'}):
            value = job()
            value['approval'].update(change)
            with self.assertRaises(SafetyError):
                validate(value, datetime.now(timezone.utc).timestamp())


class DispatchIntegrationTests(unittest.TestCase):
    setUp = test_forge.IntegrationTests.setUp
    tearDown = test_forge.IntegrationTests.tearDown

    def setup_dispatch(self):
        self.manager.approve('repo', self.repo)
        self.dispatch = Dispatcher(self.manager)
        self.dispatch.bind('project-1', 'repo', 'forge/example')
        return job(git(self.repo, 'rev-parse', 'HEAD'))

    def test_persistent_idempotency_manifest_and_cleanup(self):
        value = self.setup_dispatch()
        transport = MockTransport([(200, json.dumps({'jobs': [value]}).encode())])
        polled = DispatchClient(transport, lambda: 'dummy').poll()[0]
        manifest = self.dispatch.prepare(polled)
        json.dumps(manifest)
        restarted = Dispatcher(Manager(self.state, [self.root], self.work))
        self.assertEqual(restarted.prepare(value), manifest)
        self.assertEqual(len(list(self.work.iterdir())), 1)
        self.manager.cleanup('repo', manifest['local_task_id'])
        with self.assertRaises(SafetyError):
            restarted.prepare(value)
        self.assertEqual(list(self.work.iterdir()), [])

    def test_unknown_identity_commit_and_path(self):
        original = self.setup_dispatch()
        for changes in ({'project_id': 'unknown'}, {'repository_identity': 'other'},
                        {'commit_sha': '0' * 40}, {'project_path': '/etc'}):
            value = copy.deepcopy(original)
            value.update(changes)
            value['approval']['digest'] = digest({k: v for k, v in value.items() if k != 'approval'})
            with self.assertRaises(SafetyError):
                self.dispatch.prepare(value)
        self.assertEqual(list(self.work.iterdir()), [])

    def test_changed_approval_and_job_replay(self):
        value = self.setup_dispatch()
        self.dispatch.prepare(value)
        for change in ('content', 'approval', 'job'):
            changed = copy.deepcopy(value)
            if change == 'content': changed['title'] = 'changed'
            elif change == 'approval': changed['approval']['id'] = 'approval-2'
            else: changed['job_id'] = 'job-2'
            changed['approval']['digest'] = digest({k: v for k, v in changed.items() if k != 'approval'})
            with self.assertRaises(SafetyError): self.dispatch.prepare(changed)
        self.assertEqual(len(list(self.work.iterdir())), 1)

    def test_interrupted_intent_blocks_restart(self):
        value = self.setup_dispatch()
        with patch.object(self.manager, '_create_locked', side_effect=SafetyError('interrupted')):
            with self.assertRaises(SafetyError): self.dispatch.prepare(value)
        restarted = Dispatcher(Manager(self.state, [self.root], self.work))
        with self.assertRaises(SafetyError): restarted.prepare(value)
        self.assertEqual(list(self.work.iterdir()), [])

    def test_binding_immutable_and_dirty_source(self):
        value = self.setup_dispatch()
        with self.assertRaises(SafetyError): self.dispatch.bind('project-1', 'repo', 'other')
        (self.repo / 'dirty').write_text('dirty')
        with self.assertRaises(SafetyError): self.dispatch.prepare(value)
        (self.repo / 'dirty').unlink()
        with self.assertRaises(SafetyError): self.dispatch.prepare(value)

    def test_concurrent_replays_create_once(self):
        from concurrent.futures import ThreadPoolExecutor
        value = self.setup_dispatch()
        with ThreadPoolExecutor(max_workers=2) as pool:
            manifests = list(pool.map(self.dispatch.prepare, [value, value]))
        self.assertEqual(manifests[0], manifests[1])
        self.assertEqual(len(list(self.work.iterdir())), 1)

    def test_inconsistent_manifest_and_local_identity(self):
        value = self.setup_dispatch()
        self.dispatch.prepare(value)
        with self.manager.registry.locked(write=True) as data:
            data['dispatch_records']['approval-1']['manifest']['commit_sha'] = '0' * 40
        with self.assertRaises(SafetyError): self.dispatch.prepare(value)
        self.assertEqual(len(list(self.work.iterdir())), 1)

    def test_expiry_while_preparing_blocks_retry(self):
        value = self.setup_dispatch()
        now = datetime.now(timezone.utc).timestamp()
        with patch.object(self.dispatch, 'clock', side_effect=[now, now, now + 1000]):
            with self.assertRaises(SafetyError): self.dispatch.prepare(value)
        with self.assertRaises(SafetyError): self.dispatch.prepare(value)
        self.assertEqual(len(list(self.work.iterdir())), 1)
