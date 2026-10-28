import copy
import json
import unittest
from unittest.mock import patch
from datetime import datetime, timezone

import test_forge
from test_forge import git
from forge import Manager, SafetyError
from forge.dispatch import DispatchClient, Dispatcher, MockTransport, LoopbackTransport, digest, validate


def job(sha='a' * 40):
    content = dict(job_id='job-1', project_id='project-1', repository_identity='forge/example',
                   commit_sha=sha, task_id='task-1', title='Implement', description='Approved request')
    now = datetime.now(timezone.utc).timestamp()
    content['approval'] = dict(id='approval-1', state='approved', actor='operator',
                               approved_at=datetime.fromtimestamp(now - 10, timezone.utc).isoformat(),
                               expires_at=datetime.fromtimestamp(now + 600, timezone.utc).isoformat(),
                               digest=digest(content))
    return content


def page(jobs, cursor=None):
    return json.dumps(dict(schema_version=1, jobs=jobs, next_cursor=cursor)).encode()


def authorization(value):
    return (200, json.dumps(dict(schema_version=1, authorized=True,
                                approval_id=value['approval']['id'],
                                envelope_digest=digest(value))).encode())


class ClientTests(unittest.TestCase):
    def test_poll_retry_and_no_mutation(self):
        transport = MockTransport([(503, b'token-secret'), (200, page([job()]))])
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
        value = job(git(self.repo, 'rev-parse', 'HEAD'))
        self.client = DispatchClient(MockTransport([authorization(value)] * 30), lambda: 'dummy')
        self.dispatch.client = self.client
        return value

    def test_persistent_idempotency_manifest_and_cleanup(self):
        value = self.setup_dispatch()
        transport = MockTransport([(200, page([value]))])
        polled = DispatchClient(transport, lambda: 'dummy').poll()[0]
        manifest = self.dispatch.prepare(polled)
        json.dumps(manifest)
        restarted = Dispatcher(Manager(self.state, [self.root], self.work), self.client)
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
        restarted = Dispatcher(Manager(self.state, [self.root], self.work), self.client)
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
        with patch.object(self.dispatch, 'clock', side_effect=[now, now, now, now + 1000]):
            with self.assertRaises(SafetyError): self.dispatch.prepare(value)
        with self.assertRaises(SafetyError): self.dispatch.prepare(value)
        self.assertEqual(len(list(self.work.iterdir())), 1)


class HardenedClientTests(unittest.TestCase):
    def client(self, responses):
        return DispatchClient(MockTransport(responses), lambda: 'token-secret', sleep=lambda _: None)

    def values(self, count, large=False):
        values = []
        for i in range(count):
            value = job()
            value['job_id'] = 'job-' + str(i)
            value['approval']['id'] = 'approval-' + str(i)
            if large:
                value['description'] = '界' * 12000
            value['approval']['digest'] = digest({k: v for k, v in value.items() if k != 'approval'})
            values.append(value)
        return values

    def test_101_and_250_and_restart_from_zero(self):
        for count in (101, 250):
            values = self.values(count)
            responses = [(200, page(values[i:i+100], i+100 if i+100 < count else None))
                         for i in range(0, count, 100)]
            client = self.client(responses * 2)
            with patch.object(client.transport, 'get', wraps=client.transport.get) as get:
                self.assertEqual(client.poll(), values)
                self.assertEqual(client.poll(), values)
                paths = [call.args[0] for call in get.call_args_list]
                self.assertEqual(paths.count('/api/worker/approved-jobs?limit=100&after=0'), 2)

    def test_large_descriptions_short_pages_and_empty_continuation(self):
        values = self.values(25, large=True)
        responses = [(200, page([], 1))]
        responses += [(200, page(values[i:i+5], i+6 if i+5 < len(values) else None))
                      for i in range(0, len(values), 5)]
        self.assertEqual(self.client(responses).poll(), values)

    def test_duplicate_jobs_approvals_and_changed_envelopes(self):
        first = job()
        for kind in ('same', 'job', 'approval', 'content'):
            other = copy.deepcopy(first)
            if kind == 'job': other['approval']['id'] = 'different'
            if kind == 'approval': other['job_id'] = 'different'
            if kind == 'content': other['title'] = 'Changed'
            other['approval']['digest'] = digest({k: v for k, v in other.items() if k != 'approval'})
            client = self.client([(200, page([first], 1)), (200, page([other]))])
            if kind == 'same':
                self.assertEqual(client.poll(), [first])
            else:
                with self.assertRaises(SafetyError): client.poll()

    def test_cursors_schema_bounds_and_incomplete_feed(self):
        for cursor in (0, -1, True, '1', 2**63):
            with self.assertRaises(SafetyError): self.client([(200, page([], cursor))]).poll()
        with self.assertRaises(SafetyError):
            self.client([(200, page([], 2)), (200, page([], 1))]).poll()
        for version in (True, 2, '1'):
            body = json.dumps(dict(schema_version=version, jobs=[], next_cursor=None)).encode()
            with self.assertRaises(SafetyError): self.client([(200, body)]).poll()
        for bound in ('MAX_PAGES', 'MAX_BYTES', 'MAX_JOBS'):
            client = self.client([(200, page([job()], 1)), (200, page([]))])
            setattr(client, bound, 0 if bound != 'MAX_PAGES' else 1)
            with self.assertRaises(SafetyError): client.poll()
        for body in (page(self.values(101)), b'{"schema_version":1,"jobs":[],"jobs":[],"next_cursor":null}',
                     b'x' * (921600 + 1)):
            with self.assertRaises(SafetyError): self.client([(200, body)]).poll()

    def test_midpagination_failure_same_cursor_no_partial_result(self):
        for error in ((503, b'token-secret'), TimeoutError('token-secret')):
            client = self.client([(200, page([job()], 10))] + [error] * 3)
            with patch.object(client.transport, 'get', wraps=client.transport.get) as get:
                with self.assertRaises(SafetyError) as caught: client.poll()
                self.assertNotIn('token-secret', str(caught.exception))
                self.assertEqual([c.args[0] for c in get.call_args_list][1:],
                                 ['/api/worker/approved-jobs?limit=100&after=10'] * 3)

    def test_authorization_exact_identity_schema_and_redaction(self):
        value = job()
        correct = json.loads(authorization(value)[1])
        for key, replacement in (('schema_version', True), ('authorized', 1),
                                 ('approval_id', 'other'), ('envelope_digest', value['approval']['digest'])):
            changed = {**correct, key: replacement}
            with self.assertRaises(SafetyError):
                self.client([(200, json.dumps(changed).encode())]).authorize(value)
        for status in (301, 302, 307, 308, 401, 403, 404, 409, 503):
            client = self.client([(status, b'token-secret')])
            with self.assertRaises(SafetyError) as caught: client.authorize(value)
            self.assertNotIn('token-secret', str(caught.exception))
            self.assertEqual(client.transport.calls, 1)
        client = self.client([TimeoutError('token-secret')])
        with self.assertRaises(SafetyError) as caught: client.authorize(value)
        self.assertNotIn('token-secret', str(caught.exception))
        for token in ('secret\r\nInjected: yes', 'secret\x00', '秘密'):
            client = DispatchClient(MockTransport([]), lambda: token)
            with self.assertRaises(SafetyError): client.authorize(value)
            self.assertEqual(client.transport.calls, 0)

    def test_missing_or_corrupt_approval_metadata(self):
        for key in job()['approval']:
            value = job()
            del value['approval'][key]
            with self.assertRaises(SafetyError): self.client([(200, page([value]))]).poll()
        value = job()
        value['approval']['digest'] = '0' * 64
        with self.assertRaises(SafetyError): self.client([(200, page([value]))]).poll()


class TransportTests(unittest.TestCase):
    def test_origins_and_paths_refused_before_network(self):
        with patch('forge.dispatch.socket.socket') as socket:
            for origin in ('http://localhost:8000', 'http://127.0.0.2:8000', 'http://example.com:8000',
                           'https://127.0.0.1:8000', 'http://127.0.0.1', 'http://127.0.0.1:80/',
                           'http://user:secret@127.0.0.1:80', 'http://[::ffff:127.0.0.1]:80',
                           'http://127.0.0.1:80?x=1', 'http://127.0.0.1:80#x'):
                with self.assertRaises(SafetyError): LoopbackTransport(origin)
            transport = LoopbackTransport('http://127.0.0.1:8000')
            for path in ('http://example.com/', '//example.com/', '/api/worker/claim',
                         '/api/worker/complete', '/api/worker/approved-jobs?limit=100&after=0&x=1'):
                with self.assertRaises(SafetyError): transport.get(path, bearer_token='dummy', timeout=1)
            socket.assert_not_called()

    def test_direct_socket_proxy_ignored_peer_checked_redirect_not_followed(self):
        from unittest.mock import MagicMock
        for host, origin in (('127.0.0.1', 'http://127.0.0.1:8000'), ('::1', 'http://[::1]:8000')):
            for status in (200, 302, 307):
                sock, connection, response = MagicMock(), MagicMock(), MagicMock()
                sock.getpeername.return_value = (host, 8000)
                connection.getresponse.return_value = response
                response.status = status
                response.getheader.side_effect = lambda key, default=None: default
                response.read.return_value = page([])
                with patch.dict('os.environ', {'HTTP_PROXY': 'http://evil:99', 'ALL_PROXY': 'http://evil:99'}), \
                     patch('forge.dispatch.socket.socket', return_value=sock), \
                     patch('forge.dispatch.socket.getaddrinfo', side_effect=AssertionError('DNS forbidden')), \
                     patch('forge.dispatch.http.client.HTTPConnection', return_value=connection):
                    result = LoopbackTransport(origin).get('/api/worker/approved-jobs?limit=100&after=0',
                                                          bearer_token='dummy', timeout=1)
                    self.assertEqual(result[0], status)
                    sock.connect.assert_called_once_with((host, 8000))
                    self.assertEqual(connection.request.call_count, 1)
                    self.assertEqual(connection.request.call_args.args[0], 'GET')
                    sock.close.assert_called_once()
        with patch('forge.dispatch.socket.socket') as socket:
            socket.return_value.getpeername.return_value = ('192.0.2.1', 8000)
            with self.assertRaises(SafetyError):
                LoopbackTransport('http://127.0.0.1:8000').get('/api/worker/approved-jobs?limit=100&after=0',
                                                            bearer_token='dummy', timeout=1)


    def test_response_size_encoding_and_truncation(self):
        from unittest.mock import MagicMock
        for headers, body in (({'Content-Length': '921601'}, b''),
                              ({'Content-Length': '100'}, page([])),
                              ({'Content-Encoding': 'gzip'}, b''),
                              ({}, b'x' * 921601)):
            sock, connection, response = MagicMock(), MagicMock(), MagicMock()
            sock.getpeername.return_value = ('127.0.0.1', 8000)
            connection.getresponse.return_value = response
            response.status = 200
            response.getheader.side_effect = lambda key, default=None: headers.get(key, default)
            response.read.return_value = body
            with patch('forge.dispatch.socket.socket', return_value=sock), \
                 patch('forge.dispatch.http.client.HTTPConnection', return_value=connection):
                with self.assertRaises(SafetyError):
                    LoopbackTransport('http://127.0.0.1:8000').get('/api/worker/approved-jobs?limit=100&after=0',
                                                                bearer_token='dummy', timeout=1)
                sock.close.assert_called_once()


class AuthorizationIntegrationTests(unittest.TestCase):
    setUp = test_forge.IntegrationTests.setUp
    tearDown = test_forge.IntegrationTests.tearDown
    setup_dispatch = DispatchIntegrationTests.setup_dispatch

    def test_archive_or_expiry_before_preparation(self):
        value = self.setup_dispatch()
        for status in (401, 403, 409, 503):
            self.dispatch.client = DispatchClient(MockTransport([(status, b'')]), lambda: 'dummy')
            with self.assertRaises(SafetyError): self.dispatch.prepare(value)
            self.assertEqual(list(self.work.iterdir()), [])
        expired = copy.deepcopy(value)
        expired['approval']['expires_at'] = expired['approval']['approved_at']
        with self.assertRaises(SafetyError): self.dispatch.prepare(expired)
        self.assertEqual(list(self.work.iterdir()), [])

    def test_archive_during_creation_leaves_durable_refusal(self):
        value = self.setup_dispatch()
        transport = MockTransport([authorization(value), (403, b'archived')])
        self.dispatch.client = DispatchClient(transport, lambda: 'dummy')
        with self.assertRaises(SafetyError): self.dispatch.prepare(value)
        self.assertEqual(len(list(self.work.iterdir())), 1)
        with self.manager.registry.locked(write=False) as data:
            self.assertEqual(data['dispatch_records']['approval-1']['state'], 'preparing')
            self.assertNotIn('manifest', data['dispatch_records']['approval-1'])
        restarted = Dispatcher(Manager(self.state, [self.root], self.work), self.client)
        with self.assertRaises(SafetyError): restarted.prepare(value)
        self.assertEqual(len(list(self.work.iterdir())), 1)

    def test_replay_after_archive_or_changed_authorization(self):
        value = self.setup_dispatch()
        manifest = self.dispatch.prepare(value)
        for response in ((403, b''), (409, b''), (200, b'{"authorized":true}'), TimeoutError('secret')):
            restarted = Dispatcher(Manager(self.state, [self.root], self.work),
                                   DispatchClient(MockTransport([response]), lambda: 'dummy'))
            with self.assertRaises(SafetyError): restarted.prepare(value)
        self.assertFalse(manifest['audit']['execution'])
        self.assertEqual(len(list(self.work.iterdir())), 1)

    def test_no_client_cached_envelope_cannot_authorize(self):
        value = self.setup_dispatch()
        with self.assertRaises(SafetyError): Dispatcher(self.manager).prepare(value)
        self.assertEqual(list(self.work.iterdir()), [])

    def test_crash_after_git_success_refuses_recovery(self):
        value = self.setup_dispatch()
        create = self.manager._create_locked
        def interrupted(*args, **kwargs):
            create(*args, **kwargs)
            raise RuntimeError('simulated crash after Git')
        with patch.object(self.manager, '_create_locked', side_effect=interrupted):
            with self.assertRaises(RuntimeError): self.dispatch.prepare(value)
        self.assertEqual(len(list(self.work.iterdir())), 1)
        with self.manager.registry.locked(write=False) as data:
            self.assertEqual(data['dispatch_records']['approval-1']['state'], 'preparing')
            self.assertEqual(next(iter(data['tasks'].values()))['state'], 'creating')
        restarted = Dispatcher(Manager(self.state, [self.root], self.work), self.client)
        with self.assertRaises(SafetyError): restarted.prepare(value)
