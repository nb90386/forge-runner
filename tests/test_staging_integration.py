"""Disposable real-HTTP Forge 0.5D integration; standard library only.

Run directly or through unittest discovery. The server runs in another interpreter
because the control plane and runner intentionally have different `forge` packages.
"""
import contextlib
from datetime import datetime, timedelta, timezone
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import select
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

RUNNER = Path(__file__).resolve().parents[1]
CONTROL = Path.home() / 'Forge/projects/forge-control-development'


def serve(control, ready):
    # This branch runs before importing the runner package. No user config or
    # worker loop is imported, and server.init() targets only FORGE_DATA_DIR.
    sys.path.insert(0, control)
    import server

    def guard(event, args):
        if event in ('subprocess.Popen', 'os.system', 'os.posix_spawn', 'socket.connect'):
            (server.DATA / 'forbidden-attempt').write_text(event)
            raise AssertionError('server attempted execution or outbound connection')
    sys.addaudithook(guard)
    server.init()
    with server.ThreadingHTTPServer(('127.0.0.1', 0), server.Handler) as httpd:
        with os.fdopen(ready, 'w') as pipe:
            pipe.write(str(httpd.server_port) + '\n')
        httpd.serve_forever(poll_interval=0.05)


class StagingIntegration(unittest.TestCase):
    def test_end_to_end(self):
        self.assertTrue((CONTROL / 'server.py').is_file(), 'local control checkout required')
        sys.path.insert(0, str(RUNNER / 'src'))
        from forge.git import git

        with tempfile.TemporaryDirectory(prefix='forge-05d-', dir=str(Path(tempfile.gettempdir()).resolve())) as tmp:
            root = Path(tmp)
            repo, state, work, control = [root / name for name in ('repo', 'runner', 'work', 'control')]
            for directory in (repo, state, work, control):
                directory.mkdir(mode=0o700)
            git(repo, 'init', '-b', 'main')
            git(repo, 'config', 'user.name', 'Synthetic Fixture')
            git(repo, 'config', 'user.email', 'fixture@example.invalid')
            (repo / 'tracked').write_text('original content\n')
            git(repo, 'add', 'tracked')
            git(repo, 'commit', '-m', 'disposable fixture')
            sha = git(repo, 'rev-parse', 'HEAD')
            original = (repo / 'tracked').read_bytes()
            worker, operator = 'synthetic-worker-' + secrets.token_hex(24), 'synthetic-operator-' + secrets.token_hex(24)
            env = {'PATH': '/usr/bin:/bin', 'HOME': str(root), 'PYTHONNOUSERSITE': '1',
                   'PYTHONDONTWRITEBYTECODE': '1', 'FORGE_DATA_DIR': str(control),
                   'FORGE_ALLOWED_ROOTS': str(root), 'FORGE_WORKER_TOKEN': worker,
                   'FORGE_OPERATOR_TOKEN': operator, 'FORGE_HOST': '127.0.0.1',
                   'FORGE_PORT': '0', 'FORGE_REPOS': ''}
            read_fd, write_fd = os.pipe()
            try:
                with (root / 'server.log').open('wb') as log:
                    process = subprocess.Popen([sys.executable, '-I', str(Path(__file__).resolve()),
                                                '--serve', str(CONTROL), str(write_fd)],
                                               cwd=root, env=env, pass_fds=(write_fd,), stdout=log, stderr=log)
                os.close(write_fd)
                write_fd = None
                try:
                    with os.fdopen(read_fd) as ready:
                        read_fd = None
                        self.assertTrue(select.select([ready], [], [], 15)[0], 'server startup timed out')
                        line = ready.readline().strip()
                        if not line.isdigit():
                            diagnostic = (root / 'server.log').read_text()
                            for secret in (worker, operator):
                                diagnostic = diagnostic.replace(secret, '[redacted]')
                            self.fail('server failed before binding loopback:\n' + diagnostic)
                        port = int(line)
                    self.exercise(root, repo, state, work, control, port, worker, operator, sha, original)
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                    self.assertIsNotNone(process.returncode)
            finally:
                for fd in (read_fd, write_fd):
                    if fd is not None:
                        os.close(fd)

    def exercise(self, root, repo, state, work, control, port, worker, operator, sha, original):
        from forge import Manager, SafetyError
        from forge.git import git
        from forge.dispatch import DispatchClient, Dispatcher, LoopbackTransport, digest
        cookie = ''
        routes = {'/api/health', '/api/ui/login', '/api/ui/projects', '/api/ui/projects/archive',
                  '/api/ui/create', '/api/ui/implementation-jobs', '/api/ui/implementation-jobs/approve'}

        def call(method, path, body=None, bearer='', expected=200):
            self.assertIn(path, routes)
            headers = {'Content-Type': 'application/json', 'Cookie': cookie}
            if bearer:
                headers['Authorization'] = 'Bearer ' + bearer
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
            try:
                connection.request(method, path, json.dumps(body) if body is not None else None, headers)
                response = connection.getresponse()
                self.assertEqual(response.status, expected, path)
                return json.loads(response.read()), response.getheader('Set-Cookie', '').split(';')[0]
            finally:
                connection.close()

        # Record/limit subprocesses for the entire dispatch phase, including retries.
        real_run = subprocess.run
        commands = []

        def local_git_only(command, **kwargs):
            self.assertEqual(command[0], '/usr/bin/git')
            self.assertFalse(kwargs.get('shell', False))
            index = command.index('-C')
            self.assertTrue(Path(command[index + 1]).is_relative_to(root))
            verb = command[index + 2]
            self.assertIn(verb, {'config', 'rev-parse', 'ls-files', 'status', 'worktree', 'show-ref', 'symbolic-ref'})
            if verb == 'worktree':
                self.assertIn(command[index + 3], {'add', 'list'})
            commands.append(command[index + 2:])
            return real_run(command, **kwargs)

        real_connect = socket.socket.connect

        def loopback_only(sock, address):
            self.assertEqual(address, ('127.0.0.1', port))
            return real_connect(sock, address)

        with patch('subprocess.run', side_effect=local_git_only), patch.object(socket.socket, 'connect', loopback_only):
            call('GET', '/api/health')
            client = DispatchClient(LoopbackTransport('http://127.0.0.1:' + str(port)), lambda: worker, attempts=1)
            self.assertEqual(client.poll(), [])
            session, cookie = call('POST', '/api/ui/login', {'token': operator})
            self.assertEqual(session['role'], 'operator')
            self.assertTrue(cookie.startswith('forge_session='))
            project, _ = call('POST', '/api/ui/projects', {'path': str(repo), 'name': 'Disposable 0.5D',
                             'repository_identity': 'synthetic/forge-05d'}, expected=201)
            task, _ = call('POST', '/api/ui/create', {'title': 'Fixture', 'description': 'Never execute'}, expected=201)
            operator_cookie, cookie = cookie, ''
            job, _ = call('POST', '/api/ui/implementation-jobs', {'project_id': project['id'],
                          'task_id': task['id'], 'title': 'Preparation only', 'description': 'Never execute',
                          'commit_sha': sha}, bearer=worker, expected=201)
            # Remove operator cookie so these are truly worker-only requests.
            decision = {'id': job['id'], 'expires_at': (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()}
            call('POST', '/api/ui/implementation-jobs/approve', decision, bearer=worker, expected=403)
            cookie = operator_cookie
            call('POST', '/api/ui/implementation-jobs/approve', decision)
            envelopes = client.poll()
            self.assertEqual(len(envelopes), 1)
            envelope = envelopes[0]
            self.assertEqual(envelope['commit_sha'], sha)
            manager = Manager(state, [root], work)
            manager.approve('fixture', repo)
            dispatcher = Dispatcher(manager, client)
            with self.assertRaisesRegex(SafetyError, 'unknown project'):
                dispatcher.prepare(envelope)
            dispatcher.bind(project['id'], 'fixture', 'synthetic/forge-05d')
            manifest = dispatcher.prepare(envelope)
            registry_before = (state / 'registry.json').read_bytes()
            self.assertEqual(client.poll(), envelopes)
            # Reconstruct objects to prove idempotency survives runner restart.
            dispatcher = Dispatcher(Manager(state, [root], work), client)
            self.assertEqual(dispatcher.prepare(client.poll()[0]), manifest)
            self.assertEqual((state / 'registry.json').read_bytes(), registry_before)
            self.assertEqual(sum(c[:2] == ['worktree', 'add'] for c in commands), 1)
            self.assertEqual(len(list(work.iterdir())), 1)
            self.assertEqual(git(repo, 'worktree', 'list', '--porcelain').count('worktree '), 2)
            self.assertEqual(git(manifest['worktree_path'], 'rev-parse', 'HEAD'), sha)
            self.assertEqual((Path(manifest['worktree_path']) / 'tracked').read_bytes(), original)
            self.assertIs(manifest['audit']['execution'], False)
            self.assertEqual(manifest['job_id'], job['id'])
            self.assertEqual(manifest['project_id'], project['id'])
            self.assertEqual(manifest['repository_identity'], 'synthetic/forge-05d')
            self.assertEqual(manifest['repository_id'], 'fixture')
            self.assertEqual(manifest['commit_sha'], sha)
            self.assertEqual(manifest['schema_version'], 1)
            self.assertTrue(datetime.fromisoformat(manifest['audit']['prepared_at']).tzinfo)
            self.assertEqual(manifest['audit']['adapter'], 'forge-0.5D')
            self.assertEqual(manifest['audit']['transport'], 'LoopbackTransport')
            self.assertEqual(manifest['audit']['envelope_sha256'], digest(envelope))
            self.assertEqual(manifest['approval'], envelope['approval'])
            artifact = root / 'manifest.json'
            artifact.write_text(json.dumps(manifest, sort_keys=True))
            registry = json.loads(registry_before)
            record = registry['dispatch_records'][envelope['approval']['id']]
            self.assertEqual(record['manifest'], json.loads(artifact.read_text()))
            self.assertEqual(record['manifest_sha256'], digest(manifest))
            call('POST', '/api/ui/projects/archive', {'id': project['id']})
            self.assertEqual(client.poll(), [])
            with self.assertRaisesRegex(SafetyError, 'HTTP 403'):
                dispatcher.prepare(envelope)
            self.assertEqual((state / 'registry.json').read_bytes(), registry_before)
            self.assertEqual(sum(c[:2] == ['worktree', 'add'] for c in commands), 1)
            self.assertEqual(git(repo, 'symbolic-ref', '--short', 'HEAD'), 'main')
            self.assertEqual(git(repo, 'rev-parse', 'HEAD'), sha)
            self.assertEqual(git(repo, 'status', '--porcelain'), '')
            self.assertEqual((repo / 'tracked').read_bytes(), original)

        self.assertFalse((control / 'forbidden-attempt').exists(), 'server attempted a forbidden operation')
        with contextlib.closing(sqlite3.connect(control / 'forge.sqlite3')) as db:
            self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            self.assertEqual(db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT status,refined,result FROM tasks').fetchall(), [('inbox', '', '')])
            self.assertEqual(db.execute('SELECT status,commit_sha FROM implementation_jobs').fetchall(), [('approved', sha)])
            self.assertEqual(db.execute('SELECT status FROM projects').fetchall(), [('archived',)])
            approvals = db.execute('SELECT envelope FROM implementation_approvals').fetchall()
            self.assertEqual([json.loads(row[0]) for row in approvals], [envelope])
            events = db.execute('SELECT actor,action,subject_id,detail FROM audit_events ORDER BY seq').fetchall()
            self.assertEqual([(a, b, c) for a, b, c, _ in events], [
                ('operator', 'project.registered', project['id']),
                ('worker', 'implementation.requested', job['id']),
                ('operator', 'implementation.approved', job['id']),
                ('operator', 'project.archived', project['id'])])
            self.assertEqual(json.loads(events[2][3])['digest'], envelope['approval']['digest'])
            serialized = json.dumps(events) + artifact.read_text() + registry_before.decode()
            for secret in (worker, operator, cookie):
                self.assertNotIn(secret, serialized)


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--serve':
        serve(sys.argv[2], int(sys.argv[3]))
    else:
        unittest.main(verbosity=2)
