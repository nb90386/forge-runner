"""Offline boundary tests and explicitly configured disposable live conformance."""
from dataclasses import replace
import io
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from forge.container import ContainerAdapter, ContainerConfig, collect_artifacts
from forge.runtime import Limits, Runtime, SyntheticRequest
from forge.safety import SafetyError


def archive(name='result.txt', kind=tarfile.REGTYPE, content=b'fixture'):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as tar:
        item = tarfile.TarInfo(name)
        item.type = kind
        item.size = len(content) if kind == tarfile.REGTYPE else 0
        item.linkname = '/etc/passwd'
        tar.addfile(item, io.BytesIO(content))
    return stream.getvalue()


class ContainerTests(unittest.TestCase):
    def test_image_identity_races_refused_before_start(self):
        iid = 'sha256:' + 'a' * 64
        other = 'sha256:' + 'b' * 64
        cid = 'c' * 64
        ref = 'example.invalid/fixture@sha256:' + 'd' * 64
        limits = Limits()
        image = dict(Id=iid, RepoDigests=[ref], Config={})
        host = dict(NetworkMode='none', ReadonlyRootfs=True, Privileged=False,
                    CapDrop=['ALL'], IpcMode='private', CgroupnsMode='host', NanoCpus=int(limits.cpu * 1000000000),
                    Memory=limits.memory_bytes, MemorySwap=limits.memory_bytes,
                    PidsLimit=limits.processes, SecurityOpt=['no-new-privileges:true'],
                    Tmpfs={'/workspace': 'rw,noexec,nosuid,nodev,size=16m,mode=1777'})
        import copy
        for swap in ('initial', 'created', 'config_tag', 'before_start', 'container_swap', 'bad_create', 'none'):
            with self.subTest(swap=swap), patch.object(ContainerConfig, 'validate'):
                adapter = ContainerAdapter(ContainerConfig('/docker', '/socket', ref, iid))
                calls = []
                counts = {'image': 0, 'inspect': 0}
                def cli(args, **kwargs):
                    calls.append(args)
                    if args[0] == 'create':
                        self.assertIn(iid, args)
                        self.assertIn('--pull=never', args)
                        return 0, (b'bad' if swap == 'bad_create' else cid.encode()), b''
                    return 0, b'', b''
                def inspect(args, **kwargs):
                    counts[args[0]] += 1
                    if args[0] == 'image':
                        result = copy.deepcopy(image)
                        if swap == 'initial' or swap == 'before_start' and counts['image'] == 2:
                            result['Id'] = other
                    else:
                        result = dict(Id=cid, Image=iid, Config=dict(Image=iid, User='65534:65534'),
                                      HostConfig=host, State=dict(Running=False, ExitCode=0, Pid=0, Status='exited', StartedAt='2026-10-28T00:00:00Z', FinishedAt='2026-10-28T00:00:01Z'))
                        if swap == 'created' or swap == 'container_swap' and counts['inspect'] == 2:
                            result['Image'] = other
                        if swap == 'config_tag': result['Config']['Image'] = 'fixture:latest'
                    return [result]
                with patch.object(adapter, '_cli', side_effect=cli), patch.object(adapter, '_json', side_effect=inspect):
                    if swap == 'none':
                        self.assertEqual(adapter._run('probe', limits)[:2], ('completed', 0))
                    else:
                        with self.assertRaises(SafetyError): adapter._run('probe', limits)
                if swap == 'none':
                    self.assertIn(['start', '--attach', cid], calls)
                else:
                    self.assertFalse(any(args[0] == 'start' for args in calls))
                self.assertTrue(any(args[0] == 'rm' for args in calls))
                self.assertFalse(adapter._failed)

    def test_canonical_orbstack_binary_still_requires_checked_path(self):
        canonical = '/Applications/OrbStack.app/Contents/MacOS/xbin/docker-tools'
        with patch('forge.container.checked_path', side_effect=lambda value: Path(value)) as checked, \
                patch.object(Path, 'is_file', return_value=True), \
                patch.object(Path, 'is_socket', return_value=True), patch('os.access', return_value=True):
            ContainerConfig(canonical, '/socket', 'fixture@sha256:' + 'a' * 64).validate()
            checked.assert_any_call(canonical)
            with self.assertRaises(SafetyError):
                ContainerConfig('/other/docker-tools', '/socket', 'fixture@sha256:' + 'a' * 64).validate()
        with patch('forge.container.checked_path', side_effect=SafetyError('unsafe path')):
            with self.assertRaises(SafetyError):
                ContainerConfig(canonical, '/socket', 'fixture@sha256:' + 'a' * 64).validate()

    def test_artifact_traversal_and_links(self):
        for name, kind in (('../secret', tarfile.REGTYPE), ('/secret', tarfile.REGTYPE),
                           ('link', tarfile.SYMTYPE), ('hard', tarfile.LNKTYPE),
                           ('fifo', tarfile.FIFOTYPE), ('dev', tarfile.CHRTYPE)):
            with self.subTest(name=name), self.assertRaises(SafetyError):
                collect_artifacts(archive(name, kind), Limits())
        self.assertEqual(collect_artifacts(archive(), Limits()), (('result.txt', b'fixture'),))
        with self.assertRaises(SafetyError):
            collect_artifacts(archive(), replace(Limits(), artifact_bytes=1))

    def test_config_rejects_mutable_image_remote_endpoint(self):
        with patch('forge.container.checked_path') as checked:
            checked.return_value.is_file.return_value = True
            checked.return_value.is_socket.return_value = True
            for image in ('python:latest', 'sha256:abc', 'python@sha256:' + 'g' * 64):
                with self.assertRaises(SafetyError):
                    ContainerConfig('/docker', '/socket', image).validate()
        with self.assertRaises(SafetyError):
            ContainerAdapter({})

    def test_no_conformance_means_no_engine_execution(self):
        with patch.object(ContainerConfig, 'validate'):
            adapter = ContainerAdapter(ContainerConfig('/docker', '/socket', 'python@sha256:' + '0' * 64))
        with patch.object(adapter, '_cli', side_effect=AssertionError('not attested')):
            with self.assertRaises(SafetyError):
                adapter.execute(None, None)
            with tempfile.TemporaryDirectory() as directory:
                path = str(Path(directory).resolve())
                result = Runtime([path], container=adapter).execute(SyntheticRequest(path))
                self.assertEqual(result.status, 'unsupported')
                self.assertEqual(result.audit['enforced_guarantees'], [])

    def test_no_host_workspace_content(self):
        with patch.object(ContainerConfig, 'validate'):
            adapter = ContainerAdapter(ContainerConfig('/docker', '/socket', 'python@sha256:' + '0' * 64))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve()
            (path / 'secret').symlink_to('/etc/passwd')
            with patch.object(adapter, 'execute', side_effect=AssertionError('host content')):
                result = Runtime([str(path)], container=adapter).execute(SyntheticRequest(str(path)))
            self.assertEqual(result.status, 'rejected')

    def test_cleanup_uncertainty_poisoned(self):
        with patch.object(ContainerConfig, 'validate'):
            adapter = ContainerAdapter(ContainerConfig('/docker', '/socket', 'python@sha256:' + '0' * 64))
        with patch.object(adapter, '_cli', return_value=(1, b'', b'')):
            with self.assertRaises(SafetyError):
                adapter._run('noop', Limits())
        self.assertTrue(adapter._failed)
        with self.assertRaises(SafetyError): adapter.conform()


@unittest.skipUnless(all(os.environ.get(k) for k in
                         ('FORGE_TEST_DOCKER', 'FORGE_TEST_SOCKET', 'FORGE_TEST_IMAGE')),
                     'live daemon and audited local digest image not explicitly configured')
class LiveConformance(unittest.TestCase):
    def test_disposable_engine_conformance(self):
        adapter = ContainerAdapter(ContainerConfig(os.environ['FORGE_TEST_DOCKER'],
                                   os.environ['FORGE_TEST_SOCKET'], os.environ['FORGE_TEST_IMAGE']))
        adapter.conform()
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory).resolve())
            result = Runtime([path], container=adapter).execute(SyntheticRequest(path))
            self.assertEqual(result.status, 'completed')
            self.assertEqual(result.exit_code, 0)
            self.assertFalse(list(Path(path).iterdir()))


class ResourceFixtureTests(unittest.TestCase):
    def run_fixture(self, *, memory_status=9, memory_event=True, oom_event=True,
                    fork_errno=None, pids_event=True, enforced=True):
        """Execute the actual fixture with synthetic syscalls; never fork the host."""
        import errno
        from forge.container import FIXTURE, cgroup_membership
        if fork_errno is None: fork_errno = errno.EAGAIN
        forks = [101, OSError(fork_errno, 'synthetic')] if enforced else [101, 102]
        if enforced:
            forks.append(103)
        events = {'pids': 0, 'memory': 0}
        def opened(path, *args):
            if path == '/proc/self/cgroup': return io.StringIO('0::/system.slice/docker-fixture.scope\n')
            if path == '/proc/self/mountinfo':
                return io.StringIO('1 0 0:1 / /sys/fs/cgroup ro - cgroup2 cgroup rw')
            assert path.startswith('/sys/fs/cgroup/system.slice/docker-fixture.scope/')
            if path.endswith('pids.max'): return io.StringIO('2')
            if path.endswith('memory.max'): return io.StringIO('268435456')
            controller = 'pids' if path.endswith('pids.events') else 'memory'
            events[controller] += 1
            if controller == 'pids':
                return io.StringIO('max %d\n' % (pids_event and events[controller] > 1))
            return io.StringIO('max %d\noom_kill %d\n' % (
                memory_event and events[controller] > 2,
                oom_event and events[controller] > 2))
        def fork():
            value = forks.pop(0)
            if isinstance(value, Exception): raise value
            return value
        with patch('builtins.open', side_effect=opened), patch('os.fork', side_effect=fork), \
                patch('os.kill') as kill, \
                patch('os.waitpid', side_effect=lambda pid, flags: (pid, memory_status)), \
                patch.object(sys, 'argv', ['fixture', 'resource-fixture']):
            try:
                exec(compile(FIXTURE, '<fixture>', 'exec'), {'cgroup_membership': cgroup_membership})
            finally:
                self.assertTrue(kill.called)

    def test_cgroup_oom_kill_is_success(self):
        self.run_fixture()

    def test_cgroup_allocation_refusal_is_success(self):
        self.run_fixture(memory_status=42 << 8, oom_event=False)

    def test_missing_enforcement_and_unrelated_failures_are_refused(self):
        import errno
        for case in ({'memory_status': 0}, {'memory_status': 1 << 8},
                     {'memory_event': False}, {'oom_event': False},
                     {'pids_event': False}, {'fork_errno': errno.ENOMEM},
                     {'enforced': False}):
            with self.subTest(case=case), self.assertRaises(AssertionError):
                self.run_fixture(**case)


class EffectiveLimitsTests(unittest.TestCase):
    def verify(self, changes=None):
        from forge.container import verify_cgroups
        evidence = {'/proc/self/cgroup': '0::/parent/leaf\n',
                    '/proc/self/mountinfo': '1 0 0:1 / /sys/fs/cgroup ro - cgroup2 cgroup rw'}
        for group in ('/parent', '/parent/leaf'):
            for name, value in [('cpu.max', 'max 100000'), ('memory.max', 'max'), ('pids.max', 'max')]:
                evidence['/sys/fs/cgroup' + group + '/' + name] = value
        for name, value in [('cpu.max', '50000 100000'), ('memory.max', '1024'), ('pids.max', '16')]:
            evidence['/sys/fs/cgroup/parent/' + name] = value
        evidence.update(changes or {})
        verify_cgroups('.5', 1024, 16, evidence.__getitem__)

    def test_nonstandard_mount_and_changing_membership(self):
        from forge.container import cgroup_membership
        evidence = {'/proc/self/cgroup': '0::/system.slice/docker.scope\n',
                    '/proc/self/mountinfo': '1 0 0:1 / /custom/cgroup ro - cgroup2 cgroup rw'}
        self.assertEqual(cgroup_membership(evidence.__getitem__),
                         ('/custom/cgroup', '/system.slice/docker.scope'))
        calls = iter(['0::/parent/leaf', '0::/other'])
        def read(path):
            return next(calls) if path.endswith('/cgroup') else evidence[path]
        with self.assertRaises(ValueError): cgroup_membership(read)

    def test_parent_limits_and_stricter_limits(self):
        self.verify()
        self.verify({'/sys/fs/cgroup/parent/leaf/cpu.max': '10000 100000'})

    def test_weak_missing_and_ambiguous_evidence(self):
        for changes in ({'/sys/fs/cgroup/parent/cpu.max': '50001 100000'},
                        {'/sys/fs/cgroup/parent/memory.max': '1025'},
                        {'/sys/fs/cgroup/parent/pids.max': 'max'},
                        {'/sys/fs/cgroup/parent/leaf/cpu.max': ''},
                        {'/sys/fs/cgroup/parent/cpu.max': '1 0'},
                        {'/proc/self/cgroup': '0::/parent/leaf\n1:cpu:/other'},
                        {'/proc/self/cgroup': '0::/parent/../leaf'},
                        {'/proc/self/cgroup': '0::/parent//leaf'},
                        {'/proc/self/cgroup': r'0::/parent/leaf\040escape'},
                        {'/proc/self/cgroup': '0::/'},
                        {'/proc/self/mountinfo': ''},
                        {'/proc/self/mountinfo':
                         '1 0 0:1 / /sys/fs/cgroup ro - cgroup2 cgroup rw\n'
                         '2 0 0:2 / /sys/fs/cgroup/parent ro - tmpfs tmpfs rw'},
                        {'/proc/self/mountinfo': '1 0 0:1 /hidden /sys/fs/cgroup ro - cgroup2 cgroup rw'}):
            with self.subTest(changes=changes), self.assertRaises((ValueError, KeyError)):
                self.verify(changes)


class TerminationEvidenceTests(unittest.TestCase):
    def test_startup_required_and_cleanup_confirmed(self):
        from forge.runtime import Cancellation
        limits = Limits()
        for operation in ('timeout-fixture', 'cancel-fixture'):
            for scenario in ('started', 'missing', 'pre-canceled', 'not-running', 'cleanup'):
                with self.subTest(operation=operation, scenario=scenario), patch.object(ContainerConfig, 'validate'):
                    adapter = ContainerAdapter(ContainerConfig('/docker', '/socket', 'unused'))
                    cancellation = Cancellation() if operation == 'cancel-fixture' else None
                    if scenario == 'pre-canceled' and cancellation: cancellation.cancel()
                    host = dict(NetworkMode='none', ReadonlyRootfs=True, Privileged=False,
                                CapDrop=['ALL'], IpcMode='private', CgroupnsMode='host',
                                NanoCpus=int(limits.cpu * 1000000000), Memory=limits.memory_bytes,
                                MemorySwap=limits.memory_bytes, PidsLimit=limits.processes,
                                SecurityOpt=['no-new-privileges:true'],
                                Tmpfs={'/workspace': 'rw,noexec,nosuid,nodev,size=16m,mode=1777'})
                    obj = dict(HostConfig=host, Config=dict(User='65534:65534'),
                               State=dict(Running=False, ExitCode=137, Pid=0, Status='exited', StartedAt='2026-10-28T00:00:00Z', FinishedAt='2026-10-28T00:00:01Z'))
                    calls = []
                    def cli(args, **kwargs):
                        calls.append(args[0])
                        if args[0] == 'create': return 0, b'c' * 64, b''
                        if args[0] == 'start':
                            if scenario != 'missing':
                                obj['State'].update(Running=scenario != 'not-running', Pid=123, Status='running')
                                kwargs['on_started']()
                            raise TimeoutError()
                        if args[0] == 'stop': obj['State'].update(Running=False, Pid=0, Status='exited')
                        if args[0] == 'ps' and scenario == 'cleanup': return 0, b'remaining', b''
                        return 0, b'', b''
                    with patch.object(adapter, '_check_image'), \
                            patch.object(adapter, '_inspect_container', return_value=obj), \
                            patch.object(adapter, '_cli', side_effect=cli):
                        valid = scenario == 'started' or scenario == 'pre-canceled' and cancellation is None
                        if valid:
                            result = adapter._run(operation, limits, cancellation)
                            self.assertEqual(result[0], 'canceled' if cancellation else 'timeout')
                        else:
                            with self.assertRaises(SafetyError): adapter._run(operation, limits, cancellation)
                    self.assertIn('rm', calls)
                    self.assertIn('ps', calls)
                    self.assertEqual(adapter._failed, scenario == 'cleanup')


class FailClosedContainmentTests(unittest.TestCase):
    def test_cleanup_base_exception_permanently_poisons_adapter(self):
        for command in ('rm', 'ps'):
            with self.subTest(command=command), patch.object(ContainerConfig, 'validate'):
                adapter = ContainerAdapter(ContainerConfig('/docker', '/socket', 'unused'))
                calls = []
                interruption = SystemExit(17)
                def cli(args, **kwargs):
                    calls.append(args[0])
                    if args[0] == command:
                        raise interruption
                    return 0, b'', b''
                with patch.object(adapter, '_check_image', side_effect=SafetyError('refused')), \
                        patch.object(adapter, '_cli', side_effect=cli):
                    with self.assertRaises(SystemExit) as raised:
                        adapter._run('probe', Limits())
                    self.assertIs(raised.exception, interruption)
                    self.assertTrue(adapter._failed)
                    self.assertEqual(adapter.diagnostic()['stage'],
                                     'cleanup_remove' if command == 'rm' else 'cleanup_confirm')
                    before = list(calls)
                    for operation in (lambda: adapter._run('probe', Limits()),
                                      adapter.conform, lambda: adapter.execute(None, None)):
                        with self.assertRaises(SafetyError): operation()
                    self.assertEqual(calls, before)

    def test_every_unstructured_operation_refused_before_spawn(self):
        with patch.object(ContainerConfig, 'validate'):
            adapter = ContainerAdapter(ContainerConfig('/docker', '/socket', 'unused'))
        with patch('subprocess.Popen') as spawn, patch('socket.socket') as connect:
            for command in ('info', 'inspect', 'create', 'start', 'stop', 'rm', 'ps', 'exec', 'pull'):
                with self.subTest(command=command), self.assertRaises(SafetyError):
                    adapter._cli([command])
            spawn.assert_not_called()
            connect.assert_not_called()
        self.assertFalse(adapter._attested)

    def test_cli_failure_survives_successful_container_cleanup(self):
        with patch.object(ContainerConfig, 'validate'):
            adapter = ContainerAdapter(ContainerConfig('/docker', '/socket', 'unused'))
        calls = []
        def cli(args, **kwargs):
            calls.append(args[0])
            if args[0] == 'image':
                adapter._failed = True
                raise SafetyError('CLI descendant cleanup unconfirmed')
            return 0, b'', b''
        with patch.object(adapter, '_cli', side_effect=cli):
            with self.assertRaises(SafetyError): adapter._run('probe', Limits())
            self.assertEqual(calls, ['image', 'rm', 'ps'])
            self.assertTrue(adapter._failed)
            for operation in (lambda: adapter._run('probe', Limits()),
                              adapter.conform, lambda: adapter.execute(None, None)):
                with self.assertRaises(SafetyError): operation()
            self.assertEqual(calls, ['image', 'rm', 'ps'])
