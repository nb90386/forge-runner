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
                    CapDrop=['ALL'], IpcMode='private', NanoCpus=int(limits.cpu * 1000000000),
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
                def inspect(args):
                    counts[args[0]] += 1
                    if args[0] == 'image':
                        result = copy.deepcopy(image)
                        if swap == 'initial' or swap == 'before_start' and counts['image'] == 2:
                            result['Id'] = other
                    else:
                        result = dict(Id=cid, Image=iid, Config=dict(Image=iid, User='65534:65534'),
                                      HostConfig=host, State=dict(Running=False, ExitCode=0))
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
