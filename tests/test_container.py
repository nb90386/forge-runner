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
