"""No backend mocks may turn inventory into execution authority."""
from dataclasses import replace
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from forge.runtime import (Cancellation, Limits, Runtime, SyntheticRequest,
                           SYNTHETIC_OPERATIONS, detect_capabilities)
from forge.safety import SafetyError


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.work = self.root / 'work'
        self.work.mkdir()
        self.runtime = Runtime([str(self.work)])
        self.request = SyntheticRequest(str(self.work))

    def test_inventory_never_claims_support(self):
        for executable in (None, '/synthetic/docker'):
            with patch('forge.runtime.shutil.which', return_value=executable):
                capabilities = detect_capabilities()
                self.assertEqual(len(capabilities), 5)
                self.assertTrue(all(c.detected == bool(executable) for c in capabilities))
                self.assertTrue(all(not c.supported and not c.verified for c in capabilities))

    def test_no_host_execution_even_when_runtime_present(self):
        with patch('subprocess.Popen', side_effect=AssertionError('host execution')), \
                patch('os.system', side_effect=AssertionError('shell execution')), \
                patch('forge.runtime.shutil.which', return_value='/synthetic/docker'):
            for operation in SYNTHETIC_OPERATIONS:
                result = self.runtime.execute(replace(self.request, operation=operation))
                self.assertEqual(result.status, 'unsupported')
                self.assertFalse(result.started)
                self.assertEqual((result.stdout, result.stderr, result.artifacts), (b'', b'', ()))
                manifest = json.loads(json.dumps(result.manifest()))
                self.assertFalse(manifest['execution_authorized'])
                self.assertEqual(manifest['enforced_guarantees'], [])
                self.assertEqual(manifest['stdout_bytes'], 0)

    def test_no_runtime_and_preparation_is_not_authority(self):
        with patch('forge.runtime.shutil.which', return_value=None):
            self.assertEqual(self.runtime.execute(self.request).status, 'unsupported')
        self.assertEqual(Runtime().execute(self.request).status, 'rejected')
        self.assertEqual(self.runtime.execute({'worktree_path': str(self.work),
                                             'execution': True}).status, 'rejected')

    def test_paths_and_mount_configuration(self):
        other = self.root / 'other'
        other.mkdir()
        alias = self.root / 'alias'
        alias.symlink_to(self.work)
        for path in (str(other), str(alias), str(self.work) + '/../work',
                     str(self.work) + '//', '/', str(Path.home()), 'work'):
            with self.subTest(path=path):
                self.assertEqual(self.runtime.execute(replace(self.request, workspace=path)).status, 'rejected')
        with self.assertRaises(SafetyError):
            Runtime([str(alias)])
        self.work.rename(self.root / 'old')
        self.work.mkdir()
        self.assertEqual(self.runtime.execute(self.request).status, 'rejected')

    def test_symlink_content_never_followed_or_captured(self):
        secret = self.root / 'secret'
        secret.write_text('synthetic secret')
        (self.work / 'artifact').symlink_to(secret)
        result = self.runtime.execute(replace(self.request, operation='artifact-fixture'))
        self.assertFalse(result.started)
        self.assertEqual(result.artifacts, ())
        self.assertNotIn('synthetic secret', json.dumps(result.manifest()))

    def test_commands_and_unsafe_configuration_refused(self):
        for operation in ('claude', 'codex', 'echo hello', '$(id)', '../noop', '', None, []):
            self.assertEqual(self.runtime.execute(replace(self.request, operation=operation)).status, 'rejected')
        for changes in ({'network': True}, {'network': 0}, {'workspace_access': 'host'},
                        {'limits': {}}, {'workspace': None}):
            self.assertEqual(self.runtime.execute(replace(self.request, **changes)).status, 'rejected')
        with self.assertRaises(TypeError):
            SyntheticRequest(str(self.work), mounts=['/var/run/docker.sock'])

    def test_resource_deadline_and_capture_bounds_rejected(self):
        for field in Limits.__dataclass_fields__:
            for value in (0, -1, True, float('inf'), float('nan'), 10**30, '1'):
                with self.subTest(field=field, value=value):
                    request = replace(self.request, limits=replace(Limits(), **{field: value}))
                    self.assertEqual(self.runtime.execute(request).status, 'rejected')
        request = replace(self.request, limits=replace(Limits(), wall_seconds=1))
        self.assertEqual(self.runtime.execute(request).status, 'rejected')
        for mode in ('ro', 'rw'):
            self.assertEqual(self.runtime.execute(replace(self.request, workspace_access=mode)).status, 'unsupported')

    def test_cancellation_before_start_and_timeout_fail_closed(self):
        cancellation = Cancellation()
        cancellation.cancel()
        result = self.runtime.execute(self.request, cancellation)
        self.assertEqual(result.status, 'canceled')
        self.assertFalse(result.started)
        self.assertEqual(self.runtime.execute(self.request, object()).status, 'rejected')
        request = replace(self.request, operation='timeout-fixture')
        result = self.runtime.execute(request, Cancellation())
        self.assertEqual(result.status, 'unsupported')
        self.assertIn('terminate_then_kill', result.audit['unverified_guarantees'])
        self.assertIn('wall_time_limit', result.audit['unverified_guarantees'])


if __name__ == '__main__':
    unittest.main()
