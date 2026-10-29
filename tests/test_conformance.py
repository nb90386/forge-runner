"""Offline runner contracts. Mocked success never attests a real daemon."""
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from forge.conformance import main, run

IMAGE = 'audited@sha256:' + '1' * 64


class ConformanceTests(unittest.TestCase):
    def configured(self, **kwargs):
        return run(executable='/docker', socket='/socket', image=IMAGE,
                   approved_images=[IMAGE], live=True, **kwargs)

    def test_missing_opt_in_never_contacts_engine(self):
        with patch('forge.conformance.ContainerAdapter') as adapter:
            report = run()
        adapter.assert_not_called()
        self.assertEqual(report['status'], 'UNVERIFIED')
        self.assertEqual(set(report['checks'].values()), {'UNVERIFIED'})

    def test_approval_is_exact_and_required(self):
        with patch('forge.conformance.ContainerAdapter') as adapter:
            report = run(executable='/docker', socket='/socket', image=IMAGE,
                         approved_images=['audited:latest'], live=True)
        adapter.assert_not_called()
        self.assertEqual(report['status'], 'FAIL')

    def test_failure_keeps_unrun_checks_unverified_and_redacts(self):
        with patch('forge.conformance.ContainerAdapter', side_effect=ValueError('SECRET')):
            report = self.configured()
        self.assertEqual(report['checks']['prerequisites'], 'FAIL')
        self.assertEqual(report['checks']['disposable_isolation'], 'UNVERIFIED')
        self.assertNotIn('SECRET', json.dumps(report))

    def test_noop_or_skipped_conformance_cannot_pass(self):
        for failure in (False, True):
            with patch('forge.conformance.ContainerAdapter') as cls:
                cls.return_value._attested = False
                cls.return_value._failed = failure
                report = self.configured()
            self.assertEqual(report['status'], 'FAIL')

    def test_cleanup_failure_cannot_pass(self):
        with patch('forge.conformance.ContainerAdapter') as cls:
            cls.return_value._attested = True
            cls.return_value._failed = True
            report = self.configured()
        self.assertEqual(report['status'], 'FAIL')

    def test_completed_fixed_probes(self):
        with patch('forge.conformance.ContainerAdapter') as cls:
            cls.return_value._attested = True
            cls.return_value._failed = False
            report = self.configured()
            cls.return_value.conform.assert_called_once_with()
        self.assertEqual(report['status'], 'PASS')
        self.assertFalse(report['execution_authorized'])

    def test_cli_unverified_is_nonzero_structured_json(self):
        with patch('sys.stdout', new_callable=io.StringIO) as output:
            code = main([])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())['status'], 'UNVERIFIED')


class DiagnosticTests(unittest.TestCase):
    def adapter(self):
        from forge.container import ContainerAdapter, ContainerConfig
        with patch.object(ContainerConfig, 'validate'):
            return ContainerAdapter(ContainerConfig('/private/docker', '/private/socket', IMAGE))

    def report(self, adapter, diagnostics=True):
        def initialize(instance, config):
            instance.__dict__ = adapter.__dict__
        with patch('forge.conformance.ContainerAdapter.__init__', new=initialize):
            return run(executable='/private/docker', socket='/private/socket', image=IMAGE,
                       approved_images=[IMAGE], live=True, diagnostics=diagnostics)

    def test_result_failure_identifies_each_probe_and_stops(self):
        from forge.runtime import Limits
        limits = Limits()
        good = [ ('completed', 0, b'', b'', ()),
                 ('completed', 0, b'', b'', ()),
                 ('timeout', None, b'', b'', ()),
                 ('completed', 0, b'x' * limits.stdout_bytes, b'y' * limits.stderr_bytes, ()),
                 ('completed', 0, b'', b'', (('result.txt', b'synthetic artifact\n'),)),
                 ('canceled', None, b'', b'', ()) ]
        probes = ('probe', 'resource-fixture', 'timeout-fixture', 'capture-fixture',
                  'artifact-fixture', 'cancel-fixture')
        for index, probe in enumerate(probes):
            adapter = self.adapter()
            bad = ('completed', 99, b'SECRET /private/path', b'TOKEN=password', ())
            with self.subTest(probe=probe), \
                    patch.object(adapter, '_check_daemon'), \
                    patch.object(adapter, '_run', side_effect=good[:index] + [bad]) as execute:
                report = self.report(adapter)
            self.assertEqual(report['diagnostic'],
                             dict(probe=probe, stage='result', code='result_mismatch'))
            self.assertEqual(execute.call_count, index + 1)
            self.assertFalse(adapter._attested)
            self.assertEqual(set(report['guarantees'].values()), {'UNVERIFIED'})
            self.assertFalse(report['execution_authorized'])
            self.assertFalse(report['real_agent_execution'])
            for secret in ('SECRET', '/private/', 'password', IMAGE):
                self.assertNotIn(secret, json.dumps(report))

    def test_create_failure_cleanup_and_redaction(self):
        for cleanup in ('ok', 'remove', 'confirm', 'exception', 'interrupt'):
            adapter = self.adapter()
            calls = []
            def cli(args, **kwargs):
                calls.append(args[0])
                if args[0] == 'create':
                    return 1, b'SECRET', b'/private/path TOKEN=password'
                if args[0] == 'rm' and cleanup == 'exception':
                    raise OSError('SECRET /private/path')
                if args[0] == 'rm' and cleanup == 'interrupt':
                    raise KeyboardInterrupt('SECRET')
                if args[0] == 'ps':
                    return (1 if cleanup == 'confirm' else 0), (b'SECRET' if cleanup == 'remove' else b''), b''
                return 0, b'', b''
            with self.subTest(cleanup=cleanup), patch.object(adapter, '_check_daemon'), \
                    patch.object(adapter, '_check_image'), patch.object(adapter, '_cli', side_effect=cli):
                report = self.report(adapter)
            self.assertEqual(report['status'], 'FAIL')
            self.assertIn('rm', calls)
            expected = ('create' if cleanup == 'ok' else 'cleanup_remove' if cleanup in
                        ('exception', 'interrupt') else 'cleanup_confirm')
            self.assertEqual(report['diagnostic']['stage'], expected)
            self.assertEqual(adapter._failed, cleanup != 'ok')
            self.assertNotIn('SECRET', json.dumps(report))
            self.assertNotIn('/private/', json.dumps(report))
            if adapter._failed:
                with self.assertRaises(Exception): adapter.conform()

    def test_opt_in_and_allowlist(self):
        adapter = self.adapter()
        with patch.object(adapter, '_check_daemon', side_effect=ValueError('SECRET')):
            self.assertNotIn('diagnostic', self.report(adapter, diagnostics=False))
        for value in (('SECRET', 'start', 'refused'), ('probe', '/private/path', 'refused'),
                      ('probe', 'start', 'TOKEN=password'), None):
            adapter._diagnostic = value
            self.assertEqual(adapter.diagnostic(),
                             dict(probe='unknown', stage='unknown', code='refused'))

    def test_setup_diagnostics_forwarded_only_for_live(self):
        import test_container_setup as fixture
        args = ['--docker', '/docker', '--socket', '/socket', '--image', fixture.REF,
                '--expected-id', fixture.IID, '--diagnostics']
        with patch.object(fixture.setup, 'ContainerAdapter') as cls, \
                patch.object(fixture.setup, 'run', return_value={'status': 'FAIL'}) as live, \
                patch('sys.stdout', new_callable=io.StringIO):
            cls.return_value._json.return_value = [fixture.image()]
            self.assertEqual(fixture.setup.main(['live', *args]), 1)
            self.assertTrue(live.call_args.kwargs['diagnostics'])
        with patch('sys.stderr', new_callable=io.StringIO), self.assertRaises(SystemExit):
            fixture.setup.main(['audit', *args])

    def test_lifecycle_failure_stages_always_cleanup(self):
        from forge.runtime import Limits
        from forge.safety import SafetyError
        limits = Limits()
        cid = 'c' * 64
        for stage in ('image_check', 'create_id', 'restrictions', 'identity_recheck',
                      'start', 'stop', 'exit_state', 'artifacts', 'cleanup_remove'):
            adapter = self.adapter()
            host = dict(NetworkMode='none', ReadonlyRootfs=True, Privileged=False,
                        CapDrop=['ALL'], IpcMode='private', CgroupnsMode='host', NanoCpus=int(limits.cpu * 1000000000),
                        Memory=limits.memory_bytes, MemorySwap=limits.memory_bytes,
                        PidsLimit=limits.processes, SecurityOpt=['no-new-privileges:true'],
                        Tmpfs={'/workspace': 'rw,noexec,nosuid,nodev,size=16m,mode=1777'})
            obj = dict(HostConfig=host, Config=dict(User='65534:65534'),
                       State=dict(Running=False, ExitCode=0, Pid=0, Status='exited', StartedAt='2026-10-28T00:00:00Z', FinishedAt='2026-10-28T00:00:01Z'))
            if stage == 'restrictions': host['ReadonlyRootfs'] = False
            if stage == 'exit_state': obj['State']['Running'] = True
            calls = []
            def cli(args, **kwargs):
                calls.append(args[0])
                if args[0] == 'create':
                    return 0, (b'SECRET' if stage == 'create_id' else cid.encode()), b''
                if args[0] == 'start':
                    if stage == 'start': raise OSError('SECRET')
                    if stage == 'stop': raise TimeoutError('SECRET')
                    return 0, b'SECRET', b'TOKEN=password'
                if args[0] == 'stop': raise OSError('SECRET')
                return (1 if stage == 'cleanup_remove' and args[0] == 'rm' else 0), b'', b''
            checks = [None, None]
            if stage == 'image_check': checks[0] = SafetyError('SECRET')
            if stage == 'identity_recheck': checks[1] = SafetyError('SECRET')
            with self.subTest(stage=stage), patch.object(adapter, '_check_image', side_effect=checks), \
                    patch.object(adapter, '_inspect_container', return_value=obj), \
                    patch.object(adapter, '_cli', side_effect=cli):
                with self.assertRaises((Exception, KeyboardInterrupt)):
                    adapter._run('artifact-fixture' if stage == 'artifacts' else 'probe', limits)
            self.assertEqual(adapter.diagnostic()['stage'], stage)
            self.assertIn('rm', calls)
            self.assertIn('ps', calls)
            self.assertEqual(adapter._failed, stage == 'cleanup_remove')
            self.assertFalse(adapter._attested)
            self.assertNotIn('SECRET', json.dumps(adapter.diagnostic()))
